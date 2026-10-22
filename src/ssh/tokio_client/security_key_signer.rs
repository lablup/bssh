// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! russh [`Signer`](russh::Signer) that signs user authentication through a
//! FIDO security-key provider, following `identity_sign` in `sshconnect2.c`:
//! announce the touch when the key wants user presence, prompt for a PIN
//! once when the provider asks for one, and never block the async runtime
//! while the authenticator waits for the user.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::keys::ssh_encoding::Encode as _;
use russh::keys::ssh_key::HashAlg;
use russh::keys::ssh_key::private::KeypairData;
use zeroize::Zeroizing;

use crate::ssh::security_key::{
    ProviderSource, SK_FLAG_USER_PRESENCE_REQUIRED, SecurityKeyError, SecurityKeyProvider,
    SkAlgorithm, SkSignRequest, encode_signature, open_provider, resolve_provider_from_env,
};

/// Everything the provider needs from an `sk-*` private key file.
#[derive(Debug, Clone)]
pub(super) struct SecurityKeyIdentity {
    pub(super) algorithm: SkAlgorithm,
    application: String,
    key_handle: Zeroizing<Vec<u8>>,
    flags: u8,
    fingerprint: String,
    pub(super) path: PathBuf,
}

impl SecurityKeyIdentity {
    /// `Some` for authenticator-hosted keys, `None` for software keys.
    pub(super) fn from_private_key(key: &russh::keys::PrivateKey, path: &Path) -> Option<Self> {
        let (algorithm, application, key_handle, flags) = match key.key_data() {
            KeypairData::SkEd25519(sk) => (
                SkAlgorithm::Ed25519,
                sk.public().application().to_string(),
                sk.key_handle().to_vec(),
                sk.flags(),
            ),
            KeypairData::SkEcdsaSha2NistP256(sk) => (
                SkAlgorithm::EcdsaSha2NistP256,
                sk.public().application().to_string(),
                sk.key_handle().to_vec(),
                sk.flags(),
            ),
            _ => return None,
        };
        Some(Self {
            algorithm,
            application,
            key_handle: Zeroizing::new(key_handle),
            flags,
            fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
            path: path.to_path_buf(),
        })
    }

    fn wants_user_presence(&self) -> bool {
        self.flags & SK_FLAG_USER_PRESENCE_REQUIRED != 0
    }
}

/// Resolve and open the configured provider for one identity. Every failure
/// is reported before the key is offered, so the caller can move on to the
/// next identity without poisoning the transport.
pub(super) async fn open_security_key_provider(
    setting: Option<&str>,
    path: &Path,
) -> Result<Arc<dyn SecurityKeyProvider>, super::Error> {
    let unavailable = |reason: String| super::Error::SecurityKeyUnavailable {
        path: path.to_path_buf(),
        reason,
    };
    let source = resolve_provider_from_env(setting);
    match &source {
        ProviderSource::Disabled => {
            tracing::debug!(
                "ignoring authenticator-hosted key {} as no SecurityKeyProvider has been specified",
                path.display()
            );
            return Err(unavailable(SecurityKeyError::NoProvider.to_string()));
        }
        ProviderSource::Internal => {
            let error = SecurityKeyError::InternalUnavailable;
            crate::warningln!("SecurityKeyProvider internal: {error}");
            return Err(unavailable(error.to_string()));
        }
        ProviderSource::Library(_) => {}
    }
    let opened = tokio::task::spawn_blocking(move || open_provider(&source))
        .await
        .map_err(super::Error::JoinError)?;
    match opened {
        Ok(provider) => Ok(Arc::from(provider)),
        Err(error) => {
            crate::warningln!("{error}");
            Err(unavailable(error.to_string()))
        }
    }
}

/// Signs `to_sign` with the provider and returns it with the signature
/// appended, which is what russh expects back from a [`russh::Signer`].
#[derive(Debug)]
pub(super) struct SecurityKeySigner {
    provider: Arc<dyn SecurityKeyProvider>,
    identity: Arc<SecurityKeyIdentity>,
    /// `BatchMode no`: a touch notice may be printed and a PIN prompted.
    interactive: bool,
}

impl SecurityKeySigner {
    pub(super) fn new(
        provider: Arc<dyn SecurityKeyProvider>,
        identity: SecurityKeyIdentity,
        interactive: bool,
    ) -> Self {
        Self {
            provider,
            identity: Arc::new(identity),
            interactive,
        }
    }

    pub(super) async fn sign_blob(&self, data: Vec<u8>) -> Result<Vec<u8>, super::Error> {
        let failed = |reason: String| super::Error::SecurityKeySignFailed {
            path: self.identity.path.clone(),
            reason,
        };
        let notify = self.interactive && self.identity.wants_user_presence();
        let notify = notify && std::io::stderr().is_terminal();
        if notify {
            crate::diagnosticln!(
                "Confirm user presence for key {} {}",
                self.identity.algorithm.ssh_name(),
                self.identity.fingerprint
            );
        }
        let data = Arc::new(data);
        let mut pin: Option<Zeroizing<String>> = None;
        let mut retried = false;
        loop {
            let provider = Arc::clone(&self.provider);
            let identity = Arc::clone(&self.identity);
            let data = Arc::clone(&data);
            let attempt_pin = pin.clone();
            let result = tokio::task::spawn_blocking(move || {
                let request = SkSignRequest {
                    algorithm: identity.algorithm,
                    data: &data,
                    application: &identity.application,
                    key_handle: &identity.key_handle,
                    flags: identity.flags,
                };
                provider.sign(&request, attempt_pin.as_deref().map(String::as_str))
            })
            .await
            .map_err(super::Error::JoinError)?;
            match result {
                Ok(response) => {
                    if notify {
                        crate::diagnosticln!("User presence confirmed");
                    }
                    return encode_signature(self.identity.algorithm, &response)
                        .map_err(|error| failed(error.to_string()));
                }
                Err(SecurityKeyError::PinRequired)
                    if !retried && pin.is_none() && self.interactive =>
                {
                    retried = true;
                    pin = Some(self.prompt_pin().await?);
                }
                Err(error) => return Err(failed(error.to_string())),
            }
        }
    }

    async fn prompt_pin(&self) -> Result<Zeroizing<String>, super::Error> {
        let prompt = format!(
            "Enter PIN for {} key {}: ",
            self.identity.algorithm.ssh_name(),
            self.identity.path.display()
        );
        super::authentication::serialized_bounded_auth_prompt("security key PIN", || async {
            let prompt_task = tokio::task::spawn_blocking(move || {
                rpassword::prompt_password(prompt).map(Zeroizing::new)
            });
            prompt_task
                .await
                .map_err(super::Error::JoinError)?
                .map_err(super::Error::IoError)
        })
        .await
    }
}

impl russh::Signer for SecurityKeySigner {
    type Error = super::Error;

    async fn auth_sign(
        &mut self,
        _key: &russh::keys::agent::AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        let blob = self.sign_blob(to_sign.clone()).await?;
        let mut signed = to_sign;
        blob.as_slice().encode(&mut signed).map_err(|error| {
            super::Error::SecurityKeySignFailed {
                path: self.identity.path.clone(),
                reason: error.to_string(),
            }
        })?;
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::ssh::security_key::SkSignResponse;
    use russh::keys::ssh_key::private::SkEd25519 as SkEd25519Private;
    use russh::keys::ssh_key::public::{Ed25519PublicKey, SkEd25519 as SkEd25519Public};
    use russh::keys::ssh_key::{PrivateKey, private};

    fn sk_ed25519_key(flags: u8) -> PrivateKey {
        let public = SkEd25519Public::new(Ed25519PublicKey([9u8; 32]), "ssh:example");
        let private = SkEd25519Private::new(public, flags, vec![1, 2, 3, 4]).unwrap();
        PrivateKey::new(KeypairData::SkEd25519(private), "test").unwrap()
    }

    /// `(algorithm, data, application, key_handle, flags, had_pin)`
    type RecordedCall = (SkAlgorithm, Vec<u8>, String, Vec<u8>, u8, bool);

    #[derive(Debug, Default)]
    struct RecordingProvider {
        calls: Mutex<Vec<RecordedCall>>,
        fail_until_pin: bool,
    }

    impl SecurityKeyProvider for RecordingProvider {
        fn sign(
            &self,
            request: &SkSignRequest<'_>,
            pin: Option<&str>,
        ) -> Result<SkSignResponse, SecurityKeyError> {
            self.calls.lock().unwrap().push((
                request.algorithm,
                request.data.to_vec(),
                request.application.to_string(),
                request.key_handle.to_vec(),
                request.flags,
                pin.is_some(),
            ));
            if self.fail_until_pin && pin.is_none() {
                return Err(SecurityKeyError::PinRequired);
            }
            Ok(SkSignResponse {
                flags: request.flags,
                counter: 7,
                sig_r: Zeroizing::new(vec![0x5a; 64]),
                sig_s: Zeroizing::new(Vec::new()),
            })
        }

        fn describe(&self) -> String {
            "recording".to_string()
        }
    }

    #[test]
    fn identity_is_extracted_only_from_sk_private_keys() {
        let key = sk_ed25519_key(0x01);
        let identity = SecurityKeyIdentity::from_private_key(&key, Path::new("/k")).unwrap();
        assert_eq!(identity.algorithm, SkAlgorithm::Ed25519);
        assert_eq!(identity.application, "ssh:example");
        assert_eq!(&identity.key_handle[..], &[1, 2, 3, 4]);
        assert!(identity.wants_user_presence());
        assert!(identity.fingerprint.starts_with("SHA256:"));

        let software =
            PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap();
        assert!(SecurityKeyIdentity::from_private_key(&software, Path::new("/k")).is_none());
        let _ = private::KeypairData::Ed25519;
    }

    #[tokio::test]
    async fn signer_appends_the_provider_signature_to_the_request() {
        let key = sk_ed25519_key(0x01);
        let identity = SecurityKeyIdentity::from_private_key(&key, Path::new("/k")).unwrap();
        let provider = Arc::new(RecordingProvider::default());
        let mut signer = SecurityKeySigner::new(provider.clone(), identity, false);
        let to_sign = vec![0xaa, 0xbb, 0xcc];
        let signed = russh::Signer::auth_sign(
            &mut signer,
            &key.public_key().clone().into(),
            None,
            to_sign.clone(),
        )
        .await
        .unwrap();
        assert_eq!(&signed[..3], &to_sign[..]);
        let blob_len = u32::from_be_bytes(signed[3..7].try_into().unwrap()) as usize;
        let blob = &signed[7..];
        assert_eq!(blob.len(), blob_len);
        assert_eq!(&blob[4..30], b"sk-ssh-ed25519@openssh.com");
        assert_eq!(blob[blob.len() - 5], 0x01);
        assert_eq!(&blob[blob.len() - 4..], &7u32.to_be_bytes());

        let calls = provider.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (algorithm, data, application, key_handle, flags, had_pin) = &calls[0];
        assert_eq!(*algorithm, SkAlgorithm::Ed25519);
        assert_eq!(data, &to_sign, "the provider hashes the raw message itself");
        assert_eq!(application, "ssh:example");
        assert_eq!(key_handle, &[1, 2, 3, 4]);
        assert_eq!(*flags, 0x01);
        assert!(!had_pin);
    }

    #[tokio::test]
    async fn pin_required_in_batch_mode_fails_without_prompting() {
        let key = sk_ed25519_key(0x05);
        let identity = SecurityKeyIdentity::from_private_key(&key, Path::new("/k")).unwrap();
        let provider = Arc::new(RecordingProvider {
            fail_until_pin: true,
            ..RecordingProvider::default()
        });
        let signer = SecurityKeySigner::new(provider.clone(), identity, false);
        let error = signer.sign_blob(vec![1]).await.unwrap_err();
        match error {
            super::super::Error::SecurityKeySignFailed { path, reason } => {
                assert_eq!(path, Path::new("/k"));
                assert!(reason.contains("PIN required"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(provider.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn provider_errors_name_the_identity() {
        #[derive(Debug)]
        struct Absent;
        impl SecurityKeyProvider for Absent {
            fn sign(
                &self,
                _: &SkSignRequest<'_>,
                _: Option<&str>,
            ) -> Result<SkSignResponse, SecurityKeyError> {
                Err(SecurityKeyError::DeviceNotFound)
            }
            fn describe(&self) -> String {
                "absent".to_string()
            }
        }
        let key = sk_ed25519_key(0x01);
        let identity = SecurityKeyIdentity::from_private_key(&key, Path::new("/id_sk")).unwrap();
        let signer = SecurityKeySigner::new(Arc::new(Absent), identity, true);
        let error = signer.sign_blob(vec![1]).await.unwrap_err().to_string();
        assert!(error.contains("/id_sk"), "{error}");
        assert!(error.contains("device not found"), "{error}");
    }

    #[tokio::test]
    async fn disabled_and_internal_providers_are_skipped_before_offering_the_key() {
        let path = Path::new("/home/u/.ssh/id_ed25519_sk");
        let error = open_security_key_provider(Some("none"), path)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            super::super::Error::SecurityKeyUnavailable { .. }
        ));
        assert!(super::super::authentication::is_retryable_rejection(&error));

        let error = open_security_key_provider(Some("internal"), path)
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("built-in security key support is not available"),
            "{message}"
        );
        assert!(message.contains("id_ed25519_sk"), "{message}");

        let error = open_security_key_provider(Some("/nonexistent/provider.so"), path)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("dlopen failed"), "{error}");
        assert!(super::super::authentication::is_retryable_rejection(&error));
    }
}

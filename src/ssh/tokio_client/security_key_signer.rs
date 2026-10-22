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
//!
//! A provider failure (device absent, PIN required in `BatchMode`, provider
//! error) skips the identity the way a failed `identity_sign` does in
//! OpenSSH: the signer hands russh the request back unsigned, which russh
//! then does not send, and [`authenticate_declinable`] stops waiting for a
//! server reply that will never come. The transport stays usable for the
//! next identity.

use std::future::Future;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use tokio::sync::Notify;

use russh::keys::ssh_encoding::Encode as _;
use russh::keys::ssh_key::HashAlg;
use russh::keys::ssh_key::private::KeypairData;
use zeroize::Zeroizing;

use crate::ssh::security_key::{
    ProviderSource, SK_FLAG_USER_PRESENCE_REQUIRED, SecurityKeyError, SecurityKeyProvider,
    SkAlgorithm, SkSignRequest, encode_signature, open_provider, resolve_provider_from_env,
};

/// Everything the provider needs from an `sk-*` private key file.
#[derive(Clone)]
pub(super) struct SecurityKeyIdentity {
    pub(super) algorithm: SkAlgorithm,
    application: String,
    key_handle: Zeroizing<Vec<u8>>,
    flags: u8,
    fingerprint: String,
    pub(super) path: PathBuf,
}

/// The key handle is the authenticator's wrapped credential, so `Debug`
/// (which reaches `-vvv` traces through the signer) prints only its length.
impl std::fmt::Debug for SecurityKeyIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityKeyIdentity")
            .field("algorithm", &self.algorithm)
            .field("application", &self.application)
            .field(
                "key_handle",
                &format_args!("<redacted, {} bytes>", self.key_handle.len()),
            )
            .field("flags", &self.flags)
            .field("fingerprint", &self.fingerprint)
            .field("path", &self.path)
            .finish()
    }
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

/// Serializes every provider call in the process. sk-api makes no
/// thread-safety promise and OpenSSH never calls a provider concurrently
/// (each signature runs in its own `ssh-sk-helper`), while bssh may
/// authenticate to many hosts at once.
///
/// The lock is an async FIFO mutex acquired before the blocking task is
/// spawned, and the owned guard moves into that task. Waiting for a touch on
/// one host therefore occupies a single blocking thread rather than one per
/// queued host, which would otherwise exhaust tokio's blocking pool and stall
/// `tokio::fs` and DNS for every connection. A connection that times out
/// while queued leaves the queue without ever reaching the provider, so the
/// user is never asked to touch the key for a dead connection. Once the call
/// has started, the guard lives in the blocking task, so a dropped
/// authentication future cannot release it while the provider is running.
static PROVIDER_CALL_LOCK: LazyLock<Arc<tokio::sync::Mutex<()>>> =
    LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

/// Records a signature the signer declined to produce.
#[derive(Debug, Default)]
pub(super) struct SignatureDecline {
    error: Mutex<Option<super::Error>>,
    notify: Notify,
}

impl SignatureDecline {
    fn record(&self, error: super::Error) {
        *self
            .error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
        self.notify.notify_one();
    }

    fn take(&self) -> Option<super::Error> {
        self.error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// Drive one russh public-key or certificate exchange that signs with a
/// [`SecurityKeySigner`], ending it as soon as the signer declines.
///
/// When the signer declines, it has returned the request unsigned. russh's
/// session loop compares the returned buffer with the request it handed out
/// and, finding it unchanged, sends nothing; the `Msg::Signed` that carries
/// it is queued on russh's bounded handle channel in the same poll, because
/// authentication holds the handle exclusively and that channel is otherwise
/// empty. The handle-side future then waits for a server reply that will
/// never arrive, so it is dropped here (its receive is cancellation-safe) and
/// the recorded signing error is returned instead. The server never saw a
/// signed request, so the next identity can be offered on the same transport,
/// as OpenSSH's `sign_and_send_pubkey` failure path does.
pub(super) async fn authenticate_declinable<T, F>(
    decline: &SignatureDecline,
    exchange: F,
) -> Result<T, super::Error>
where
    F: Future<Output = Result<T, super::Error>>,
{
    tokio::pin!(exchange);
    let result = tokio::select! {
        biased;
        result = &mut exchange => result,
        () = decline.notify.notified() => Err(decline
            .take()
            .unwrap_or_else(|| super::Error::AuthenticationPolicy(
                "security key signature declined".to_string(),
            ))),
    };
    match decline.take() {
        Some(error) => Err(error),
        None => result,
    }
}

/// Resolve the provider for an `sk-*` identity file before its private half
/// is decrypted, as OpenSSH skips such keys from their public half when no
/// provider is configured. The public key of an OpenSSH-format private key is
/// stored unencrypted, so this never prompts. Returns `None` for software
/// keys and for files that are not OpenSSH-format private keys (the regular
/// loader reports those).
pub(super) async fn preflight_security_key_file(
    setting: Option<&str>,
    path: &Path,
) -> Result<Option<Arc<dyn SecurityKeyProvider>>, super::Error> {
    let Ok(text) = tokio::fs::read_to_string(path).await.map(Zeroizing::new) else {
        return Ok(None);
    };
    let Ok(key) = russh::keys::ssh_key::PrivateKey::from_openssh(text.as_bytes()) else {
        return Ok(None);
    };
    if !matches!(
        key.algorithm(),
        russh::keys::ssh_key::Algorithm::SkEd25519
            | russh::keys::ssh_key::Algorithm::SkEcdsaSha2NistP256
    ) {
        return Ok(None);
    }
    open_security_key_provider(setting, path).await.map(Some)
}

/// Signs `to_sign` with the provider and returns it with the signature
/// appended, which is what russh expects back from a [`russh::Signer`].
#[derive(Debug)]
pub(super) struct SecurityKeySigner {
    provider: Arc<dyn SecurityKeyProvider>,
    identity: Arc<SecurityKeyIdentity>,
    /// `BatchMode no`: a touch notice may be printed and a PIN prompted.
    interactive: bool,
    decline: Arc<SignatureDecline>,
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
            decline: Arc::new(SignatureDecline::default()),
        }
    }

    /// Where a declined signature is reported; pass it to
    /// [`authenticate_declinable`] around the russh exchange.
    pub(super) fn decline(&self) -> Arc<SignatureDecline> {
        Arc::clone(&self.decline)
    }

    pub(super) async fn sign_blob(&self, data: Vec<u8>) -> Result<Vec<u8>, super::Error> {
        let failed = |reason: String| super::Error::SecurityKeySignFailed {
            path: self.identity.path.clone(),
            reason,
        };
        // `sshsk_sign` refuses a malformed key before opening the provider;
        // doing the same here also keeps the touch notice from appearing for
        // a signature that will never be attempted.
        SkSignRequest {
            algorithm: self.identity.algorithm,
            data: &data,
            application: &self.identity.application,
            key_handle: &self.identity.key_handle,
            flags: self.identity.flags,
        }
        .validate()
        .map_err(|error| failed(error.to_string()))?;
        let notify = self.interactive && self.identity.wants_user_presence();
        let notify = notify && std::io::stderr().is_terminal();
        let data = Arc::new(data);
        let mut pin: Option<Zeroizing<String>> = None;
        let mut retried = false;
        loop {
            let provider = Arc::clone(&self.provider);
            let identity = Arc::clone(&self.identity);
            let data = Arc::clone(&data);
            let attempt_pin = pin.clone();
            let serialized = Arc::clone(&PROVIDER_CALL_LOCK).lock_owned().await;
            // Announced only once this identity holds the provider, so the
            // notice matches the authenticator that is actually waiting
            // (`identity_sign` notifies again on the PIN retry as well).
            if notify {
                crate::diagnosticln!(
                    "Confirm user presence for key {} {}",
                    self.identity.algorithm.ssh_name(),
                    self.identity.fingerprint
                );
            }
            let result = tokio::task::spawn_blocking(move || {
                let _serialized = serialized;
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
        let signed = match self.sign_blob(to_sign.clone()).await {
            Ok(blob) => {
                let mut signed = to_sign.clone();
                blob.as_slice()
                    .encode(&mut signed)
                    .map(|()| signed)
                    .map_err(|error| super::Error::SecurityKeySignFailed {
                        path: self.identity.path.clone(),
                        reason: error.to_string(),
                    })
            }
            Err(error) => Err(error),
        };
        match signed {
            Ok(signed) => Ok(signed),
            Err(error) => {
                // OpenSSH reports "sign_and_send_pubkey: signing failed for
                // ..." and moves on to the next identity.
                match &error {
                    super::Error::SecurityKeySignFailed { .. } => crate::warningln!("{error}"),
                    other => crate::warningln!(
                        "security key signing failed for {}: {other}",
                        self.identity.path.display()
                    ),
                }
                self.decline.record(error);
                // Unchanged length: russh sends nothing for this request.
                Ok(to_sign)
            }
        }
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

    #[test]
    fn identity_debug_output_redacts_the_key_handle() {
        let public = SkEd25519Public::new(Ed25519PublicKey([9u8; 32]), "ssh:example");
        let handle = vec![0xde, 0xad, 0xbe, 0xef, 0x42];
        let private = SkEd25519Private::new(public, 0x01, handle).unwrap();
        let key = PrivateKey::new(KeypairData::SkEd25519(private), "test").unwrap();
        let identity = SecurityKeyIdentity::from_private_key(&key, Path::new("/k")).unwrap();
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("<redacted, 5 bytes>"), "{rendered}");
        for leaked in ["222, 173, 190, 239", "0xde", "de, ad", "deadbeef"] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
        let signer =
            SecurityKeySigner::new(Arc::new(RecordingProvider::default()), identity, false);
        assert!(!format!("{signer:?}").contains("222, 173, 190, 239"));
    }

    #[tokio::test]
    async fn a_key_without_an_application_never_reaches_the_provider() {
        let public = SkEd25519Public::new(Ed25519PublicKey([9u8; 32]), "");
        let private = SkEd25519Private::new(public, 0x01, vec![1, 2]).unwrap();
        let key = PrivateKey::new(KeypairData::SkEd25519(private), "test").unwrap();
        let identity = SecurityKeyIdentity::from_private_key(&key, Path::new("/k")).unwrap();
        let provider = Arc::new(RecordingProvider::default());
        let signer = SecurityKeySigner::new(provider.clone(), identity, false);
        let error = signer.sign_blob(vec![1]).await.unwrap_err();
        assert!(
            matches!(
                &error,
                super::super::Error::SecurityKeySignFailed { reason, .. }
                    if reason.contains("no application")
            ),
            "{error:?}"
        );
        assert!(provider.calls.lock().unwrap().is_empty());
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn provider_calls_never_overlap_across_signers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug, Default)]
        struct OverlapProbe {
            in_flight: AtomicUsize,
            max_in_flight: AtomicUsize,
        }
        impl SecurityKeyProvider for OverlapProbe {
            fn sign(
                &self,
                request: &SkSignRequest<'_>,
                _: Option<&str>,
            ) -> Result<SkSignResponse, SecurityKeyError> {
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_in_flight.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(30));
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(SkSignResponse {
                    flags: request.flags,
                    counter: 1,
                    sig_r: Zeroizing::new(vec![0x5a; 64]),
                    sig_s: Zeroizing::new(Vec::new()),
                })
            }
            fn describe(&self) -> String {
                "overlap-probe".to_string()
            }
        }

        let provider = Arc::new(OverlapProbe::default());
        let key = sk_ed25519_key(0x00);
        let tasks = (0..4)
            .map(|_| {
                let identity =
                    SecurityKeyIdentity::from_private_key(&key, Path::new("/k")).unwrap();
                let signer = SecurityKeySigner::new(provider.clone(), identity, false);
                tokio::spawn(async move { signer.sign_blob(vec![1, 2, 3]).await })
            })
            .collect::<Vec<_>>();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(provider.max_in_flight.load(Ordering::SeqCst), 1);
    }

    /// A provider that blocks inside `sign` until released, standing in for
    /// an authenticator that waits for a touch.
    #[derive(Debug, Default)]
    struct GatedProvider {
        calls: std::sync::atomic::AtomicUsize,
        open: Mutex<bool>,
        opened: std::sync::Condvar,
    }

    impl GatedProvider {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn release(&self) {
            *self.open.lock().unwrap_or_else(|e| e.into_inner()) = true;
            self.opened.notify_all();
        }

        async fn wait_for_calls(&self, expected: usize) {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
            while self.calls() < expected {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "provider never reached {expected} calls"
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    }

    impl SecurityKeyProvider for GatedProvider {
        fn sign(
            &self,
            request: &SkSignRequest<'_>,
            _: Option<&str>,
        ) -> Result<SkSignResponse, SecurityKeyError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
            while !*open {
                open = self.opened.wait(open).unwrap_or_else(|e| e.into_inner());
            }
            Ok(SkSignResponse {
                flags: request.flags,
                counter: 1,
                sig_r: Zeroizing::new(vec![0x5a; 64]),
                sig_s: Zeroizing::new(Vec::new()),
            })
        }

        fn describe(&self) -> String {
            "gated".to_string()
        }
    }

    /// Releases the gate even when an assertion fails, so a blocked provider
    /// thread never outlives the test.
    struct ReleaseOnDrop(Arc<GatedProvider>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    fn gated_signer(provider: &Arc<GatedProvider>) -> SecurityKeySigner {
        let key = sk_ed25519_key(0x00);
        let identity = SecurityKeyIdentity::from_private_key(&key, Path::new("/k")).unwrap();
        SecurityKeySigner::new(
            Arc::clone(provider) as Arc<dyn SecurityKeyProvider>,
            identity,
            false,
        )
    }

    /// A connection that gives up (ConnectTimeout) while another host holds
    /// the authenticator must leave the queue: it must never reach the
    /// provider afterwards and ask for a touch nobody is waiting for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_queued_signature_never_reaches_the_provider() {
        let provider = Arc::new(GatedProvider::default());
        let _release = ReleaseOnDrop(Arc::clone(&provider));

        let holder = gated_signer(&provider);
        let holder = tokio::spawn(async move { holder.sign_blob(vec![1]).await });
        provider.wait_for_calls(1).await;

        let queued = gated_signer(&provider);
        let queued = tokio::spawn(async move { queued.sign_blob(vec![2]).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        queued.abort();
        assert!(queued.await.unwrap_err().is_cancelled());

        provider.release();
        holder.await.unwrap().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            provider.calls(),
            1,
            "the cancelled signature was still sent to the provider"
        );
    }

    /// Hosts queued behind a touch must not each pin a blocking thread: with
    /// a small blocking pool, unrelated `spawn_blocking` work (tokio::fs, DNS)
    /// still has to run while the authenticator waits.
    #[test]
    fn queued_signatures_do_not_occupy_blocking_threads() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let provider = Arc::new(GatedProvider::default());
        let release = ReleaseOnDrop(Arc::clone(&provider));
        runtime.block_on(async {
            let signers = (0..4)
                .map(|index| {
                    let signer = gated_signer(&provider);
                    tokio::spawn(async move { signer.sign_blob(vec![index]).await })
                })
                .collect::<Vec<_>>();
            provider.wait_for_calls(1).await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let unrelated = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::task::spawn_blocking(|| 42),
            )
            .await;
            provider.release();
            assert_eq!(
                unrelated
                    .expect("blocking pool exhausted by queued security-key signers")
                    .unwrap(),
                42
            );
            for signer in signers {
                signer.await.unwrap().unwrap();
            }
        });
        drop(release);
        drop(runtime);
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

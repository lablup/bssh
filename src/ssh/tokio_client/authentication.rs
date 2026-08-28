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

//! SSH authentication methods and server verification.
//!
//! This module provides authentication mechanisms including:
//! - Password authentication
//! - Private key authentication (file or in-memory)
//! - Public key authentication
//! - SSH agent authentication
//! - Keyboard-interactive authentication
//!
//! It also provides server verification methods via `ServerCheckMethod`.

use russh::client::{Handle, Handler};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// An authentification token.
///
/// Used when creating a [`Client`] for authentification.
/// Supports password, private key, public key, SSH agent, and keyboard interactive authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMethod {
    Password(Zeroizing<String>),
    PrivateKey {
        /// entire contents of private key file
        key_data: Zeroizing<String>,
        key_pass: Option<Zeroizing<String>>,
    },
    PrivateKeyFile {
        key_file_path: PathBuf,
        key_pass: Option<Zeroizing<String>>,
    },
    PrivateKeyFileWithPolicy {
        key_file_path: PathBuf,
        key_pass: Option<Zeroizing<String>>,
        accepted_algorithms: Vec<String>,
        allow_passphrase_prompt: bool,
        use_keychain: bool,
    },
    OpenSshCertificateFile {
        key_file_path: PathBuf,
        certificate_file_path: PathBuf,
        allow_passphrase_prompt: bool,
        use_keychain: bool,
        key_pass: Option<Zeroizing<String>>,
        accepted_algorithms: Vec<String>,
    },
    PasswordPrompt {
        attempts: u32,
    },
    Methods(Vec<AuthMethod>),
    #[cfg(not(target_os = "windows"))]
    PublicKeyFile {
        key_file_path: PathBuf,
    },
    #[cfg(not(target_os = "windows"))]
    Agent,
    #[cfg(not(target_os = "windows"))]
    AgentWithPolicy {
        accepted_algorithms: Vec<String>,
    },
    #[cfg(not(target_os = "windows"))]
    AgentPublicKeyFile {
        key_file_path: PathBuf,
        accepted_algorithms: Vec<String>,
    },
    #[cfg(not(target_os = "windows"))]
    AgentCertificateFile {
        certificate_file_path: PathBuf,
        accepted_algorithms: Vec<String>,
    },
    KeyboardInteractive(AuthKeyboardInteractive),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PromptResponse {
    exact: bool,
    prompt: String,
    response: Zeroizing<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct AuthKeyboardInteractive {
    /// Hnts to the server the preferred methods to be used for authentication.
    submethods: Option<String>,
    responses: Vec<PromptResponse>,
}

impl AuthMethod {
    /// Convenience method to create a [`AuthMethod`] from a string literal.
    pub fn with_password(password: &str) -> Self {
        Self::Password(Zeroizing::new(password.to_string()))
    }

    pub fn with_key(key: &str, passphrase: Option<&str>) -> Self {
        Self::PrivateKey {
            key_data: Zeroizing::new(key.to_string()),
            key_pass: passphrase.map(|p| Zeroizing::new(p.to_string())),
        }
    }

    pub fn with_key_file<T: AsRef<std::path::Path>>(
        key_file_path: T,
        passphrase: Option<&str>,
    ) -> Self {
        Self::PrivateKeyFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            key_pass: passphrase.map(|p| Zeroizing::new(p.to_string())),
        }
    }

    pub fn with_key_file_policy<T: AsRef<std::path::Path>>(
        key_file_path: T,
        passphrase: Option<&str>,
        accepted_algorithms: Vec<String>,
    ) -> Self {
        Self::PrivateKeyFileWithPolicy {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            key_pass: passphrase.map(|p| Zeroizing::new(p.to_string())),
            accepted_algorithms,
            allow_passphrase_prompt: false,
            use_keychain: false,
        }
    }

    pub fn with_certificate_file<T: AsRef<std::path::Path>, U: AsRef<std::path::Path>>(
        key_file_path: T,
        certificate_file_path: U,
        passphrase: Option<&str>,
        accepted_algorithms: Vec<String>,
    ) -> Self {
        Self::OpenSshCertificateFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            certificate_file_path: certificate_file_path.as_ref().to_path_buf(),
            key_pass: passphrase.map(|p| Zeroizing::new(p.to_string())),
            accepted_algorithms,
            allow_passphrase_prompt: false,
            use_keychain: false,
        }
    }

    pub(crate) fn with_configured_key_file<T: AsRef<std::path::Path>>(
        key_file_path: T,
        accepted_algorithms: Vec<String>,
        allow_passphrase_prompt: bool,
        use_keychain: bool,
    ) -> Self {
        Self::PrivateKeyFileWithPolicy {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            key_pass: None,
            accepted_algorithms,
            allow_passphrase_prompt,
            use_keychain,
        }
    }

    pub(crate) fn with_configured_certificate_file<
        T: AsRef<std::path::Path>,
        U: AsRef<std::path::Path>,
    >(
        key_file_path: T,
        certificate_file_path: U,
        accepted_algorithms: Vec<String>,
        allow_passphrase_prompt: bool,
        use_keychain: bool,
    ) -> Self {
        Self::OpenSshCertificateFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            certificate_file_path: certificate_file_path.as_ref().to_path_buf(),
            key_pass: None,
            accepted_algorithms,
            allow_passphrase_prompt,
            use_keychain,
        }
    }

    pub fn with_password_prompt(attempts: u32) -> Self {
        Self::PasswordPrompt { attempts }
    }

    pub fn with_methods(methods: Vec<Self>) -> Self {
        match methods.as_slice() {
            [method] => method.clone(),
            _ => Self::Methods(methods),
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn with_public_key_file<T: AsRef<std::path::Path>>(key_file_path: T) -> Self {
        Self::PublicKeyFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
        }
    }

    /// Creates a new SSH agent authentication method.
    ///
    /// This will attempt to authenticate using all identities available in the SSH agent.
    /// The SSH agent must be running and the SSH_AUTH_SOCK environment variable must be set.
    ///
    /// # Example
    /// ```no_run
    /// use bssh::ssh::tokio_client::AuthMethod;
    ///
    /// let auth = AuthMethod::with_agent();
    /// ```
    ///
    /// # Platform Support
    /// This method is only available on Unix-like systems (Linux, macOS, etc.).
    /// It is not available on Windows.
    #[cfg(not(target_os = "windows"))]
    pub fn with_agent() -> Self {
        Self::Agent
    }

    #[cfg(not(target_os = "windows"))]
    pub fn with_agent_policy(accepted_algorithms: Vec<String>) -> Self {
        Self::AgentWithPolicy {
            accepted_algorithms,
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub(crate) fn with_agent_public_key_file<T: AsRef<std::path::Path>>(
        key_file_path: T,
        accepted_algorithms: Vec<String>,
    ) -> Self {
        Self::AgentPublicKeyFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            accepted_algorithms,
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn with_agent_certificate_file<T: AsRef<std::path::Path>>(
        certificate_file_path: T,
        accepted_algorithms: Vec<String>,
    ) -> Self {
        Self::AgentCertificateFile {
            certificate_file_path: certificate_file_path.as_ref().to_path_buf(),
            accepted_algorithms,
        }
    }

    pub const fn with_keyboard_interactive(auth: AuthKeyboardInteractive) -> Self {
        Self::KeyboardInteractive(auth)
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Password(_) | Self::PasswordPrompt { .. } => "password",
            Self::KeyboardInteractive(_) => "keyboard-interactive",
            Self::Methods(_) => "multiple",
            _ => "publickey",
        }
    }

    fn identity_description(&self) -> Option<String> {
        match self {
            Self::PrivateKeyFile { key_file_path, .. }
            | Self::PrivateKeyFileWithPolicy { key_file_path, .. } => {
                Some(key_file_path.display().to_string())
            }
            #[cfg(not(target_os = "windows"))]
            Self::PublicKeyFile { key_file_path }
            | Self::AgentPublicKeyFile { key_file_path, .. } => {
                Some(key_file_path.display().to_string())
            }
            Self::OpenSshCertificateFile {
                key_file_path,
                certificate_file_path,
                ..
            } => Some(format!(
                "{} (key {})",
                certificate_file_path.display(),
                key_file_path.display()
            )),
            Self::AgentCertificateFile {
                #[cfg(not(target_os = "windows"))]
                certificate_file_path,
                ..
            } => Some(certificate_file_path.display().to_string()),
            _ => None,
        }
    }
}

impl AuthKeyboardInteractive {
    pub fn new() -> Self {
        Default::default()
    }

    /// Hnts to the server the preferred methods to be used for authentication.
    pub fn with_submethods(mut self, submethods: impl Into<String>) -> Self {
        self.submethods = Some(submethods.into());
        self
    }

    /// Adds a response to the list of responses for a given prompt.
    ///
    /// The comparison for the prompt is done using a "contains".
    pub fn with_response(mut self, prompt: impl Into<String>, response: impl Into<String>) -> Self {
        self.responses.push(PromptResponse {
            exact: false,
            prompt: prompt.into(),
            response: Zeroizing::new(response.into()),
        });

        self
    }

    /// Adds a response to the list of responses for a given exact prompt.
    pub fn with_response_exact(
        mut self,
        prompt: impl Into<String>,
        response: impl Into<String>,
    ) -> Self {
        self.responses.push(PromptResponse {
            exact: true,
            prompt: prompt.into(),
            response: Zeroizing::new(response.into()),
        });

        self
    }
}

impl PromptResponse {
    fn matches(&self, received_prompt: &str) -> bool {
        if self.exact {
            self.prompt.eq(received_prompt)
        } else {
            received_prompt.contains(&self.prompt)
        }
    }
}

impl From<AuthKeyboardInteractive> for AuthMethod {
    fn from(value: AuthKeyboardInteractive) -> Self {
        Self::with_keyboard_interactive(value)
    }
}

/// Server host key verification methods.
///
/// These methods control how the client verifies the server's host key during connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServerCheckMethod {
    /// No verification - accept any host key (insecure, for testing only)
    NoCheck,
    /// Verify against a specific base64 encoded public key
    PublicKey(String),
    /// Verify against a public key file
    PublicKeyFile(String),
    /// Use default known_hosts file (~/.ssh/known_hosts)
    DefaultKnownHostsFile,
    /// Use a specific known_hosts file path
    KnownHostsFile(String),
    /// Verify against several known_hosts files in declared lookup order.
    KnownHostsFiles(Vec<String>),
    /// Trust On First Use across several read stores, recording only to the
    /// first explicitly configured user store when one exists.
    AcceptNewKnownHostsFiles {
        files: Vec<String>,
        write_path: Option<String>,
    },
    /// Trust On First Use against a specific known_hosts file path:
    /// matching keys are accepted, unknown hosts are recorded and accepted,
    /// changed keys are rejected (OpenSSH `StrictHostKeyChecking=accept-new`)
    AcceptNewKnownHostsFile(String),
    /// Trust On First Use for the lifetime of this process only.
    ///
    /// Used when `StrictHostKeyChecking=accept-new` is requested but no
    /// default known_hosts path can be determined. This keeps the default from
    /// becoming unconditional `NoCheck`: the first key seen for a host:port is
    /// accepted, and a different key later in the same run is rejected.
    AcceptNewInMemory,
    /// Use `alias` as the known-hosts identity for the wrapped verification
    /// method. The alias has logical port 22 so it remains unbracketed even
    /// when the network connection uses a non-default port.
    HostKeyAlias {
        alias: String,
        method: Box<ServerCheckMethod>,
    },
}

impl ServerCheckMethod {
    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_public_key(key: &str) -> Self {
        Self::PublicKey(key.to_string())
    }

    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_public_key_file(key_file_name: &str) -> Self {
        Self::PublicKeyFile(key_file_name.to_string())
    }

    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_known_hosts_file(known_hosts_file: &str) -> Self {
        Self::KnownHostsFile(known_hosts_file.to_string())
    }

    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_accept_new_known_hosts_file(known_hosts_file: &str) -> Self {
        Self::AcceptNewKnownHostsFile(known_hosts_file.to_string())
    }
}

pub(crate) fn public_key_allowed(
    algorithm: &russh::keys::ssh_key::Algorithm,
    accepted: &[String],
) -> bool {
    if accepted.is_empty() {
        return true;
    }
    if matches!(algorithm, russh::keys::ssh_key::Algorithm::Rsa { .. }) {
        return accepted.iter().any(|candidate| {
            matches!(
                candidate.as_str(),
                "rsa-sha2-512" | "rsa-sha2-256" | "ssh-rsa"
            )
        });
    }
    accepted.contains(&algorithm.to_string())
}

fn policy_hashes(
    algorithm: &russh::keys::ssh_key::Algorithm,
    accepted: &[String],
) -> Vec<Option<russh::keys::ssh_key::HashAlg>> {
    if !matches!(algorithm, russh::keys::ssh_key::Algorithm::Rsa { .. }) {
        return accepted
            .iter()
            .any(|candidate| candidate == &algorithm.to_string())
            .then_some(None)
            .into_iter()
            .collect();
    }

    let mut hashes = Vec::new();
    for candidate in accepted {
        let hash = match candidate.as_str() {
            "rsa-sha2-512" => Some(Some(russh::keys::ssh_key::HashAlg::Sha512)),
            "rsa-sha2-256" => Some(Some(russh::keys::ssh_key::HashAlg::Sha256)),
            "ssh-rsa" => Some(None),
            _ => None,
        };
        if let Some(hash) = hash
            && !hashes.contains(&hash)
        {
            hashes.push(hash);
        }
    }
    hashes
}

pub(crate) fn certificate_allowed(
    certificate: &russh::keys::ssh_key::Certificate,
    accepted: &[String],
) -> bool {
    if accepted.is_empty() {
        return true;
    }

    let algorithm = certificate.algorithm();
    if matches!(algorithm, russh::keys::ssh_key::Algorithm::Rsa { .. }) {
        return accepted.iter().any(|candidate| {
            matches!(
                candidate.as_str(),
                "rsa-sha2-512-cert-v01@openssh.com"
                    | "rsa-sha2-256-cert-v01@openssh.com"
                    | "ssh-rsa-cert-v01@openssh.com"
            )
        });
    }

    accepted.contains(&algorithm.to_certificate_type().to_string())
}

pub(crate) fn local_certificate_allowed(
    certificate: &russh::keys::ssh_key::Certificate,
    accepted: &[String],
) -> bool {
    accepted.is_empty() || !certificate_policy_hashes(&certificate.algorithm(), accepted).is_empty()
}

fn certificate_policy_hashes(
    algorithm: &russh::keys::ssh_key::Algorithm,
    accepted: &[String],
) -> Vec<Option<russh::keys::ssh_key::HashAlg>> {
    if !matches!(algorithm, russh::keys::ssh_key::Algorithm::Rsa { .. }) {
        return accepted
            .contains(&algorithm.to_certificate_type().to_string())
            .then_some(None)
            .into_iter()
            .collect();
    }

    let mut hashes = Vec::new();
    for candidate in accepted {
        let hash = match candidate.as_str() {
            "rsa-sha2-512-cert-v01@openssh.com" => {
                Some(Some(russh::keys::ssh_key::HashAlg::Sha512))
            }
            "rsa-sha2-256-cert-v01@openssh.com" => {
                Some(Some(russh::keys::ssh_key::HashAlg::Sha256))
            }
            "ssh-rsa-cert-v01@openssh.com" => Some(None),
            _ => None,
        };
        if let Some(hash) = hash
            && !hashes.contains(&hash)
        {
            hashes.push(hash);
        }
    }
    hashes
}

#[cfg(not(target_os = "windows"))]
const AGENT_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(not(target_os = "windows"))]
async fn bounded_agent_operation<T, F>(
    action: &'static str,
    operation: F,
) -> Result<T, super::Error>
where
    F: std::future::Future<Output = Result<T, super::Error>>,
{
    tokio::time::timeout(AGENT_OPERATION_TIMEOUT, operation)
        .await
        .map_err(|_| super::Error::AgentOperationTimeout {
            action,
            seconds: AGENT_OPERATION_TIMEOUT.as_secs(),
        })?
}

const AUTH_PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
static AUTH_PROMPT_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
static KEY_USER_INTERACTION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn record_key_user_interaction() {
    KEY_USER_INTERACTION_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

async fn bounded_auth_prompt<T, F>(prompt: &'static str, operation: F) -> Result<T, super::Error>
where
    F: std::future::Future<Output = Result<T, super::Error>>,
{
    tokio::time::timeout(AUTH_PROMPT_TIMEOUT, operation)
        .await
        .map_err(|_| super::Error::AuthenticationPromptTimeout {
            prompt,
            seconds: AUTH_PROMPT_TIMEOUT.as_secs(),
        })?
}

async fn serialized_bounded_auth_prompt<T, F, Fut>(
    prompt: &'static str,
    operation: F,
) -> Result<T, super::Error>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, super::Error>>,
{
    let _prompt_guard = AUTH_PROMPT_MUTEX.lock().await;
    bounded_auth_prompt(prompt, operation()).await
}

async fn load_policy_private_key(
    key_file_path: &std::path::Path,
    key_pass: Option<Zeroizing<String>>,
    allow_passphrase_prompt: bool,
    use_keychain: bool,
) -> Result<russh::keys::PrivateKey, super::Error> {
    if let Some(passphrase) = key_pass {
        return russh::keys::load_secret_key(key_file_path, Some(&passphrase))
            .map_err(super::Error::KeyInvalid);
    }

    match russh::keys::load_secret_key(key_file_path, None) {
        Ok(key) => return Ok(key),
        Err(russh::keys::Error::KeyIsEncrypted) => {}
        Err(error) => return Err(super::Error::KeyInvalid(error)),
    }

    // BatchMode must reject before even consulting macOS Keychain: a locked
    // keychain may display its own user-authentication prompt.
    if !allow_passphrase_prompt {
        return Err(super::Error::KeyPassphrasePromptDisabled {
            path: key_file_path.to_path_buf(),
        });
    }
    // Only actual user-interaction paths are serialized. Key parsing, agent
    // authentication, and use of pre-collected credentials remain concurrent.
    let _prompt_guard = AUTH_PROMPT_MUTEX.lock().await;

    #[cfg(target_os = "macos")]
    #[cfg(target_os = "macos")]
    if use_keychain {
        #[cfg(test)]
        record_key_user_interaction();
        let retrieved = bounded_auth_prompt("macOS Keychain retrieval", async {
            crate::ssh::keychain_macos::retrieve_passphrase(key_file_path)
                .await
                .map_err(|error| super::Error::AuthenticationPolicy(error.to_string()))
        })
        .await;
        match retrieved {
            Ok(Some(passphrase)) => {
                return russh::keys::load_secret_key(key_file_path, Some(&passphrase))
                    .map_err(super::Error::KeyInvalid);
            }
            Ok(None) => {}
            Err(error @ super::Error::AuthenticationPromptTimeout { .. }) => return Err(error),
            Err(error) => tracing::warn!(
                "Failed to retrieve passphrase for '{}' from Keychain: {error}",
                key_file_path.display()
            ),
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = use_keychain;

    #[cfg(test)]
    record_key_user_interaction();
    let display_path = key_file_path.display().to_string();
    let prompt_task = tokio::task::spawn_blocking(move || {
        rpassword::prompt_password(format!("Enter passphrase for key {display_path}: "))
    });
    let passphrase = bounded_auth_prompt("private-key passphrase", async {
        prompt_task
            .await
            .map_err(super::Error::JoinError)?
            .map_err(super::Error::IoError)
    })
    .await?;
    let passphrase = Zeroizing::new(passphrase);

    #[cfg(target_os = "macos")]
    if use_keychain {
        let stored = bounded_auth_prompt("macOS Keychain storage", async {
            crate::ssh::keychain_macos::store_passphrase(key_file_path, &passphrase)
                .await
                .map_err(|error| super::Error::AuthenticationPolicy(error.to_string()))
        })
        .await;
        if let Err(error) = stored {
            tracing::warn!(
                "Failed to store passphrase for '{}' in Keychain: {error}",
                key_file_path.display()
            );
        }
    }

    russh::keys::load_secret_key(key_file_path, Some(&passphrase)).map_err(super::Error::KeyInvalid)
}
async fn default_hashes<H: Handler>(
    handle: &mut Handle<H>,
    algorithm: &russh::keys::ssh_key::Algorithm,
) -> Result<Vec<Option<russh::keys::ssh_key::HashAlg>>, super::Error> {
    if matches!(algorithm, russh::keys::ssh_key::Algorithm::Rsa { .. }) {
        let negotiated = handle.best_supported_rsa_hash().await?.flatten();
        Ok(negotiated.map(|hash| vec![Some(hash)]).unwrap_or_else(|| {
            vec![
                Some(russh::keys::ssh_key::HashAlg::Sha512),
                Some(russh::keys::ssh_key::HashAlg::Sha256),
            ]
        }))
    } else {
        Ok(vec![None])
    }
}

async fn authenticate_private_key_with_policy<H: Handler>(
    handle: &mut Handle<H>,
    username: &String,
    key: Arc<russh::keys::PrivateKey>,
    accepted: &[String],
) -> Result<(), super::Error> {
    let hashes = if accepted.is_empty() {
        default_hashes(handle, &key.algorithm()).await?
    } else {
        policy_hashes(&key.algorithm(), accepted)
    };
    if hashes.is_empty() {
        return Err(super::Error::IdentityAlgorithmExcluded(format!(
            "key algorithm '{}' is excluded by PubkeyAcceptedAlgorithms",
            key.algorithm()
        )));
    }

    for hash in hashes {
        let result = handle
            .authenticate_publickey(
                username,
                russh::keys::PrivateKeyWithHashAlg::new(Arc::clone(&key), hash),
            )
            .await?;
        if result.success() {
            return Ok(());
        }
    }
    Err(super::Error::KeyAuthFailed)
}

#[derive(Debug)]
struct LocalPrivateKeySigner {
    key: Arc<russh::keys::PrivateKey>,
}

impl russh::Signer for LocalPrivateKeySigner {
    type Error = super::Error;

    fn auth_sign(
        &mut self,
        _key: &russh::keys::agent::AgentIdentity,
        hash_alg: Option<russh::keys::ssh_key::HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let key = Arc::clone(&self.key);
        async move {
            use russh::keys::ssh_encoding::Encode as _;

            let signature = sign_local_private_key(key, hash_alg, &to_sign)?;
            let mut signed = to_sign;
            signature
                .encode(&mut signed)
                .map_err(|error| super::Error::KeyInvalid(error.into()))?;
            Ok(signed)
        }
    }
}

fn sign_local_private_key(
    key: Arc<russh::keys::PrivateKey>,
    hash_alg: Option<russh::keys::ssh_key::HashAlg>,
    data: &[u8],
) -> Result<Vec<u8>, super::Error> {
    use russh::keys::ssh_encoding::Encode as _;

    let key = russh::keys::PrivateKeyWithHashAlg::new(key, hash_alg);
    let signature = match key.key_data() {
        russh::keys::ssh_key::private::KeypairData::Rsa(rsa_keypair) => {
            let russh::keys::ssh_key::Algorithm::Rsa { hash } = key.algorithm() else {
                return Err(super::Error::AuthenticationPolicy(
                    "RSA key did not retain its selected signature hash".to_string(),
                ));
            };
            russh::keys::signature::Signer::try_sign(&(rsa_keypair, hash), data)
        }
        keypair => russh::keys::signature::Signer::try_sign(keypair, data),
    }
    .map_err(|error| super::Error::KeyInvalid(russh::keys::Error::SshKey(error.into())))?;
    let mut encoded = Vec::new();
    signature
        .encode(&mut encoded)
        .map_err(|error| super::Error::KeyInvalid(error.into()))?;
    Ok(encoded)
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_certificate_file<H: Handler>(
    handle: &mut Handle<H>,
    username: &String,
    key_file_path: PathBuf,
    certificate_file_path: PathBuf,
    key_pass: Option<Zeroizing<String>>,
    accepted: Vec<String>,
    allow_passphrase_prompt: bool,
    use_keychain: bool,
) -> Result<(), super::Error> {
    let key = load_policy_private_key(
        &key_file_path,
        key_pass,
        allow_passphrase_prompt,
        use_keychain,
    )
    .await?;
    let certificate =
        russh::keys::load_openssh_certificate(&certificate_file_path).map_err(|error| {
            super::Error::AuthenticationPolicy(format!(
                "unable to load certificate '{}': {error}",
                certificate_file_path.display()
            ))
        })?;
    if certificate.cert_type() != russh::keys::ssh_key::certificate::CertType::User {
        return Err(super::Error::AuthenticationPolicy(format!(
            "certificate '{}' is not a user certificate",
            certificate_file_path.display()
        )));
    }
    if certificate.public_key() != key.public_key().key_data() {
        return Err(super::Error::AuthenticationPolicy(format!(
            "certificate '{}' does not match private key '{}'",
            certificate_file_path.display(),
            key_file_path.display()
        )));
    }
    let hashes = if accepted.is_empty() {
        default_hashes(handle, &certificate.algorithm()).await?
    } else {
        certificate_policy_hashes(&certificate.algorithm(), &accepted)
    };
    if hashes.is_empty() {
        return Err(super::Error::IdentityAlgorithmExcluded(format!(
            "certificate algorithm '{}' is excluded by PubkeyAcceptedAlgorithms",
            certificate.algorithm().to_certificate_type()
        )));
    }

    let mut signer = LocalPrivateKeySigner { key: Arc::new(key) };
    for hash in hashes {
        let result = handle
            .authenticate_certificate_with(username, certificate.clone(), hash, &mut signer)
            .await?;
        if result.success() {
            return Ok(());
        }
    }
    Err(super::Error::KeyAuthFailed)
}

async fn authenticate_password_prompt<H: Handler>(
    handle: &mut Handle<H>,
    username: &str,
    attempts: u32,
) -> Result<(), super::Error> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        return Err(super::Error::AuthenticationPolicy(
            "password prompting is unavailable without a terminal".to_string(),
        ));
    }

    for _ in 0..attempts {
        let prompt_username = username.to_owned();
        let password = serialized_bounded_auth_prompt("password", move || async move {
            let prompt_task = tokio::task::spawn_blocking(move || {
                rpassword::prompt_password(format!("{prompt_username}'s password: "))
            });
            prompt_task
                .await
                .map_err(super::Error::JoinError)?
                .map_err(super::Error::IoError)
        })
        .await?;
        let password = Zeroizing::new(password);
        if handle
            .authenticate_password(username.to_owned(), &*password)
            .await?
            .success()
        {
            return Ok(());
        }
    }
    Err(super::Error::PasswordWrong)
}

#[cfg(not(target_os = "windows"))]
async fn authenticate_agent_public_key_file<H: Handler>(
    handle: &mut Handle<H>,
    username: &String,
    key_file_path: PathBuf,
    accepted: &[String],
) -> Result<(), super::Error> {
    use russh::keys::agent::AgentIdentity;

    let public_key =
        russh::keys::load_public_key(&key_file_path).map_err(super::Error::KeyInvalid)?;
    if !public_key_allowed(&public_key.algorithm(), accepted) {
        return Err(super::Error::IdentityAlgorithmExcluded(format!(
            "key algorithm '{}' is excluded by PubkeyAcceptedAlgorithms",
            public_key.algorithm()
        )));
    }
    let mut agent = bounded_agent_operation("connect", async {
        russh::keys::agent::client::AgentClient::connect_env()
            .await
            .map_err(|_| super::Error::AgentConnectionFailed)
    })
    .await?;
    let identities = bounded_agent_operation("request identities", async {
        agent
            .request_identities()
            .await
            .map_err(|_| super::Error::AgentRequestIdentitiesFailed)
    })
    .await?;
    let matching_key = identities.into_iter().find_map(|identity| match identity {
        AgentIdentity::PublicKey { key, .. } if key.key_data() == public_key.key_data() => {
            Some(key)
        }
        _ => None,
    });
    let Some(matching_key) = matching_key else {
        return Err(super::Error::KeyAuthFailed);
    };
    let hashes = if accepted.is_empty() {
        default_hashes(handle, &matching_key.algorithm()).await?
    } else {
        policy_hashes(&matching_key.algorithm(), accepted)
    };
    for hash in hashes {
        let result = bounded_agent_operation("sign public key", async {
            handle
                .authenticate_publickey_with(username, matching_key.clone(), hash, &mut agent)
                .await
                .map_err(super::Error::from)
        })
        .await?;
        if result.success() {
            return Ok(());
        }
    }
    Err(super::Error::KeyAuthFailed)
}

#[cfg(not(target_os = "windows"))]
async fn authenticate_agent_with_policy<H: Handler>(
    handle: &mut Handle<H>,
    username: &String,
    accepted: &[String],
) -> Result<(), super::Error> {
    use russh::keys::agent::AgentIdentity;

    let mut agent = bounded_agent_operation("connect", async {
        russh::keys::agent::client::AgentClient::connect_env()
            .await
            .map_err(|_| super::Error::AgentConnectionFailed)
    })
    .await?;
    let identities = bounded_agent_operation("request identities", async {
        agent
            .request_identities()
            .await
            .map_err(|_| super::Error::AgentRequestIdentitiesFailed)
    })
    .await?;
    if identities.is_empty() {
        return Err(super::Error::AgentNoIdentities);
    }

    for identity in identities {
        match identity {
            AgentIdentity::PublicKey { key, .. } => {
                let hashes = if accepted.is_empty() {
                    default_hashes(handle, &key.algorithm()).await?
                } else {
                    policy_hashes(&key.algorithm(), accepted)
                };
                for hash in hashes {
                    let result = bounded_agent_operation("sign public key", async {
                        handle
                            .authenticate_publickey_with(username, key.clone(), hash, &mut agent)
                            .await
                            .map_err(super::Error::from)
                    })
                    .await?;
                    if result.success() {
                        return Ok(());
                    }
                }
            }
            AgentIdentity::Certificate { certificate, .. }
                if certificate_allowed(&certificate, accepted) =>
            {
                let hashes = if accepted.is_empty() {
                    default_hashes(handle, &certificate.algorithm()).await?
                } else {
                    certificate_policy_hashes(&certificate.algorithm(), accepted)
                };
                for hash in hashes {
                    let result = bounded_agent_operation("sign certificate", async {
                        handle
                            .authenticate_certificate_with(
                                username,
                                certificate.clone(),
                                hash,
                                &mut agent,
                            )
                            .await
                            .map_err(super::Error::from)
                    })
                    .await?;
                    if result.success() {
                        return Ok(());
                    }
                }
            }
            AgentIdentity::Certificate { .. } => {}
        }
    }

    Err(super::Error::AgentAuthenticationFailed)
}

#[cfg(not(target_os = "windows"))]
struct AgentIdentitySigner {
    agent: russh::keys::agent::client::AgentClient<tokio::net::UnixStream>,
    identity: russh::keys::agent::AgentIdentity,
}

#[cfg(not(target_os = "windows"))]
impl russh::Signer for AgentIdentitySigner {
    type Error = russh::AgentAuthError;

    async fn auth_sign(
        &mut self,
        _certificate: &russh::keys::agent::AgentIdentity,
        hash_alg: Option<russh::keys::ssh_key::HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        self.agent
            .sign_request(&self.identity, hash_alg, to_sign)
            .await
            .map_err(Into::into)
    }
}

#[cfg(not(target_os = "windows"))]
async fn authenticate_agent_certificate_file<H: Handler>(
    handle: &mut Handle<H>,
    username: &String,
    certificate_file_path: PathBuf,
    accepted: &[String],
) -> Result<(), super::Error> {
    let certificate =
        russh::keys::load_openssh_certificate(&certificate_file_path).map_err(|error| {
            super::Error::AuthenticationPolicy(format!(
                "unable to load certificate '{}': {error}",
                certificate_file_path.display()
            ))
        })?;
    if certificate.cert_type() != russh::keys::ssh_key::certificate::CertType::User {
        return Err(super::Error::AuthenticationPolicy(format!(
            "certificate '{}' is not a user certificate",
            certificate_file_path.display()
        )));
    }
    if !certificate_allowed(&certificate, accepted) {
        return Err(super::Error::IdentityAlgorithmExcluded(format!(
            "certificate algorithm '{}' is excluded by PubkeyAcceptedAlgorithms",
            certificate.algorithm().to_certificate_type()
        )));
    }

    let mut agent = bounded_agent_operation("connect", async {
        russh::keys::agent::client::AgentClient::connect_env()
            .await
            .map_err(|_| super::Error::AgentConnectionFailed)
    })
    .await?;
    let identities = bounded_agent_operation("request identities", async {
        agent
            .request_identities()
            .await
            .map_err(|_| super::Error::AgentRequestIdentitiesFailed)
    })
    .await?;
    let Some(identity) = identities
        .into_iter()
        .find(|identity| identity.public_key().key_data() == certificate.public_key())
    else {
        return Err(super::Error::KeyAuthFailed);
    };
    let mut signer = AgentIdentitySigner { agent, identity };

    let hashes = if accepted.is_empty() {
        default_hashes(handle, &certificate.algorithm()).await?
    } else {
        certificate_policy_hashes(&certificate.algorithm(), accepted)
    };
    for hash in hashes {
        let result = bounded_agent_operation("sign certificate", async {
            handle
                .authenticate_certificate_with(username, certificate.clone(), hash, &mut signer)
                .await
                .map_err(super::Error::from)
        })
        .await?;
        if result.success() {
            return Ok(());
        }
    }
    Err(super::Error::KeyAuthFailed)
}

/// Try an ordered authentication plan on one established SSH transport.
pub(crate) async fn authenticate<H: Handler>(
    handle: &mut Handle<H>,
    username: &String,
    auth: AuthMethod,
) -> Result<(), super::Error> {
    let AuthMethod::Methods(methods) = auth else {
        return authenticate_single(handle, username, auth).await;
    };

    if methods.is_empty() {
        return Err(super::Error::AuthenticationPolicy(
            "no authentication methods remain after applying ssh_config".to_string(),
        ));
    }

    let mut attempted = Vec::new();
    let mut attempted_identities = Vec::new();
    for method in methods {
        let label = method.label();
        if !attempted.contains(&label) {
            attempted.push(label);
        }
        if let Some(identity) = method.identity_description()
            && !attempted_identities.contains(&identity)
        {
            attempted_identities.push(identity);
        }
        match authenticate_single(handle, username, method).await {
            Ok(()) => return Ok(()),
            Err(error) if is_retryable_rejection(&error) => {}
            Err(error) => return Err(error),
        }
    }

    Err(super::Error::AuthenticationExhausted {
        methods: attempted.join(","),
        identity_status: if attempted_identities.is_empty() {
            "none".to_string()
        } else {
            format!("attempted {}", attempted_identities.join(", "))
        },
        agent_status: "attempted only identities allowed by ssh_config".to_string(),
        password_status: "disabled, unavailable, or all configured attempts were rejected",
    })
}

fn is_retryable_rejection(error: &super::Error) -> bool {
    matches!(
        error,
        super::Error::KeyboardInteractiveAuthFailed
            | super::Error::KeyboardInteractiveNoResponseForPrompt(_)
            | super::Error::KeyAuthFailed
            | super::Error::KeyInvalid(_)
            | super::Error::KeyPassphrasePromptDisabled { .. }
            | super::Error::IdentityAlgorithmExcluded(_)
            | super::Error::AgentOperationTimeout { .. }
            | super::Error::AgentAuthError(russh::AgentAuthError::Key(_))
            | super::Error::PasswordWrong
            | super::Error::AgentConnectionFailed
            | super::Error::AgentRequestIdentitiesFailed
            | super::Error::AgentNoIdentities
            | super::Error::AgentAuthenticationFailed
    )
}

/// This takes a handle and performs authentification with the given method.
async fn authenticate_single<H: Handler>(
    handle: &mut Handle<H>,
    username: &String,
    auth: AuthMethod,
) -> Result<(), super::Error> {
    use russh::client::KeyboardInteractiveAuthResponse;

    match auth {
        AuthMethod::Password(password) => {
            let is_authentificated = handle.authenticate_password(username, &**password).await?;
            if !is_authentificated.success() {
                return Err(super::Error::PasswordWrong);
            }
        }
        AuthMethod::PrivateKey { key_data, key_pass } => {
            let cprivk =
                russh::keys::decode_secret_key(&key_data, key_pass.as_ref().map(|p| &***p))
                    .map_err(super::Error::KeyInvalid)?;
            let is_authentificated = handle
                .authenticate_publickey(
                    username,
                    russh::keys::PrivateKeyWithHashAlg::new(
                        Arc::new(cprivk),
                        handle.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await?;
            if !is_authentificated.success() {
                return Err(super::Error::KeyAuthFailed);
            }
        }
        AuthMethod::PrivateKeyFile {
            key_file_path,
            key_pass,
        } => {
            let cprivk =
                russh::keys::load_secret_key(key_file_path, key_pass.as_ref().map(|p| &***p))
                    .map_err(super::Error::KeyInvalid)?;
            let is_authentificated = handle
                .authenticate_publickey(
                    username,
                    russh::keys::PrivateKeyWithHashAlg::new(
                        Arc::new(cprivk),
                        handle.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await?;
            if !is_authentificated.success() {
                return Err(super::Error::KeyAuthFailed);
            }
        }
        AuthMethod::PrivateKeyFileWithPolicy {
            key_file_path,
            key_pass,
            accepted_algorithms,
            allow_passphrase_prompt,
            use_keychain,
        } => {
            let key = load_policy_private_key(
                &key_file_path,
                key_pass,
                allow_passphrase_prompt,
                use_keychain,
            )
            .await?;
            authenticate_private_key_with_policy(
                handle,
                username,
                Arc::new(key),
                &accepted_algorithms,
            )
            .await?;
        }
        AuthMethod::OpenSshCertificateFile {
            key_file_path,
            certificate_file_path,
            key_pass,
            accepted_algorithms,
            allow_passphrase_prompt,
            use_keychain,
        } => {
            authenticate_certificate_file(
                handle,
                username,
                key_file_path,
                certificate_file_path,
                key_pass,
                accepted_algorithms,
                allow_passphrase_prompt,
                use_keychain,
            )
            .await?;
        }
        AuthMethod::PasswordPrompt { attempts } => {
            authenticate_password_prompt(handle, username, attempts).await?;
        }
        AuthMethod::Methods(_) => {
            return Err(super::Error::AuthenticationPolicy(
                "nested authentication plans are not supported".to_string(),
            ));
        }
        #[cfg(not(target_os = "windows"))]
        AuthMethod::PublicKeyFile { key_file_path } => {
            let cpubk =
                russh::keys::load_public_key(key_file_path).map_err(super::Error::KeyInvalid)?;
            let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|_| super::Error::AgentConnectionFailed)?;
            let mut auth_identity_found = false;
            for identity in agent
                .request_identities()
                .await
                .map_err(super::Error::KeyInvalid)?
            {
                if *identity.public_key() == cpubk {
                    auth_identity_found = true;
                    break;
                }
            }

            if !auth_identity_found {
                return Err(super::Error::KeyAuthFailed);
            }

            let is_authentificated = handle
                .authenticate_publickey_with(
                    username,
                    cpubk,
                    handle.best_supported_rsa_hash().await?.flatten(),
                    &mut agent,
                )
                .await?;
            if !is_authentificated.success() {
                return Err(super::Error::KeyAuthFailed);
            }
        }
        #[cfg(not(target_os = "windows"))]
        AuthMethod::Agent => {
            let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|_| super::Error::AgentConnectionFailed)?;

            let identities = agent
                .request_identities()
                .await
                .map_err(|_| super::Error::AgentRequestIdentitiesFailed)?;

            if identities.is_empty() {
                return Err(super::Error::AgentNoIdentities);
            }

            let mut auth_success = false;
            for identity in identities {
                let result = handle
                    .authenticate_publickey_with(
                        username,
                        identity.public_key().into_owned(),
                        handle.best_supported_rsa_hash().await?.flatten(),
                        &mut agent,
                    )
                    .await;

                if let Ok(auth_result) = result
                    && auth_result.success()
                {
                    auth_success = true;
                    break;
                }
            }

            if !auth_success {
                return Err(super::Error::AgentAuthenticationFailed);
            }
        }
        #[cfg(not(target_os = "windows"))]
        AuthMethod::AgentPublicKeyFile {
            key_file_path,
            accepted_algorithms,
        } => {
            authenticate_agent_public_key_file(
                handle,
                username,
                key_file_path,
                &accepted_algorithms,
            )
            .await?;
        }
        #[cfg(not(target_os = "windows"))]
        AuthMethod::AgentWithPolicy {
            accepted_algorithms,
        } => {
            authenticate_agent_with_policy(handle, username, &accepted_algorithms).await?;
        }
        #[cfg(not(target_os = "windows"))]
        AuthMethod::AgentCertificateFile {
            certificate_file_path,
            accepted_algorithms,
        } => {
            authenticate_agent_certificate_file(
                handle,
                username,
                certificate_file_path,
                &accepted_algorithms,
            )
            .await?;
        }
        AuthMethod::KeyboardInteractive(mut kbd) => {
            let mut res = handle
                .authenticate_keyboard_interactive_start(username, kbd.submethods)
                .await?;
            loop {
                let prompts = match res {
                    KeyboardInteractiveAuthResponse::Success => break,
                    KeyboardInteractiveAuthResponse::Failure { .. } => {
                        return Err(super::Error::KeyboardInteractiveAuthFailed);
                    }
                    KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => prompts,
                };

                let mut responses = vec![];
                for prompt in prompts {
                    let Some(pos) = kbd
                        .responses
                        .iter()
                        .position(|pr| pr.matches(&prompt.prompt))
                    else {
                        return Err(super::Error::KeyboardInteractiveNoResponseForPrompt(
                            prompt.prompt,
                        ));
                    };
                    let pr = kbd.responses.remove(pos);
                    responses.push(pr.response.to_string());
                }

                res = handle
                    .authenticate_keyboard_interactive_respond(responses)
                    .await?;
            }
        }
    };
    Ok(())
}

#[cfg(test)]
mod policy_execution_tests {
    use super::*;
    use russh::keys::ssh_key::{Algorithm, LineEnding};
    use russh::server::{Auth, Session};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use tokio::sync::Mutex;

    struct ScriptedAuthServer {
        attempts: Arc<Mutex<Vec<String>>>,
        key_names: HashMap<russh::keys::ssh_key::public::KeyData, String>,
        accepted_key: Option<String>,
        accepted_certificate: Option<String>,
    }

    impl russh::server::Handler for ScriptedAuthServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<Auth, Self::Error> {
            self.attempts.lock().await.push("password".to_string());
            Ok(Auth::reject())
        }

        async fn auth_publickey_offered(
            &mut self,
            _user: &str,
            _public_key: &russh::keys::PublicKey,
        ) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn auth_publickey(
            &mut self,
            _user: &str,
            public_key: &russh::keys::PublicKey,
        ) -> Result<Auth, Self::Error> {
            let name = self
                .key_names
                .get(public_key.key_data())
                .cloned()
                .unwrap_or_else(|| "unknown-key".to_string());
            self.attempts.lock().await.push(name.clone());
            if self.accepted_key.as_ref() == Some(&name) {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::reject())
            }
        }

        async fn auth_openssh_certificate(
            &mut self,
            _user: &str,
            certificate: &russh::keys::ssh_key::Certificate,
        ) -> Result<Auth, Self::Error> {
            let key_id = certificate.key_id().to_string();
            self.attempts.lock().await.push(format!("cert:{key_id}"));
            if self.accepted_certificate.as_ref() == Some(&key_id) {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::reject())
            }
        }

        async fn channel_open_session(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            _reply: russh::server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            drop(channel);
            Ok(())
        }
    }

    async fn start_server(server: ScriptedAuthServer) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let mut config = russh::server::Config {
            auth_rejection_time: std::time::Duration::ZERO,
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            inactivity_timeout: None,
            ..russh::server::Config::default()
        };
        config
            .keys
            .push(russh::keys::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = russh::server::run_stream(config, socket, server).await;
        });
        (address, task)
    }

    async fn connect(address: SocketAddr) -> Handle<super::super::ClientHandler> {
        let handler = super::super::ClientHandler::new(
            "127.0.0.1".to_string(),
            address,
            ServerCheckMethod::NoCheck,
        );
        russh::client::connect(Arc::new(russh::client::Config::default()), address, handler)
            .await
            .unwrap()
    }

    fn write_key(path: &std::path::Path) -> russh::keys::PrivateKey {
        let key = russh::keys::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        std::fs::write(path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        key
    }

    #[tokio::test]
    async fn scripted_server_observes_exact_method_and_key_order() {
        let directory = tempfile::TempDir::new().unwrap();
        let first_path = directory.path().join("first-key");
        let second_path = directory.path().join("second-key");
        let first = write_key(&first_path);
        let second = write_key(&second_path);
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let key_names = HashMap::from([
            (
                first.public_key().key_data().clone(),
                "first-key".to_string(),
            ),
            (
                second.public_key().key_data().clone(),
                "second-key".to_string(),
            ),
        ]);
        let (address, task) = start_server(ScriptedAuthServer {
            attempts: Arc::clone(&attempts),
            key_names,
            accepted_key: Some("second-key".to_string()),
            accepted_certificate: None,
        })
        .await;
        let mut handle = connect(address).await;
        let methods = AuthMethod::with_methods(vec![
            AuthMethod::with_password("wrong"),
            AuthMethod::with_key_file_policy(&first_path, None, vec!["ssh-ed25519".into()]),
            AuthMethod::with_key_file_policy(&second_path, None, vec!["ssh-ed25519".into()]),
        ]);

        authenticate(&mut handle, &"user".to_string(), methods)
            .await
            .unwrap();
        assert_eq!(
            attempts.lock().await.as_slice(),
            ["password", "first-key", "second-key"]
        );
        task.abort();
    }

    #[tokio::test]
    async fn scripted_server_accepts_matching_user_certificate() {
        let directory = tempfile::TempDir::new().unwrap();
        let key_path = directory.path().join("user-key");
        let certificate_path = directory.path().join("user-cert.pub");
        let subject = write_key(&key_path);
        let ca = russh::keys::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mut builder = russh::keys::ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            subject.public_key(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder.key_id("matching-user-cert").unwrap();
        builder
            .cert_type(russh::keys::ssh_key::certificate::CertType::User)
            .unwrap();
        builder.valid_principal("user").unwrap();
        std::fs::write(
            &certificate_path,
            builder.sign(&ca).unwrap().to_openssh().unwrap(),
        )
        .unwrap();

        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (address, task) = start_server(ScriptedAuthServer {
            attempts: Arc::clone(&attempts),
            key_names: HashMap::new(),
            accepted_key: None,
            accepted_certificate: Some("matching-user-cert".to_string()),
        })
        .await;
        let mut handle = connect(address).await;
        let method = AuthMethod::with_certificate_file(
            key_path,
            certificate_path,
            None,
            vec!["ssh-ed25519-cert-v01@openssh.com".into()],
        );

        authenticate(&mut handle, &"user".to_string(), method)
            .await
            .unwrap();
        assert_eq!(
            attempts.lock().await.as_slice(),
            ["cert:matching-user-cert"]
        );
        task.abort();
    }

    #[tokio::test]
    async fn unavailable_cli_identities_are_retryable_before_a_valid_key() {
        let directory = tempfile::TempDir::new().unwrap();
        let missing_path = directory.path().join("missing-key");
        let malformed_path = directory.path().join("malformed-key");
        let valid_path = directory.path().join("valid-key");
        std::fs::write(&malformed_path, "not an SSH private key").unwrap();
        let valid = write_key(&valid_path);
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (address, task) = start_server(ScriptedAuthServer {
            attempts: Arc::clone(&attempts),
            key_names: HashMap::from([(
                valid.public_key().key_data().clone(),
                "valid-key".to_string(),
            )]),
            accepted_key: Some("valid-key".to_string()),
            accepted_certificate: None,
        })
        .await;
        let mut handle = connect(address).await;
        let methods = AuthMethod::with_methods(vec![
            AuthMethod::with_configured_key_file(
                missing_path,
                vec!["ssh-ed25519".into()],
                false,
                false,
            ),
            AuthMethod::with_configured_key_file(
                malformed_path,
                vec!["ssh-ed25519".into()],
                false,
                false,
            ),
            AuthMethod::with_configured_key_file(
                valid_path,
                vec!["ssh-ed25519".into()],
                false,
                false,
            ),
        ]);

        authenticate(&mut handle, &"user".to_string(), methods)
            .await
            .unwrap();
        assert_eq!(attempts.lock().await.as_slice(), ["valid-key"]);
        task.abort();
    }

    #[tokio::test]
    async fn batch_mode_and_earlier_success_cause_zero_key_interactions() {
        KEY_USER_INTERACTION_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        let directory = tempfile::TempDir::new().unwrap();
        let first_path = directory.path().join("first-key");
        let encrypted_path = directory.path().join("encrypted-key");
        let malformed_path = directory.path().join("malformed-key");
        let first = write_key(&first_path);
        let encrypted = russh::keys::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .unwrap()
            .encrypt(&mut rand::rng(), "secret")
            .unwrap();
        std::fs::write(
            &encrypted_path,
            encrypted.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();

        std::fs::write(&malformed_path, "not an SSH private key").unwrap();

        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (address, task) = start_server(ScriptedAuthServer {
            attempts: Arc::clone(&attempts),
            key_names: HashMap::from([(
                first.public_key().key_data().clone(),
                "first-key".to_string(),
            )]),
            accepted_key: Some("first-key".to_string()),
            accepted_certificate: None,
        })
        .await;
        let mut handle = connect(address).await;
        let methods = AuthMethod::with_methods(vec![
            AuthMethod::with_configured_key_file(
                &first_path,
                vec!["ssh-ed25519".into()],
                true,
                false,
            ),
            AuthMethod::with_configured_key_file(
                &encrypted_path,
                vec!["ssh-ed25519".into()],
                true,
                false,
            ),
            AuthMethod::with_configured_key_file(
                &malformed_path,
                vec!["ssh-ed25519".into()],
                true,
                false,
            ),
        ]);
        authenticate(&mut handle, &"user".to_string(), methods)
            .await
            .unwrap();
        task.abort();

        let error = load_policy_private_key(&encrypted_path, None, false, true)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            super::super::Error::KeyPassphrasePromptDisabled { .. }
        ));
        assert_eq!(
            KEY_USER_INTERACTION_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "BatchMode must skip Keychain and passphrase prompts, and a later key must stay lazy"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn password_prompts_have_a_typed_timeout_bound() {
        let error = serialized_bounded_auth_prompt("password", || async {
            std::future::pending::<Result<(), super::super::Error>>().await
        })
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            super::super::Error::AuthenticationPromptTimeout {
                prompt: "password",
                seconds: 30,
            }
        ));
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test(start_paused = true)]
    async fn agent_operations_have_a_typed_timeout_bound() {
        let error = bounded_agent_operation("request identities", async {
            std::future::pending::<Result<(), super::super::Error>>().await
        })
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            super::super::Error::AgentOperationTimeout {
                action: "request identities",
                seconds: 5,
            }
        ));
    }

    #[test]
    fn rsa_public_key_and_certificate_hashes_preserve_policy_order() {
        let rsa = Algorithm::Rsa { hash: None };
        let defaults = super::super::algorithms::default_pubkey_algorithms();
        let default_hashes = policy_hashes(&rsa, &defaults);
        assert!(default_hashes.contains(&Some(russh::keys::ssh_key::HashAlg::Sha512)));
        assert!(default_hashes.contains(&Some(russh::keys::ssh_key::HashAlg::Sha256)));
        assert!(!default_hashes.contains(&None));

        let sha1_opt_in =
            super::super::algorithms::resolve_pubkey_algorithms(&["+ssh-rsa".to_string()]).unwrap();
        assert!(policy_hashes(&rsa, &sha1_opt_in).contains(&None));
        assert_eq!(
            policy_hashes(&rsa, &["rsa-sha2-256".into(), "rsa-sha2-512".into()]),
            [
                Some(russh::keys::ssh_key::HashAlg::Sha256),
                Some(russh::keys::ssh_key::HashAlg::Sha512)
            ]
        );
        assert_eq!(
            certificate_policy_hashes(
                &rsa,
                &[
                    "rsa-sha2-256-cert-v01@openssh.com".into(),
                    "rsa-sha2-512-cert-v01@openssh.com".into(),
                ]
            ),
            [
                Some(russh::keys::ssh_key::HashAlg::Sha256),
                Some(russh::keys::ssh_key::HashAlg::Sha512)
            ]
        );
        let cert_sha1_opt_in = super::super::algorithms::resolve_pubkey_algorithms(&[
            "+ssh-rsa-cert-v01@openssh.com".to_string(),
        ])
        .unwrap();
        assert!(certificate_policy_hashes(&rsa, &cert_sha1_opt_in).contains(&None));
        assert!(!public_key_allowed(&rsa, &["ssh-ed25519".into()]));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn prompt_mutex_serializes_only_actual_user_interactions() {
        let directory = tempfile::TempDir::new().unwrap();
        let plain_path = directory.path().join("plain-key");
        write_key(&plain_path);

        let guard = AUTH_PROMPT_MUTEX.lock().await;
        let loaded = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            load_policy_private_key(&plain_path, None, true, false),
        )
        .await
        .expect("unencrypted key loading must not wait for the prompt mutex");
        assert!(loaded.is_ok());
        drop(guard);

        let (first_entered_tx, first_entered_rx) = tokio::sync::oneshot::channel();
        let (first_release_tx, first_release_rx) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(serialized_bounded_auth_prompt(
            "first",
            move || async move {
                let _ = first_entered_tx.send(());
                let _ = first_release_rx.await;
                Ok::<_, super::super::Error>(())
            },
        ));
        first_entered_rx.await.unwrap();

        let (second_entered_tx, second_entered_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(serialized_bounded_auth_prompt(
            "second",
            move || async move {
                let _ = second_entered_tx.send(());
                Ok::<_, super::super::Error>(())
            },
        ));
        let mut second_entered_rx = second_entered_rx;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut second_entered_rx,)
                .await
                .is_err(),
            "a second interactive prompt must wait for the first"
        );
        let _ = first_release_tx.send(());
        first.await.unwrap().unwrap();
        second_entered_rx.await.unwrap();
        second.await.unwrap().unwrap();
    }

    #[test]
    fn local_rsa_signer_emits_the_selected_wire_signature_algorithm() {
        use russh::keys::ssh_encoding::Decode as _;

        let directory = tempfile::TempDir::new().unwrap();
        let key_path = directory.path().join("rsa-key");
        crate::keygen::generate_rsa(&key_path, 2048, None).unwrap();
        let key = Arc::new(russh::keys::load_secret_key(&key_path, None).unwrap());
        for hash in [
            Some(russh::keys::ssh_key::HashAlg::Sha512),
            Some(russh::keys::ssh_key::HashAlg::Sha256),
            None,
        ] {
            let encoded = sign_local_private_key(Arc::clone(&key), hash, b"authenticate").unwrap();
            let mut reader = encoded.as_slice();
            let signature = russh::keys::ssh_key::Signature::decode(&mut reader).unwrap();
            assert_eq!(signature.algorithm(), Algorithm::Rsa { hash });
            assert!(reader.is_empty());
        }
    }

    #[test]
    fn agent_local_failures_are_retryable_but_ssh_send_failures_are_fatal() {
        assert!(is_retryable_rejection(
            &super::super::Error::AgentOperationTimeout {
                action: "request identities",
                seconds: 5,
            }
        ));
        assert!(is_retryable_rejection(
            &super::super::Error::AgentAuthError(russh::AgentAuthError::Key(
                russh::keys::Error::AgentFailure,
            ))
        ));
        assert!(!is_retryable_rejection(
            &super::super::Error::AgentAuthError(russh::AgentAuthError::Send(russh::SendError {},))
        ));
    }

    #[tokio::test]
    async fn exhausted_plan_diagnostic_preserves_unavailable_identity_paths() {
        let directory = tempfile::TempDir::new().unwrap();
        let missing_path = directory.path().join("missing-key");
        let rejected_path = directory.path().join("rejected-key");
        let rejected = write_key(&rejected_path);
        let (address, task) = start_server(ScriptedAuthServer {
            attempts: Arc::new(Mutex::new(Vec::new())),
            key_names: HashMap::from([(
                rejected.public_key().key_data().clone(),
                "rejected-key".to_string(),
            )]),
            accepted_key: None,
            accepted_certificate: None,
        })
        .await;
        let mut handle = connect(address).await;
        let methods = AuthMethod::with_methods(vec![
            AuthMethod::with_configured_key_file(
                &missing_path,
                vec!["ssh-ed25519".into()],
                false,
                false,
            ),
            AuthMethod::with_configured_key_file(
                &rejected_path,
                vec!["ssh-ed25519".into()],
                false,
                false,
            ),
        ]);

        let error = authenticate(&mut handle, &"user".to_string(), methods)
            .await
            .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains(&missing_path.display().to_string()));
        assert!(rendered.contains(&rejected_path.display().to_string()));
        task.abort();
    }
}

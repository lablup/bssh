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

//! Centralized authentication logic for SSH connections.
//!
//! This module consolidates all authentication-related functionality to eliminate
//! duplication across the codebase and provide a single source of truth for
//! authentication method determination.
//!
//! # Security Considerations
//! - All credential data is protected using `Zeroizing` to ensure secure memory cleanup
//! - File paths are validated to prevent path traversal attacks
//! - Authentication attempts use constant-time operations where possible
//! - Error messages do not leak sensitive information

use anyhow::Result;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

use super::tokio_client::{AuthMethod, SshAuthenticationPolicy};
use crate::security::Password;

/// Maximum username length to prevent DoS attacks
const MAX_USERNAME_LENGTH: usize = 256;

/// Maximum hostname length per RFC 1035
const MAX_HOSTNAME_LENGTH: usize = 253;

struct PreparedIdentity {
    path: PathBuf,
    algorithm: Option<russh::keys::ssh_key::Algorithm>,
    public_key: Option<russh::keys::ssh_key::public::KeyData>,
    public_only: bool,
}
/// Context for determining SSH authentication method.
///
/// This structure encapsulates all parameters needed to determine the appropriate
/// authentication method for an SSH connection.
///
/// # Security
/// - Usernames and hostnames are validated to prevent injection attacks
/// - File paths are canonicalized to prevent path traversal
/// - All sensitive data uses `Zeroizing` for secure cleanup
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Optional path to SSH key file (validated and canonicalized)
    pub key_path: Option<PathBuf>,
    /// Whether to use SSH agent for authentication
    pub use_agent: bool,
    /// Whether to use password authentication
    pub use_password: bool,
    /// Whether to allow automatic password fallback (for interactive mode)
    pub allow_password_fallback: bool,
    /// Whether to use macOS Keychain for passphrase storage/retrieval (macOS only)
    #[cfg(target_os = "macos")]
    pub use_keychain: bool,
    /// Username for authentication prompts (validated)
    pub username: String,
    /// Host for authentication prompts (validated)
    pub host: String,
    /// Pre-collected SSH password shared across all per-node connection tasks.
    ///
    /// When set, `password_auth()` consumes this value instead of prompting,
    /// so the user is asked exactly once per command (in the dispatcher) and
    /// the same password is reused for every node and for the password
    /// fallback path. Wrapped in `Arc` so cloning the context across tasks
    /// does not duplicate the underlying secret.
    pub password: Option<Arc<Password>>,
    /// Resolved ssh_config authentication policy for this destination.
    pub policy: SshAuthenticationPolicy,
    /// Test seam for terminal availability; production leaves this unset.
    prompt_available: Option<bool>,
}

impl AuthContext {
    /// Create a new authentication context with validation.
    ///
    /// # Errors
    /// Returns an error if username or hostname are invalid
    pub fn new(username: String, host: String) -> Result<Self> {
        // Validate username to prevent injection attacks
        if username.is_empty() {
            anyhow::bail!("Username cannot be empty");
        }
        if username.len() > MAX_USERNAME_LENGTH {
            anyhow::bail!("Username too long (max {MAX_USERNAME_LENGTH} characters)");
        }
        if username.contains(['/', '\0', '\n', '\r']) {
            anyhow::bail!("Username contains invalid characters");
        }

        // Validate hostname
        if host.is_empty() {
            anyhow::bail!("Hostname cannot be empty");
        }
        if host.len() > MAX_HOSTNAME_LENGTH {
            anyhow::bail!("Hostname too long (max {MAX_HOSTNAME_LENGTH} characters)");
        }
        if host.contains(['\0', '\n', '\r']) {
            anyhow::bail!("Hostname contains invalid characters");
        }

        Ok(Self {
            key_path: None,
            use_agent: false,
            use_password: false,
            allow_password_fallback: false,
            #[cfg(target_os = "macos")]
            use_keychain: false,
            username,
            host,
            password: None,
            policy: SshAuthenticationPolicy::default(),
            prompt_available: None,
        })
    }

    /// Set the preferred SSH key path without touching the filesystem.
    ///
    /// Loading, canonicalization, and validation are intentionally deferred to
    /// the ordered authentication attempt so an unavailable `-i` entry cannot
    /// prevent a later identity, agent, or password method from succeeding.
    pub fn with_key_path(mut self, key_path: Option<PathBuf>) -> Result<Self> {
        self.key_path = key_path;
        Ok(self)
    }

    /// Enable SSH agent authentication.
    pub fn with_agent(mut self, use_agent: bool) -> Self {
        self.use_agent = use_agent;
        self
    }

    /// Enable password authentication.
    pub fn with_password(mut self, use_password: bool) -> Self {
        self.use_password = use_password;
        self
    }

    /// Enable automatic password fallback (for interactive mode).
    ///
    /// When enabled, password authentication will be attempted automatically
    /// after SSH key authentication fails, matching OpenSSH behavior.
    pub fn with_password_fallback(mut self, allow: bool) -> Self {
        self.allow_password_fallback = allow;
        self
    }

    /// Enable macOS Keychain integration for passphrase storage/retrieval.
    ///
    /// This method is only available on macOS.
    #[cfg(target_os = "macos")]
    pub fn with_keychain(mut self, use_keychain: bool) -> Self {
        self.use_keychain = use_keychain;
        self
    }

    /// Provide a pre-collected SSH password.
    ///
    /// Used by callers (the dispatcher) that prompt for the password once,
    /// up-front, before fanning out parallel SSH connections. When set,
    /// `password_auth()` consumes this value instead of prompting interactively.
    ///
    /// The password is shared via `Arc`, so cloning this context (e.g.,
    /// per-node) does not duplicate the underlying secret material.
    pub fn with_pre_collected_password(mut self, password: Option<Arc<Password>>) -> Self {
        self.password = password;
        self
    }

    /// Apply the concrete host's resolved ssh_config authentication policy.
    pub fn with_policy(mut self, policy: SshAuthenticationPolicy) -> Self {
        self.policy = policy;
        self
    }

    #[cfg(test)]
    fn with_prompt_available(mut self, available: bool) -> Self {
        self.prompt_available = Some(available);
        self
    }

    /// Determine the appropriate authentication method based on the context.
    ///
    /// This method implements the standard authentication priority with security hardening:
    /// 1. Password authentication (if explicitly requested via --password flag)
    /// 2. SSH agent (if explicitly requested and available)
    /// 3. Specified key file (if provided and valid)
    /// 4. SSH agent auto-detection (if use_agent is true)
    /// 5. Default key locations (~/.ssh/id_ed25519, ~/.ssh/id_rsa, etc.)
    /// 6. Password authentication fallback (interactive terminal only, matches OpenSSH behavior)
    ///
    /// The password fallback (step 6) matches standard OpenSSH behavior where password
    /// authentication is attempted as a last resort when all key-based methods fail.
    /// This only occurs in interactive terminals (when stdin is a TTY).
    ///
    /// # Security
    /// - All file operations use canonical paths
    /// - Authentication timing is normalized to prevent timing attacks
    /// - Credentials are securely zeroized after use
    /// - Password prompts only appear in interactive terminals
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No authentication method is available (non-interactive environment)
    /// - SSH key file cannot be read or is invalid
    /// - Password/passphrase prompt fails or times out
    /// - SSH agent is requested but not available (Windows)
    pub async fn determine_method(&self) -> Result<AuthMethod> {
        // Use async operations to prevent timing attacks
        let start_time = std::time::Instant::now();

        let result = self.determine_method_internal().await;

        // Normalize timing to prevent timing attacks
        let elapsed = start_time.elapsed();
        if elapsed < Duration::from_millis(50) {
            tokio::time::sleep(Duration::from_millis(50) - elapsed).await;
        }

        result
    }

    fn authentication_exhausted_error(&self, password_status: &'static str) -> anyhow::Error {
        let agent_status = if cfg!(target_os = "windows") {
            "not supported on Windows".to_string()
        } else {
            match std::env::var_os("SSH_AUTH_SOCK") {
                Some(socket) if std::path::Path::new(&socket).exists() => {
                    "available but no usable identities were found".to_string()
                }
                Some(_) => "configured socket path does not exist".to_string(),
                None => "not available (SSH_AUTH_SOCK is not set)".to_string(),
            }
        };

        anyhow::Error::new(crate::ssh::tokio_client::Error::AuthenticationExhausted {
            methods: "publickey".to_string(),
            identity_status: "none selected by the resolved policy".to_string(),
            agent_status,
            password_status,
        })
    }

    async fn determine_method_internal(&self) -> Result<AuthMethod> {
        let publickey_methods = if self.policy.method_enabled("publickey") {
            self.publickey_methods().await?
        } else {
            Vec::new()
        };
        let password_method = if self.policy.method_enabled("password") {
            self.password_method().await?
        } else {
            None
        };

        let mut methods = Vec::new();
        let mut publickey_added = false;
        let mut password_added = false;
        for preferred in &self.policy.preferred_authentications {
            match preferred.to_ascii_lowercase().as_str() {
                "publickey" if !publickey_added => {
                    methods.extend(publickey_methods.iter().cloned());
                    publickey_added = true;
                }
                "password" if !password_added => {
                    methods.extend(password_method.iter().cloned());
                    password_added = true;
                }
                _ => {}
            }
        }

        if methods.is_empty() {
            let password_status = if self.policy.batch_mode {
                "disabled by BatchMode"
            } else if !self.policy.password_authentication {
                "disabled by PasswordAuthentication"
            } else {
                "not available in non-interactive mode"
            };
            return Err(self.authentication_exhausted_error(password_status));
        }

        Ok(AuthMethod::with_methods(methods))
    }

    fn prompt_available(&self) -> bool {
        self.prompt_available
            .unwrap_or_else(|| std::io::stdin().is_terminal())
    }

    async fn password_method(&self) -> Result<Option<AuthMethod>> {
        if self.policy.batch_mode {
            return Ok(None);
        }
        if self.use_password {
            if let Some(password) = &self.password {
                return Ok(Some(AuthMethod::with_password(password.as_str())));
            }
            if !self.prompt_available() {
                return Ok(None);
            }
            return Ok(Some(AuthMethod::with_password_prompt(
                self.policy.number_of_password_prompts,
            )));
        }
        if !self.prompt_available() {
            return Ok(None);
        }
        Ok(Some(AuthMethod::with_password_prompt(
            self.policy.number_of_password_prompts,
        )))
    }

    async fn prepare_identity(
        &self,
        path: &Path,
        required: bool,
    ) -> Result<Option<PreparedIdentity>> {
        let unresolved = |path: PathBuf| PreparedIdentity {
            path,
            algorithm: None,
            public_key: None,
            public_only: false,
        };
        let canonical_path = match path.canonicalize() {
            Ok(path) if path.is_file() => path,
            Ok(_) | Err(_) if required => {
                tracing::warn!(
                    "Identity file '{}' is not accessible; later authentication methods will still be tried",
                    path.display()
                );
                return Ok(Some(unresolved(path.to_path_buf())));
            }
            _ => return Ok(None),
        };

        if let Ok(public_key) = russh::keys::load_public_key(&canonical_path) {
            return Ok(Some(PreparedIdentity {
                path: canonical_path,
                algorithm: Some(public_key.algorithm()),
                public_key: Some(public_key.key_data().clone()),
                public_only: true,
            }));
        }

        let key_contents = match tokio::fs::read_to_string(&canonical_path).await {
            Ok(contents) => Zeroizing::new(contents),
            Err(error) if required => {
                tracing::warn!(
                    "Identity file '{}' could not be read ({error}); later authentication methods will still be tried",
                    canonical_path.display()
                );
                return Ok(Some(unresolved(canonical_path)));
            }
            Err(_) => return Ok(None),
        };
        let metadata = russh::keys::PrivateKey::from_openssh(key_contents.as_bytes())
            .map(|key| (key.algorithm(), key.public_key().key_data().clone()))
            .or_else(|_| {
                russh::keys::load_secret_key(&canonical_path, None)
                    .map(|key| (key.algorithm(), key.public_key().key_data().clone()))
            });
        let (algorithm, public_key) = match metadata {
            Ok((algorithm, public_key)) => (Some(algorithm), Some(public_key)),
            Err(_) => {
                let mut companion = canonical_path.as_os_str().to_os_string();
                companion.push(".pub");
                match russh::keys::load_public_key(PathBuf::from(companion)) {
                    Ok(public_key) => (
                        Some(public_key.algorithm()),
                        Some(public_key.key_data().clone()),
                    ),
                    Err(_) => (None, None),
                }
            }
        };

        Ok(Some(PreparedIdentity {
            path: canonical_path,
            algorithm,
            public_key,
            public_only: false,
        }))
    }

    async fn publickey_methods(&self) -> Result<Vec<AuthMethod>> {
        let mut configured = Vec::new();
        if let Some(path) = self.key_path.as_deref()
            && let Some(identity) = self.prepare_identity(path, true).await?
        {
            configured.push(identity);
        }
        for path in &self.policy.cli_identity_files {
            if let Some(identity) = self.prepare_identity(path, true).await?
                && !configured
                    .iter()
                    .any(|candidate: &PreparedIdentity| candidate.path == identity.path)
            {
                configured.push(identity);
            }
        }
        let explicit_identity_count = configured.len();
        for path in &self.policy.identity_files {
            if let Some(identity) = self.prepare_identity(path, false).await?
                && !configured
                    .iter()
                    .any(|candidate: &PreparedIdentity| candidate.path == identity.path)
            {
                configured.push(identity);
            }
        }

        let mut defaults = Vec::new();
        if !self.policy.identities_only && !self.policy.identity_file_none {
            for path in self.default_key_paths() {
                if let Some(identity) = self.prepare_identity(&path, false).await?
                    && !configured
                        .iter()
                        .chain(defaults.iter())
                        .any(|candidate: &PreparedIdentity| candidate.path == identity.path)
                {
                    defaults.push(identity);
                }
            }
        }

        let all_identities = configured.iter().chain(defaults.iter()).collect::<Vec<_>>();
        let mut certificates_by_identity = vec![Vec::<PathBuf>::new(); all_identities.len()];
        let accepted = self
            .policy
            .pubkey_accepted_algorithms
            .clone()
            .unwrap_or_default();
        #[cfg(target_os = "macos")]
        let use_keychain = self.use_keychain;
        #[cfg(not(target_os = "macos"))]
        let use_keychain = false;
        #[cfg(not(target_os = "windows"))]
        let agent_available = self.use_agent || std::env::var_os("SSH_AUTH_SOCK").is_some();
        #[cfg(target_os = "windows")]
        let agent_available = false;
        let mut explicit_certificates = Vec::new();
        for certificate_path in &self.policy.certificate_files {
            let certificate =
                russh::keys::load_openssh_certificate(certificate_path).map_err(|error| {
                    anyhow::Error::new(crate::ssh::tokio_client::Error::AuthenticationPolicy(
                        format!(
                            "unable to load certificate '{}': {error}",
                            certificate_path.display()
                        ),
                    ))
                })?;
            if certificate.cert_type() != russh::keys::ssh_key::certificate::CertType::User {
                return Err(anyhow::Error::new(
                    crate::ssh::tokio_client::Error::AuthenticationPolicy(format!(
                        "certificate '{}' is not a user certificate",
                        certificate_path.display()
                    )),
                ));
            }
            let index = all_identities
                .iter()
                .position(|identity| identity.public_key.as_ref() == Some(certificate.public_key()))
                .or_else(|| {
                    let mut unknown = all_identities
                        .iter()
                        .enumerate()
                        .filter(|(_, identity)| identity.public_key.is_none());
                    let candidate = unknown.next().map(|(index, _)| index);
                    candidate.filter(|_| unknown.next().is_none())
                });
            let Some(index) = index else {
                if crate::ssh::tokio_client::authentication::certificate_allowed(
                    &certificate,
                    &accepted,
                ) {
                    #[cfg(not(target_os = "windows"))]
                    explicit_certificates.push(AuthMethod::with_agent_certificate_file(
                        certificate_path,
                        accepted.clone(),
                    ));
                }
                continue;
            };
            if crate::ssh::tokio_client::authentication::local_certificate_allowed(
                &certificate,
                &accepted,
            ) {
                let identity = all_identities[index];
                #[cfg(not(target_os = "windows"))]
                if identity.public_only {
                    explicit_certificates.push(AuthMethod::with_agent_certificate_file(
                        certificate_path,
                        accepted.clone(),
                    ));
                    continue;
                }
                explicit_certificates.push(AuthMethod::with_configured_certificate_file(
                    &identity.path,
                    certificate_path,
                    accepted.clone(),
                    !self.policy.batch_mode,
                    use_keychain,
                ));
            }
        }

        // OpenSSH automatically considers a certificate stored next to an
        // identity as either `<identity>-cert.pub` or a certificate-valued
        // `<identity>.pub`. Plain public-key companions are ignored here.
        for (index, identity) in all_identities.iter().enumerate() {
            for certificate_path in Self::automatic_certificate_paths(&identity.path) {
                if self.policy.certificate_files.contains(&certificate_path)
                    || certificates_by_identity[index].contains(&certificate_path)
                {
                    continue;
                }
                let Ok(certificate) = russh::keys::load_openssh_certificate(&certificate_path)
                else {
                    continue;
                };
                if certificate.cert_type() == russh::keys::ssh_key::certificate::CertType::User
                    && identity.public_key.as_ref() == Some(certificate.public_key())
                    && crate::ssh::tokio_client::authentication::local_certificate_allowed(
                        &certificate,
                        &accepted,
                    )
                {
                    certificates_by_identity[index].push(certificate_path);
                }
            }
        }

        // OpenSSH places every explicitly configured CertificateFile before
        // IdentityFile and ambient-agent candidates, preserving declaration order.
        let mut methods = explicit_certificates;
        self.append_identity_methods(
            &mut methods,
            &configured[..explicit_identity_count],
            &certificates_by_identity[..explicit_identity_count],
        );
        self.append_identity_methods(
            &mut methods,
            &configured[explicit_identity_count..],
            &certificates_by_identity[explicit_identity_count..configured.len()],
        );

        #[cfg(not(target_os = "windows"))]
        {
            if agent_available && !self.policy.identities_only && !self.policy.identity_file_none {
                methods.push(AuthMethod::with_agent_policy(accepted.clone()));
            }
        }

        self.append_identity_methods(
            &mut methods,
            &defaults,
            &certificates_by_identity[configured.len()..],
        );
        Ok(methods)
    }

    fn automatic_certificate_paths(identity_path: &Path) -> [PathBuf; 2] {
        let mut certificate = identity_path.as_os_str().to_os_string();
        certificate.push("-cert.pub");
        let mut public = identity_path.as_os_str().to_os_string();
        public.push(".pub");
        [PathBuf::from(certificate), PathBuf::from(public)]
    }

    fn append_identity_methods(
        &self,
        methods: &mut Vec<AuthMethod>,
        identities: &[PreparedIdentity],
        certificates: &[Vec<PathBuf>],
    ) {
        let accepted = self
            .policy
            .pubkey_accepted_algorithms
            .clone()
            .unwrap_or_default();
        #[cfg(target_os = "macos")]
        let use_keychain = self.use_keychain;
        #[cfg(not(target_os = "macos"))]
        let use_keychain = false;
        let allow_passphrase_prompt = !self.policy.batch_mode;

        for (identity, certificate_paths) in identities.iter().zip(certificates) {
            #[cfg(not(target_os = "windows"))]
            if identity.public_only {
                if self.use_agent || std::env::var_os("SSH_AUTH_SOCK").is_some() {
                    for certificate_path in certificate_paths {
                        methods.push(AuthMethod::with_agent_certificate_file(
                            certificate_path,
                            accepted.clone(),
                        ));
                    }
                    methods.push(AuthMethod::with_agent_public_key_file(
                        &identity.path,
                        accepted.clone(),
                    ));
                }
                continue;
            }

            for certificate_path in certificate_paths {
                methods.push(AuthMethod::with_configured_certificate_file(
                    &identity.path,
                    certificate_path,
                    accepted.clone(),
                    allow_passphrase_prompt,
                    use_keychain,
                ));
            }
            if identity.algorithm.as_ref().is_none_or(|algorithm| {
                crate::ssh::tokio_client::authentication::public_key_allowed(algorithm, &accepted)
            }) {
                methods.push(AuthMethod::with_configured_key_file(
                    &identity.path,
                    accepted.clone(),
                    allow_passphrase_prompt,
                    use_keychain,
                ));
            }
        }
    }

    fn default_key_paths(&self) -> Vec<PathBuf> {
        let Some(home_dir) = dirs::home_dir() else {
            return Vec::new();
        };
        let ssh_dir = home_dir.join(".ssh");
        ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"]
            .into_iter()
            .map(|name| ssh_dir.join(name))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::EnvGuard;
    use russh::keys::ssh_key::LineEnding;
    use serial_test::serial;
    use tempfile::TempDir;

    fn write_test_key(path: &Path) -> russh::keys::PrivateKey {
        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        std::fs::write(path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        key
    }

    #[tokio::test]
    async fn test_auth_context_creation() {
        let ctx = AuthContext::new("testuser".to_string(), "testhost".to_string()).unwrap();
        assert_eq!(ctx.username, "testuser");
        assert_eq!(ctx.host, "testhost");
        assert_eq!(ctx.key_path, None);
        assert!(!ctx.use_agent);
        assert!(!ctx.use_password);
        assert!(ctx.password.is_none());
    }

    #[tokio::test]
    async fn test_auth_context_with_pre_collected_password() {
        let password = Arc::new(Password::new("test123".to_string()).unwrap());
        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_password(true)
            .with_pre_collected_password(Some(Arc::clone(&password)));

        assert!(ctx.use_password);
        assert!(ctx.password.is_some());
        assert_eq!(ctx.password.as_ref().unwrap().as_str(), "test123");
        // Both the test holder and the AuthContext share the same Arc.
        assert_eq!(Arc::strong_count(&password), 2);
    }

    #[tokio::test]
    async fn test_password_auth_uses_pre_collected_password() {
        // Verifies that when a pre-collected password is provided, password_method()
        // returns immediately with AuthMethod::Password(...) instead of prompting.
        // Critically, this means it never blocks on stdin — even in a non-interactive
        // test environment.
        let password = Arc::new(Password::new("pre_collected_secret".to_string()).unwrap());
        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_password(true)
            .with_pre_collected_password(Some(password));

        let auth = ctx
            .password_method()
            .await
            .expect("should not prompt")
            .expect("password method");

        match auth {
            AuthMethod::Password(stored) => {
                assert_eq!(stored.as_str(), "pre_collected_secret");
            }
            other => panic!("Expected AuthMethod::Password, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_auth_context_validation() {
        // Test empty username
        let result = AuthContext::new("".to_string(), "host".to_string());
        assert!(result.is_err());

        // Test username with invalid characters
        let result = AuthContext::new("user/name".to_string(), "host".to_string());
        assert!(result.is_err());

        // Test empty hostname
        let result = AuthContext::new("user".to_string(), "".to_string());
        assert!(result.is_err());

        // Test overly long username
        let long_username = "a".repeat(MAX_USERNAME_LENGTH + 1);
        let result = AuthContext::new(long_username, "host".to_string());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_context_with_key_path() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key");
        std::fs::write(&key_path, "fake key content").unwrap();

        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_key_path(Some(key_path.clone()))
            .unwrap();
        assert_eq!(ctx.key_path.as_deref(), Some(key_path.as_path()));
    }

    #[tokio::test]
    async fn test_auth_context_defers_invalid_key_path_failure_to_attempt_time() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("missing-key");
        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_key_path(Some(key_path.clone()))
            .unwrap();
        assert_eq!(ctx.key_path.as_deref(), Some(key_path.as_path()));
    }

    #[tokio::test]
    async fn test_auth_context_with_agent() {
        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_agent(true);

        assert!(ctx.use_agent);
    }

    #[tokio::test]
    async fn test_auth_context_with_password() {
        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_password(true);

        assert!(ctx.use_password);
    }

    #[tokio::test]
    async fn test_determine_method_with_key_file() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key");
        write_test_key(&key_path);

        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_key_path(Some(key_path.clone()))
            .unwrap()
            .with_policy(SshAuthenticationPolicy {
                identities_only: true,
                preferred_authentications: vec!["publickey".into()],
                ..SshAuthenticationPolicy::default()
            });

        let auth = ctx.determine_method().await.unwrap();

        match auth {
            AuthMethod::PrivateKeyFileWithPolicy { key_file_path, .. } => {
                // Path should be canonicalized
                assert!(key_file_path.is_absolute());
            }
            _ => panic!("Expected policy-aware private-key auth method"),
        }
    }

    #[tokio::test]
    async fn test_timing_attack_mitigation() {
        let ctx = AuthContext::new("user".to_string(), "host".to_string()).unwrap();

        // Measure time for failed authentication
        let start = std::time::Instant::now();
        let _ = ctx.determine_method().await;
        let duration = start.elapsed();

        // Should take at least 50ms due to timing normalization
        assert!(duration >= Duration::from_millis(50));
    }

    #[tokio::test]
    #[serial]
    async fn test_password_fallback_in_non_interactive() {
        // Create a fake home directory WITHOUT default keys (to trigger fallback)
        let temp_dir = TempDir::new().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        // Intentionally NOT creating any key files

        // Set test environment; guards restore prior values on drop.
        let _home = EnvGuard::set("HOME", temp_dir.path().to_str().unwrap());
        let _sock = EnvGuard::remove("SSH_AUTH_SOCK");

        let ctx = AuthContext::new("user".to_string(), "host".to_string()).unwrap();

        // In non-interactive environment (like tests), should fail with helpful error
        let result = ctx.determine_method().await;
        assert!(result.is_err());

        // Error message should mention authentication failure
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("authentication"));
    }
    fn write_user_certificate(
        path: &Path,
        subject: &russh::keys::PrivateKey,
        ca: &russh::keys::PrivateKey,
    ) {
        let mut builder = russh::keys::ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            subject.public_key(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder.key_id("issue-296").unwrap();
        builder
            .cert_type(russh::keys::ssh_key::certificate::CertType::User)
            .unwrap();
        builder.valid_principal("user").unwrap();
        std::fs::write(path, builder.sign(ca).unwrap().to_openssh().unwrap()).unwrap();
    }

    fn method_names(auth: AuthMethod) -> Vec<String> {
        let methods = match auth {
            AuthMethod::Methods(methods) => methods,
            method => vec![method],
        };
        methods
            .into_iter()
            .map(|method| match method {
                AuthMethod::Password(_) => "password".to_string(),
                AuthMethod::PasswordPrompt { attempts } => format!("password-prompt:{attempts}"),
                AuthMethod::PrivateKeyFileWithPolicy { key_file_path, .. } => format!(
                    "key:{}",
                    key_file_path.file_name().unwrap().to_string_lossy()
                ),
                AuthMethod::OpenSshCertificateFile {
                    certificate_file_path,
                    ..
                } => format!(
                    "cert:{}",
                    certificate_file_path.file_name().unwrap().to_string_lossy()
                ),
                #[cfg(not(target_os = "windows"))]
                AuthMethod::AgentWithPolicy { .. } => "agent".to_string(),
                #[cfg(not(target_os = "windows"))]
                AuthMethod::AgentPublicKeyFile { key_file_path, .. } => format!(
                    "agent-key:{}",
                    key_file_path.file_name().unwrap().to_string_lossy()
                ),
                #[cfg(not(target_os = "windows"))]
                AuthMethod::AgentCertificateFile {
                    certificate_file_path,
                    ..
                } => format!(
                    "agent-cert:{}",
                    certificate_file_path.file_name().unwrap().to_string_lossy()
                ),
                other => format!("unexpected:{other:?}"),
            })
            .collect()
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    #[serial]
    async fn policy_orders_explicit_credentials_before_ssh_config_candidates() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        let _home = EnvGuard::set("HOME", home.path());
        let _socket = EnvGuard::set("SSH_AUTH_SOCK", home.path().join("agent.sock"));
        let cli_key = home.path().join("cli-key");
        let cli_second = home.path().join("cli-second");
        let config_key = home.path().join("config-key");
        write_test_key(&cli_key);
        write_test_key(&cli_second);
        write_test_key(&config_key);
        let policy = SshAuthenticationPolicy {
            cli_identity_files: vec![cli_key.clone(), cli_second],
            identity_files: vec![config_key],
            preferred_authentications: vec!["password".into(), "publickey".into()],
            pubkey_accepted_algorithms: Some(vec!["ssh-ed25519".into()]),
            ..SshAuthenticationPolicy::default()
        };
        let password = Arc::new(Password::new("secret".to_string()).unwrap());
        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_key_path(Some(cli_key))
            .unwrap()
            .with_agent(true)
            .with_password(true)
            .with_pre_collected_password(Some(password))
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();
        assert_eq!(
            method_names(auth),
            [
                "password",
                "key:cli-key",
                "key:cli-second",
                "key:config-key",
                "agent",
            ]
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    #[serial]
    async fn identities_only_blocks_agent_and_default_keys() {
        let home = TempDir::new().unwrap();
        let ssh_dir = home.path().join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        let _home = EnvGuard::set("HOME", home.path());
        let _socket = EnvGuard::set("SSH_AUTH_SOCK", home.path().join("agent.sock"));
        let configured = home.path().join("configured-key");
        write_test_key(&configured);
        write_test_key(&ssh_dir.join("id_ed25519"));
        let policy = SshAuthenticationPolicy {
            identity_files: vec![configured],
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            ..SshAuthenticationPolicy::default()
        };
        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_agent(true)
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();
        assert_eq!(method_names(auth), ["key:configured-key"]);
    }

    #[tokio::test]
    async fn disabled_and_unpreferred_methods_are_never_planned() {
        let home = TempDir::new().unwrap();
        let key_path = home.path().join("identity");
        write_test_key(&key_path);
        let password = Arc::new(Password::new("secret".to_string()).unwrap());
        let policy = SshAuthenticationPolicy {
            identity_files: vec![key_path],
            identities_only: true,
            preferred_authentications: vec!["password".into(), "publickey".into()],
            pubkey_authentication: false,
            ..SshAuthenticationPolicy::default()
        };
        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_password(true)
            .with_pre_collected_password(Some(password))
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();
        assert_eq!(method_names(auth), ["password"]);

        let policy = SshAuthenticationPolicy {
            preferred_authentications: vec!["publickey".into()],
            pubkey_authentication: false,
            ..SshAuthenticationPolicy::default()
        };
        let error = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_prompt_available(true)
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Permission denied"));
    }

    #[tokio::test]
    async fn batch_mode_never_plans_password_or_passphrase_prompts() {
        let password_policy = SshAuthenticationPolicy {
            preferred_authentications: vec!["password".into()],
            pubkey_authentication: false,
            batch_mode: true,
            ..SshAuthenticationPolicy::default()
        };
        let password = Arc::new(Password::new("already-collected".to_string()).unwrap());
        let error = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_password(true)
            .with_pre_collected_password(Some(password))
            .with_prompt_available(true)
            .with_policy(password_policy)
            .determine_method()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("BatchMode"));

        let home = TempDir::new().unwrap();
        let encrypted_key = home.path().join("encrypted-key");
        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let encrypted = key.encrypt(&mut rand::rng(), "secret").unwrap();
        std::fs::write(
            &encrypted_key,
            encrypted.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        let key_policy = SshAuthenticationPolicy {
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            batch_mode: true,
            ..SshAuthenticationPolicy::default()
        };
        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_key_path(Some(encrypted_key))
            .unwrap()
            .with_prompt_available(true)
            .with_policy(key_policy)
            .determine_method()
            .await
            .unwrap();
        assert!(matches!(
            auth,
            AuthMethod::PrivateKeyFileWithPolicy {
                allow_passphrase_prompt: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn later_invalid_keys_and_password_prompt_stay_lazy_and_ordered() {
        let home = TempDir::new().unwrap();
        let first_key = home.path().join("first-key");
        let encrypted_key = home.path().join("encrypted-key");
        let malformed_key = home.path().join("malformed-key");
        write_test_key(&first_key);
        let encrypted = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap()
        .encrypt(&mut rand::rng(), "secret")
        .unwrap();
        std::fs::write(
            &encrypted_key,
            encrypted.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::write(&malformed_key, "not an SSH private key").unwrap();

        let policy = SshAuthenticationPolicy {
            cli_identity_files: vec![first_key.clone(), encrypted_key, malformed_key],
            identities_only: true,
            preferred_authentications: vec!["publickey".into(), "password".into()],
            ..SshAuthenticationPolicy::default()
        };
        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_key_path(Some(first_key))
            .unwrap()
            .with_password(true)
            .with_prompt_available(true)
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();

        assert_eq!(
            method_names(auth),
            [
                "key:first-key",
                "key:encrypted-key",
                "key:malformed-key",
                "password-prompt:3",
            ]
        );
    }
    #[tokio::test]
    async fn number_of_password_prompts_is_the_exact_attempt_bound() {
        let policy = SshAuthenticationPolicy {
            preferred_authentications: vec!["password".into()],
            pubkey_authentication: false,
            number_of_password_prompts: 2,
            ..SshAuthenticationPolicy::default()
        };
        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_prompt_available(true)
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();
        assert_eq!(method_names(auth), ["password-prompt:2"]);
    }

    #[tokio::test]
    async fn matching_user_certificate_precedes_plain_key() {
        let home = TempDir::new().unwrap();
        let key_path = home.path().join("user-key");
        let certificate_path = home.path().join("user-cert.pub");
        let subject = write_test_key(&key_path);
        let ca = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        write_user_certificate(&certificate_path, &subject, &ca);
        let policy = SshAuthenticationPolicy {
            identity_files: vec![key_path],
            certificate_files: vec![certificate_path],
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            pubkey_accepted_algorithms: Some(vec![
                "ssh-ed25519-cert-v01@openssh.com".into(),
                "ssh-ed25519".into(),
            ]),
            ..SshAuthenticationPolicy::default()
        };
        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();
        assert_eq!(method_names(auth), ["cert:user-cert.pub", "key:user-key"]);
    }

    #[tokio::test]
    async fn automatic_certificate_companion_precedes_plain_identity() {
        let home = TempDir::new().unwrap();
        let key_path = home.path().join("automatic-key");
        let certificate_path = AuthContext::automatic_certificate_paths(&key_path)[1].clone();
        let subject = write_test_key(&key_path);
        let ca = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        write_user_certificate(&certificate_path, &subject, &ca);
        let policy = SshAuthenticationPolicy {
            identity_files: vec![key_path],
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            ..SshAuthenticationPolicy::default()
        };

        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();

        assert_eq!(
            method_names(auth),
            ["cert:automatic-key.pub", "key:automatic-key"]
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    #[serial]
    async fn identities_only_allows_only_a_listed_agent_public_identity() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        let _home = EnvGuard::set("HOME", home.path());
        let socket_path = home.path().join("agent.sock");
        std::fs::write(&socket_path, []).unwrap();
        let _socket = EnvGuard::set("SSH_AUTH_SOCK", &socket_path);
        let private_path = home.path().join("listed-key");
        let public_path = home.path().join("listed-key.pub");
        let key = write_test_key(&private_path);
        std::fs::write(&public_path, key.public_key().to_openssh().unwrap()).unwrap();
        let policy = SshAuthenticationPolicy {
            identity_files: vec![public_path],
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            ..SshAuthenticationPolicy::default()
        };

        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_agent(true)
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();

        assert_eq!(method_names(auth), ["agent-key:listed-key.pub"]);
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    #[serial]
    async fn certificate_file_can_pair_with_an_allowed_agent_identity() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        let _home = EnvGuard::set("HOME", home.path());
        let socket_path = home.path().join("agent.sock");
        std::fs::write(&socket_path, []).unwrap();
        let _socket = EnvGuard::set("SSH_AUTH_SOCK", &socket_path);
        let key_path = home.path().join("agent-key");
        let certificate_path = home.path().join("agent-cert.pub");
        let subject = write_test_key(&key_path);
        let ca = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        write_user_certificate(&certificate_path, &subject, &ca);
        let policy = SshAuthenticationPolicy {
            certificate_files: vec![certificate_path],
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            ..SshAuthenticationPolicy::default()
        };

        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();

        assert_eq!(method_names(auth), ["agent-cert:agent-cert.pub"]);
    }

    #[tokio::test]
    #[serial]
    async fn mismatched_local_certificate_remains_a_retryable_agent_candidate() {
        let home = TempDir::new().unwrap();
        let _socket = EnvGuard::remove("SSH_AUTH_SOCK");
        let key_path = home.path().join("configured-key");
        write_test_key(&key_path);
        let other_key_path = home.path().join("other-key");
        let other_subject = write_test_key(&other_key_path);
        let ca = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let certificate_path = home.path().join("mismatch-cert.pub");
        write_user_certificate(&certificate_path, &other_subject, &ca);
        let policy = SshAuthenticationPolicy {
            identity_files: vec![key_path],
            certificate_files: vec![certificate_path],
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            ..SshAuthenticationPolicy::default()
        };
        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();
        assert_eq!(
            method_names(auth),
            ["agent-cert:mismatch-cert.pub", "key:configured-key"]
        );
    }

    #[tokio::test]
    async fn missing_and_malformed_cli_identities_leave_later_keys_reachable() {
        let home = TempDir::new().unwrap();
        let missing = home.path().join("missing-key");
        let malformed = home.path().join("malformed-key");
        let valid = home.path().join("valid-key");
        std::fs::write(&malformed, "not an SSH private key").unwrap();
        write_test_key(&valid);
        let policy = SshAuthenticationPolicy {
            cli_identity_files: vec![missing, malformed, valid],
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            ..SshAuthenticationPolicy::default()
        };

        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();

        assert_eq!(
            method_names(auth),
            ["key:missing-key", "key:malformed-key", "key:valid-key"]
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    #[serial]
    async fn identities_only_public_identity_keeps_matching_agent_certificate_first() {
        let home = TempDir::new().unwrap();
        let private_path = home.path().join("listed-key");
        let public_path = home.path().join("listed-key.pub");
        let certificate_path = home.path().join("listed-cert.pub");
        let subject = write_test_key(&private_path);
        std::fs::write(&public_path, subject.public_key().to_openssh().unwrap()).unwrap();
        let ca = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        write_user_certificate(&certificate_path, &subject, &ca);
        let policy = SshAuthenticationPolicy {
            identity_files: vec![public_path],
            certificate_files: vec![certificate_path],
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            ..SshAuthenticationPolicy::default()
        };

        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_agent(true)
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();

        assert_eq!(
            method_names(auth),
            ["agent-cert:listed-cert.pub", "agent-key:listed-key.pub"]
        );
    }

    #[tokio::test]
    async fn encrypted_rsa_companion_is_filtered_before_any_passphrase_prompt() {
        let home = TempDir::new().unwrap();
        let rsa_path = home.path().join("encrypted-rsa");
        crate::keygen::generate_rsa(&rsa_path, 2048, None).unwrap();
        let rsa = russh::keys::load_secret_key(&rsa_path, None).unwrap();
        let encrypted = rsa.encrypt(&mut rand::rng(), "secret").unwrap();
        std::fs::write(
            &rsa_path,
            encrypted.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        let ed25519_path = home.path().join("valid-ed25519");
        write_test_key(&ed25519_path);
        let policy = SshAuthenticationPolicy {
            cli_identity_files: vec![rsa_path, ed25519_path],
            identities_only: true,
            preferred_authentications: vec!["publickey".into()],
            pubkey_accepted_algorithms: Some(vec!["ssh-ed25519".into()]),
            ..SshAuthenticationPolicy::default()
        };

        let auth = AuthContext::new("user".into(), "host".into())
            .unwrap()
            .with_prompt_available(true)
            .with_policy(policy)
            .determine_method()
            .await
            .unwrap();

        assert_eq!(method_names(auth), ["key:valid-ed25519"]);
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    #[serial]
    async fn identity_file_none_suppresses_defaults_and_ambient_agent() {
        let home = TempDir::new().unwrap();
        let ssh_dir = home.path().join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        write_test_key(&ssh_dir.join("id_ed25519"));
        let _home = EnvGuard::set("HOME", home.path());
        let _socket = EnvGuard::set("SSH_AUTH_SOCK", home.path().join("agent.sock"));
        let ssh_config = crate::ssh::SshConfig::parse(
            "Host target\n    IdentityFile none\n    IdentitiesOnly no\n",
        )
        .unwrap();
        let resolved = crate::ssh::tokio_client::SshConnectionConfigResolver::new()
            .with_ssh_config(Some(ssh_config))
            .resolve_for_host("target");
        assert!(resolved.auth_policy.identity_file_none);
        assert!(resolved.auth_policy.identity_files.is_empty());
        let password = Arc::new(Password::new("secret".to_string()).unwrap());

        let auth = AuthContext::new("user".into(), "target".into())
            .unwrap()
            .with_agent(true)
            .with_password(true)
            .with_pre_collected_password(Some(password))
            .with_policy(resolved.auth_policy)
            .determine_method()
            .await
            .unwrap();

        assert_eq!(method_names(auth), ["password"]);
    }
}

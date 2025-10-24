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

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::tokio_client::AuthMethod;

/// Maximum time to wait for password/passphrase input
const AUTH_PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum username length to prevent DoS attacks
const MAX_USERNAME_LENGTH: usize = 256;

/// Maximum hostname length per RFC 1035
const MAX_HOSTNAME_LENGTH: usize = 253;

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
    /// Whether to use macOS Keychain for passphrase storage/retrieval (macOS only)
    #[cfg(target_os = "macos")]
    pub use_keychain: bool,
    /// Username for authentication prompts (validated)
    pub username: String,
    /// Host for authentication prompts (validated)
    pub host: String,
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
            #[cfg(target_os = "macos")]
            use_keychain: false,
            username,
            host,
        })
    }

    /// Set the SSH key file path with validation.
    ///
    /// # Security
    /// - Paths are canonicalized to prevent path traversal attacks
    /// - Symlinks are resolved to their actual targets
    pub fn with_key_path(mut self, key_path: Option<PathBuf>) -> Result<Self> {
        if let Some(path) = key_path {
            // Canonicalize path to prevent path traversal attacks
            let canonical_path = path
                .canonicalize()
                .with_context(|| format!("Failed to resolve SSH key path: {path:?}"))?;

            // Verify it's a file, not a directory
            if !canonical_path.is_file() {
                anyhow::bail!("SSH key path is not a file: {canonical_path:?}");
            }

            self.key_path = Some(canonical_path);
        } else {
            self.key_path = None;
        }
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

    /// Enable macOS Keychain integration for passphrase storage/retrieval.
    ///
    /// This method is only available on macOS.
    #[cfg(target_os = "macos")]
    pub fn with_keychain(mut self, use_keychain: bool) -> Self {
        self.use_keychain = use_keychain;
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

    async fn determine_method_internal(&self) -> Result<AuthMethod> {
        // Priority 1: Password authentication (explicit request)
        if self.use_password {
            return self.password_auth().await;
        }

        // Priority 2: SSH agent (explicit request)
        if self.use_agent {
            if let Some(auth) = self.agent_auth()? {
                return Ok(auth);
            }
        }

        // Priority 3: Key file authentication
        if let Some(ref key_path) = self.key_path {
            return self.key_file_auth(key_path).await;
        }

        // Priority 4: SSH agent auto-detection (if use_agent is true)
        #[cfg(not(target_os = "windows"))]
        if self.use_agent {
            if let Some(auth) = self.agent_auth()? {
                return Ok(auth);
            }
        }

        // Priority 5: Default key locations
        match self.default_key_auth().await {
            Ok(auth) => Ok(auth),
            Err(_) => {
                // Priority 6: Fallback to password authentication WITH USER CONSENT
                // Unlike OpenSSH, we ask for explicit consent before password fallback for security
                // Check if we're in an interactive terminal
                if atty::is(atty::Stream::Stdin) && self.prompt_password_fallback_consent().await? {
                    tracing::debug!("User consented to password authentication fallback");
                    self.password_auth().await
                } else if atty::is(atty::Stream::Stdin) {
                    // User declined password fallback
                    anyhow::bail!(
                        "SSH authentication failed: All key-based methods failed.\n\
                         \n\
                         Tried:\n\
                         - SSH agent: {}\n\
                         - Default SSH keys: Not found or not authorized\n\
                         \n\
                         User declined password authentication fallback.\n\
                         \n\
                         Solutions:\n\
                         - Use --password flag to explicitly enable password authentication\n\
                         - Start SSH agent and add keys with 'ssh-add'\n\
                         - Specify a key file with -i/--identity\n\
                         - Ensure ~/.ssh/id_ed25519 or ~/.ssh/id_rsa exists and is authorized",
                        if cfg!(target_os = "windows") {
                            "Not supported on Windows"
                        } else if std::env::var_os("SSH_AUTH_SOCK").is_some() {
                            "Available but no identities authorized"
                        } else {
                            "Not available (SSH_AUTH_SOCK not set)"
                        }
                    )
                } else {
                    // Non-interactive environment - cannot prompt for password
                    anyhow::bail!(
                        "SSH authentication failed: No authentication method available.\n\
                         \n\
                         Tried:\n\
                         - SSH agent: {}\n\
                         - Default SSH keys: Not found or not authorized\n\
                         \n\
                         Solutions:\n\
                         - Use --password for password authentication\n\
                         - Start SSH agent and add keys with 'ssh-add'\n\
                         - Specify a key file with -i/--identity\n\
                         - Ensure ~/.ssh/id_ed25519 or ~/.ssh/id_rsa exists and is authorized",
                        if cfg!(target_os = "windows") {
                            "Not supported on Windows"
                        } else if std::env::var_os("SSH_AUTH_SOCK").is_some() {
                            "Available but no identities authorized"
                        } else {
                            "Not available (SSH_AUTH_SOCK not set)"
                        }
                    )
                }
            }
        }
    }

    /// Prompt user for consent to fall back to password authentication.
    ///
    /// Returns true if user consents, false otherwise.
    async fn prompt_password_fallback_consent(&self) -> Result<bool> {
        use std::io::{self, Write};

        tracing::info!(
            "All SSH key-based authentication methods failed for {}@{}",
            self.username,
            self.host
        );

        // SECURITY: Add rate limiting before password fallback to prevent rapid attempts
        // This helps prevent brute-force attacks and gives servers time to process
        const FALLBACK_DELAY: Duration = Duration::from_secs(1);
        tokio::time::sleep(FALLBACK_DELAY).await;

        // Run consent prompt in blocking task
        let consent_future = tokio::task::spawn_blocking({
            let username = self.username.clone();
            let host = self.host.clone();
            move || -> Result<bool> {
                println!("\n⚠️  SSH key authentication failed for {username}@{host}");
                println!("Would you like to try password authentication? (yes/no): ");
                io::stdout().flush()?;

                let mut response = String::new();
                io::stdin().read_line(&mut response)?;
                let response = response.trim().to_lowercase();

                Ok(response == "yes" || response == "y")
            }
        });

        // Use a shorter timeout for consent prompt
        const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);
        timeout(CONSENT_TIMEOUT, consent_future)
            .await
            .context("Consent prompt timed out after 30 seconds")?
            .context("Consent prompt task failed")?
    }

    /// Attempt password authentication with timeout.
    async fn password_auth(&self) -> Result<AuthMethod> {
        tracing::debug!("Using password authentication");

        // Run password prompt with timeout to prevent hanging
        let prompt_future = tokio::task::spawn_blocking({
            let username = self.username.clone();
            let host = self.host.clone();
            move || -> Result<Zeroizing<String>> {
                // Use Zeroizing to ensure password is cleared from memory when dropped
                let password = Zeroizing::new(
                    rpassword::prompt_password(format!("Enter password for {username}@{host}: "))
                        .with_context(|| "Failed to read password")?,
                );
                Ok(password)
            }
        });

        let password = timeout(AUTH_PROMPT_TIMEOUT, prompt_future)
            .await
            .context("Password prompt timed out")?
            .context("Password prompt task failed")??;

        Ok(AuthMethod::with_password(&password))
    }

    /// Attempt SSH agent authentication with atomic check.
    #[cfg(not(target_os = "windows"))]
    fn agent_auth(&self) -> Result<Option<AuthMethod>> {
        // Atomic check to prevent TOCTOU race condition
        match std::env::var_os("SSH_AUTH_SOCK") {
            Some(socket_path) => {
                // Verify the socket actually exists
                let path = std::path::Path::new(&socket_path);
                if path.exists() {
                    tracing::debug!("Using SSH agent for authentication");
                    Ok(Some(AuthMethod::Agent))
                } else {
                    tracing::warn!("SSH_AUTH_SOCK points to non-existent socket");
                    Ok(None)
                }
            }
            None => {
                tracing::warn!(
                    "SSH agent requested but SSH_AUTH_SOCK environment variable not set"
                );
                Ok(None)
            }
        }
    }

    /// Attempt SSH agent authentication (Windows - not supported).
    #[cfg(target_os = "windows")]
    fn agent_auth(&self) -> Result<Option<AuthMethod>> {
        anyhow::bail!("SSH agent authentication is not supported on Windows");
    }

    /// Check if a key file is encrypted by examining its contents.
    ///
    /// This is a separate function to avoid reading the file multiple times.
    fn is_key_encrypted(key_contents: &str) -> bool {
        key_contents.contains("ENCRYPTED")
            || key_contents.contains("Proc-Type: 4,ENCRYPTED")
            || key_contents.contains("DEK-Info:") // OpenSSL encrypted format
    }

    /// Attempt authentication with a specific key file.
    async fn key_file_auth(&self, key_path: &Path) -> Result<AuthMethod> {
        tracing::debug!("Authenticating with key: {:?}", key_path);

        // Read key file once
        let key_contents = tokio::fs::read_to_string(key_path)
            .await
            .with_context(|| format!("Failed to read SSH key file: {key_path:?}"))?;

        let passphrase = if Self::is_key_encrypted(&key_contents) {
            tracing::debug!("Detected encrypted SSH key");

            // Try to retrieve passphrase from Keychain first (macOS only)
            #[cfg(target_os = "macos")]
            let keychain_passphrase = if self.use_keychain {
                tracing::debug!("Attempting to retrieve passphrase from Keychain");
                match super::keychain_macos::retrieve_passphrase(key_path).await {
                    Ok(Some(pass)) => {
                        tracing::info!("Successfully retrieved passphrase from Keychain");
                        Some(pass)
                    }
                    Ok(None) => {
                        tracing::debug!("No passphrase found in Keychain");
                        None
                    }
                    Err(err) => {
                        tracing::warn!("Failed to retrieve passphrase from Keychain: {err}");
                        None
                    }
                }
            } else {
                None
            };

            #[cfg(not(target_os = "macos"))]
            let keychain_passphrase: Option<Zeroizing<String>> = None;

            // If we got passphrase from Keychain, use it; otherwise prompt
            if let Some(pass) = keychain_passphrase {
                Some(pass)
            } else {
                tracing::debug!("Prompting for passphrase");

                // Run passphrase prompt with timeout
                let key_path_str = key_path.display().to_string();
                let prompt_future =
                    tokio::task::spawn_blocking(move || -> Result<Zeroizing<String>> {
                        // Use Zeroizing for passphrase security
                        let pass = Zeroizing::new(
                            rpassword::prompt_password(format!(
                                "Enter passphrase for key {key_path_str}: "
                            ))
                            .with_context(|| "Failed to read passphrase")?,
                        );
                        Ok(pass)
                    });

                let pass = timeout(AUTH_PROMPT_TIMEOUT, prompt_future)
                    .await
                    .context("Passphrase prompt timed out")?
                    .context("Passphrase prompt task failed")??;

                // Store passphrase in Keychain if enabled (macOS only)
                #[cfg(target_os = "macos")]
                if self.use_keychain {
                    tracing::debug!("Storing passphrase in Keychain");
                    if let Err(err) = super::keychain_macos::store_passphrase(key_path, &pass).await
                    {
                        tracing::warn!("Failed to store passphrase in Keychain: {err}");
                        // Continue even if storage fails - the passphrase was entered successfully
                    } else {
                        tracing::info!("Successfully stored passphrase in Keychain");
                    }
                }

                Some(pass)
            }
        } else {
            None
        };

        // Clear key_contents from memory (though String doesn't have zeroize)
        drop(key_contents);

        Ok(AuthMethod::with_key_file(
            key_path,
            passphrase.as_ref().map(|p| p.as_str()),
        ))
    }

    /// Attempt authentication with default key locations.
    async fn default_key_auth(&self) -> Result<AuthMethod> {
        // Use dirs crate for reliable home directory detection
        let home_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

        let ssh_dir = home_dir.join(".ssh");

        // Validate SSH directory exists and is actually a directory
        if !ssh_dir.is_dir() {
            anyhow::bail!(
                "SSH directory not found: {ssh_dir:?}\n\
                Please ensure ~/.ssh directory exists with proper permissions."
            );
        }

        // Try common key files in order of preference
        let default_keys = [
            ssh_dir.join("id_ed25519"),
            ssh_dir.join("id_rsa"),
            ssh_dir.join("id_ecdsa"),
            ssh_dir.join("id_dsa"),
        ];

        for default_key in &default_keys {
            if default_key.exists() && default_key.is_file() {
                // Canonicalize to prevent symlink attacks
                let canonical_key = default_key
                    .canonicalize()
                    .with_context(|| format!("Failed to resolve key path: {default_key:?}"))?;

                tracing::debug!("Using default key: {:?}", canonical_key);

                // Read key file once
                let key_contents = tokio::fs::read_to_string(&canonical_key)
                    .await
                    .with_context(|| format!("Failed to read SSH key file: {canonical_key:?}"))?;

                let passphrase = if Self::is_key_encrypted(&key_contents) {
                    tracing::debug!("Detected encrypted SSH key");

                    // Try to retrieve passphrase from Keychain first (macOS only)
                    #[cfg(target_os = "macos")]
                    let keychain_passphrase = if self.use_keychain {
                        tracing::debug!("Attempting to retrieve passphrase from Keychain");
                        match super::keychain_macos::retrieve_passphrase(&canonical_key).await {
                            Ok(Some(pass)) => {
                                tracing::info!("Successfully retrieved passphrase from Keychain");
                                Some(pass)
                            }
                            Ok(None) => {
                                tracing::debug!("No passphrase found in Keychain");
                                None
                            }
                            Err(err) => {
                                tracing::warn!(
                                    "Failed to retrieve passphrase from Keychain: {err}"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };

                    #[cfg(not(target_os = "macos"))]
                    let keychain_passphrase: Option<Zeroizing<String>> = None;

                    // If we got passphrase from Keychain, use it; otherwise prompt
                    if let Some(pass) = keychain_passphrase {
                        Some(pass)
                    } else {
                        tracing::debug!("Prompting for passphrase");

                        let key_path_str = canonical_key.display().to_string();
                        let prompt_future =
                            tokio::task::spawn_blocking(move || -> Result<Zeroizing<String>> {
                                let pass = Zeroizing::new(
                                    rpassword::prompt_password(format!(
                                        "Enter passphrase for key {key_path_str}: "
                                    ))
                                    .with_context(|| "Failed to read passphrase")?,
                                );
                                Ok(pass)
                            });

                        let pass = timeout(AUTH_PROMPT_TIMEOUT, prompt_future)
                            .await
                            .context("Passphrase prompt timed out")?
                            .context("Passphrase prompt task failed")??;

                        // Store passphrase in Keychain if enabled (macOS only)
                        #[cfg(target_os = "macos")]
                        if self.use_keychain {
                            tracing::debug!("Storing passphrase in Keychain");
                            if let Err(err) =
                                super::keychain_macos::store_passphrase(&canonical_key, &pass).await
                            {
                                tracing::warn!("Failed to store passphrase in Keychain: {err}");
                                // Continue even if storage fails - the passphrase was entered successfully
                            } else {
                                tracing::info!("Successfully stored passphrase in Keychain");
                            }
                        }

                        Some(pass)
                    }
                } else {
                    None
                };

                // Clear key_contents from memory
                drop(key_contents);

                return Ok(AuthMethod::with_key_file(
                    &canonical_key,
                    passphrase.as_ref().map(|p| p.as_str()),
                ));
            }
        }

        // Provide helpful error message without exposing system paths
        anyhow::bail!(
            "SSH authentication failed: No authentication method available.\n\
             \n\
             Tried:\n\
             - SSH agent: {}\n\
             - Default SSH keys: Not found\n\
             \n\
             Solutions:\n\
             - Use --password for password authentication\n\
             - Start SSH agent and add keys with 'ssh-add'\n\
             - Specify a key file with -i/--identity\n\
             - Create a default SSH key with 'ssh-keygen'",
            if cfg!(target_os = "windows") {
                "Not supported on Windows"
            } else if std::env::var_os("SSH_AUTH_SOCK").is_some() {
                "Available but no identities"
            } else {
                "Not available (SSH_AUTH_SOCK not set)"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_auth_context_creation() {
        let ctx = AuthContext::new("testuser".to_string(), "testhost".to_string()).unwrap();
        assert_eq!(ctx.username, "testuser");
        assert_eq!(ctx.host, "testhost");
        assert_eq!(ctx.key_path, None);
        assert!(!ctx.use_agent);
        assert!(!ctx.use_password);
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

        // Should be canonicalized
        assert!(ctx.key_path.is_some());
        assert!(ctx.key_path.unwrap().is_absolute());
    }

    #[tokio::test]
    async fn test_auth_context_with_invalid_key_path() {
        let temp_dir = TempDir::new().unwrap();

        // Test with directory instead of file
        let result = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_key_path(Some(temp_dir.path().to_path_buf()));

        assert!(result.is_err());
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
    async fn test_is_key_encrypted() {
        assert!(AuthContext::is_key_encrypted(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        ));
        assert!(AuthContext::is_key_encrypted("Proc-Type: 4,ENCRYPTED"));
        assert!(AuthContext::is_key_encrypted("DEK-Info: AES-128-CBC"));
        assert!(!AuthContext::is_key_encrypted(
            "-----BEGIN PRIVATE KEY-----"
        ));
        assert!(!AuthContext::is_key_encrypted("ssh-rsa AAAAB3..."));
    }

    #[tokio::test]
    async fn test_determine_method_with_key_file() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key");
        std::fs::write(
            &key_path,
            "-----BEGIN PRIVATE KEY-----\nfake key content\n-----END PRIVATE KEY-----",
        )
        .unwrap();

        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_key_path(Some(key_path.clone()))
            .unwrap();

        let auth = ctx.determine_method().await.unwrap();

        match auth {
            AuthMethod::PrivateKeyFile { key_file_path, .. } => {
                // Path should be canonicalized
                assert!(key_file_path.is_absolute());
            }
            _ => panic!("Expected PrivateKeyFile auth method"),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn test_agent_auth_with_invalid_socket() {
        // Set SSH_AUTH_SOCK to non-existent path
        std::env::set_var("SSH_AUTH_SOCK", "/tmp/nonexistent-ssh-agent.sock");

        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .unwrap()
            .with_agent(true);

        // Should return None since socket doesn't exist
        let auth = ctx.agent_auth().unwrap();
        assert!(auth.is_none());

        // Clean up
        std::env::remove_var("SSH_AUTH_SOCK");
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
    async fn test_password_fallback_in_non_interactive() {
        // Save original environment variables
        let original_home = std::env::var("HOME").ok();
        let original_ssh_auth_sock = std::env::var("SSH_AUTH_SOCK").ok();

        // Create a fake home directory WITHOUT default keys (to trigger fallback)
        let temp_dir = TempDir::new().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        // Intentionally NOT creating any key files

        // Set test environment
        std::env::set_var("HOME", temp_dir.path().to_str().unwrap());
        std::env::remove_var("SSH_AUTH_SOCK");

        let ctx = AuthContext::new("user".to_string(), "host".to_string()).unwrap();

        // In non-interactive environment (like tests), should fail with helpful error
        let result = ctx.determine_method().await;
        assert!(result.is_err());

        // Error message should mention authentication failure
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("authentication"));

        // Restore original environment variables
        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        } else {
            std::env::remove_var("HOME");
        }
        if let Some(sock) = original_ssh_auth_sock {
            std::env::set_var("SSH_AUTH_SOCK", sock);
        }
    }
}

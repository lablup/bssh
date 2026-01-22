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

//! Public key authentication verifier.
//!
//! This module provides the [`PublicKeyVerifier`] which implements public key
//! authentication by loading and parsing authorized_keys files.
//!
//! # OpenSSH authorized_keys Format
//!
//! The verifier supports the standard OpenSSH authorized_keys format:
//!
//! ```text
//! # Comment line
//! ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host
//! ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ... another@host
//! ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTIt... third@host
//! ```
//!
//! # Security
//!
//! The verifier includes security features:
//!
//! - Username validation to prevent path traversal
//! - Constant-time key comparison where possible
//! - Comprehensive logging of auth attempts
//!
//! # Configuration
//!
//! Two modes are supported:
//!
//! 1. **Directory mode**: `{dir}/{username}/authorized_keys`
//! 2. **Pattern mode**: `/home/{user}/.ssh/authorized_keys`

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use russh::keys::ssh_key::PublicKey;

use super::provider::AuthProvider;
use crate::shared::auth_types::{AuthResult, UserInfo};
use crate::shared::validation::validate_username;

/// Configuration for public key authentication.
///
/// Specifies where to find authorized_keys files for users.
#[derive(Debug, Clone)]
pub struct PublicKeyAuthConfig {
    /// Directory containing authorized_keys files.
    /// Structure: `{dir}/{username}/authorized_keys`
    pub authorized_keys_dir: Option<PathBuf>,

    /// Alternative: file path pattern with `{user}` placeholder.
    /// Example: `/home/{user}/.ssh/authorized_keys`
    pub authorized_keys_pattern: Option<String>,
}

impl PublicKeyAuthConfig {
    /// Create a new configuration with a directory path.
    ///
    /// The directory should contain subdirectories for each user,
    /// with an `authorized_keys` file in each.
    ///
    /// # Arguments
    ///
    /// * `dir` - Path to the directory (e.g., `/etc/bssh/authorized_keys/`)
    ///
    /// # Example
    ///
    /// ```
    /// use bssh::server::auth::PublicKeyAuthConfig;
    ///
    /// let config = PublicKeyAuthConfig::with_directory("/etc/bssh/authorized_keys");
    /// ```
    pub fn with_directory(dir: impl Into<PathBuf>) -> Self {
        Self {
            authorized_keys_dir: Some(dir.into()),
            authorized_keys_pattern: None,
        }
    }

    /// Create a new configuration with a file pattern.
    ///
    /// The pattern should contain `{user}` which will be replaced
    /// with the username.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Path pattern (e.g., `/home/{user}/.ssh/authorized_keys`)
    ///
    /// # Example
    ///
    /// ```
    /// use bssh::server::auth::PublicKeyAuthConfig;
    ///
    /// let config = PublicKeyAuthConfig::with_pattern("/home/{user}/.ssh/authorized_keys");
    /// ```
    pub fn with_pattern(pattern: impl Into<String>) -> Self {
        Self {
            authorized_keys_dir: None,
            authorized_keys_pattern: Some(pattern.into()),
        }
    }

    /// Get the authorized_keys file path for a user.
    ///
    /// # Arguments
    ///
    /// * `username` - The validated username
    ///
    /// # Returns
    ///
    /// The path to the user's authorized_keys file.
    fn get_authorized_keys_path(&self, username: &str) -> PathBuf {
        if let Some(ref pattern) = self.authorized_keys_pattern {
            PathBuf::from(pattern.replace("{user}", username))
        } else if let Some(ref dir) = self.authorized_keys_dir {
            dir.join(username).join("authorized_keys")
        } else {
            // Default to home directory pattern
            PathBuf::from(format!("/home/{username}/.ssh/authorized_keys"))
        }
    }
}

impl Default for PublicKeyAuthConfig {
    fn default() -> Self {
        Self {
            authorized_keys_dir: None,
            authorized_keys_pattern: Some("/home/{user}/.ssh/authorized_keys".to_string()),
        }
    }
}

/// Options parsed from authorized_keys file entries.
///
/// These options follow the OpenSSH authorized_keys format and can
/// restrict what the key can be used for.
#[derive(Debug, Clone, Default)]
pub struct AuthKeyOptions {
    /// Force a specific command to be executed
    pub command: Option<String>,

    /// Environment variables to set
    pub environment: Vec<String>,

    /// Restrict connections to specific source addresses
    pub from: Vec<String>,

    /// Disable PTY allocation
    pub no_pty: bool,

    /// Disable port forwarding
    pub no_port_forwarding: bool,

    /// Disable agent forwarding
    pub no_agent_forwarding: bool,

    /// Disable X11 forwarding
    pub no_x11_forwarding: bool,
}

/// A parsed authorized key entry.
#[derive(Debug)]
pub struct AuthorizedKey {
    /// The public key
    pub key: PublicKey,

    /// Optional comment (usually user@host)
    pub comment: Option<String>,

    /// Key options from the authorized_keys file
    pub options: AuthKeyOptions,
}

/// Public key authentication verifier.
///
/// Verifies public keys against authorized_keys files in the OpenSSH format.
///
/// # Example
///
/// ```no_run
/// use bssh::server::auth::{PublicKeyVerifier, PublicKeyAuthConfig, AuthProvider};
///
/// # async fn example() -> anyhow::Result<()> {
/// let config = PublicKeyAuthConfig::with_directory("/etc/bssh/authorized_keys");
/// let verifier = PublicKeyVerifier::new(config);
///
/// // Check if a user exists
/// let exists = verifier.user_exists("testuser").await?;
/// # Ok(())
/// # }
/// ```
pub struct PublicKeyVerifier {
    config: PublicKeyAuthConfig,
}

impl PublicKeyVerifier {
    /// Create a new public key verifier.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration specifying authorized_keys file locations
    pub fn new(config: PublicKeyAuthConfig) -> Self {
        Self { config }
    }

    /// Verify if a public key is authorized for a user.
    ///
    /// # Arguments
    ///
    /// * `username` - The username to check (will be validated)
    /// * `key` - The public key to verify
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the key is authorized, `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if username validation fails.
    pub async fn verify(&self, username: &str, key: &PublicKey) -> Result<bool> {
        // Validate username to prevent path traversal
        let username = validate_username(username).context("Invalid username")?;

        // Load authorized keys for user
        let authorized_keys = self.load_authorized_keys(&username).await?;

        // Check if key matches any authorized key
        for authorized_key in &authorized_keys {
            if self.keys_match(key, authorized_key) {
                tracing::info!(
                    user = %username,
                    key_type = %key.algorithm(),
                    "Public key authentication successful"
                );
                return Ok(true);
            }
        }

        tracing::debug!(
            user = %username,
            key_type = %key.algorithm(),
            authorized_keys_count = %authorized_keys.len(),
            "No matching authorized key found"
        );
        Ok(false)
    }

    /// Load authorized keys for a user.
    ///
    /// # Arguments
    ///
    /// * `username` - The validated username
    ///
    /// # Returns
    ///
    /// A vector of parsed authorized keys. Returns empty vector if the
    /// authorized_keys file doesn't exist.
    async fn load_authorized_keys(&self, username: &str) -> Result<Vec<AuthorizedKey>> {
        let path = self.config.get_authorized_keys_path(username);

        // SECURITY: Check file permissions and reject symlinks before reading
        // This prevents TOCTOU race conditions by using metadata operations
        #[cfg(unix)]
        self.check_file_permissions(&path)?;

        // Read the file - handle NotFound case to return empty vector
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(
                    user = %username,
                    path = %path.display(),
                    "No authorized_keys file found"
                );
                return Ok(Vec::new());
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("Failed to read authorized_keys file: {}", path.display())
                });
            }
        };

        self.parse_authorized_keys(&content)
    }

    /// Check that file permissions are secure (Unix only).
    ///
    /// # Security Checks
    ///
    /// - Rejects symlinks to prevent TOCTOU attacks
    /// - Rejects world-writable files (0o002)
    /// - Rejects group-writable files (0o020)
    /// - Validates parent directory permissions
    #[cfg(unix)]
    fn check_file_permissions(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        // Use symlink_metadata to detect symlinks without following them
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File doesn't exist - this is OK, will be handled by caller
                return Ok(());
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("Failed to get metadata for {}", path.display())
                });
            }
        };

        // SECURITY: Reject symlinks to prevent TOCTOU attacks
        if metadata.is_symlink() {
            anyhow::bail!(
                "authorized_keys file {} is a symbolic link. Symlinks are not allowed for security reasons.",
                path.display()
            );
        }

        let mode = metadata.mode();

        // SECURITY: Check if file is world-writable (critical security risk)
        if mode & 0o002 != 0 {
            anyhow::bail!(
                "authorized_keys file {} is world-writable (mode {:o})",
                path.display(),
                mode & 0o777
            );
        }

        // SECURITY: Check if file is group-writable (security risk)
        if mode & 0o020 != 0 {
            anyhow::bail!(
                "authorized_keys file {} is group-writable (mode {:o}). This is a security risk.",
                path.display(),
                mode & 0o777
            );
        }

        // SECURITY: Validate parent directory permissions
        if let Some(parent) = path.parent() {
            if let Ok(parent_metadata) = std::fs::symlink_metadata(parent) {
                let parent_mode = parent_metadata.mode();

                // Parent directory should not be world-writable or group-writable
                if parent_mode & 0o002 != 0 {
                    anyhow::bail!(
                        "Parent directory {} of authorized_keys is world-writable (mode {:o})",
                        parent.display(),
                        parent_mode & 0o777
                    );
                }

                if parent_mode & 0o020 != 0 {
                    tracing::warn!(
                        "Parent directory {} of authorized_keys is group-writable (mode {:o}). This is a potential security risk.",
                        parent.display(),
                        parent_mode & 0o777
                    );
                }

                // Check ownership - parent directory should be owned by same user as file
                let file_uid = metadata.uid();
                let parent_uid = parent_metadata.uid();

                if file_uid != parent_uid {
                    tracing::warn!(
                        "authorized_keys file {} (uid: {}) and parent directory {} (uid: {}) have different owners",
                        path.display(),
                        file_uid,
                        parent.display(),
                        parent_uid
                    );
                }
            }
        }

        Ok(())
    }

    /// Parse authorized_keys file content.
    ///
    /// # Arguments
    ///
    /// * `content` - The file content as a string
    ///
    /// # Returns
    ///
    /// A vector of successfully parsed authorized keys. Invalid lines
    /// are logged and skipped.
    fn parse_authorized_keys(&self, content: &str) -> Result<Vec<AuthorizedKey>> {
        let mut keys = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match self.parse_authorized_key_line(line) {
                Ok(key) => keys.push(key),
                Err(e) => {
                    tracing::warn!(
                        line = %line_num + 1,
                        error = %e,
                        "Failed to parse authorized_keys line"
                    );
                }
            }
        }

        Ok(keys)
    }

    /// Parse a single authorized_keys line.
    ///
    /// Format: `[options] key-type base64-key [comment]`
    ///
    /// # Arguments
    ///
    /// * `line` - A single line from the authorized_keys file
    fn parse_authorized_key_line(&self, line: &str) -> Result<AuthorizedKey> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.is_empty() {
            anyhow::bail!("Empty line");
        }

        // Try to determine if first part is options or key type
        let (options, key_type_idx) = if is_key_type(parts[0]) {
            (AuthKeyOptions::default(), 0)
        } else {
            // First part is options, parse them
            let opts = parse_key_options(parts[0])?;
            (opts, 1)
        };

        if parts.len() <= key_type_idx + 1 {
            anyhow::bail!("Missing key data");
        }

        let key_type = parts[key_type_idx];
        let key_data = parts[key_type_idx + 1];

        // Get comment if present
        let comment = if parts.len() > key_type_idx + 2 {
            Some(parts[key_type_idx + 2..].join(" "))
        } else {
            None
        };

        // Parse the public key
        let key_str = format!("{key_type} {key_data}");
        let key = parse_public_key(&key_str).with_context(|| {
            format!("Failed to parse public key of type {key_type}")
        })?;

        Ok(AuthorizedKey {
            key,
            comment,
            options,
        })
    }

    /// Check if two public keys match.
    ///
    /// Uses the key's algorithm and encoded data for comparison.
    fn keys_match(&self, client_key: &PublicKey, authorized: &AuthorizedKey) -> bool {
        // Compare using the public key's encoded form for consistent comparison
        client_key == &authorized.key
    }
}

#[async_trait]
impl AuthProvider for PublicKeyVerifier {
    async fn verify_publickey(&self, username: &str, key: &PublicKey) -> Result<AuthResult> {
        match self.verify(username, key).await {
            Ok(true) => Ok(AuthResult::Accept),
            Ok(false) => Ok(AuthResult::Reject),
            Err(e) => {
                tracing::error!(
                    user = %username,
                    error = %e,
                    "Error during public key verification"
                );
                Ok(AuthResult::Reject)
            }
        }
    }

    async fn verify_password(&self, _username: &str, _password: &str) -> Result<AuthResult> {
        // Public key verifier doesn't handle password auth
        Ok(AuthResult::Reject)
    }

    async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>> {
        // Validate username first
        let username = validate_username(username).context("Invalid username")?;

        // Check if user has an authorized_keys file using symlink_metadata
        // to avoid following symlinks (security)
        let path = self.config.get_authorized_keys_path(&username);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => Ok(Some(UserInfo::new(username))),
            Ok(_) => Ok(None), // Exists but not a regular file (e.g., symlink, directory)
            Err(_) => Ok(None), // Doesn't exist or can't access
        }
    }

    async fn user_exists(&self, username: &str) -> Result<bool> {
        // SECURITY: Use constant-time behavior to prevent user enumeration via timing
        // Always perform the same operations regardless of whether user exists

        // Validate username first
        let username_result = validate_username(username);

        // Always compute the path, even if username is invalid
        let path = self.config.get_authorized_keys_path(
            username_result.as_deref().unwrap_or("_invalid_")
        );

        // Always perform a filesystem check using symlink_metadata to avoid following symlinks
        let file_exists = std::fs::symlink_metadata(&path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);

        // Return false if username was invalid, true if username is valid AND file exists
        Ok(username_result.is_ok() && file_exists)
    }
}

/// Check if a string looks like a key type.
fn is_key_type(s: &str) -> bool {
    matches!(
        s,
        "ssh-rsa"
            | "ssh-dss"
            | "ssh-ed25519"
            | "ssh-ed448"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    )
}

/// Parse key options from authorized_keys format.
fn parse_key_options(options_str: &str) -> Result<AuthKeyOptions> {
    let mut options = AuthKeyOptions::default();

    // Options are comma-separated
    for option in options_str.split(',') {
        let option = option.trim();

        if option.is_empty() {
            continue;
        }

        if let Some((key, value)) = option.split_once('=') {
            // Option with value
            let value = value.trim_matches('"');
            match key {
                "command" => options.command = Some(value.to_string()),
                "environment" => options.environment.push(value.to_string()),
                "from" => {
                    for addr in value.split(',') {
                        options.from.push(addr.trim().to_string());
                    }
                }
                _ => {
                    tracing::debug!(option = %key, "Unknown authorized_keys option");
                }
            }
        } else {
            // Boolean option
            match option {
                "no-pty" => options.no_pty = true,
                "no-port-forwarding" => options.no_port_forwarding = true,
                "no-agent-forwarding" => options.no_agent_forwarding = true,
                "no-X11-forwarding" => options.no_x11_forwarding = true,
                _ => {
                    tracing::debug!(option = %option, "Unknown authorized_keys option");
                }
            }
        }
    }

    Ok(options)
}

/// Parse a public key from OpenSSH format string.
fn parse_public_key(key_str: &str) -> Result<PublicKey> {
    let parts: Vec<&str> = key_str.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid key format: expected 'type base64data'");
    }

    let key_data = parts[1];

    // Decode base64 and parse
    russh::keys::parse_public_key_base64(key_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse public key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_key_type() {
        assert!(is_key_type("ssh-ed25519"));
        assert!(is_key_type("ssh-rsa"));
        assert!(is_key_type("ecdsa-sha2-nistp256"));
        assert!(!is_key_type("no-pty"));
        assert!(!is_key_type("command=\"/bin/date\""));
    }

    #[test]
    fn test_parse_key_options_empty() {
        let options = parse_key_options("").unwrap();
        assert!(options.command.is_none());
        assert!(!options.no_pty);
    }

    #[test]
    fn test_parse_key_options_no_pty() {
        let options = parse_key_options("no-pty").unwrap();
        assert!(options.no_pty);
    }

    #[test]
    fn test_parse_key_options_multiple() {
        let options = parse_key_options("no-pty,no-port-forwarding").unwrap();
        assert!(options.no_pty);
        assert!(options.no_port_forwarding);
    }

    #[test]
    fn test_parse_key_options_command() {
        let options = parse_key_options("command=\"/bin/date\"").unwrap();
        assert_eq!(options.command, Some("/bin/date".to_string()));
    }

    #[test]
    fn test_config_with_directory() {
        let config = PublicKeyAuthConfig::with_directory("/etc/bssh/keys");
        let path = config.get_authorized_keys_path("testuser");
        assert_eq!(path, PathBuf::from("/etc/bssh/keys/testuser/authorized_keys"));
    }

    #[test]
    fn test_config_with_pattern() {
        let config = PublicKeyAuthConfig::with_pattern("/home/{user}/.ssh/authorized_keys");
        let path = config.get_authorized_keys_path("testuser");
        assert_eq!(path, PathBuf::from("/home/testuser/.ssh/authorized_keys"));
    }

    #[test]
    fn test_config_default() {
        let config = PublicKeyAuthConfig::default();
        let path = config.get_authorized_keys_path("testuser");
        assert_eq!(path, PathBuf::from("/home/testuser/.ssh/authorized_keys"));
    }

    #[test]
    fn test_parse_authorized_keys_comments() {
        let verifier = PublicKeyVerifier::new(PublicKeyAuthConfig::default());
        let content = "# This is a comment\n\n# Another comment\n";
        let keys = verifier.parse_authorized_keys(content).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_authorized_key_line_ed25519() {
        let verifier = PublicKeyVerifier::new(PublicKeyAuthConfig::default());

        // Valid ed25519 key
        let line =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example";
        let result = verifier.parse_authorized_key_line(line);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.comment, Some("test@example".to_string()));
    }

    #[test]
    fn test_parse_authorized_key_line_with_options() {
        let verifier = PublicKeyVerifier::new(PublicKeyAuthConfig::default());

        // Key with options
        let line = "no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example";
        let result = verifier.parse_authorized_key_line(line);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert!(key.options.no_pty);
    }

    #[test]
    fn test_parse_authorized_key_line_invalid() {
        let verifier = PublicKeyVerifier::new(PublicKeyAuthConfig::default());

        // Invalid key data
        let line = "ssh-ed25519 notbase64!@#$";
        let result = verifier.parse_authorized_key_line(line);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_user_exists_invalid_username() {
        let verifier = PublicKeyVerifier::new(PublicKeyAuthConfig::default());

        // Path traversal attempt should return false
        let exists = verifier.user_exists("../etc/passwd").await.unwrap();
        assert!(!exists);

        // Empty username
        let exists = verifier.user_exists("").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_verify_invalid_username() {
        let verifier = PublicKeyVerifier::new(PublicKeyAuthConfig::default());

        // Create a dummy key for testing
        let key_str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let key = parse_public_key(key_str).unwrap();

        // Path traversal attempt should fail
        let result = verifier.verify("../etc/passwd", &key).await;
        assert!(result.is_err());
    }
}

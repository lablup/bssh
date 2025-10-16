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

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use super::tokio_client::AuthMethod;

/// Context for determining SSH authentication method.
///
/// This structure encapsulates all parameters needed to determine the appropriate
/// authentication method for an SSH connection.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Optional path to SSH key file
    pub key_path: Option<PathBuf>,
    /// Whether to use SSH agent for authentication
    pub use_agent: bool,
    /// Whether to use password authentication
    pub use_password: bool,
    /// Username for authentication prompts
    pub username: String,
    /// Host for authentication prompts
    pub host: String,
}

impl AuthContext {
    /// Create a new authentication context.
    pub fn new(username: String, host: String) -> Self {
        Self {
            key_path: None,
            use_agent: false,
            use_password: false,
            username,
            host,
        }
    }

    /// Set the SSH key file path.
    pub fn with_key_path(mut self, key_path: Option<PathBuf>) -> Self {
        self.key_path = key_path;
        self
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

    /// Determine the appropriate authentication method based on the context.
    ///
    /// This method implements the standard authentication priority:
    /// 1. Password authentication (if explicitly requested)
    /// 2. SSH agent (if explicitly requested and available)
    /// 3. Specified key file (if provided)
    /// 4. SSH agent auto-detection (if use_agent is true)
    /// 5. Default key locations (~/.ssh/id_ed25519, ~/.ssh/id_rsa, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No authentication method is available
    /// - SSH key file cannot be read
    /// - Password/passphrase prompt fails
    /// - SSH agent is requested but not available (Windows)
    pub fn determine_method(&self) -> Result<AuthMethod> {
        // Priority 1: Password authentication
        if self.use_password {
            return self.password_auth();
        }

        // Priority 2: SSH agent (explicit request)
        if self.use_agent {
            if let Some(auth) = self.agent_auth()? {
                return Ok(auth);
            }
        }

        // Priority 3: Key file authentication
        if let Some(ref key_path) = self.key_path {
            return self.key_file_auth(key_path);
        }

        // Priority 4: SSH agent auto-detection (if use_agent is true)
        #[cfg(not(target_os = "windows"))]
        if self.use_agent {
            if let Some(auth) = self.agent_auth()? {
                return Ok(auth);
            }
        }

        // Priority 5: Default key locations
        self.default_key_auth()
    }

    /// Attempt password authentication.
    fn password_auth(&self) -> Result<AuthMethod> {
        tracing::debug!("Using password authentication");
        // Use Zeroizing to ensure password is cleared from memory when dropped
        let password = Zeroizing::new(
            rpassword::prompt_password(format!(
                "Enter password for {}@{}: ",
                self.username, self.host
            ))
            .with_context(|| "Failed to read password")?,
        );
        Ok(AuthMethod::with_password(&password))
    }

    /// Attempt SSH agent authentication.
    #[cfg(not(target_os = "windows"))]
    fn agent_auth(&self) -> Result<Option<AuthMethod>> {
        if std::env::var("SSH_AUTH_SOCK").is_ok() {
            tracing::debug!("Using SSH agent for authentication");
            return Ok(Some(AuthMethod::Agent));
        }
        tracing::warn!("SSH agent requested but SSH_AUTH_SOCK environment variable not set");
        Ok(None)
    }

    /// Attempt SSH agent authentication (Windows - not supported).
    #[cfg(target_os = "windows")]
    fn agent_auth(&self) -> Result<Option<AuthMethod>> {
        anyhow::bail!("SSH agent authentication is not supported on Windows");
    }

    /// Attempt authentication with a specific key file.
    fn key_file_auth(&self, key_path: &Path) -> Result<AuthMethod> {
        tracing::debug!("Authenticating with key: {:?}", key_path);

        // Check if the key is encrypted by attempting to read it
        let key_contents = std::fs::read_to_string(key_path)
            .with_context(|| format!("Failed to read SSH key file: {key_path:?}"))?;

        let passphrase = if key_contents.contains("ENCRYPTED")
            || key_contents.contains("Proc-Type: 4,ENCRYPTED")
        {
            tracing::debug!("Detected encrypted SSH key, prompting for passphrase");
            // Use Zeroizing for passphrase security
            let pass = Zeroizing::new(
                rpassword::prompt_password(format!("Enter passphrase for key {key_path:?}: "))
                    .with_context(|| "Failed to read passphrase")?,
            );
            Some(pass)
        } else {
            None
        };

        Ok(AuthMethod::with_key_file(
            key_path,
            passphrase.as_ref().map(|p| p.as_str()),
        ))
    }

    /// Attempt authentication with default key locations.
    fn default_key_auth(&self) -> Result<AuthMethod> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let home_path = Path::new(&home).join(".ssh");

        // Try common key files in order of preference
        let default_keys = [
            home_path.join("id_ed25519"),
            home_path.join("id_rsa"),
            home_path.join("id_ecdsa"),
            home_path.join("id_dsa"),
        ];

        for default_key in &default_keys {
            if default_key.exists() {
                tracing::debug!("Using default key: {:?}", default_key);

                // Check if the key is encrypted
                let key_contents = std::fs::read_to_string(default_key)
                    .with_context(|| format!("Failed to read SSH key file: {default_key:?}"))?;

                let passphrase = if key_contents.contains("ENCRYPTED")
                    || key_contents.contains("Proc-Type: 4,ENCRYPTED")
                {
                    tracing::debug!("Detected encrypted SSH key, prompting for passphrase");
                    // Use Zeroizing for passphrase security
                    let pass = Zeroizing::new(
                        rpassword::prompt_password(format!(
                            "Enter passphrase for key {default_key:?}: "
                        ))
                        .with_context(|| "Failed to read passphrase")?,
                    );
                    Some(pass)
                } else {
                    None
                };

                return Ok(AuthMethod::with_key_file(
                    default_key,
                    passphrase.as_ref().map(|p| p.as_str()),
                ));
            }
        }

        anyhow::bail!(
            "SSH authentication failed: No authentication method available.\n\
             Tried:\n\
             - SSH agent: {}\n\
             - Default key files (~/.ssh/id_ed25519, ~/.ssh/id_rsa, etc. not found)\n\
             \n\
             Solutions:\n\
             - Use --password for password authentication\n\
             - Start SSH agent and add keys with 'ssh-add'\n\
             - Specify a key file with -i/--identity\n\
             - Create a default key at ~/.ssh/id_ed25519 or ~/.ssh/id_rsa",
            if std::env::var("SSH_AUTH_SOCK").is_ok() {
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

    #[test]
    fn test_auth_context_creation() {
        let ctx = AuthContext::new("testuser".to_string(), "testhost".to_string());
        assert_eq!(ctx.username, "testuser");
        assert_eq!(ctx.host, "testhost");
        assert_eq!(ctx.key_path, None);
        assert!(!ctx.use_agent);
        assert!(!ctx.use_password);
    }

    #[test]
    fn test_auth_context_with_key_path() {
        let key_path = PathBuf::from("/path/to/key");
        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .with_key_path(Some(key_path.clone()));

        assert_eq!(ctx.key_path, Some(key_path));
    }

    #[test]
    fn test_auth_context_with_agent() {
        let ctx = AuthContext::new("user".to_string(), "host".to_string()).with_agent(true);

        assert!(ctx.use_agent);
    }

    #[test]
    fn test_auth_context_with_password() {
        let ctx = AuthContext::new("user".to_string(), "host".to_string()).with_password(true);

        assert!(ctx.use_password);
    }

    #[test]
    fn test_determine_method_with_key_file() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key");
        std::fs::write(&key_path, "fake key content").unwrap();

        let ctx = AuthContext::new("user".to_string(), "host".to_string())
            .with_key_path(Some(key_path.clone()));

        let auth = ctx.determine_method().unwrap();

        match auth {
            AuthMethod::PrivateKeyFile { key_file_path, .. } => {
                assert_eq!(key_file_path, key_path);
            }
            _ => panic!("Expected PrivateKeyFile auth method"),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_determine_method_with_agent() {
        // Set up SSH agent environment
        std::env::set_var("SSH_AUTH_SOCK", "/tmp/test-ssh-agent.sock");

        let ctx = AuthContext::new("user".to_string(), "host".to_string()).with_agent(true);

        let auth = ctx.determine_method().unwrap();

        // Clean up
        std::env::remove_var("SSH_AUTH_SOCK");

        match auth {
            AuthMethod::Agent => {}
            _ => panic!("Expected Agent auth method"),
        }
    }

    #[test]
    fn test_determine_method_fallback_to_default() {
        // Save original environment variables
        let original_home = std::env::var("HOME").ok();
        let original_ssh_auth_sock = std::env::var("SSH_AUTH_SOCK").ok();

        // Create a fake home directory with default key
        let temp_dir = TempDir::new().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let default_key = ssh_dir.join("id_rsa");
        std::fs::write(&default_key, "fake key").unwrap();

        // Set test environment
        std::env::set_var("HOME", temp_dir.path().to_str().unwrap());
        std::env::remove_var("SSH_AUTH_SOCK");

        let ctx = AuthContext::new("user".to_string(), "host".to_string());
        let auth = ctx.determine_method().unwrap();

        // Restore original environment variables
        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        } else {
            std::env::remove_var("HOME");
        }
        if let Some(sock) = original_ssh_auth_sock {
            std::env::set_var("SSH_AUTH_SOCK", sock);
        }

        match auth {
            AuthMethod::PrivateKeyFile { key_file_path, .. } => {
                assert_eq!(key_file_path, default_key);
            }
            _ => panic!("Expected PrivateKeyFile auth method"),
        }
    }
}

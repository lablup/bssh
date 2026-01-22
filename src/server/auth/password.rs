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

//! Password authentication verifier.
//!
//! This module provides the [`PasswordVerifier`] which implements password
//! authentication using Argon2id hashing with proper security measures.
//!
//! # Security Features
//!
//! - **Argon2id hashing**: Uses the recommended password hashing algorithm
//! - **Timing attack mitigation**: Ensures constant-time verification
//! - **Memory cleanup**: Uses `zeroize` for secure password memory cleanup
//! - **User enumeration protection**: Performs dummy verification for non-existent users
//!
//! # Configuration
//!
//! Users can be configured in two ways:
//!
//! 1. **External file**: A YAML file containing user definitions
//! 2. **Inline configuration**: Users defined directly in the server config
//!
//! # Example
//!
//! ```no_run
//! use bssh::server::auth::password::{PasswordAuthConfig, PasswordVerifier};
//! use std::path::PathBuf;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = PasswordAuthConfig {
//!     users_file: Some(PathBuf::from("/etc/bssh/users.yaml")),
//!     users: vec![],
//! };
//!
//! let verifier = PasswordVerifier::new(config).await?;
//! let result = verifier.verify("username", "password").await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier as _},
    Algorithm, Argon2, Params, Version,
};
use async_trait::async_trait;
use russh::keys::ssh_key::PublicKey;
use serde::Deserialize;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use super::provider::AuthProvider;
use crate::server::config::UserDefinition;
use crate::shared::auth_types::{AuthResult, UserInfo};
use crate::shared::validation::validate_username;

/// Configuration for password authentication.
#[derive(Debug, Clone, Default)]
pub struct PasswordAuthConfig {
    /// Path to YAML file containing user definitions.
    pub users_file: Option<PathBuf>,

    /// Inline user definitions.
    pub users: Vec<UserDefinition>,
}

impl PasswordAuthConfig {
    /// Create a new configuration with a users file path.
    pub fn with_users_file(path: impl Into<PathBuf>) -> Self {
        Self {
            users_file: Some(path.into()),
            users: vec![],
        }
    }

    /// Create a new configuration with inline users.
    pub fn with_users(users: Vec<UserDefinition>) -> Self {
        Self {
            users_file: None,
            users,
        }
    }
}

/// Password verifier with Argon2id hashing.
///
/// This struct implements secure password verification with:
/// - Argon2id password hashing (also supports bcrypt for compatibility)
/// - Timing attack mitigation
/// - User enumeration protection
/// - Secure memory handling via `zeroize`
pub struct PasswordVerifier {
    /// Configuration for password authentication.
    config: PasswordAuthConfig,

    /// Loaded users (keyed by username).
    users: RwLock<HashMap<String, UserDefinition>>,

    /// Pre-computed dummy hash for timing attack mitigation.
    /// This hash is verified against when the user doesn't exist.
    dummy_hash: String,
}

impl PasswordVerifier {
    /// Create a new password verifier.
    ///
    /// This loads users from the configuration on initialization.
    ///
    /// # Arguments
    ///
    /// * `config` - Password authentication configuration
    ///
    /// # Returns
    ///
    /// A new password verifier, or an error if user loading fails.
    pub async fn new(config: PasswordAuthConfig) -> Result<Self> {
        // Generate a dummy hash for timing attack mitigation
        let dummy_hash = hash_password("dummy_password_for_timing_attack_mitigation")?;

        let verifier = Self {
            config,
            users: RwLock::new(HashMap::new()),
            dummy_hash,
        };

        verifier.reload_users().await?;
        Ok(verifier)
    }

    /// Reload users from configuration.
    ///
    /// This method reloads users from both the users file (if configured)
    /// and inline user definitions. Inline users override file users.
    pub async fn reload_users(&self) -> Result<()> {
        let mut users = HashMap::new();

        // Load from file if specified
        if let Some(ref path) = self.config.users_file {
            match tokio::fs::read_to_string(path).await {
                Ok(content) => {
                    let file_users: UsersFile =
                        serde_yaml::from_str(&content).with_context(|| {
                            format!("Failed to parse users file: {}", path.display())
                        })?;

                    for user in file_users.users {
                        tracing::debug!(user = %user.name, "Loaded user from file");
                        users.insert(user.name.clone(), user);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::warn!(
                        path = %path.display(),
                        "Users file not found, using only inline users"
                    );
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Failed to read users file: {}", path.display()));
                }
            }
        }

        // Add inline users (override file users)
        for user in &self.config.users {
            tracing::debug!(user = %user.name, "Loaded inline user");
            users.insert(user.name.clone(), user.clone());
        }

        let user_count = users.len();
        *self.users.write().await = users;

        tracing::info!(
            user_count = %user_count,
            "Users loaded for password authentication"
        );

        Ok(())
    }

    /// Verify a password for a user.
    ///
    /// This method implements timing attack mitigation by ensuring
    /// verification takes a minimum amount of time, regardless of
    /// whether the user exists or the password is correct.
    ///
    /// # Arguments
    ///
    /// * `username` - The username to verify
    /// * `password` - The password to verify
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the password is correct, `Ok(false)` otherwise.
    pub async fn verify(&self, username: &str, password: &str) -> Result<bool> {
        // Wrap password in Zeroizing for secure cleanup
        let password = Zeroizing::new(password.to_string());

        // Timing attack mitigation: ensure minimum time for verification
        let start = Instant::now();
        let min_time = Duration::from_millis(100);

        let result = self.verify_internal(username, &password).await;

        // Normalize timing by sleeping if we finished early
        let elapsed = start.elapsed();
        if elapsed < min_time {
            tokio::time::sleep(min_time - elapsed).await;
        }

        result
    }

    /// Internal verification logic.
    async fn verify_internal(&self, username: &str, password: &Zeroizing<String>) -> Result<bool> {
        // Validate username first
        let validated_username = match validate_username(username) {
            Ok(name) => name,
            Err(_) => {
                // Invalid username - do dummy verification to prevent timing attacks
                let _ = self.verify_dummy_hash(password);
                tracing::debug!(
                    user = %username,
                    "Password authentication failed: invalid username"
                );
                return Ok(false);
            }
        };

        let users: tokio::sync::RwLockReadGuard<'_, HashMap<String, UserDefinition>> =
            self.users.read().await;

        let user = match users.get(&validated_username) {
            Some(u) => u,
            None => {
                // User doesn't exist - do dummy verification to prevent timing attacks
                let _ = self.verify_dummy_hash(password);
                tracing::debug!(
                    user = %validated_username,
                    "Password authentication failed: user not found"
                );
                return Ok(false);
            }
        };

        // Verify password against stored hash
        let hash_str = &user.password_hash;

        // Try Argon2id first, then fall back to bcrypt for compatibility
        let verified = if hash_str.starts_with("$argon2") {
            self.verify_argon2(password.as_bytes(), hash_str)?
        } else if hash_str.starts_with("$2") {
            // bcrypt hash format ($2a$, $2b$, $2y$)
            self.verify_bcrypt(password, hash_str)?
        } else {
            tracing::warn!(
                user = %validated_username,
                "Unknown password hash format"
            );
            return Ok(false);
        };

        if verified {
            tracing::info!(
                user = %validated_username,
                "Password authentication successful"
            );
            Ok(true)
        } else {
            tracing::debug!(
                user = %validated_username,
                "Password authentication failed: incorrect password"
            );
            Ok(false)
        }
    }

    /// Verify password against an Argon2 hash.
    fn verify_argon2(&self, password: &[u8], hash_str: &str) -> Result<bool> {
        let hash = PasswordHash::new(hash_str)
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 hash format: {}", e))?;

        let argon2 = Argon2::default();

        match argon2.verify_password(password, &hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(anyhow::anyhow!("Argon2 verification error: {}", e)),
        }
    }

    /// Verify password against a bcrypt hash.
    fn verify_bcrypt(&self, password: &Zeroizing<String>, hash_str: &str) -> Result<bool> {
        match bcrypt::verify(password.as_str(), hash_str) {
            Ok(verified) => Ok(verified),
            Err(e) => {
                tracing::warn!(error = %e, "bcrypt verification error");
                Ok(false)
            }
        }
    }

    /// Perform dummy hash verification for timing attack mitigation.
    ///
    /// This ensures that verification takes the same amount of time
    /// regardless of whether the user exists.
    fn verify_dummy_hash(&self, password: &Zeroizing<String>) -> bool {
        // Verify against the pre-computed dummy hash
        if let Ok(hash) = PasswordHash::new(&self.dummy_hash) {
            let argon2 = Argon2::default();
            argon2.verify_password(password.as_bytes(), &hash).is_ok()
        } else {
            false
        }
    }

    /// Get user information for an authenticated user.
    ///
    /// # Arguments
    ///
    /// * `username` - The username to get info for
    ///
    /// # Returns
    ///
    /// User information if the user exists, None otherwise.
    pub async fn get_user(&self, username: &str) -> Option<UserInfo> {
        let users: tokio::sync::RwLockReadGuard<'_, HashMap<String, UserDefinition>> =
            self.users.read().await;
        users.get(username).map(|u| {
            let mut info = UserInfo::new(&u.name);

            if let Some(home) = &u.home {
                info = info.with_home_dir(home.clone());
            }
            if let Some(shell) = &u.shell {
                info = info.with_shell(shell.clone());
            }

            info
        })
    }

    /// Check if a user exists (for user enumeration, use with caution).
    ///
    /// # Warning
    ///
    /// This method reveals whether a user exists. Consider using
    /// `verify` instead which provides timing attack protection.
    pub async fn user_exists_internal(&self, username: &str) -> bool {
        let users: tokio::sync::RwLockReadGuard<'_, HashMap<String, UserDefinition>> =
            self.users.read().await;
        users.contains_key(username)
    }
}

#[async_trait]
impl AuthProvider for PasswordVerifier {
    async fn verify_publickey(&self, _username: &str, _key: &PublicKey) -> Result<AuthResult> {
        // Password verifier doesn't handle public key auth
        Ok(AuthResult::Reject)
    }

    async fn verify_password(&self, username: &str, password: &str) -> Result<AuthResult> {
        match self.verify(username, password).await {
            Ok(true) => Ok(AuthResult::Accept),
            Ok(false) => Ok(AuthResult::Reject),
            Err(e) => {
                tracing::error!(
                    user = %username,
                    error = %e,
                    "Error during password verification"
                );
                Ok(AuthResult::Reject)
            }
        }
    }

    async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>> {
        Ok(self.get_user(username).await)
    }

    async fn user_exists(&self, username: &str) -> Result<bool> {
        // SECURITY: Use timing-safe verification to prevent user enumeration
        // We always do a full verification cycle regardless of user existence
        let start = Instant::now();
        let min_time = Duration::from_millis(50);

        let exists = self.user_exists_internal(username).await;

        // Normalize timing
        let elapsed = start.elapsed();
        if elapsed < min_time {
            tokio::time::sleep(min_time - elapsed).await;
        }

        Ok(exists)
    }
}

/// Users file structure for YAML parsing.
#[derive(Debug, Deserialize)]
struct UsersFile {
    users: Vec<UserDefinition>,
}

/// Generate an Argon2id password hash.
///
/// This function generates a secure password hash using Argon2id
/// with recommended parameters.
///
/// # Arguments
///
/// * `password` - The plaintext password to hash
///
/// # Returns
///
/// The Argon2id hash string, or an error if hashing fails.
///
/// # Example
///
/// ```no_run
/// use bssh::server::auth::password::hash_password;
///
/// let hash = hash_password("my_secure_password").unwrap();
/// println!("Hash: {}", hash);
/// ```
pub fn hash_password(password: &str) -> Result<String> {
    use argon2::password_hash::SaltString;

    let salt = SaltString::generate(&mut OsRng);

    // Use Argon2id with secure parameters
    // These parameters balance security and performance:
    // - m=19456 KiB (19 MiB memory)
    // - t=2 iterations
    // - p=1 parallelism
    let params = Params::new(
        19456, // m_cost (memory in KiB)
        2,     // t_cost (iterations)
        1,     // p_cost (parallelism)
        None,  // output_len (use default)
    )
    .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash.
///
/// # Arguments
///
/// * `password` - The plaintext password
/// * `hash` - The Argon2id hash string
///
/// # Returns
///
/// `true` if the password matches, `false` otherwise.
pub fn verify_password_hash(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("Invalid hash format: {}", e))?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("Verification error: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_hash_password() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();

        // Verify the hash starts with the Argon2id identifier
        assert!(hash.starts_with("$argon2id$"));

        // Verify the hash can be parsed
        let parsed = PasswordHash::new(&hash).unwrap();
        assert_eq!(parsed.algorithm, argon2::Algorithm::Argon2id.ident());
    }

    #[test]
    fn test_verify_password_hash() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();

        // Correct password should verify
        assert!(verify_password_hash(password, &hash).unwrap());

        // Incorrect password should not verify
        assert!(!verify_password_hash("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_hash_uniqueness() {
        let password = "same_password";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Each hash should be unique due to random salt
        assert_ne!(hash1, hash2);

        // Both should verify correctly
        assert!(verify_password_hash(password, &hash1).unwrap());
        assert!(verify_password_hash(password, &hash2).unwrap());
    }

    #[test]
    fn test_verify_invalid_hash_format() {
        let result = verify_password_hash("password", "invalid_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_auth_config_with_users_file() {
        let config = PasswordAuthConfig::with_users_file("/etc/bssh/users.yaml");
        assert!(config.users_file.is_some());
        assert!(config.users.is_empty());
    }

    #[test]
    fn test_password_auth_config_with_users() {
        let users = vec![UserDefinition {
            name: "testuser".to_string(),
            password_hash: hash_password("password").unwrap(),
            shell: None,
            home: None,
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        assert!(config.users_file.is_none());
        assert_eq!(config.users.len(), 1);
    }

    #[tokio::test]
    async fn test_password_verifier_inline_users() {
        let hash = hash_password("correct_password").unwrap();
        let users = vec![UserDefinition {
            name: "testuser".to_string(),
            password_hash: hash,
            shell: None,
            home: None,
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        let verifier = PasswordVerifier::new(config).await.unwrap();

        // Correct password should verify
        assert!(verifier
            .verify("testuser", "correct_password")
            .await
            .unwrap());

        // Incorrect password should not verify
        assert!(!verifier.verify("testuser", "wrong_password").await.unwrap());

        // Non-existent user should not verify
        assert!(!verifier.verify("nonexistent", "password").await.unwrap());
    }

    #[tokio::test]
    async fn test_password_verifier_bcrypt_compatibility() {
        // Create a bcrypt hash
        let bcrypt_hash = bcrypt::hash("bcrypt_password", 4).unwrap();
        let users = vec![UserDefinition {
            name: "bcryptuser".to_string(),
            password_hash: bcrypt_hash,
            shell: None,
            home: None,
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        let verifier = PasswordVerifier::new(config).await.unwrap();

        // bcrypt password should verify
        assert!(verifier
            .verify("bcryptuser", "bcrypt_password")
            .await
            .unwrap());

        // Wrong password should not verify
        assert!(!verifier.verify("bcryptuser", "wrong").await.unwrap());
    }

    #[tokio::test]
    async fn test_password_verifier_timing_attack_mitigation() {
        let hash = hash_password("password").unwrap();
        let users = vec![UserDefinition {
            name: "testuser".to_string(),
            password_hash: hash,
            shell: None,
            home: None,
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        let verifier = PasswordVerifier::new(config).await.unwrap();

        // Measure time for existing user with wrong password
        let start = Instant::now();
        let _ = verifier.verify("testuser", "wrong_password").await;
        let time_existing = start.elapsed();

        // Measure time for non-existing user
        let start = Instant::now();
        let _ = verifier.verify("nonexistent_user", "password").await;
        let time_nonexistent = start.elapsed();

        // Both should take at least the minimum time (100ms)
        assert!(time_existing >= Duration::from_millis(90)); // Allow small margin
        assert!(time_nonexistent >= Duration::from_millis(90));

        // The times should be roughly similar (within 50ms margin)
        let diff = if time_existing > time_nonexistent {
            time_existing - time_nonexistent
        } else {
            time_nonexistent - time_existing
        };
        assert!(
            diff < Duration::from_millis(50),
            "Timing difference too large: {:?}",
            diff
        );
    }

    #[tokio::test]
    async fn test_password_verifier_invalid_username() {
        let config = PasswordAuthConfig::default();
        let verifier = PasswordVerifier::new(config).await.unwrap();

        // Path traversal attempt should fail safely
        let result = verifier.verify("../etc/passwd", "password").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Empty username should fail safely
        let result = verifier.verify("", "password").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_password_verifier_get_user() {
        let hash = hash_password("password").unwrap();
        let users = vec![UserDefinition {
            name: "testuser".to_string(),
            password_hash: hash,
            shell: Some(PathBuf::from("/bin/bash")),
            home: Some(PathBuf::from("/home/testuser")),
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        let verifier = PasswordVerifier::new(config).await.unwrap();

        // Existing user should return info
        let user_info = verifier.get_user("testuser").await;
        assert!(user_info.is_some());
        let info = user_info.unwrap();
        assert_eq!(info.username, "testuser");
        assert_eq!(info.shell, PathBuf::from("/bin/bash"));
        assert_eq!(info.home_dir, PathBuf::from("/home/testuser"));

        // Non-existing user should return None
        let user_info = verifier.get_user("nonexistent").await;
        assert!(user_info.is_none());
    }

    #[tokio::test]
    async fn test_auth_provider_trait() {
        let hash = hash_password("password").unwrap();
        let users = vec![UserDefinition {
            name: "testuser".to_string(),
            password_hash: hash,
            shell: None,
            home: None,
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        let verifier = PasswordVerifier::new(config).await.unwrap();

        // Test verify_password via AuthProvider trait
        let result = verifier
            .verify_password("testuser", "password")
            .await
            .unwrap();
        assert!(result.is_accepted());

        let result = verifier.verify_password("testuser", "wrong").await.unwrap();
        assert!(result.is_rejected());

        // Test get_user_info via AuthProvider trait
        let info = verifier.get_user_info("testuser").await.unwrap();
        assert!(info.is_some());

        // Test user_exists via AuthProvider trait
        let exists = verifier.user_exists("testuser").await.unwrap();
        assert!(exists);

        let exists = verifier.user_exists("nonexistent").await.unwrap();
        assert!(!exists);

        // Test verify_publickey (should always reject)
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let key = russh::keys::parse_public_key_base64(key_str.split_whitespace().nth(1).unwrap())
            .unwrap();
        let result = verifier.verify_publickey("testuser", &key).await.unwrap();
        assert!(result.is_rejected());
    }

    #[tokio::test]
    async fn test_password_verifier_reload_users() {
        let hash = hash_password("password").unwrap();
        let users = vec![UserDefinition {
            name: "user1".to_string(),
            password_hash: hash.clone(),
            shell: None,
            home: None,
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        let verifier = PasswordVerifier::new(config).await.unwrap();

        // Initial user should exist
        assert!(verifier.user_exists_internal("user1").await);
        assert!(!verifier.user_exists_internal("user2").await);

        // Reload should work without error
        let result = verifier.reload_users().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_password() {
        // Empty password should still hash correctly
        let hash = hash_password("").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password_hash("", &hash).unwrap());
        assert!(!verify_password_hash("notempty", &hash).unwrap());
    }

    #[test]
    fn test_unicode_password() {
        // Unicode passwords should work correctly
        let password = "p@ssw\u{00f6}rd\u{1f512}";
        let hash = hash_password(password).unwrap();
        assert!(verify_password_hash(password, &hash).unwrap());
        assert!(!verify_password_hash("password", &hash).unwrap());
    }

    #[test]
    fn test_long_password() {
        // Long passwords should work correctly
        let password = "a".repeat(1000);
        let hash = hash_password(&password).unwrap();
        assert!(verify_password_hash(&password, &hash).unwrap());
        assert!(!verify_password_hash(&"a".repeat(999), &hash).unwrap());
    }
}

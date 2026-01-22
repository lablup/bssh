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

//! Composite authentication provider.
//!
//! This module provides a composite authentication provider that combines
//! multiple authentication methods (public key and password authentication).

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use russh::keys::ssh_key::PublicKey;

use super::password::{PasswordAuthConfig, PasswordVerifier};
use super::provider::AuthProvider;
use super::publickey::{PublicKeyAuthConfig, PublicKeyVerifier};
use crate::shared::auth_types::{AuthResult, UserInfo};

/// Composite authentication provider that supports multiple auth methods.
///
/// This provider delegates to specific providers based on the authentication
/// method being used. It supports:
///
/// - Public key authentication via [`PublicKeyVerifier`]
/// - Password authentication via [`PasswordVerifier`]
///
/// # Example
///
/// ```no_run
/// use bssh::server::auth::CompositeAuthProvider;
/// use bssh::server::auth::PublicKeyAuthConfig;
/// use bssh::server::auth::PasswordAuthConfig;
///
/// # async fn example() -> anyhow::Result<()> {
/// let pubkey_config = PublicKeyAuthConfig::with_directory("/etc/bssh/authorized_keys");
/// let password_config = PasswordAuthConfig::default();
///
/// let provider = CompositeAuthProvider::new(
///     Some(pubkey_config),
///     Some(password_config),
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct CompositeAuthProvider {
    /// Public key verifier (if public key auth is enabled).
    publickey_verifier: Option<PublicKeyVerifier>,

    /// Password verifier (if password auth is enabled).
    password_verifier: Option<Arc<PasswordVerifier>>,
}

impl CompositeAuthProvider {
    /// Create a new composite auth provider.
    ///
    /// # Arguments
    ///
    /// * `publickey_config` - Configuration for public key authentication (None to disable)
    /// * `password_config` - Configuration for password authentication (None to disable)
    ///
    /// # Returns
    ///
    /// A new composite auth provider, or an error if initialization fails.
    pub async fn new(
        publickey_config: Option<PublicKeyAuthConfig>,
        password_config: Option<PasswordAuthConfig>,
    ) -> Result<Self> {
        let publickey_verifier = publickey_config.map(PublicKeyVerifier::new);

        let password_verifier = match password_config {
            Some(config) => Some(Arc::new(PasswordVerifier::new(config).await?)),
            None => None,
        };

        tracing::info!(
            publickey_enabled = publickey_verifier.is_some(),
            password_enabled = password_verifier.is_some(),
            "Composite auth provider initialized"
        );

        Ok(Self {
            publickey_verifier,
            password_verifier,
        })
    }

    /// Create a provider with only public key authentication.
    pub fn publickey_only(config: PublicKeyAuthConfig) -> Self {
        Self {
            publickey_verifier: Some(PublicKeyVerifier::new(config)),
            password_verifier: None,
        }
    }

    /// Create a provider with only password authentication.
    pub async fn password_only(config: PasswordAuthConfig) -> Result<Self> {
        Ok(Self {
            publickey_verifier: None,
            password_verifier: Some(Arc::new(PasswordVerifier::new(config).await?)),
        })
    }

    /// Check if public key authentication is enabled.
    pub fn publickey_enabled(&self) -> bool {
        self.publickey_verifier.is_some()
    }

    /// Check if password authentication is enabled.
    pub fn password_enabled(&self) -> bool {
        self.password_verifier.is_some()
    }

    /// Get a reference to the password verifier (if enabled).
    pub fn password_verifier(&self) -> Option<&Arc<PasswordVerifier>> {
        self.password_verifier.as_ref()
    }

    /// Reload password users from configuration.
    ///
    /// This allows hot-reloading of user configuration without restarting the server.
    pub async fn reload_password_users(&self) -> Result<()> {
        if let Some(ref verifier) = self.password_verifier {
            verifier.reload_users().await?;
        }
        Ok(())
    }
}

#[async_trait]
impl AuthProvider for CompositeAuthProvider {
    async fn verify_publickey(&self, username: &str, key: &PublicKey) -> Result<AuthResult> {
        if let Some(ref verifier) = self.publickey_verifier {
            verifier.verify_publickey(username, key).await
        } else {
            // Public key auth not enabled
            Ok(AuthResult::Reject)
        }
    }

    async fn verify_password(&self, username: &str, password: &str) -> Result<AuthResult> {
        if let Some(ref verifier) = self.password_verifier {
            verifier.verify_password(username, password).await
        } else {
            // Password auth not enabled
            Ok(AuthResult::Reject)
        }
    }

    async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>> {
        // Try to get user info from password verifier first (has more detailed info)
        if let Some(ref verifier) = self.password_verifier {
            if let Some(info) = verifier.get_user_info(username).await? {
                return Ok(Some(info));
            }
        }

        // Fall back to public key verifier
        if let Some(ref verifier) = self.publickey_verifier {
            return verifier.get_user_info(username).await;
        }

        Ok(None)
    }

    async fn user_exists(&self, username: &str) -> Result<bool> {
        // Check password verifier first
        if let Some(ref verifier) = self.password_verifier {
            if verifier.user_exists(username).await? {
                return Ok(true);
            }
        }

        // Check public key verifier
        if let Some(ref verifier) = self.publickey_verifier {
            if verifier.user_exists(username).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::auth::hash_password;
    use crate::server::config::UserDefinition;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_composite_provider_publickey_only() {
        let config = PublicKeyAuthConfig::with_directory("/tmp/nonexistent");
        let provider = CompositeAuthProvider::publickey_only(config);

        assert!(provider.publickey_enabled());
        assert!(!provider.password_enabled());
    }

    #[tokio::test]
    async fn test_composite_provider_password_only() {
        let hash = hash_password("password").unwrap();
        let users = vec![UserDefinition {
            name: "testuser".to_string(),
            password_hash: hash,
            shell: None,
            home: None,
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        let provider = CompositeAuthProvider::password_only(config).await.unwrap();

        assert!(!provider.publickey_enabled());
        assert!(provider.password_enabled());

        // Test password verification
        let result = provider
            .verify_password("testuser", "password")
            .await
            .unwrap();
        assert!(result.is_accepted());

        let result = provider.verify_password("testuser", "wrong").await.unwrap();
        assert!(result.is_rejected());
    }

    #[tokio::test]
    async fn test_composite_provider_both() {
        let pubkey_config = PublicKeyAuthConfig::with_directory("/tmp/nonexistent");
        let hash = hash_password("password").unwrap();
        let users = vec![UserDefinition {
            name: "testuser".to_string(),
            password_hash: hash,
            shell: None,
            home: None,
            env: HashMap::new(),
        }];
        let password_config = PasswordAuthConfig::with_users(users);

        let provider = CompositeAuthProvider::new(Some(pubkey_config), Some(password_config))
            .await
            .unwrap();

        assert!(provider.publickey_enabled());
        assert!(provider.password_enabled());
    }

    #[tokio::test]
    async fn test_composite_provider_user_info() {
        let hash = hash_password("password").unwrap();
        let users = vec![UserDefinition {
            name: "testuser".to_string(),
            password_hash: hash,
            shell: Some("/bin/bash".into()),
            home: Some("/home/testuser".into()),
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        let provider = CompositeAuthProvider::password_only(config).await.unwrap();

        let info = provider.get_user_info("testuser").await.unwrap();
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.username, "testuser");
        assert_eq!(info.shell.to_str().unwrap(), "/bin/bash");
        assert_eq!(info.home_dir.to_str().unwrap(), "/home/testuser");
    }

    #[tokio::test]
    async fn test_composite_provider_user_exists() {
        let hash = hash_password("password").unwrap();
        let users = vec![UserDefinition {
            name: "existinguser".to_string(),
            password_hash: hash,
            shell: None,
            home: None,
            env: HashMap::new(),
        }];

        let config = PasswordAuthConfig::with_users(users);
        let provider = CompositeAuthProvider::password_only(config).await.unwrap();

        assert!(provider.user_exists("existinguser").await.unwrap());
        assert!(!provider.user_exists("nonexistent").await.unwrap());
    }

    #[tokio::test]
    async fn test_composite_provider_disabled_methods() {
        let pubkey_config = PublicKeyAuthConfig::with_directory("/tmp/nonexistent");
        let provider = CompositeAuthProvider::publickey_only(pubkey_config);

        // Password auth should reject when disabled
        let result = provider.verify_password("user", "pass").await.unwrap();
        assert!(result.is_rejected());
    }
}

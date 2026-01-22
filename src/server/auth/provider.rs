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

//! Authentication provider trait and implementations.
//!
//! This module defines the core [`AuthProvider`] trait that all authentication
//! backends must implement. The trait is designed to be:
//!
//! - **Async**: All methods are async for I/O operations
//! - **Extensible**: New auth methods can be added
//! - **Thread-safe**: Implements `Send + Sync`
//!
//! # Implementing AuthProvider
//!
//! To create a custom authentication provider:
//!
//! ```ignore
//! use async_trait::async_trait;
//! use bssh::server::auth::{AuthProvider, AuthResult, UserInfo};
//! use russh::keys::ssh_key::PublicKey;
//! use anyhow::Result;
//!
//! struct MyAuthProvider;
//!
//! #[async_trait]
//! impl AuthProvider for MyAuthProvider {
//!     async fn verify_publickey(&self, username: &str, key: &PublicKey) -> Result<AuthResult> {
//!         // Custom implementation
//!         Ok(AuthResult::Reject)
//!     }
//!
//!     async fn verify_password(&self, username: &str, password: &str) -> Result<AuthResult> {
//!         // Custom implementation
//!         Ok(AuthResult::Reject)
//!     }
//!
//!     async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>> {
//!         Ok(None)
//!     }
//!
//!     async fn user_exists(&self, username: &str) -> Result<bool> {
//!         Ok(false)
//!     }
//! }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use russh::keys::ssh_key::PublicKey;

use crate::shared::auth_types::{AuthResult, UserInfo};

/// Trait for authentication providers.
///
/// This trait defines the interface that all authentication backends must
/// implement. It supports multiple authentication methods as defined by
/// the SSH protocol (RFC 4252).
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to allow concurrent use
/// across multiple SSH connections.
///
/// # Error Handling
///
/// Methods return `Result<AuthResult>` rather than just `AuthResult` to
/// allow for I/O errors and other failures to be distinguished from
/// authentication rejections.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Verify public key authentication.
    ///
    /// This method is called when a client attempts to authenticate using
    /// a public key. The server should verify that:
    ///
    /// 1. The username is valid
    /// 2. The public key is authorized for the user
    ///
    /// # Arguments
    ///
    /// * `username` - The username attempting to authenticate
    /// * `key` - The public key presented by the client
    ///
    /// # Returns
    ///
    /// - `Ok(AuthResult::Accept)` if the key is authorized
    /// - `Ok(AuthResult::Reject)` if the key is not authorized
    /// - `Ok(AuthResult::Partial { .. })` for multi-factor auth scenarios
    /// - `Err(...)` if an error occurred during verification
    ///
    /// # Security
    ///
    /// Implementations should:
    /// - Validate the username to prevent path traversal
    /// - Use constant-time comparison where possible
    /// - Log authentication attempts
    async fn verify_publickey(&self, username: &str, key: &PublicKey) -> Result<AuthResult>;

    /// Verify password authentication.
    ///
    /// This method is called when a client attempts to authenticate using
    /// a password. Password authentication is generally less secure than
    /// public key authentication and may be disabled in the server config.
    ///
    /// # Arguments
    ///
    /// * `username` - The username attempting to authenticate
    /// * `password` - The password presented by the client
    ///
    /// # Returns
    ///
    /// - `Ok(AuthResult::Accept)` if the password is correct
    /// - `Ok(AuthResult::Reject)` if the password is incorrect
    /// - `Ok(AuthResult::Partial { .. })` for multi-factor auth scenarios
    /// - `Err(...)` if an error occurred during verification
    ///
    /// # Security
    ///
    /// Implementations should:
    /// - Use constant-time string comparison
    /// - Never log the actual password
    /// - Consider rate limiting
    async fn verify_password(&self, username: &str, password: &str) -> Result<AuthResult>;

    /// Get user information after successful authentication.
    ///
    /// This method retrieves information about an authenticated user,
    /// which is used to set up the session environment.
    ///
    /// # Arguments
    ///
    /// * `username` - The authenticated username
    ///
    /// # Returns
    ///
    /// - `Ok(Some(UserInfo))` if the user exists
    /// - `Ok(None)` if the user does not exist
    /// - `Err(...)` if an error occurred
    async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>>;

    /// Check if a user exists.
    ///
    /// This method checks whether a user account exists, without performing
    /// authentication. It's useful for early rejection of invalid usernames.
    ///
    /// # Arguments
    ///
    /// * `username` - The username to check
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the user exists
    /// - `Ok(false)` if the user does not exist
    /// - `Err(...)` if an error occurred
    ///
    /// # Security
    ///
    /// Be careful not to leak user enumeration information. Consider always
    /// returning `Ok(true)` and letting authentication fail naturally, or
    /// using timing attack mitigation.
    async fn user_exists(&self, username: &str) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test auth provider that always rejects
    struct RejectAllProvider;

    #[async_trait]
    impl AuthProvider for RejectAllProvider {
        async fn verify_publickey(&self, _username: &str, _key: &PublicKey) -> Result<AuthResult> {
            Ok(AuthResult::Reject)
        }

        async fn verify_password(&self, _username: &str, _password: &str) -> Result<AuthResult> {
            Ok(AuthResult::Reject)
        }

        async fn get_user_info(&self, _username: &str) -> Result<Option<UserInfo>> {
            Ok(None)
        }

        async fn user_exists(&self, _username: &str) -> Result<bool> {
            Ok(false)
        }
    }

    /// A test auth provider that always accepts
    struct AcceptAllProvider;

    #[async_trait]
    impl AuthProvider for AcceptAllProvider {
        async fn verify_publickey(&self, _username: &str, _key: &PublicKey) -> Result<AuthResult> {
            Ok(AuthResult::Accept)
        }

        async fn verify_password(&self, _username: &str, _password: &str) -> Result<AuthResult> {
            Ok(AuthResult::Accept)
        }

        async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>> {
            Ok(Some(UserInfo::new(username)))
        }

        async fn user_exists(&self, _username: &str) -> Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_reject_all_provider() {
        let provider = RejectAllProvider;

        let result = provider.verify_password("test", "pass").await.unwrap();
        assert!(result.is_rejected());

        let exists = provider.user_exists("test").await.unwrap();
        assert!(!exists);

        let info = provider.get_user_info("test").await.unwrap();
        assert!(info.is_none());
    }

    #[tokio::test]
    async fn test_accept_all_provider() {
        let provider = AcceptAllProvider;

        let result = provider.verify_password("test", "pass").await.unwrap();
        assert!(result.is_accepted());

        let exists = provider.user_exists("test").await.unwrap();
        assert!(exists);

        let info = provider.get_user_info("test").await.unwrap();
        assert!(info.is_some());
        assert_eq!(info.unwrap().username, "test");
    }
}

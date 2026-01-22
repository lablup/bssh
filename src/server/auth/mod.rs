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

//! Authentication provider infrastructure for bssh-server.
//!
//! This module provides the authentication framework for the SSH server,
//! including traits for authentication providers and implementations for
//! public key and password authentication.
//!
//! # Architecture
//!
//! The authentication system is designed around the [`AuthProvider`] trait,
//! which allows for extensible authentication methods. Currently supported:
//!
//! - **Public Key Authentication**: Via [`PublicKeyVerifier`]
//! - **Password Authentication**: Via [`PasswordVerifier`] with Argon2id hashing
//! - **Composite Authentication**: Via [`CompositeAuthProvider`] combining multiple methods
//!
//! # Security Features
//!
//! - Username validation to prevent path traversal attacks
//! - Rate limiting integration
//! - Logging of authentication attempts (success/failure)
//! - Timing attack mitigation with constant-time verification
//! - Secure memory cleanup using `zeroize` for password handling
//! - User enumeration protection via dummy hash verification
//!
//! # Usage
//!
//! ## Public Key Authentication
//!
//! ```no_run
//! use bssh::server::auth::{AuthProvider, PublicKeyVerifier, PublicKeyAuthConfig};
//!
//! // Create a public key verifier
//! let config = PublicKeyAuthConfig::with_directory("/etc/bssh/authorized_keys");
//! let verifier = PublicKeyVerifier::new(config);
//!
//! // Use with SSH handler
//! // verifier.verify_publickey("username", &public_key).await
//! ```
//!
//! ## Password Authentication
//!
//! ```no_run
//! use bssh::server::auth::{PasswordVerifier, PasswordAuthConfig, hash_password};
//! use bssh::server::config::UserDefinition;
//! use std::collections::HashMap;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Hash a password using Argon2id
//! let hash = hash_password("secure_password")?;
//!
//! // Create inline user configuration
//! let users = vec![UserDefinition {
//!     name: "testuser".to_string(),
//!     password_hash: hash,
//!     shell: None,
//!     home: None,
//!     env: HashMap::new(),
//! }];
//!
//! let config = PasswordAuthConfig::with_users(users);
//! let verifier = PasswordVerifier::new(config).await?;
//!
//! // Verify a password
//! let result = verifier.verify("testuser", "secure_password").await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Composite Authentication
//!
//! ```no_run
//! use bssh::server::auth::{CompositeAuthProvider, PublicKeyAuthConfig, PasswordAuthConfig};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let pubkey_config = PublicKeyAuthConfig::with_directory("/etc/bssh/authorized_keys");
//! let password_config = PasswordAuthConfig::default();
//!
//! let provider = CompositeAuthProvider::new(
//!     Some(pubkey_config),
//!     Some(password_config),
//! ).await?;
//! # Ok(())
//! # }
//! ```

pub mod composite;
pub mod password;
pub mod provider;
pub mod publickey;

pub use composite::CompositeAuthProvider;
pub use password::{hash_password, verify_password_hash, PasswordAuthConfig, PasswordVerifier};
pub use provider::AuthProvider;
pub use publickey::{AuthKeyOptions, AuthorizedKey, PublicKeyAuthConfig, PublicKeyVerifier};

// Re-export shared auth types for convenience
pub use crate::shared::auth_types::{AuthResult, UserInfo};

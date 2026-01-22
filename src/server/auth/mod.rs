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
//! public key authentication.
//!
//! # Architecture
//!
//! The authentication system is designed around the [`AuthProvider`] trait,
//! which allows for extensible authentication methods. Currently supported:
//!
//! - **Public Key Authentication**: Via [`PublicKeyVerifier`]
//!
//! # Security Features
//!
//! - Username validation to prevent path traversal attacks
//! - Rate limiting integration
//! - Logging of authentication attempts (success/failure)
//! - Timing attack mitigation where possible
//!
//! # Usage
//!
//! ```no_run
//! use bssh::server::auth::{AuthProvider, PublicKeyVerifier, PublicKeyAuthConfig};
//! use std::path::PathBuf;
//!
//! // Create a public key verifier
//! let config = PublicKeyAuthConfig::with_directory("/etc/bssh/authorized_keys");
//! let verifier = PublicKeyVerifier::new(config);
//!
//! // Use with SSH handler
//! // verifier.verify("username", &public_key).await
//! ```

pub mod provider;
pub mod publickey;

pub use provider::AuthProvider;
pub use publickey::{AuthKeyOptions, AuthorizedKey, PublicKeyAuthConfig, PublicKeyVerifier};

// Re-export shared auth types for convenience
pub use crate::shared::auth_types::{AuthResult, UserInfo};

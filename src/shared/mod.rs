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

//! Shared module for code reuse between bssh client and server.
//!
//! This module contains utilities and types that are used by both the
//! bssh SSH client and the bssh-server implementations. By centralizing
//! this shared code, we ensure:
//!
//! - Consistent behavior between client and server
//! - No code duplication
//! - Easier maintenance
//!
//! # Modules
//!
//! - [`validation`]: Input validation utilities for usernames, hostnames, paths
//! - [`rate_limit`]: Generic token bucket rate limiter
//! - [`auth_types`]: Common authentication types and results
//! - [`error`]: Shared error types
//!
//! # Usage
//!
//! The shared module is designed to be used transparently by other modules.
//! For backward compatibility, the existing modules (`security`, `jump`)
//! re-export these shared utilities, so existing code continues to work.
//!
//! ## Direct Usage
//!
//! ```rust
//! use bssh::shared::validation::validate_hostname;
//! use bssh::shared::rate_limit::RateLimiter;
//! use bssh::shared::auth_types::{AuthResult, UserInfo};
//!
//! // Validate a hostname
//! let hostname = validate_hostname("example.com").unwrap();
//!
//! // Use the generic rate limiter
//! let limiter: RateLimiter<String> = RateLimiter::new();
//! ```
//!
//! ## Via Re-exports (Backward Compatible)
//!
//! ```rust
//! // These continue to work as before
//! use bssh::security::validate_hostname;
//! use bssh::jump::rate_limiter::ConnectionRateLimiter;
//! ```

pub mod auth_types;
pub mod error;
pub mod rate_limit;
pub mod validation;

// Re-export commonly used items at the module level for convenience
pub use auth_types::{AuthResult, ServerCheckMethod, UserInfo};
pub use error::{AuthError, ConnectionError, RateLimitError, ValidationError};
pub use rate_limit::{ConnectionRateLimiter, RateLimitConfig, RateLimiter};
pub use validation::{
    sanitize_error_message, validate_hostname, validate_local_path, validate_remote_path,
    validate_username,
};

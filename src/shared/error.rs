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

//! Shared error types for client and server implementations.
//!
//! This module provides common error types that can be used by both
//! the bssh client and server implementations.
//!
//! # Error Categories
//!
//! - [`ValidationError`]: Input validation failures
//! - [`AuthError`]: Authentication-related errors
//! - [`ConnectionError`]: Connection and network errors
//! - [`RateLimitError`]: Rate limiting errors

use std::fmt;
use std::io;

/// Error type for input validation failures.
///
/// This error is returned when user input fails validation checks.
///
/// # Examples
///
/// ```
/// use bssh::shared::error::ValidationError;
///
/// let err = ValidationError::new("username", "contains invalid characters");
/// assert!(err.to_string().contains("username"));
/// ```
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// The field or input that failed validation
    pub field: String,
    /// Description of why validation failed
    pub message: String,
}

impl ValidationError {
    /// Create a new validation error.
    ///
    /// # Arguments
    ///
    /// * `field` - The name of the field that failed validation
    /// * `message` - Description of the validation failure
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }

    /// Create an error for an empty field.
    pub fn empty(field: impl Into<String>) -> Self {
        let field = field.into();
        Self {
            message: format!("{field} cannot be empty"),
            field,
        }
    }

    /// Create an error for a field that is too long.
    pub fn too_long(field: impl Into<String>, max_length: usize) -> Self {
        let field = field.into();
        Self {
            message: format!("{field} exceeds maximum length of {max_length}"),
            field,
        }
    }

    /// Create an error for invalid characters.
    pub fn invalid_characters(field: impl Into<String>) -> Self {
        let field = field.into();
        Self {
            message: format!("{field} contains invalid characters"),
            field,
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Validation error for '{}': {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Error type for authentication failures.
///
/// This enum represents various authentication-related errors that can
/// occur during the SSH authentication process.
#[derive(Debug)]
pub enum AuthError {
    /// Invalid credentials (wrong password, invalid key, etc.)
    InvalidCredentials,

    /// Authentication method not supported by server
    MethodNotSupported(String),

    /// User not found or not allowed
    UserNotAllowed(String),

    /// Account is locked or disabled
    AccountLocked(String),

    /// Too many authentication attempts
    TooManyAttempts,

    /// Authentication timeout
    Timeout,

    /// SSH agent not available
    AgentNotAvailable,

    /// No identities available in SSH agent
    NoIdentities,

    /// Key file not found or unreadable
    KeyFileError(String),

    /// Key format invalid or corrupted
    KeyInvalid(String),

    /// Passphrase required but not provided
    PassphraseRequired,

    /// Passphrase incorrect
    PassphraseIncorrect,

    /// Server rejected the connection
    ServerRejected(String),

    /// Internal error during authentication
    Internal(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::MethodNotSupported(method) => {
                write!(f, "Authentication method '{method}' not supported")
            }
            AuthError::UserNotAllowed(_) => {
                write!(f, "User is not allowed to connect")
            }
            AuthError::AccountLocked(_) => write!(f, "Account is locked"),
            AuthError::TooManyAttempts => write!(f, "Too many authentication attempts"),
            AuthError::Timeout => write!(f, "Authentication timed out"),
            AuthError::AgentNotAvailable => write!(f, "SSH agent not available"),
            AuthError::NoIdentities => write!(f, "No identities available in SSH agent"),
            AuthError::KeyFileError(path) => write!(f, "Cannot read key file: {path}"),
            AuthError::KeyInvalid(reason) => write!(f, "Invalid key: {reason}"),
            AuthError::PassphraseRequired => write!(f, "Passphrase required for key"),
            AuthError::PassphraseIncorrect => write!(f, "Incorrect passphrase"),
            AuthError::ServerRejected(reason) => write!(f, "Server rejected: {reason}"),
            AuthError::Internal(reason) => write!(f, "Internal authentication error: {reason}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Error type for connection failures.
///
/// This enum represents various connection-related errors that can occur
/// during SSH connection establishment.
#[derive(Debug)]
pub enum ConnectionError {
    /// Could not resolve hostname
    DnsResolutionFailed(String),

    /// Connection refused by server
    ConnectionRefused(String),

    /// Connection timed out
    Timeout(String),

    /// Network unreachable
    NetworkUnreachable(String),

    /// Host unreachable
    HostUnreachable(String),

    /// Server closed connection unexpectedly
    ConnectionClosed(String),

    /// Protocol version mismatch
    ProtocolMismatch(String),

    /// Host key verification failed
    HostKeyVerificationFailed(String),

    /// Rate limited
    RateLimited(String),

    /// TLS/SSL error
    TlsError(String),

    /// IO error
    Io(io::Error),

    /// Other error
    Other(String),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionError::DnsResolutionFailed(host) => {
                write!(f, "Could not resolve hostname: {host}")
            }
            ConnectionError::ConnectionRefused(host) => {
                write!(f, "Connection refused by {host}")
            }
            ConnectionError::Timeout(msg) => write!(f, "Connection timed out: {msg}"),
            ConnectionError::NetworkUnreachable(msg) => write!(f, "Network unreachable: {msg}"),
            ConnectionError::HostUnreachable(host) => write!(f, "Host unreachable: {host}"),
            ConnectionError::ConnectionClosed(msg) => write!(f, "Connection closed: {msg}"),
            ConnectionError::ProtocolMismatch(msg) => write!(f, "Protocol mismatch: {msg}"),
            ConnectionError::HostKeyVerificationFailed(msg) => {
                write!(f, "Host key verification failed: {msg}")
            }
            ConnectionError::RateLimited(msg) => write!(f, "Rate limited: {msg}"),
            ConnectionError::TlsError(msg) => write!(f, "TLS error: {msg}"),
            ConnectionError::Io(err) => write!(f, "IO error: {err}"),
            ConnectionError::Other(msg) => write!(f, "Connection error: {msg}"),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnectionError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> Self {
        ConnectionError::Io(err)
    }
}

/// Error type for rate limiting.
///
/// This error is returned when a rate limit is exceeded.
#[derive(Debug, Clone)]
pub struct RateLimitError {
    /// The identifier that was rate limited (e.g., hostname, IP)
    pub identifier: String,
    /// Estimated wait time in seconds before retry
    pub wait_seconds: f64,
}

impl RateLimitError {
    /// Create a new rate limit error.
    ///
    /// # Arguments
    ///
    /// * `identifier` - The identifier that was rate limited
    /// * `wait_seconds` - Estimated wait time before retry
    pub fn new(identifier: impl Into<String>, wait_seconds: f64) -> Self {
        Self {
            identifier: identifier.into(),
            wait_seconds,
        }
    }
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Rate limit exceeded for '{}'. Please wait {:.1} seconds before retrying.",
            self.identifier, self.wait_seconds
        )
    }
}

impl std::error::Error for RateLimitError {}

/// A result type using our shared error types.
pub type SharedResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error() {
        let err = ValidationError::new("username", "contains spaces");
        assert_eq!(err.field, "username");
        assert!(err.to_string().contains("Validation error"));

        let empty_err = ValidationError::empty("password");
        assert!(empty_err.message.contains("cannot be empty"));

        let long_err = ValidationError::too_long("hostname", 253);
        assert!(long_err.message.contains("253"));
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::InvalidCredentials;
        assert!(err.to_string().contains("Invalid credentials"));

        let method_err = AuthError::MethodNotSupported("kerberos".to_string());
        assert!(method_err.to_string().contains("kerberos"));
    }

    #[test]
    fn test_connection_error() {
        let err = ConnectionError::ConnectionRefused("example.com:22".to_string());
        assert!(err.to_string().contains("Connection refused"));

        let io_err = ConnectionError::from(io::Error::new(io::ErrorKind::NotFound, "test"));
        assert!(io_err.to_string().contains("IO error"));
    }

    #[test]
    fn test_rate_limit_error() {
        let err = RateLimitError::new("192.168.1.1", 5.5);
        assert!(err.to_string().contains("192.168.1.1"));
        assert!(err.to_string().contains("5.5"));
    }
}

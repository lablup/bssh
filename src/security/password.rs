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

//! Secure SSH password handling with automatic memory clearing.
//!
//! This module provides:
//! - `Password`: A secure wrapper for SSH authentication passwords with automatic
//!   zeroization (mirrors the `SudoPassword` design).
//! - Helpers for collecting the password once, up-front, from either the
//!   `BSSH_PASSWORD` environment variable (discouraged) or an interactive prompt.
//!
//! # Security Considerations
//! - Passwords are automatically cleared from memory when dropped.
//! - Debug output never reveals the password.
//! - Empty passwords are rejected at construction time.
//! - Cloning produces an independent copy that is also zeroized on drop.
//!
//! # Why hoist the prompt to the dispatcher?
//! Prompting per-connection (inside each parallel SSH task) races multiple
//! tasks for stdin and interleaves with the progress UI. By collecting the
//! password once before the executor / `indicatif` UI is initialized and
//! sharing an `Arc<Password>` across every per-node auth task, the prompt is
//! shown exactly once and reused for all nodes in the cluster.

use anyhow::Result;
use secrecy::{ExposeSecret, SecretString};
use std::fmt;

/// A secure wrapper for SSH authentication passwords.
///
/// Automatically clears its contents from memory when dropped. Designed to be
/// wrapped in `Arc<Password>` and shared across all per-node SSH connection
/// tasks so that the password is collected exactly once.
///
/// # Security
/// - Password is automatically zeroized when dropped.
/// - Debug output does not reveal the password.
/// - Clone creates a new copy that is also zeroized independently.
/// - Safe to share across tasks (via `Arc<Password>`).
#[derive(Clone)]
pub struct Password {
    /// The actual password stored securely.
    inner: SecretString,
}

impl Password {
    /// Create a new `Password` from a string.
    ///
    /// The password will be automatically cleared from memory when dropped.
    ///
    /// # Arguments
    /// * `password` - The password string (will be moved into a secure container).
    ///
    /// # Returns
    /// * `Ok(Password)` if the password is non-empty.
    /// * `Err` if the password is empty.
    pub fn new(password: String) -> Result<Self> {
        if password.is_empty() {
            anyhow::bail!("Password cannot be empty");
        }
        Ok(Self {
            inner: SecretString::new(password.into_boxed_str()),
        })
    }

    /// Get the password as a string slice.
    ///
    /// # Security Note
    /// The returned slice should be used immediately and not stored.
    /// Consumers (e.g., `AuthMethod::with_password`) typically copy this
    /// into their own `Zeroizing` container.
    pub fn as_str(&self) -> &str {
        self.inner.expose_secret()
    }

    /// Check if the password is empty.
    ///
    /// Note: this always returns `false` since empty passwords are rejected
    /// during construction; kept for API symmetry with `SudoPassword`.
    pub fn is_empty(&self) -> bool {
        self.inner.expose_secret().is_empty()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Prompt the user for an SSH password securely.
///
/// Uses `rpassword` to read the password without echoing it to the terminal.
/// The prompt is intentionally non-host-specific because the same password is
/// reused for every node in the cluster.
///
/// # Security Note
/// - The password is never printed to stdout/stderr.
/// - The password is stored in a `Password` (backed by `SecretString`).
/// - Empty passwords are rejected with a clear error message.
///
/// # Important: call this BEFORE initializing any progress UI (`indicatif`).
/// Prompting after `MultiProgress` is rendered will interleave the prompt
/// with progress bar output and corrupt the terminal state.
pub fn prompt_password() -> Result<Password> {
    let password = rpassword::prompt_password("Enter SSH password (used for all hosts): ")
        .map_err(|e| anyhow::anyhow!("Failed to read password: {}", e))?;

    if password.is_empty() {
        anyhow::bail!("Empty password not allowed. Please enter a valid SSH password.");
    }

    Password::new(password)
}

/// Get SSH password from environment variable (if set).
///
/// # Security Warning
/// Using environment variables for passwords is NOT recommended in production
/// as they may be visible in process listings and shell history. Provided for
/// automation scenarios where the security trade-off is acceptable.
///
/// # Returns
/// * `Some(Password)` if `BSSH_PASSWORD` is set and non-empty.
/// * `None` if the environment variable is not set.
/// * `Err` if `BSSH_PASSWORD` is set but empty (empty passwords are rejected).
pub fn get_password_from_env() -> Result<Option<Password>> {
    match std::env::var("BSSH_PASSWORD") {
        Ok(password) if !password.is_empty() => Ok(Some(Password::new(password)?)),
        Ok(_) => {
            anyhow::bail!("BSSH_PASSWORD is set but empty. Empty passwords are not allowed.");
        }
        Err(_) => Ok(None),
    }
}

/// Get the SSH password from either environment or interactive prompt.
///
/// First checks `BSSH_PASSWORD`; if unset, prompts the user interactively.
///
/// # Arguments
/// * `warn_env` - If `true`, print a warning when using the environment variable.
///
/// # Returns
/// A `Password` containing the entered password.
///
/// # Important
/// Call this BEFORE any progress UI is initialized so the prompt is shown
/// cleanly. The dispatcher invokes this once per command and threads the
/// resulting `Arc<Password>` through every per-node connection task.
pub fn get_password(warn_env: bool) -> Result<Password> {
    match get_password_from_env()? {
        Some(password) => {
            if warn_env {
                eprintln!(
                    "Warning: Using SSH password from BSSH_PASSWORD environment variable. \
                     This is not recommended for security reasons."
                );
            }
            Ok(password)
        }
        None => prompt_password(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::EnvGuard;
    use serial_test::serial;

    #[test]
    fn test_password_creation() {
        let password = Password::new("test123".to_string()).unwrap();
        assert_eq!(password.as_str(), "test123");
        assert!(!password.is_empty());
    }

    #[test]
    fn test_password_empty_rejection() {
        let result = Password::new(String::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_password_debug_redaction() {
        let password = Password::new("secret".to_string()).unwrap();
        let debug_output = format!("{password:?}");
        assert!(!debug_output.contains("secret"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_clone_independence() {
        let p1 = Password::new("original".to_string()).unwrap();
        let p2 = p1.clone();

        assert_eq!(p1.as_str(), "original");
        assert_eq!(p2.as_str(), "original");
        // Each clone is zeroized independently on drop.
    }

    #[test]
    fn test_arc_sharing() {
        use std::sync::Arc;
        let p = Arc::new(Password::new("shared".to_string()).unwrap());
        let c1 = Arc::clone(&p);
        let c2 = Arc::clone(&p);

        // All three references see the same value (the same underlying secret).
        assert_eq!(p.as_str(), "shared");
        assert_eq!(c1.as_str(), "shared");
        assert_eq!(c2.as_str(), "shared");
        assert_eq!(Arc::strong_count(&p), 3);
    }

    #[test]
    #[serial]
    fn test_get_password_from_env_empty() {
        // Empty BSSH_PASSWORD should error; guard restores prior value on drop.
        let _guard = EnvGuard::set("BSSH_PASSWORD", "");
        let result = get_password_from_env();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    #[serial]
    fn test_get_password_from_env_valid() {
        let _guard = EnvGuard::set("BSSH_PASSWORD", "test_password");
        let result = get_password_from_env();

        assert!(result.is_ok());
        let password = result.unwrap();
        assert!(password.is_some());
        assert_eq!(password.unwrap().as_str(), "test_password");
    }

    #[test]
    #[serial]
    fn test_get_password_from_env_not_set() {
        let _guard = EnvGuard::remove("BSSH_PASSWORD");
        let result = get_password_from_env();

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    /// Verify that the env-driven helper used by the dispatcher returns the
    /// same password every caller would observe — modeling the dispatcher-level
    /// collection pattern (collect once, share to every node).
    #[test]
    #[serial]
    fn test_get_password_dispatcher_collection_pattern() {
        use std::sync::Arc;

        let _guard = EnvGuard::set("BSSH_PASSWORD", "shared_password");

        // Dispatcher path: collect once, no warning here (warn behavior covered separately).
        let password = get_password(false).expect("env password should succeed");

        // Wrap in Arc (this is exactly what the dispatcher does before fanning out to
        // per-node connection tasks).
        let shared = Arc::new(password);

        // Simulate three parallel per-node auth tasks pulling the same password.
        let n1 = Arc::clone(&shared);
        let n2 = Arc::clone(&shared);
        let n3 = Arc::clone(&shared);

        assert_eq!(n1.as_str(), "shared_password");
        assert_eq!(n2.as_str(), "shared_password");
        assert_eq!(n3.as_str(), "shared_password");
        // All three nodes observed an identical password (single prompt invariant).
        assert_eq!(Arc::strong_count(&shared), 4);
    }
}

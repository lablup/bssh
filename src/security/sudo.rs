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

//! Secure sudo password handling with automatic memory clearing.
//!
//! This module provides:
//! - `SudoPassword`: A secure wrapper for sudo passwords with automatic zeroization
//! - Sudo prompt detection patterns for various Linux distributions
//! - Secure password input functions
//!
//! # Security Considerations
//! - Passwords are automatically cleared from memory when dropped
//! - Never log or print sudo passwords
//! - Environment variable usage is discouraged due to security risks

use anyhow::Result;
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use zeroize::Zeroizing;

/// Common sudo password prompt patterns across different distributions
///
/// These patterns are case-insensitive and designed to match:
/// - Standard sudo prompts: `[sudo] password for username:`
/// - Generic password prompts: `Password:`
/// - User-specific prompts: `username's password:`
/// - Custom sudo prompts that may vary by distribution
pub const SUDO_PROMPT_PATTERNS: &[&str] = &[
    "[sudo] password for ",
    "password for ",
    "password:",
    "'s password:",
    "sudo password",
    "enter password",
    "[sudo]",
];

/// Patterns indicating sudo authentication failure
pub const SUDO_FAILURE_PATTERNS: &[&str] = &[
    "sorry, try again",
    "incorrect password",
    "authentication failure",
    "permission denied",
    "sudo: 3 incorrect password attempts",
    "sudo: no password was provided",
];

/// A secure wrapper for sudo passwords that automatically clears memory on drop.
///
/// This struct uses the `secrecy` crate which is specifically designed for handling
/// secret values in memory. It ensures the password is securely cleared when dropped,
/// and works correctly with cloning (each clone is independent and properly zeroized).
///
/// # Security
/// - Password is automatically zeroized when dropped
/// - Debug output does not reveal the password
/// - Clone creates a new copy that is also zeroized independently
/// - Works correctly in multi-threaded contexts (safe to share across tasks)
#[derive(Clone)]
pub struct SudoPassword {
    /// The actual password stored securely
    inner: SecretString,
}

impl SudoPassword {
    /// Create a new SudoPassword from a string.
    ///
    /// The password will be automatically cleared from memory when dropped.
    ///
    /// # Arguments
    /// * `password` - The password string (will be zeroized after conversion)
    ///
    /// # Returns
    /// * `Ok(SudoPassword)` if the password is non-empty
    /// * `Err` if the password is empty
    pub fn new(password: String) -> Result<Self> {
        if password.is_empty() {
            anyhow::bail!("Password cannot be empty");
        }
        Ok(Self {
            inner: SecretString::new(password.into_boxed_str()),
        })
    }

    /// Get the password as bytes for sending over SSH.
    ///
    /// # Security Note
    /// The returned bytes should be used immediately and not stored.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.expose_secret().as_bytes()
    }

    /// Get the password with a newline appended for sudo input.
    ///
    /// Sudo requires a newline after the password to submit it.
    ///
    /// # Security Note
    /// Returns a `Zeroizing<Vec<u8>>` to ensure the copy is also cleared from memory.
    pub fn with_newline(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = self.inner.expose_secret().as_bytes().to_vec();
        bytes.push(b'\n');
        Zeroizing::new(bytes)
    }

    /// Check if the password is empty.
    ///
    /// Note: This should always return false since empty passwords are rejected
    /// during construction, but kept for API compatibility.
    pub fn is_empty(&self) -> bool {
        self.inner.expose_secret().is_empty()
    }
}

impl fmt::Debug for SudoPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SudoPassword")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Check if the given output contains a sudo password prompt.
///
/// This function performs case-insensitive matching against known
/// sudo prompt patterns.
///
/// # Arguments
/// * `output` - The command output to check (stdout or stderr)
///
/// # Returns
/// `true` if a sudo prompt is detected, `false` otherwise
pub fn contains_sudo_prompt(output: &str) -> bool {
    let lower = output.to_lowercase();
    SUDO_PROMPT_PATTERNS
        .iter()
        .any(|pattern| lower.contains(*pattern))
}

/// Check if the given output contains a sudo authentication failure message.
///
/// # Arguments
/// * `output` - The command output to check
///
/// # Returns
/// `true` if a failure message is detected, `false` otherwise
pub fn contains_sudo_failure(output: &str) -> bool {
    let lower = output.to_lowercase();
    SUDO_FAILURE_PATTERNS
        .iter()
        .any(|pattern| lower.contains(*pattern))
}

/// Prompt the user for a sudo password securely.
///
/// This function uses `rpassword` to securely read the password without
/// echoing it to the terminal.
///
/// # Returns
/// A `SudoPassword` containing the entered password, or an error if
/// reading fails or the password is empty.
///
/// # Security Note
/// - The password is never printed to stdout/stderr
/// - The password is stored in a zeroizing container
/// - Empty passwords are rejected with a clear error message
pub fn prompt_sudo_password() -> Result<SudoPassword> {
    eprintln!("Enter sudo password: ");
    let password = rpassword::read_password().map_err(|e| {
        anyhow::anyhow!("Failed to read sudo password: {}", e)
    })?;

    if password.is_empty() {
        anyhow::bail!("Empty password not allowed. Please enter a valid sudo password.");
    }

    SudoPassword::new(password)
}

/// Get sudo password from environment variable (if set).
///
/// # Security Warning
/// Using environment variables for passwords is NOT recommended in production
/// as they may be visible in process listings and shell history.
/// This is provided for automation scenarios where the security trade-off
/// is acceptable.
///
/// # Returns
/// * `Some(SudoPassword)` if `BSSH_SUDO_PASSWORD` is set and non-empty
/// * `None` if the environment variable is not set or empty
/// * `Err` if the password fails validation
pub fn get_sudo_password_from_env() -> Result<Option<SudoPassword>> {
    match std::env::var("BSSH_SUDO_PASSWORD") {
        Ok(password) if !password.is_empty() => {
            Ok(Some(SudoPassword::new(password)?))
        }
        Ok(_) => {
            // Empty password from environment
            anyhow::bail!("BSSH_SUDO_PASSWORD is set but empty. Empty passwords are not allowed.");
        }
        Err(_) => Ok(None),
    }
}

/// Get sudo password from either environment or interactive prompt.
///
/// This function first checks the `BSSH_SUDO_PASSWORD` environment variable.
/// If not set, it prompts the user interactively.
///
/// # Arguments
/// * `warn_env` - If `true`, print a warning when using environment variable
///
/// # Returns
/// A `SudoPassword` containing the password.
pub fn get_sudo_password(warn_env: bool) -> Result<SudoPassword> {
    match get_sudo_password_from_env()? {
        Some(password) => {
            if warn_env {
                eprintln!(
                    "Warning: Using sudo password from BSSH_SUDO_PASSWORD environment variable. \
                     This is not recommended for security reasons."
                );
            }
            Ok(password)
        }
        None => prompt_sudo_password(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_sudo_password_creation() {
        let password = SudoPassword::new("test123".to_string()).unwrap();
        assert_eq!(password.as_bytes(), b"test123");
        assert!(!password.is_empty());
    }

    #[test]
    fn test_sudo_password_empty_rejection() {
        let result = SudoPassword::new(String::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_sudo_password_with_newline() {
        let password = SudoPassword::new("test123".to_string()).unwrap();
        let with_newline = password.with_newline();
        assert_eq!(&*with_newline, b"test123\n");
    }

    #[test]
    fn test_sudo_password_with_newline_is_zeroizing() {
        let password = SudoPassword::new("test123".to_string()).unwrap();
        let with_newline = password.with_newline();
        // The type should be Zeroizing<Vec<u8>>
        // When dropped, it will automatically clear memory
        assert_eq!(&*with_newline, b"test123\n");
        drop(with_newline);
        // After drop, memory should be cleared (we can't verify this in safe Rust,
        // but the type system ensures it)
    }

    #[test]
    fn test_sudo_password_debug_redaction() {
        let password = SudoPassword::new("secret".to_string()).unwrap();
        let debug_output = format!("{:?}", password);
        assert!(!debug_output.contains("secret"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_contains_sudo_prompt() {
        // Standard sudo prompts
        assert!(contains_sudo_prompt("[sudo] password for user:"));
        assert!(contains_sudo_prompt("Password:"));
        assert!(contains_sudo_prompt("user's password:"));
        assert!(contains_sudo_prompt("[sudo] password for admin:"));

        // Case insensitive
        assert!(contains_sudo_prompt("[SUDO] PASSWORD FOR USER:"));
        assert!(contains_sudo_prompt("PASSWORD:"));

        // Should not match
        assert!(!contains_sudo_prompt("Command executed successfully"));
        assert!(!contains_sudo_prompt("root@server:~#"));
    }

    #[test]
    fn test_contains_sudo_failure() {
        assert!(contains_sudo_failure("Sorry, try again."));
        assert!(contains_sudo_failure("sudo: 3 incorrect password attempts"));
        assert!(contains_sudo_failure("Authentication failure"));
        assert!(contains_sudo_failure("Permission denied"));

        // Should not match
        assert!(!contains_sudo_failure("Command executed successfully"));
        assert!(!contains_sudo_failure("password accepted"));
    }

    #[test]
    fn test_clone_independence() {
        let password1 = SudoPassword::new("original".to_string()).unwrap();
        let password2 = password1.clone();

        // Both should work independently
        assert_eq!(password1.as_bytes(), b"original");
        assert_eq!(password2.as_bytes(), b"original");

        // When dropped, each will be zeroized independently
        // (secrecy::SecretString handles this correctly)
    }

    #[test]
    #[serial]
    fn test_get_sudo_password_from_env_empty() {
        // Ensure variable is not set from other tests
        std::env::remove_var("BSSH_SUDO_PASSWORD");
        // Set environment variable to empty string
        std::env::set_var("BSSH_SUDO_PASSWORD", "");
        let result = get_sudo_password_from_env();
        std::env::remove_var("BSSH_SUDO_PASSWORD");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    #[serial]
    fn test_get_sudo_password_from_env_valid() {
        // Ensure variable is not set from other tests
        std::env::remove_var("BSSH_SUDO_PASSWORD");
        // Set environment variable to valid password
        std::env::set_var("BSSH_SUDO_PASSWORD", "test_password");
        let result = get_sudo_password_from_env();
        std::env::remove_var("BSSH_SUDO_PASSWORD");

        assert!(result.is_ok());
        let password = result.unwrap();
        assert!(password.is_some());
        assert_eq!(password.unwrap().as_bytes(), b"test_password");
    }

    #[test]
    #[serial]
    fn test_get_sudo_password_from_env_not_set() {
        std::env::remove_var("BSSH_SUDO_PASSWORD");
        let result = get_sudo_password_from_env();

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}

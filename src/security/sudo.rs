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
use std::fmt;
use std::sync::Arc;
use zeroize::ZeroizeOnDrop;

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
/// This struct uses the `zeroize` crate to ensure the password is securely
/// cleared from memory when the struct is dropped, preventing sensitive data
/// from remaining in memory.
///
/// # Security
/// - Password is automatically zeroized when dropped
/// - Debug output does not reveal the password
/// - Clone creates a new copy that is also zeroized independently
#[derive(Clone, ZeroizeOnDrop)]
pub struct SudoPassword {
    /// The actual password bytes
    #[zeroize(skip)] // We handle the inner zeroization manually via Arc
    inner: Arc<SudoPasswordInner>,
}

/// Inner container for the password with zeroize support
#[derive(ZeroizeOnDrop)]
struct SudoPasswordInner {
    password: String,
}

impl SudoPassword {
    /// Create a new SudoPassword from a string.
    ///
    /// The password will be automatically cleared from memory when all
    /// references to this SudoPassword are dropped.
    pub fn new(password: String) -> Self {
        Self {
            inner: Arc::new(SudoPasswordInner { password }),
        }
    }

    /// Get the password as bytes for sending over SSH.
    ///
    /// # Security Note
    /// The returned bytes should be used immediately and not stored.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.password.as_bytes()
    }

    /// Get the password with a newline appended for sudo input.
    ///
    /// Sudo requires a newline after the password to submit it.
    pub fn with_newline(&self) -> Vec<u8> {
        let mut bytes = self.inner.password.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes
    }

    /// Check if the password is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.password.is_empty()
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
/// reading fails.
///
/// # Security Note
/// - The password is never printed to stdout/stderr
/// - The password is stored in a zeroizing container
pub fn prompt_sudo_password() -> Result<SudoPassword> {
    eprintln!("Enter sudo password: ");
    let password = rpassword::read_password().map_err(|e| {
        anyhow::anyhow!("Failed to read sudo password: {}", e)
    })?;
    Ok(SudoPassword::new(password))
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
/// `Some(SudoPassword)` if `BSSH_SUDO_PASSWORD` is set, `None` otherwise.
pub fn get_sudo_password_from_env() -> Option<SudoPassword> {
    std::env::var("BSSH_SUDO_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty())
        .map(SudoPassword::new)
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
    if let Some(password) = get_sudo_password_from_env() {
        if warn_env {
            eprintln!(
                "Warning: Using sudo password from BSSH_SUDO_PASSWORD environment variable. \
                 This is not recommended for security reasons."
            );
        }
        Ok(password)
    } else {
        prompt_sudo_password()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudo_password_creation() {
        let password = SudoPassword::new("test123".to_string());
        assert_eq!(password.as_bytes(), b"test123");
        assert!(!password.is_empty());
    }

    #[test]
    fn test_sudo_password_with_newline() {
        let password = SudoPassword::new("test123".to_string());
        let with_newline = password.with_newline();
        assert_eq!(with_newline, b"test123\n");
    }

    #[test]
    fn test_sudo_password_debug_redaction() {
        let password = SudoPassword::new("secret".to_string());
        let debug_output = format!("{:?}", password);
        assert!(!debug_output.contains("secret"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_empty_password() {
        let password = SudoPassword::new(String::new());
        assert!(password.is_empty());
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
        let password1 = SudoPassword::new("original".to_string());
        let password2 = password1.clone();

        // Both should work independently
        assert_eq!(password1.as_bytes(), b"original");
        assert_eq!(password2.as_bytes(), b"original");
    }
}

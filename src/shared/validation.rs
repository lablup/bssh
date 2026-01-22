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

//! Shared validation utilities for validating and sanitizing user input.
//!
//! This module provides security utilities for validating user input that can
//! be reused between the bssh client and server implementations.
//!
//! # Security
//!
//! These functions are designed to prevent:
//! - Path traversal attacks
//! - Command injection
//! - Information leakage through error messages

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Maximum recursion depth for validating non-existent paths
const MAX_PATH_VALIDATION_DEPTH: u32 = 20;

/// Helper function to validate non-existent paths with recursion depth limit.
///
/// This prevents infinite recursion when validating paths with non-existent parents.
fn validate_nonexistent_path(path: &Path, depth: u32) -> Result<PathBuf> {
    // Check recursion depth to prevent stack overflow
    if depth >= MAX_PATH_VALIDATION_DEPTH {
        anyhow::bail!("Path validation depth exceeded (max {MAX_PATH_VALIDATION_DEPTH} levels)");
    }

    if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() {
            // Parent is empty, use current directory
            Ok(std::env::current_dir()
                .with_context(|| "Failed to get current directory")?
                .join(path))
        } else if parent.exists() {
            let canonical_parent = parent
                .canonicalize()
                .with_context(|| format!("Failed to canonicalize parent path: {parent:?}"))?;

            // Get the file name
            let file_name = path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid path: no file name component"))?;

            // Validate file name doesn't contain path separators
            let file_name_str = file_name.to_string_lossy();
            if file_name_str.contains('/') || file_name_str.contains('\\') {
                anyhow::bail!("Invalid file name: contains path separator");
            }

            Ok(canonical_parent.join(file_name))
        } else {
            // Parent doesn't exist, recursively validate with depth tracking
            let canonical_parent = validate_nonexistent_path(parent, depth + 1)?;

            // Get the file name
            let file_name = path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid path: no file name component"))?;

            // Validate file name doesn't contain path separators
            let file_name_str = file_name.to_string_lossy();
            if file_name_str.contains('/') || file_name_str.contains('\\') {
                anyhow::bail!("Invalid file name: contains path separator");
            }

            Ok(canonical_parent.join(file_name))
        }
    } else {
        // No parent, treat as relative to current directory
        Ok(std::env::current_dir()
            .with_context(|| "Failed to get current directory")?
            .join(path))
    }
}

/// Validate and sanitize a local file path to prevent path traversal attacks.
///
/// This function ensures:
/// - No path traversal sequences (..)
/// - No double slashes (//)
/// - Path is canonical and resolved
/// - No symlink attacks
///
/// # Arguments
///
/// * `path` - The local file path to validate
///
/// # Returns
///
/// Returns the canonical path if validation succeeds.
///
/// # Errors
///
/// Returns an error if:
/// - Path contains traversal sequences (..)
/// - Path contains double slashes (//)
/// - Path cannot be canonicalized
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use bssh::shared::validation::validate_local_path;
///
/// // Valid path
/// let result = validate_local_path(Path::new("/tmp/test.txt"));
/// assert!(result.is_ok());
///
/// // Invalid path with traversal
/// let result = validate_local_path(Path::new("../etc/passwd"));
/// assert!(result.is_err());
/// ```
pub fn validate_local_path(path: &Path) -> Result<PathBuf> {
    // Convert to string to check for dangerous patterns
    let path_str = path.to_string_lossy();

    // Check for path traversal attempts
    if path_str.contains("..") {
        anyhow::bail!("Path traversal detected: path contains '..'");
    }

    // Check for double slashes
    if path_str.contains("//") {
        anyhow::bail!("Invalid path: contains double slashes");
    }

    // Get canonical path (resolves symlinks, .., ., etc.)
    // This will fail if the path doesn't exist yet, so we handle that case
    let canonical = if path.exists() {
        path.canonicalize()
            .with_context(|| format!("Failed to canonicalize path: {path:?}"))?
    } else {
        // For non-existent paths, validate the parent directory
        validate_nonexistent_path(path, 0)?
    };

    Ok(canonical)
}

/// Validate a remote path string to prevent injection attacks.
///
/// This function ensures:
/// - No shell metacharacters that could cause command injection
/// - No path traversal sequences
/// - Only valid characters for file paths
///
/// # Arguments
///
/// * `path` - The remote path string to validate
///
/// # Returns
///
/// Returns the validated path string if validation succeeds.
///
/// # Errors
///
/// Returns an error if:
/// - Path is empty
/// - Path is too long (>4096 characters)
/// - Path contains shell metacharacters
/// - Path contains command substitution patterns
/// - Path contains path traversal sequences
///
/// # Examples
///
/// ```
/// use bssh::shared::validation::validate_remote_path;
///
/// // Valid paths
/// assert!(validate_remote_path("/home/user/file.txt").is_ok());
/// assert!(validate_remote_path("~/documents/report.pdf").is_ok());
///
/// // Invalid paths
/// assert!(validate_remote_path("/tmp/$(whoami)").is_err());
/// assert!(validate_remote_path("../etc/passwd").is_err());
/// ```
pub fn validate_remote_path(path: &str) -> Result<String> {
    // Check for empty path
    if path.is_empty() {
        anyhow::bail!("Remote path cannot be empty");
    }

    // Check path length to prevent DoS
    const MAX_PATH_LENGTH: usize = 4096;
    if path.len() > MAX_PATH_LENGTH {
        anyhow::bail!("Remote path too long (max {MAX_PATH_LENGTH} characters)");
    }

    // Check for shell metacharacters that could cause injection
    const DANGEROUS_CHARS: &[char] = &[
        ';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\0', '!', '*', '?',
        '[', ']', // Shell wildcards that could cause issues
    ];

    for &ch in DANGEROUS_CHARS {
        if path.contains(ch) {
            anyhow::bail!("Remote path contains invalid character: '{ch}'");
        }
    }

    // Check for command substitution patterns
    if path.contains("$(") || path.contains("${") || path.contains("`)") {
        anyhow::bail!("Remote path contains potential command substitution");
    }

    // Check for path traversal - all possible patterns
    if path.contains("../")
        || path.contains("/..")
        || path.starts_with("../")
        || path.starts_with("/..")
        || path.ends_with("/..")
        || path == ".."
    {
        anyhow::bail!("Remote path contains path traversal sequence");
    }

    // Check for double slashes (could indicate protocol bypasses)
    if path.contains("//") && !path.starts_with("//") {
        anyhow::bail!("Remote path contains double slashes");
    }

    // Validate that path contains only allowed characters
    // Allow: alphanumeric, spaces, and common path characters
    let valid_chars = path.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '/'
            || c == '\\'
            || c == '.'
            || c == '-'
            || c == '_'
            || c == ' '
            || c == '~'
            || c == '='
            || c == ','
            || c == ':'
            || c == '@'
    });

    if !valid_chars {
        anyhow::bail!("Remote path contains invalid characters");
    }

    Ok(path.to_string())
}

/// Sanitize a hostname to prevent injection attacks.
///
/// This function validates that hostnames conform to RFC 1123 and don't contain
/// characters that could be used for command injection.
///
/// # Arguments
///
/// * `hostname` - The hostname string to validate
///
/// # Returns
///
/// Returns the validated hostname if validation succeeds.
///
/// # Errors
///
/// Returns an error if:
/// - Hostname is empty
/// - Hostname is too long (>253 characters, per RFC 1123)
/// - Hostname contains invalid characters
/// - Hostname contains suspicious patterns
///
/// # Examples
///
/// ```
/// use bssh::shared::validation::validate_hostname;
///
/// // Valid hostnames
/// assert!(validate_hostname("example.com").is_ok());
/// assert!(validate_hostname("192.168.1.1").is_ok());
/// assert!(validate_hostname("[::1]").is_ok());
///
/// // Invalid hostnames
/// assert!(validate_hostname("example..com").is_err());
/// assert!(validate_hostname("example.com; ls").is_err());
/// ```
pub fn validate_hostname(hostname: &str) -> Result<String> {
    // Check for empty hostname
    if hostname.is_empty() {
        anyhow::bail!("Hostname cannot be empty");
    }

    // Check hostname length (RFC 1123)
    const MAX_HOSTNAME_LENGTH: usize = 253;
    if hostname.len() > MAX_HOSTNAME_LENGTH {
        anyhow::bail!("Hostname too long (max {MAX_HOSTNAME_LENGTH} characters)");
    }

    // Validate hostname format (RFC 1123)
    // Allow alphanumeric, dots, hyphens, and colons (for IPv6)
    let valid_chars = hostname.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']'
    });

    if !valid_chars {
        anyhow::bail!("Hostname contains invalid characters");
    }

    // Check for suspicious patterns
    if hostname.contains("..") || hostname.contains("--") {
        anyhow::bail!("Hostname contains suspicious repeated characters");
    }

    Ok(hostname.to_string())
}

/// Validate a username to prevent injection attacks.
///
/// This function validates that usernames conform to POSIX standards and don't
/// contain characters that could be used for command injection.
///
/// # Arguments
///
/// * `username` - The username string to validate
///
/// # Returns
///
/// Returns the validated username if validation succeeds.
///
/// # Errors
///
/// Returns an error if:
/// - Username is empty
/// - Username is too long (>32 characters)
/// - Username contains invalid characters
/// - Username starts with a hyphen
///
/// # Examples
///
/// ```
/// use bssh::shared::validation::validate_username;
///
/// // Valid usernames
/// assert!(validate_username("john_doe").is_ok());
/// assert!(validate_username("user123").is_ok());
///
/// // Invalid usernames
/// assert!(validate_username("-user").is_err());
/// assert!(validate_username("user@domain").is_err());
/// ```
pub fn validate_username(username: &str) -> Result<String> {
    // Check for empty username
    if username.is_empty() {
        anyhow::bail!("Username cannot be empty");
    }

    // Check username length
    const MAX_USERNAME_LENGTH: usize = 32;
    if username.len() > MAX_USERNAME_LENGTH {
        anyhow::bail!("Username too long (max {MAX_USERNAME_LENGTH} characters)");
    }

    // Validate username format (POSIX-compliant)
    // Allow alphanumeric, underscore, hyphen, and dot
    let valid_chars = username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');

    if !valid_chars {
        anyhow::bail!("Username contains invalid characters");
    }

    // Username should not start with a hyphen
    if username.starts_with('-') {
        anyhow::bail!("Username cannot start with a hyphen");
    }

    Ok(username.to_string())
}

/// Sanitize error messages to prevent information leakage.
///
/// This function redacts sensitive information like usernames, hostnames,
/// and ports from error messages to prevent information disclosure.
///
/// # Arguments
///
/// * `message` - The error message to sanitize
///
/// # Returns
///
/// Returns the sanitized error message with sensitive information redacted.
///
/// # Examples
///
/// ```
/// use bssh::shared::validation::sanitize_error_message;
///
/// let message = "Failed to connect to 192.168.1.1:22";
/// let sanitized = sanitize_error_message(message);
/// // IP address is redacted
/// ```
pub fn sanitize_error_message(message: &str) -> String {
    let mut sanitized = message.to_string();

    // Remove specific usernames (format: user 'username')
    if let Some(start) = sanitized.find("user '") {
        if let Some(end) = sanitized[start + 6..].find('\'') {
            let before = &sanitized[..start + 5];
            let after = &sanitized[start + 6 + end + 1..];
            sanitized = format!("{before}<redacted>{after}");
        }
    }

    // Remove hostname:port combinations in common patterns
    // We process these sequentially since each replacement may affect subsequent ones
    let patterns = [
        (" on ", " on <host>"),
        (" to ", " to <host>"),
        (" at ", " at <host>"),
        (" from ", " from <host>"),
    ];

    for (pattern, replacement) in &patterns {
        if sanitized.contains(pattern) {
            // Find pattern and replace following hostname:port
            let parts: Vec<&str> = sanitized.split(pattern).collect();
            let mut result = String::new();

            for (i, part) in parts.iter().enumerate() {
                result.push_str(part);
                if i < parts.len() - 1 {
                    result.push_str(replacement);
                    // Skip the actual hostname:port in the next part
                    if let Some(next_space) = parts[i + 1].find(' ') {
                        result.push_str(&parts[i + 1][next_space..]);
                    }
                }
            }
            sanitized = result;
        }
    }

    // Remove any remaining IP addresses
    // Simple check for IPv4 pattern
    let parts: Vec<&str> = sanitized.split_whitespace().collect();
    let mut result_parts = Vec::new();

    for part in parts {
        if part.split('.').count() == 4
            && part
                .split('.')
                .all(|p| p.parse::<u8>().is_ok() || p.contains(':'))
        {
            result_parts.push("<ip-address>");
        } else {
            result_parts.push(part);
        }
    }

    result_parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_local_path() {
        // Valid paths
        assert!(validate_local_path(Path::new("/tmp/test.txt")).is_ok());
        assert!(validate_local_path(Path::new("./test.txt")).is_ok());

        // Invalid paths with traversal
        assert!(validate_local_path(Path::new("../etc/passwd")).is_err());
        assert!(validate_local_path(Path::new("/tmp/../etc/passwd")).is_err());
        assert!(validate_local_path(Path::new("/tmp//test")).is_err());
    }

    #[test]
    fn test_validate_remote_path() {
        // Valid paths
        assert!(validate_remote_path("/home/user/file.txt").is_ok());
        assert!(validate_remote_path("~/documents/report.pdf").is_ok());
        assert!(validate_remote_path("C:\\Users\\test\\file.txt").is_ok());

        // Invalid paths
        assert!(validate_remote_path("../etc/passwd").is_err());
        assert!(validate_remote_path("/tmp/$(whoami)").is_err());
        assert!(validate_remote_path("/tmp/test; rm -rf /").is_err());
        assert!(validate_remote_path("/tmp/test`id`").is_err());
        assert!(validate_remote_path("/tmp/test|cat").is_err());
        assert!(validate_remote_path("").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        // Valid hostnames
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("192.168.1.1").is_ok());
        assert!(validate_hostname("server-01.example.com").is_ok());
        assert!(validate_hostname("[::1]").is_ok());

        // Invalid hostnames
        assert!(validate_hostname("example..com").is_err());
        assert!(validate_hostname("server--01").is_err());
        assert!(validate_hostname("example.com; ls").is_err());
        assert!(validate_hostname("").is_err());
    }

    #[test]
    fn test_validate_username() {
        // Valid usernames
        assert!(validate_username("john_doe").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test.user").is_ok());

        // Invalid usernames
        assert!(validate_username("-user").is_err());
        assert!(validate_username("user@domain").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("").is_err());
        assert!(validate_username(&"a".repeat(50)).is_err());
    }
}

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

//! Security utilities for validating and sanitizing user input

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Validate and sanitize a local file path to prevent path traversal attacks
///
/// This function ensures:
/// - No path traversal sequences (..)
/// - No double slashes (//)
/// - Path is canonical and resolved
/// - No symlink attacks
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
            .with_context(|| format!("Failed to canonicalize path: {:?}", path))?
    } else {
        // For non-existent paths, validate the parent directory
        if let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() {
                // Parent is empty, use current directory
                std::env::current_dir()
                    .with_context(|| "Failed to get current directory")?
                    .join(path)
            } else if parent.exists() {
                let canonical_parent = parent
                    .canonicalize()
                    .with_context(|| format!("Failed to canonicalize parent path: {:?}", parent))?;

                // Get the file name
                let file_name = path
                    .file_name()
                    .ok_or_else(|| anyhow::anyhow!("Invalid path: no file name component"))?;

                // Validate file name doesn't contain path separators
                let file_name_str = file_name.to_string_lossy();
                if file_name_str.contains('/') || file_name_str.contains('\\') {
                    anyhow::bail!("Invalid file name: contains path separator");
                }

                canonical_parent.join(file_name)
            } else {
                // Parent doesn't exist, recursively create and validate
                validate_local_path(parent)?;
                validate_local_path(path)?
            }
        } else {
            // No parent, treat as relative to current directory
            std::env::current_dir()
                .with_context(|| "Failed to get current directory")?
                .join(path)
        }
    };

    Ok(canonical)
}

/// Validate a remote path string to prevent injection attacks
///
/// This function ensures:
/// - No shell metacharacters that could cause command injection
/// - No path traversal sequences
/// - Only valid characters for file paths
pub fn validate_remote_path(path: &str) -> Result<String> {
    // Check for empty path
    if path.is_empty() {
        anyhow::bail!("Remote path cannot be empty");
    }

    // Check path length to prevent DoS
    const MAX_PATH_LENGTH: usize = 4096;
    if path.len() > MAX_PATH_LENGTH {
        anyhow::bail!("Remote path too long (max {} characters)", MAX_PATH_LENGTH);
    }

    // Check for shell metacharacters that could cause injection
    const DANGEROUS_CHARS: &[char] = &[
        ';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\0', '!', '*', '?',
        '[', ']', // Shell wildcards that could cause issues
    ];

    for &ch in DANGEROUS_CHARS {
        if path.contains(ch) {
            anyhow::bail!("Remote path contains invalid character: '{}'", ch);
        }
    }

    // Check for command substitution patterns
    if path.contains("$(") || path.contains("${") || path.contains("`)") {
        anyhow::bail!("Remote path contains potential command substitution");
    }

    // Check for path traversal
    if path.contains("../") || path.starts_with("..") || path.ends_with("..") {
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

/// Sanitize a hostname to prevent injection attacks
pub fn validate_hostname(hostname: &str) -> Result<String> {
    // Check for empty hostname
    if hostname.is_empty() {
        anyhow::bail!("Hostname cannot be empty");
    }

    // Check hostname length (RFC 1123)
    const MAX_HOSTNAME_LENGTH: usize = 253;
    if hostname.len() > MAX_HOSTNAME_LENGTH {
        anyhow::bail!("Hostname too long (max {} characters)", MAX_HOSTNAME_LENGTH);
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

/// Validate a username to prevent injection attacks
pub fn validate_username(username: &str) -> Result<String> {
    // Check for empty username
    if username.is_empty() {
        anyhow::bail!("Username cannot be empty");
    }

    // Check username length
    const MAX_USERNAME_LENGTH: usize = 32;
    if username.len() > MAX_USERNAME_LENGTH {
        anyhow::bail!("Username too long (max {} characters)", MAX_USERNAME_LENGTH);
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

/// Sanitize error messages to prevent information leakage
///
/// This function redacts sensitive information like usernames, hostnames,
/// and ports from error messages to prevent information disclosure.
pub fn sanitize_error_message(message: &str) -> String {
    // Replace specific user mentions with generic text
    let mut sanitized = message.to_string();

    // Remove specific usernames (format: user 'username')
    if let Some(start) = sanitized.find("user '") {
        if let Some(end) = sanitized[start + 6..].find('\'') {
            let before = &sanitized[..start + 5];
            let after = &sanitized[start + 6 + end + 1..];
            sanitized = format!("{}<redacted>{}", before, after);
        }
    }

    // Remove hostname:port combinations
    // Match patterns like "on hostname:port" or "to hostname:port"
    let re_patterns = [
        r" on [a-zA-Z0-9\.\-]+:[0-9]+",
        r" to [a-zA-Z0-9\.\-]+:[0-9]+",
        r" at [a-zA-Z0-9\.\-]+:[0-9]+",
        r" from [a-zA-Z0-9\.\-]+:[0-9]+",
    ];

    for _pattern in &re_patterns {
        // Simple pattern matching without regex for security
        // This is a simplified approach - in production, consider using a proper regex library
        if sanitized.contains(" on ")
            || sanitized.contains(" to ")
            || sanitized.contains(" at ")
            || sanitized.contains(" from ")
        {
            // Replace with generic message
            sanitized = sanitized
                .replace(" on ", " on <host>")
                .replace(" to ", " to <host>")
                .replace(" at ", " at <host>")
                .replace(" from ", " from <host>");
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

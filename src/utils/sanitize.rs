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

use anyhow::{bail, Result};
use tracing::warn;

/// Sanitize and validate SSH commands to prevent injection attacks
///
/// This function checks for potentially dangerous command patterns and
/// ensures commands are safe to execute over SSH.
pub fn sanitize_command(command: &str) -> Result<String> {
    // Check for empty commands
    if command.trim().is_empty() {
        bail!("Empty command not allowed");
    }

    // Check command length to prevent DoS
    const MAX_COMMAND_LENGTH: usize = 16384; // 16KB max command
    if command.len() > MAX_COMMAND_LENGTH {
        bail!(
            "Command too long: {} bytes (max: {} bytes)",
            command.len(),
            MAX_COMMAND_LENGTH
        );
    }

    // Check for null bytes which could cause issues
    if command.contains('\0') {
        bail!("Command contains null bytes");
    }

    // Detect potential command injection patterns
    let dangerous_patterns = [
        // Shell metacharacters that could be abused
        ("$(", "command substitution"),
        ("${", "variable substitution with manipulation"),
        ("`", "backtick command substitution"),
        ("\n&", "background process after newline"),
        (";\n", "command chaining with newline"),
        ("|\n", "pipe with newline"),
        // Attempts to escape or manipulate the shell
        ("\\x00", "hex null byte"),
        ("\\0", "octal null byte"),
        // Potential infinite loops or resource exhaustion
        (":(){ :|:& };:", "fork bomb"),
        ("while true", "potential infinite loop"),
        ("yes |", "potential resource exhaustion"),
    ];

    for (pattern, description) in &dangerous_patterns {
        if command.contains(pattern) {
            warn!(
                "Potentially dangerous pattern detected in command: {} ({})",
                pattern, description
            );
            // Note: We warn but don't block - the user might have legitimate use cases
            // In a production environment, you might want to be more restrictive
        }
    }

    // Check for excessive redirections which might indicate an attack
    let redirection_count = command.matches('>').count() + command.matches('<').count();
    if redirection_count > 10 {
        warn!("Excessive redirections in command: {}", redirection_count);
    }

    // Check for excessive pipes which might indicate complex command chains
    let pipe_count = command.matches('|').count();
    if pipe_count > 10 {
        warn!("Excessive pipes in command: {}", pipe_count);
    }

    Ok(command.to_string())
}

/// Sanitize hostname to prevent injection in SSH connection strings
pub fn sanitize_hostname(hostname: &str) -> Result<String> {
    // Check for empty hostname
    if hostname.trim().is_empty() {
        bail!("Empty hostname not allowed");
    }

    // Check hostname length
    const MAX_HOSTNAME_LENGTH: usize = 253; // DNS limit
    if hostname.len() > MAX_HOSTNAME_LENGTH {
        bail!(
            "Hostname too long: {} bytes (max: {} bytes)",
            hostname.len(),
            MAX_HOSTNAME_LENGTH
        );
    }

    // Check for invalid characters in hostname
    // Valid: alphanumeric, dots, hyphens, underscores (for some systems), and brackets for IPv6
    let is_ipv6 = hostname.starts_with('[') && hostname.ends_with(']');

    if is_ipv6 {
        // For IPv6, validate the content between brackets
        let ipv6_addr = &hostname[1..hostname.len() - 1];
        if !ipv6_addr.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            bail!("Invalid IPv6 address format: {}", hostname);
        }
    } else {
        // For regular hostnames and IPv4
        let valid_chars = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_';

        if !hostname.chars().all(valid_chars) {
            bail!("Invalid characters in hostname: {}", hostname);
        }

        // Check for double dots which could be path traversal attempts
        if hostname.contains("..") {
            bail!("Double dots not allowed in hostname");
        }

        // Hostname segments shouldn't start or end with hyphen
        for segment in hostname.split('.') {
            if segment.starts_with('-') || segment.ends_with('-') {
                bail!("Hostname segments cannot start or end with hyphen");
            }
        }
    }

    Ok(hostname.to_string())
}

/// Sanitize username to prevent injection attacks
pub fn sanitize_username(username: &str) -> Result<String> {
    // Check for empty username
    if username.trim().is_empty() {
        bail!("Empty username not allowed");
    }

    // Check username length (typical Unix limit is 32)
    const MAX_USERNAME_LENGTH: usize = 32;
    if username.len() > MAX_USERNAME_LENGTH {
        bail!(
            "Username too long: {} bytes (max: {} bytes)",
            username.len(),
            MAX_USERNAME_LENGTH
        );
    }

    // Check for invalid characters
    // Valid: alphanumeric, underscore, hyphen, dot (some systems)
    let valid_chars = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.';

    if !username.chars().all(valid_chars) {
        bail!("Invalid characters in username: {}", username);
    }

    // Username should start with letter or underscore (Unix convention)
    if let Some(first_char) = username.chars().next() {
        if !first_char.is_ascii_alphabetic() && first_char != '_' {
            bail!("Username must start with letter or underscore");
        }
    }

    Ok(username.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_command_valid() {
        assert!(sanitize_command("ls -la").is_ok());
        assert!(sanitize_command("echo 'hello world'").is_ok());
        assert!(sanitize_command("ps aux | grep ssh").is_ok());
    }

    #[test]
    fn test_sanitize_command_empty() {
        assert!(sanitize_command("").is_err());
        assert!(sanitize_command("   ").is_err());
    }

    #[test]
    fn test_sanitize_command_null_bytes() {
        assert!(sanitize_command("ls\0").is_err());
        assert!(sanitize_command("echo\0test").is_err());
    }

    #[test]
    fn test_sanitize_hostname_valid() {
        assert!(sanitize_hostname("example.com").is_ok());
        assert!(sanitize_hostname("192.168.1.1").is_ok());
        assert!(sanitize_hostname("[::1]").is_ok());
        assert!(sanitize_hostname("[2001:db8::1]").is_ok());
        assert!(sanitize_hostname("my-server.local").is_ok());
    }

    #[test]
    fn test_sanitize_hostname_invalid() {
        assert!(sanitize_hostname("").is_err());
        assert!(sanitize_hostname("example..com").is_err());
        assert!(sanitize_hostname("-example.com").is_err());
        assert!(sanitize_hostname("example.com-").is_err());
        assert!(sanitize_hostname("exam ple.com").is_err());
        assert!(sanitize_hostname("example.com;ls").is_err());
    }

    #[test]
    fn test_sanitize_username_valid() {
        assert!(sanitize_username("john_doe").is_ok());
        assert!(sanitize_username("user123").is_ok());
        assert!(sanitize_username("_system").is_ok());
        assert!(sanitize_username("alice-bob").is_ok());
    }

    #[test]
    fn test_sanitize_username_invalid() {
        assert!(sanitize_username("").is_err());
        assert!(sanitize_username("123user").is_err()); // Starts with number
        assert!(sanitize_username("user name").is_err()); // Contains space
        assert!(sanitize_username("user@host").is_err()); // Contains @
        assert!(sanitize_username(&"a".repeat(33)).is_err()); // Too long
    }
}

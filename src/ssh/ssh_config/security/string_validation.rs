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

//! String validation for preventing command injection

use anyhow::Result;

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
pub fn validate_executable_string(
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
    validate_quotes(value, option_name, line_number)?;

    // Additional validation for ControlPath - it should be a path, not a command
    if option_name == "ControlPath" {
        validate_control_path_specific(value, line_number)?;
    }

    // Additional validation for ProxyCommand
    if option_name == "ProxyCommand" {
        validate_proxy_command(value, line_number)?;
    }

    // Additional validation for KnownHostsCommand and LocalCommand
    // These also execute locally and need the same security checks
    if option_name == "KnownHostsCommand" || option_name == "LocalCommand" {
        validate_local_executable_command(value, option_name, line_number)?;
    }

    Ok(())
}

/// Validate quote usage to detect potential injection
fn validate_quotes(value: &str, option_name: &str, line_number: usize) -> Result<()> {
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

    Ok(())
}

/// Additional validation specific to ControlPath
fn validate_control_path_specific(value: &str, line_number: usize) -> Result<()> {
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

    Ok(())
}

/// Additional validation for ProxyCommand
fn validate_proxy_command(value: &str, line_number: usize) -> Result<()> {
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

    Ok(())
}

/// Additional validation for locally executed commands (LocalCommand, KnownHostsCommand)
fn validate_local_executable_command(
    value: &str,
    option_name: &str,
    line_number: usize,
) -> Result<()> {
    // Check for suspicious executable names or patterns
    let trimmed = value.trim();

    // Look for common data exfiltration or download patterns
    let lower_value = value.to_lowercase();
    if lower_value.contains("curl ")
        || lower_value.contains("wget ")
        || lower_value.contains("nc ")
        || lower_value.contains("netcat ")
        || lower_value.contains("socat ")
        || lower_value.contains("telnet ")
    {
        anyhow::bail!(
            "Security violation: {} contains network command at line {}. \
             Commands like curl, wget, nc could be used for data exfiltration or downloading malicious content.",
            option_name,
            line_number
        );
    }

    // Block destructive commands
    if lower_value.contains("rm ")
        || lower_value.contains("dd ")
        || lower_value.contains("mkfs")
        || lower_value.contains("format ")
    {
        anyhow::bail!(
            "Security violation: {} contains potentially destructive command at line {}. \
             Commands like rm, dd, mkfs could cause data loss.",
            option_name,
            line_number
        );
    }

    // Warn about shell invocation but don't block (may be legitimate)
    if trimmed.starts_with("bash ")
        || trimmed.starts_with("sh ")
        || trimmed.starts_with("/bin/bash")
        || trimmed.starts_with("/bin/sh")
        || trimmed.starts_with("python ")
        || trimmed.starts_with("perl ")
        || trimmed.starts_with("ruby ")
    {
        tracing::warn!(
            "{} at line {} invokes a shell or interpreter '{}'. \
             Ensure this is intentional and from a trusted source.",
            option_name,
            line_number,
            trimmed.split_whitespace().next().unwrap_or("")
        );
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
pub fn validate_control_path(path: &str, line_number: usize) -> Result<()> {
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

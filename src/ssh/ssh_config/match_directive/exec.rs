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

//! Exec command execution for Match directive

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use super::MatchContext;

/// Maximum timeout for exec commands
const EXEC_TIMEOUT_SECS: u64 = 5;

/// Execute a command for Match exec condition
pub fn execute_match_command(command: &str, context: &MatchContext) -> Result<bool> {
    // Security validation
    validate_exec_command(command)?;

    // Expand variables in command
    let expanded_command = expand_variables(command, &context.variables);

    tracing::debug!("Executing Match exec command: {}", expanded_command);

    // Parse command into program and args using shell parsing for proper handling
    let parts = shell_words::split(&expanded_command)
        .with_context(|| format!("Failed to parse command: {expanded_command}"))?;

    if parts.is_empty() {
        anyhow::bail!("Empty command for Match exec");
    }

    let program = &parts[0];
    let args = &parts[1..];

    // Execute with proper timeout enforcement
    #[cfg(unix)]
    {
        use std::process::Stdio;
        use std::time::Instant;

        let start = Instant::now();
        let timeout = Duration::from_secs(EXEC_TIMEOUT_SECS);

        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set environment variables
        for (key, value) in &context.variables {
            cmd.env(format!("SSH_MATCH_{}", key.to_uppercase()), value);
        }

        // Spawn the process
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                tracing::debug!("Failed to spawn Match exec command '{}': {}", program, e);
                return Ok(false); // Command execution failure means condition doesn't match
            }
        };

        // Wait with timeout using a loop
        loop {
            // Try to get the exit status without blocking
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process exited
                    let success = status.success();
                    let elapsed = start.elapsed();

                    tracing::debug!(
                        "Match exec command '{}' completed in {:.1}s with status: {} (exit code: {:?})",
                        program,
                        elapsed.as_secs_f64(),
                        success,
                        status.code()
                    );

                    return Ok(success);
                }
                Ok(None) => {
                    // Process still running, check timeout
                    if start.elapsed() > timeout {
                        // Timeout exceeded, kill the process
                        tracing::warn!(
                            "Match exec command '{}' exceeded timeout of {}s, killing process",
                            program,
                            EXEC_TIMEOUT_SECS
                        );

                        // Try to kill the process
                        let _ = child.kill();
                        // Wait a bit for it to die
                        std::thread::sleep(Duration::from_millis(100));
                        // Force wait to clean up zombie
                        let _ = child.wait();

                        return Ok(false);
                    }

                    // Sleep a bit before checking again
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    tracing::error!("Error waiting for Match exec command '{}': {}", program, e);
                    // Try to kill the process just in case
                    let _ = child.kill();
                    return Ok(false);
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        use std::process::Stdio;

        // On non-Unix systems, use a simpler approach
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set environment variables
        for (key, value) in &context.variables {
            cmd.env(format!("SSH_MATCH_{}", key.to_uppercase()), value);
        }

        // Note: Windows doesn't have good timeout support without additional dependencies
        match cmd.status() {
            Ok(status) => {
                let success = status.success();
                tracing::debug!(
                    "Match exec command '{}' returned: {} (exit code: {:?})",
                    program,
                    success,
                    status.code()
                );
                Ok(success)
            }
            Err(e) => {
                tracing::debug!("Match exec command '{}' failed: {}", program, e);
                Ok(false)
            }
        }
    }
}

/// Validate an exec command for security
pub fn validate_exec_command(command: &str) -> Result<()> {
    // Check command length first
    const MAX_COMMAND_LENGTH: usize = 1024;
    if command.len() > MAX_COMMAND_LENGTH {
        anyhow::bail!(
            "Match exec command is too long ({} bytes). Maximum allowed is {} bytes.",
            command.len(),
            MAX_COMMAND_LENGTH
        );
    }

    // Check for newlines and control characters
    if command
        .chars()
        .any(|c| c.is_control() && c != ' ' && c != '\t')
    {
        anyhow::bail!(
            "Match exec command contains control characters. This is blocked for security."
        );
    }

    // Check for dangerous patterns with more comprehensive list
    const DANGEROUS_PATTERNS: &[&str] = &[
        "rm ", "rm\t", "rm-", "rmdir", "dd ", "dd\t", "mkfs", "format", "fdisk", ">", ">>", "<",
        "<<", // File redirection
        "|",  // Pipes
        ";",  // Command chaining
        "&&", "||", // Conditional execution
        "&",  // Background execution
        "`",  // Command substitution
        "$(", // Command substitution
        "${", // Variable expansion that could be dangerous
        "\\n", "\\r", // Escaped newlines
        "../", "..\\", // Directory traversal
        "~/.", "~root", // Hidden file or root access attempts
    ];

    for pattern in DANGEROUS_PATTERNS {
        if command.contains(pattern) {
            anyhow::bail!(
                "Match exec command contains potentially dangerous pattern '{pattern}'. \
                 This is blocked for security reasons."
            );
        }
    }

    // Check for quotes that might hide dangerous patterns
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = '\0';

    for ch in command.chars() {
        match ch {
            '\'' if prev_char != '\\' => in_single_quote = !in_single_quote,
            '"' if prev_char != '\\' => in_double_quote = !in_double_quote,
            '`' if !in_single_quote => {
                anyhow::bail!(
                    "Match exec command contains backtick outside single quotes. \
                     This could allow command substitution."
                );
            }
            '$' if !in_single_quote => {
                // $ is dangerous in double quotes or unquoted
                if let Some(next) = command.chars().nth(command.find('$').unwrap() + 1) {
                    if next == '(' || next == '{' {
                        anyhow::bail!(
                            "Match exec command contains potential command or variable substitution. \
                             This is blocked for security."
                        );
                    }
                }
            }
            _ => {}
        }
        prev_char = ch;
    }

    // Ensure quotes are balanced
    if in_single_quote || in_double_quote {
        anyhow::bail!("Match exec command has unbalanced quotes.");
    }

    // Block potentially dangerous executables
    const BLOCKED_COMMANDS: &[&str] = &[
        "sh", "bash", "zsh", "ksh", "csh", "fish", // Shells
        "python", "python2", "python3", "perl", "ruby", "php", "node", // Interpreters
        "nc", "netcat", "ncat", "socat", // Network tools
        "wget", "curl", "fetch", // Download tools
        "chmod", "chown", "chgrp", // Permission changes
    ];

    // Extract the first word (command name)
    let first_word = command
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_start_matches('/');

    // Check against blocked commands
    for blocked in BLOCKED_COMMANDS {
        if first_word == *blocked || first_word.ends_with(&format!("/{blocked}")) {
            anyhow::bail!(
                "Match exec command uses blocked executable '{blocked}'. \
                 Executing shells or interpreters is not allowed for security."
            );
        }
    }

    // Warn about potentially sensitive commands
    const SENSITIVE_COMMANDS: &[&str] = &["sudo", "su", "doas", "passwd", "ssh", "scp", "sftp"];
    for cmd in SENSITIVE_COMMANDS {
        if first_word == *cmd || first_word.ends_with(&format!("/{cmd}")) {
            tracing::warn!(
                "Match exec command uses potentially sensitive command '{}'. \
                 Please ensure this is intentional and secure.",
                cmd
            );
        }
    }

    // Restrict to allowlisted commands for maximum security (optional, logged as info)
    const SAFE_COMMANDS: &[&str] = &[
        "test", "[", "ls", "cat", "grep", "head", "tail", "echo", "true", "false", "date",
        "hostname",
    ];
    if !SAFE_COMMANDS
        .iter()
        .any(|&safe| first_word == safe || first_word.ends_with(&format!("/{safe}")))
    {
        tracing::info!(
            "Match exec command '{}' is not in the safe command allowlist. \
             Consider using one of: {:?}",
            first_word,
            SAFE_COMMANDS
        );
    }

    Ok(())
}

/// Expand variables in a command string
pub fn expand_variables(command: &str, variables: &HashMap<String, String>) -> String {
    // Early return if no % characters to expand
    if !command.contains('%') {
        return command.to_string();
    }

    let mut result = String::with_capacity(command.len() + 32);
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(&next_ch) = chars.peek() {
                // Look for single character variable
                let key = next_ch.to_string();
                if let Some(value) = variables.get(&key) {
                    result.push_str(value);
                    chars.next(); // Consume the variable character
                } else {
                    result.push(ch); // Keep the % if no matching variable
                }
            } else {
                result.push(ch); // Keep trailing %
            }
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::ssh_config::match_directive::MatchContext;

    #[test]
    fn test_validate_exec_command() {
        // Valid commands
        assert!(validate_exec_command("test -f /tmp/file").is_ok());
        assert!(validate_exec_command("ls -la").is_ok());
        assert!(validate_exec_command("echo hello").is_ok());

        // Dangerous commands
        assert!(validate_exec_command("rm -rf /").is_err());
        assert!(validate_exec_command("ls; rm file").is_err());
        assert!(validate_exec_command("echo `whoami`").is_err());
        assert!(validate_exec_command("cat file | grep pattern").is_err());
        assert!(validate_exec_command("dd if=/dev/zero of=/dev/sda").is_err());
    }

    #[test]
    fn test_expand_variables() {
        let mut variables = HashMap::new();
        variables.insert("h".to_string(), "example.com".to_string());
        variables.insert("u".to_string(), "testuser".to_string());
        variables.insert("l".to_string(), "localuser".to_string());

        let command = "test -f /tmp/%h.lock";
        let expanded = expand_variables(command, &variables);
        assert_eq!(expanded, "test -f /tmp/example.com.lock");

        let command = "echo %u@%h";
        let expanded = expand_variables(command, &variables);
        assert_eq!(expanded, "echo testuser@example.com");
    }

    #[test]
    fn test_validate_exec_security_edge_cases() {
        // Test boundary condition: exactly 1024 characters
        let long_cmd = "a".repeat(1024);
        assert!(validate_exec_command(&long_cmd).is_ok());

        // Test over limit: 1025 characters
        let too_long_cmd = "a".repeat(1025);
        assert!(validate_exec_command(&too_long_cmd).is_err());

        // Test unbalanced quotes
        assert!(validate_exec_command("echo \"hello").is_err());
        assert!(validate_exec_command("echo 'hello").is_err());
        assert!(validate_exec_command("echo \"hello'").is_err());

        // Test dangerous patterns with spaces (validation checks for "rm ")
        assert!(validate_exec_command("rm -rf /").is_err());
        assert!(validate_exec_command("dd if=/dev/zero").is_err());

        // Test semicolon (shell command separator)
        assert!(validate_exec_command("ls;rm file").is_err());
        assert!(validate_exec_command("echo hello ; rm file").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_exec_timeout() {
        use std::time::Instant;

        let context = MatchContext::new("example.com".to_string(), None).unwrap();

        // Test command that sleeps longer than timeout
        let start = Instant::now();
        let result = execute_match_command("sleep 10", &context).unwrap();
        let duration = start.elapsed();

        // Should timeout and return false
        assert!(
            !result,
            "Long-running command should timeout and return false"
        );
        assert!(
            duration.as_secs() <= EXEC_TIMEOUT_SECS + 1,
            "Should timeout within {EXEC_TIMEOUT_SECS} seconds, took {duration:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_exec_nonexistent_command() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();

        // Test command that doesn't exist
        let result = execute_match_command("nonexistent_command_12345", &context).unwrap();

        // Should return false for nonexistent command
        assert!(!result, "Nonexistent command should return false");
    }

    #[test]
    #[cfg(unix)]
    fn test_exec_exit_code_handling() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();

        // Test command that exits with success (0)
        let result = execute_match_command("test -d /tmp", &context).unwrap();
        assert!(result, "Successful command should return true");

        // Test command that exits with failure (non-zero)
        let result = execute_match_command("test -f /nonexistent_file_12345", &context).unwrap();
        assert!(!result, "Failed command should return false");
    }

    #[test]
    #[cfg(windows)]
    fn test_exec_disabled_on_windows() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();

        // exec should be disabled on Windows
        let result = execute_match_command("echo test", &context);

        assert!(
            result.is_err(),
            "exec should be disabled on Windows for security"
        );
    }

    #[test]
    fn test_expand_variables_edge_cases() {
        let mut variables = HashMap::new();
        variables.insert("h".to_string(), "example.com".to_string());

        // Test unknown variable (should be left unchanged)
        let command = "test -f /tmp/%unknown";
        let expanded = expand_variables(command, &variables);
        assert_eq!(expanded, "test -f /tmp/%unknown");

        // Test escaped percent
        let command = "echo 100%%";
        let expanded = expand_variables(command, &variables);
        assert!(expanded.contains("%"));

        // Test variable at start
        let command = "%h.example.com";
        let expanded = expand_variables(command, &variables);
        assert_eq!(expanded, "example.com.example.com");

        // Test variable at end
        let command = "prefix-%h";
        let expanded = expand_variables(command, &variables);
        assert_eq!(expanded, "prefix-example.com");
    }
}

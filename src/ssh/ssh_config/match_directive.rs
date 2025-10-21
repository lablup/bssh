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

//! Match directive support for SSH configuration
//!
//! This module handles the Match directive which provides conditional configuration
//! based on various criteria like hostname, username, and command execution results.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use super::pattern::matches_pattern;

/// Maximum timeout for exec commands
const EXEC_TIMEOUT_SECS: u64 = 5;

/// Match condition types supported by SSH
#[derive(Debug, Clone, PartialEq)]
pub enum MatchCondition {
    /// Match by hostname pattern
    Host(Vec<String>),
    /// Match by remote username
    User(Vec<String>),
    /// Match by local username
    LocalUser(Vec<String>),
    /// Match by command execution result
    Exec(String),
    /// Match all connections (always true)
    All,
}

/// A Match block with its conditions and configuration
#[derive(Debug, Clone)]
pub struct MatchBlock {
    /// Conditions that must all be satisfied (AND logic)
    pub conditions: Vec<MatchCondition>,
    /// Configuration options within this Match block
    pub config: super::types::SshHostConfig,
    /// Line number where this Match block starts (for debugging)
    #[allow(dead_code)]
    pub line_number: usize,
}

impl MatchBlock {
    /// Create a new Match block
    pub fn new(line_number: usize) -> Self {
        Self {
            conditions: Vec::new(),
            config: super::types::SshHostConfig::default(),
            line_number,
        }
    }

    /// Check if all conditions match for the given context
    pub fn matches(&self, context: &MatchContext) -> Result<bool> {
        // All conditions must match (AND logic)
        for condition in &self.conditions {
            if !condition.matches(context)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Context for evaluating Match conditions
#[derive(Debug, Clone)]
pub struct MatchContext {
    /// The hostname being connected to
    pub hostname: String,
    /// The remote username (if specified)
    pub remote_user: Option<String>,
    /// The local username
    pub local_user: String,
    /// Additional context variables for exec commands
    pub variables: HashMap<String, String>,
}

impl MatchContext {
    /// Create a new match context
    pub fn new(hostname: String, remote_user: Option<String>) -> Result<Self> {
        // Get local username
        let local_user = whoami::username();

        let mut variables = HashMap::new();
        variables.insert("h".to_string(), hostname.clone());
        variables.insert("host".to_string(), hostname.clone());
        variables.insert("l".to_string(), local_user.clone());
        variables.insert("localuser".to_string(), local_user.clone());

        if let Some(ref user) = remote_user {
            variables.insert("u".to_string(), user.clone());
            variables.insert("user".to_string(), user.clone());
        }

        Ok(Self {
            hostname,
            remote_user,
            local_user,
            variables,
        })
    }
}

impl MatchCondition {
    /// Parse a Match directive line into conditions
    pub fn parse_match_line(line: &str, line_number: usize) -> Result<Vec<MatchCondition>> {
        let line = line.trim();

        // Remove "Match" keyword (case-insensitive)
        let conditions_str = if line.to_lowercase().starts_with("match ") {
            &line[6..]
        } else if let Some(pos) = line.find('=') {
            // Match=conditions syntax
            if line[..pos].trim().to_lowercase() == "match" {
                line[pos + 1..].trim()
            } else {
                anyhow::bail!("Invalid Match directive at line {}", line_number);
            }
        } else {
            anyhow::bail!("Invalid Match directive at line {}", line_number);
        };

        if conditions_str.is_empty() {
            anyhow::bail!(
                "Match directive requires conditions at line {}",
                line_number
            );
        }

        // Parse conditions
        let mut conditions = Vec::new();
        let mut parts = conditions_str.split_whitespace();

        while let Some(keyword) = parts.next() {
            let keyword_lower = keyword.to_lowercase();

            match keyword_lower.as_str() {
                "host" => {
                    let patterns = collect_patterns(&mut parts)?;
                    if patterns.is_empty() {
                        anyhow::bail!("Match host requires patterns at line {}", line_number);
                    }
                    conditions.push(MatchCondition::Host(patterns));
                }
                "user" => {
                    let patterns = collect_patterns(&mut parts)?;
                    if patterns.is_empty() {
                        anyhow::bail!("Match user requires patterns at line {}", line_number);
                    }
                    conditions.push(MatchCondition::User(patterns));
                }
                "localuser" => {
                    let patterns = collect_patterns(&mut parts)?;
                    if patterns.is_empty() {
                        anyhow::bail!("Match localuser requires patterns at line {}", line_number);
                    }
                    conditions.push(MatchCondition::LocalUser(patterns));
                }
                "exec" => {
                    // Exec condition takes the rest of the line as command
                    let remaining: Vec<&str> = parts.collect();
                    if remaining.is_empty() {
                        anyhow::bail!("Match exec requires a command at line {}", line_number);
                    }

                    // Check if the command is quoted
                    let exec_part = conditions_str
                        [conditions_str.to_lowercase().find("exec").unwrap() + 4..]
                        .trim();
                    let command = if exec_part.starts_with('"') && exec_part.ends_with('"') {
                        // Remove quotes
                        exec_part[1..exec_part.len() - 1].to_string()
                    } else {
                        remaining.join(" ")
                    };

                    conditions.push(MatchCondition::Exec(command));
                    break; // Exec consumes the rest of the line
                }
                "all" => {
                    conditions.push(MatchCondition::All);
                }
                _ => {
                    anyhow::bail!(
                        "Unknown Match condition '{}' at line {}",
                        keyword,
                        line_number
                    );
                }
            }
        }

        if conditions.is_empty() {
            anyhow::bail!(
                "Match directive requires at least one condition at line {}",
                line_number
            );
        }

        Ok(conditions)
    }

    /// Check if this condition matches the given context
    pub fn matches(&self, context: &MatchContext) -> Result<bool> {
        match self {
            MatchCondition::Host(patterns) => {
                // Check if hostname matches any of the patterns
                for pattern in patterns {
                    if matches_pattern(&context.hostname, pattern) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            MatchCondition::User(patterns) => {
                // Check if remote username matches any of the patterns
                if let Some(ref user) = context.remote_user {
                    for pattern in patterns {
                        if matches_pattern(user, pattern) {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            MatchCondition::LocalUser(patterns) => {
                // Check if local username matches any of the patterns
                for pattern in patterns {
                    if matches_pattern(&context.local_user, pattern) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            MatchCondition::Exec(command) => {
                // Execute the command and check exit status
                execute_match_command(command, context)
            }
            MatchCondition::All => {
                // Always matches
                Ok(true)
            }
        }
    }
}

/// Collect patterns until the next keyword
fn collect_patterns(parts: &mut std::str::SplitWhitespace) -> Result<Vec<String>> {
    let mut patterns = Vec::new();

    // Peek at upcoming parts to collect patterns
    let remaining: Vec<&str> = parts.clone().collect();

    for part in remaining {
        // Stop if we hit another Match keyword
        let lower = part.to_lowercase();
        if matches!(
            lower.as_str(),
            "host" | "user" | "localuser" | "exec" | "all"
        ) {
            break;
        }

        patterns.push(part.to_string());
        // Consume the part from the iterator
        parts.next();
    }

    Ok(patterns)
}

/// Execute a command for Match exec condition
fn execute_match_command(command: &str, context: &MatchContext) -> Result<bool> {
    // Security validation
    validate_exec_command(command)?;

    // Expand variables in command
    let expanded_command = expand_variables(command, &context.variables);

    tracing::debug!("Executing Match exec command: {}", expanded_command);

    // Parse command into program and args using shell parsing for proper handling
    let parts = shell_words::split(&expanded_command)
        .with_context(|| format!("Failed to parse command: {}", expanded_command))?;

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
fn validate_exec_command(command: &str) -> Result<()> {
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
                "Match exec command contains potentially dangerous pattern '{}'. \
                 This is blocked for security reasons.",
                pattern
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
        if first_word == *blocked || first_word.ends_with(&format!("/{}", blocked)) {
            anyhow::bail!(
                "Match exec command uses blocked executable '{}'. \
                 Executing shells or interpreters is not allowed for security.",
                blocked
            );
        }
    }

    // Warn about potentially sensitive commands
    const SENSITIVE_COMMANDS: &[&str] = &["sudo", "su", "doas", "passwd", "ssh", "scp", "sftp"];
    for cmd in SENSITIVE_COMMANDS {
        if first_word == *cmd || first_word.ends_with(&format!("/{}", cmd)) {
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
        .any(|&safe| first_word == safe || first_word.ends_with(&format!("/{}", safe)))
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
fn expand_variables(command: &str, variables: &HashMap<String, String>) -> String {
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

    #[test]
    fn test_parse_match_conditions() {
        // Test host condition
        let conditions = MatchCondition::parse_match_line("Match host *.example.com", 1).unwrap();
        assert_eq!(conditions.len(), 1);
        match &conditions[0] {
            MatchCondition::Host(patterns) => assert_eq!(patterns, &["*.example.com"]),
            _ => panic!("Expected Host condition"),
        }

        // Test multiple conditions
        let conditions =
            MatchCondition::parse_match_line("Match host *.example.com user admin", 1).unwrap();
        assert_eq!(conditions.len(), 2);

        // Test all condition
        let conditions = MatchCondition::parse_match_line("Match all", 1).unwrap();
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0], MatchCondition::All);

        // Test exec condition
        let conditions =
            MatchCondition::parse_match_line("Match exec \"test -f /tmp/vpn\"", 1).unwrap();
        assert_eq!(conditions.len(), 1);
        match &conditions[0] {
            MatchCondition::Exec(cmd) => assert_eq!(cmd, "test -f /tmp/vpn"),
            _ => panic!("Expected Exec condition"),
        }
    }

    #[test]
    fn test_match_host_condition() {
        let context =
            MatchContext::new("web1.example.com".to_string(), Some("testuser".to_string()))
                .unwrap();

        let condition = MatchCondition::Host(vec!["*.example.com".to_string()]);
        assert!(condition.matches(&context).unwrap());

        let condition = MatchCondition::Host(vec!["*.test.com".to_string()]);
        assert!(!condition.matches(&context).unwrap());
    }

    #[test]
    fn test_match_user_condition() {
        let context =
            MatchContext::new("example.com".to_string(), Some("admin".to_string())).unwrap();

        let condition = MatchCondition::User(vec!["admin".to_string()]);
        assert!(condition.matches(&context).unwrap());

        let condition = MatchCondition::User(vec!["root".to_string()]);
        assert!(!condition.matches(&context).unwrap());

        // Test with no remote user
        let context_no_user = MatchContext::new("example.com".to_string(), None).unwrap();

        let condition = MatchCondition::User(vec!["admin".to_string()]);
        assert!(!condition.matches(&context_no_user).unwrap());
    }

    #[test]
    fn test_match_localuser_condition() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();

        let local_user = whoami::username();
        let condition = MatchCondition::LocalUser(vec![local_user.clone()]);
        assert!(condition.matches(&context).unwrap());

        let condition = MatchCondition::LocalUser(vec!["nonexistentuser12345".to_string()]);
        assert!(!condition.matches(&context).unwrap());
    }

    #[test]
    fn test_match_all_condition() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();

        let condition = MatchCondition::All;
        assert!(condition.matches(&context).unwrap());
    }

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
    fn test_match_block() {
        let mut block = MatchBlock::new(10);
        block
            .conditions
            .push(MatchCondition::Host(vec!["*.example.com".to_string()]));
        block
            .conditions
            .push(MatchCondition::User(vec!["admin".to_string()]));

        // Test matching context
        let context =
            MatchContext::new("web.example.com".to_string(), Some("admin".to_string())).unwrap();
        assert!(block.matches(&context).unwrap());

        // Test non-matching context (wrong user)
        let context =
            MatchContext::new("web.example.com".to_string(), Some("guest".to_string())).unwrap();
        assert!(!block.matches(&context).unwrap());

        // Test non-matching context (wrong host)
        let context =
            MatchContext::new("web.test.com".to_string(), Some("admin".to_string())).unwrap();
        assert!(!block.matches(&context).unwrap());
    }
}

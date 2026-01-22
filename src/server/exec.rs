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

//! Command execution for SSH exec requests.
//!
//! This module provides the command executor for handling SSH exec requests,
//! allowing clients to execute remote commands on the server.
//!
//! # Features
//!
//! - Command execution via shell with `-c` flag
//! - Environment variable configuration
//! - Stdout/stderr streaming to SSH channel
//! - Command timeout support
//! - Command allow/block list validation
//! - Exit code propagation
//!
//! # Security
//!
//! The executor validates commands against configured blocked patterns
//! and optionally restricts to an allowed list. Environment variables
//! are sanitized before command execution.
//!
//! ## Security Measures
//!
//! - Command injection protection via shell metacharacter detection
//! - Allowlist validation prevents command chaining bypasses
//! - Dangerous environment variables are blocked (LD_PRELOAD, etc.)
//! - Process group management for proper cleanup on timeout
//! - Resource limits should be configured at OS level (systemd, ulimit)
//!
//! # Example
//!
//! ```ignore
//! use bssh::server::exec::{CommandExecutor, ExecConfig};
//!
//! let config = ExecConfig::default();
//! let executor = CommandExecutor::new(config);
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use regex::Regex;
use russh::server::Handle;
use russh::{ChannelId, CryptoVec};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::shared::auth_types::UserInfo;

/// Standard exit code for timeout
const EXIT_CODE_TIMEOUT: i32 = 124;

/// Standard exit code for permission denied / command rejected
const EXIT_CODE_REJECTED: i32 = 126;

/// Dangerous environment variables that should never be set from external sources
const DANGEROUS_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "PERL5LIB",
    "PYTHONPATH",
    "RUBYLIB",
];

/// Configuration for command execution.
///
/// Controls how commands are executed, including security restrictions,
/// environment variables, and timeouts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecConfig {
    /// Default shell for command execution.
    #[serde(default = "default_shell")]
    pub default_shell: PathBuf,

    /// Environment variables to set for all commands.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Command timeout in seconds. 0 means no timeout.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Working directory for command execution.
    /// If not set, uses the user's home directory.
    #[serde(default)]
    pub working_dir: Option<PathBuf>,

    /// Allowed commands (whitelist). If set, only these commands are permitted.
    /// If None, all commands except blocked ones are allowed.
    #[serde(default)]
    pub allowed_commands: Option<Vec<String>>,

    /// Blocked command patterns. Commands containing these patterns are rejected.
    #[serde(default = "default_blocked_commands")]
    pub blocked_commands: Vec<String>,
}

fn default_shell() -> PathBuf {
    PathBuf::from("/bin/sh")
}

fn default_timeout_secs() -> u64 {
    3600 // 1 hour default
}

fn default_blocked_commands() -> Vec<String> {
    vec![
        // Destructive filesystem operations
        "rm".to_string(),
        "mkfs".to_string(),
        "dd".to_string(),
        "shred".to_string(),
        // System modification
        "reboot".to_string(),
        "shutdown".to_string(),
        "halt".to_string(),
        "poweroff".to_string(),
        // Privilege escalation
        "sudo".to_string(),
        "su".to_string(),
        "doas".to_string(),
        // Package management
        "apt".to_string(),
        "apt-get".to_string(),
        "yum".to_string(),
        "dnf".to_string(),
        "pacman".to_string(),
        // Kernel modules
        "insmod".to_string(),
        "rmmod".to_string(),
        "modprobe".to_string(),
    ]
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            default_shell: default_shell(),
            env: HashMap::new(),
            timeout_secs: default_timeout_secs(),
            working_dir: None,
            allowed_commands: None,
            blocked_commands: default_blocked_commands(),
        }
    }
}

impl ExecConfig {
    /// Create a new ExecConfig with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the timeout as a Duration, or None if timeout is disabled (0).
    pub fn timeout(&self) -> Option<Duration> {
        if self.timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.timeout_secs))
        }
    }

    /// Set the default shell.
    pub fn with_shell(mut self, shell: impl Into<PathBuf>) -> Self {
        self.default_shell = shell.into();
        self
    }

    /// Set the timeout in seconds.
    pub fn with_timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Set the working directory.
    pub fn with_working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Add an environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Set the allowed commands list.
    pub fn with_allowed_commands(mut self, commands: Vec<String>) -> Self {
        self.allowed_commands = Some(commands);
        self
    }

    /// Add a blocked command pattern.
    pub fn with_blocked_command(mut self, pattern: impl Into<String>) -> Self {
        self.blocked_commands.push(pattern.into());
        self
    }
}

/// Command executor for SSH exec requests.
///
/// Handles the execution of commands requested by SSH clients,
/// including environment setup, process management, and output streaming.
pub struct CommandExecutor {
    config: ExecConfig,
}

impl CommandExecutor {
    /// Create a new command executor with the given configuration.
    pub fn new(config: ExecConfig) -> Self {
        Self { config }
    }

    /// Execute a command and stream output to the SSH channel.
    ///
    /// # Arguments
    ///
    /// * `command` - The command string to execute
    /// * `user_info` - Information about the authenticated user
    /// * `channel_id` - The SSH channel ID to send output to
    /// * `handle` - The russh session handle for sending data
    ///
    /// # Returns
    ///
    /// Returns the command's exit code, or an error if execution failed.
    ///
    /// # Exit Codes
    ///
    /// - 0: Success
    /// - 1-125: Command exit codes
    /// - 124: Command timed out
    /// - 126: Command validation failed (blocked)
    /// - 127: Command not found
    pub async fn execute(
        &self,
        command: &str,
        user_info: &UserInfo,
        channel_id: ChannelId,
        handle: Handle,
    ) -> Result<i32> {
        // Validate command against blocked/allowed lists
        if let Err(e) = self.validate_command(command) {
            tracing::warn!(
                user = %user_info.username,
                command = %command,
                "Command validation failed: {}",
                e
            );
            // Send error message to stderr
            let error_msg = format!("Command rejected: {e}\n");
            let _ = handle
                .extended_data(channel_id, 1, CryptoVec::from_slice(error_msg.as_bytes()))
                .await;
            return Ok(EXIT_CODE_REJECTED);
        }

        tracing::info!(
            user = %user_info.username,
            command = %command,
            "Executing command"
        );

        // Build the command
        let mut cmd = Command::new(&self.config.default_shell);
        cmd.arg("-c").arg(command);

        // Clear environment and set safe defaults
        cmd.env_clear();
        cmd.env("HOME", &user_info.home_dir);
        cmd.env("USER", &user_info.username);
        cmd.env("LOGNAME", &user_info.username);
        cmd.env("SHELL", &user_info.shell);
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");

        // Add configured environment variables (with safety checks)
        for (key, value) in &self.config.env {
            // Block dangerous environment variables
            if DANGEROUS_ENV_VARS.contains(&key.as_str()) {
                tracing::warn!(
                    user = %user_info.username,
                    env_var = %key,
                    "Blocked dangerous environment variable"
                );
                continue;
            }
            cmd.env(key, value);
        }

        // Set working directory
        let work_dir = self
            .config
            .working_dir
            .clone()
            .unwrap_or_else(|| user_info.home_dir.clone());
        cmd.current_dir(&work_dir);

        // Configure stdio
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        // Enable kill_on_drop to ensure child processes are terminated
        cmd.kill_on_drop(true);

        // On Unix systems, create a new process group for better cleanup
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }

        // Spawn process
        let mut child = cmd.spawn().context("Failed to spawn command")?;

        // Take stdout and stderr for streaming
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        // Create handles for streaming tasks
        let stdout_handle = handle.clone();
        let stderr_handle = handle.clone();

        // Spawn streaming tasks
        let stdout_task = tokio::spawn(async move {
            if let Some(stdout) = stdout {
                Self::stream_output(stdout, channel_id, stdout_handle, false).await
            } else {
                Ok(())
            }
        });

        let stderr_task = tokio::spawn(async move {
            if let Some(stderr) = stderr {
                Self::stream_output(stderr, channel_id, stderr_handle, true).await
            } else {
                Ok(())
            }
        });

        // Wait for completion with optional timeout
        let exit_status = if let Some(timeout) = self.config.timeout() {
            match tokio::time::timeout(timeout, child.wait()).await {
                Ok(status) => status?,
                Err(_) => {
                    tracing::warn!(
                        user = %user_info.username,
                        command = %command,
                        "Command timed out after {} seconds",
                        self.config.timeout_secs
                    );
                    // Kill the entire process group on Unix systems
                    #[cfg(unix)]
                    {
                        if let Some(pid) = child.id() {
                            // Kill the process group (negative PID)
                            // SAFETY: We're sending a signal to a process group we created
                            unsafe {
                                libc::kill(-(pid as i32), libc::SIGKILL);
                            }
                        }
                    }
                    // Fallback: kill the immediate child
                    let _ = child.kill().await;

                    // Send timeout message to stderr
                    let timeout_msg = format!(
                        "Command timed out after {} seconds\n",
                        self.config.timeout_secs
                    );
                    let _ = handle
                        .extended_data(channel_id, 1, CryptoVec::from_slice(timeout_msg.as_bytes()))
                        .await;
                    return Ok(EXIT_CODE_TIMEOUT);
                }
            }
        } else {
            child.wait().await?
        };

        // Wait for output streams to complete
        let _ = tokio::join!(stdout_task, stderr_task);

        let exit_code = exit_status.code().unwrap_or(1);
        tracing::debug!(
            user = %user_info.username,
            command = %command,
            exit_code = %exit_code,
            "Command completed"
        );

        Ok(exit_code)
    }

    /// Stream process output to SSH channel.
    async fn stream_output(
        mut output: impl AsyncReadExt + Unpin,
        channel_id: ChannelId,
        handle: Handle,
        is_stderr: bool,
    ) -> Result<()> {
        let mut buffer = [0u8; 8192];

        loop {
            let n = output.read(&mut buffer).await?;
            if n == 0 {
                break;
            }

            let data = CryptoVec::from_slice(&buffer[..n]);

            let result = if is_stderr {
                // Extended data type 1 = stderr
                handle.extended_data(channel_id, 1, data).await
            } else {
                handle.data(channel_id, data).await
            };

            if result.is_err() {
                tracing::warn!(
                    channel = ?channel_id,
                    is_stderr = %is_stderr,
                    "Failed to send data to channel"
                );
                break;
            }
        }

        Ok(())
    }

    /// Validate command against allowed/blocked lists.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the command is allowed, or an error describing
    /// why it was rejected.
    ///
    /// # Security
    ///
    /// This function implements multiple layers of validation:
    /// 1. Detects shell command chaining and injection attempts
    /// 2. Checks against blocked command patterns (case-insensitive, normalized)
    /// 3. Validates against allowlist (if configured)
    pub fn validate_command(&self, command: &str) -> Result<()> {
        // Normalize command: lowercase and collapse whitespace
        let normalized = command.to_lowercase();
        let normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");

        // Detect command chaining attempts (CRITICAL security check)
        let chaining_patterns = [
            ";",   // Command separator
            "&&",  // AND operator
            "||",  // OR operator
            "|",   // Pipe
            "`",   // Command substitution (backticks)
            "$(",  // Command substitution
            "$((", // Arithmetic expansion
            ">",   // Redirection
            ">>",  // Append redirection
            "<",   // Input redirection
            "<<<", // Here string
            "&",   // Background execution (at end)
            "\n",  // Newline command separator
            "\r",  // Carriage return
        ];

        for pattern in &chaining_patterns {
            if command.contains(pattern) {
                // Allow pipe for legitimate use cases, but log it
                if *pattern == "|" && !command.contains("||") {
                    tracing::info!("Command contains pipe operator: {}", command);
                    continue;
                }
                // Allow redirection for legitimate cases but be cautious
                if (*pattern == ">" || *pattern == ">>") && !command.contains("/dev/") {
                    tracing::info!("Command contains redirection: {}", command);
                    continue;
                }
                anyhow::bail!(
                    "Command contains shell metacharacter that could enable command chaining: '{pattern}'"
                );
            }
        }

        // Check for dangerous patterns using regex
        let dangerous_patterns = [
            (r"(?i)\$\{[^}]*\}", "Variable expansion"),
            (r"(?i)\$[A-Za-z_][A-Za-z0-9_]*", "Variable substitution"),
            (r"(?i)<\([^)]*\)", "Process substitution"),
            (r"(?i)>\([^)]*\)", "Process substitution"),
        ];

        for (pattern, description) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(command) {
                    anyhow::bail!("Command contains dangerous pattern ({})", description);
                }
            }
        }

        // Check blocked commands with normalized, case-insensitive matching
        for blocked in &self.config.blocked_commands {
            let blocked_normalized = blocked.to_lowercase();

            // Check if the command contains the blocked pattern
            if normalized.contains(&blocked_normalized) {
                anyhow::bail!("Command contains blocked pattern: '{blocked}'");
            }

            // Also check if the first word matches (for command names)
            if let Some(first_word) = normalized.split_whitespace().next() {
                if first_word == blocked_normalized {
                    anyhow::bail!("Command '{first_word}' is blocked");
                }
            }
        }

        // Check allowed commands (if whitelist is configured)
        if let Some(ref allowed) = self.config.allowed_commands {
            // First, ensure there are no command chaining attempts in allowlist mode
            // This prevents bypasses like "ls; rm -rf /"
            if command.contains(';')
                || command.contains("&&")
                || command.contains("||")
                || command.contains("$(")
                || command.contains('`')
            {
                anyhow::bail!("Command chaining is not allowed when using command allowlist");
            }

            // Extract the command name (first word before any space)
            let cmd_name = command.split_whitespace().next().unwrap_or("");

            // Check if command is in allowlist
            let is_allowed = allowed.iter().any(|a| {
                // Exact match only - no prefix matching to prevent bypasses
                cmd_name == a
            });

            if !is_allowed {
                anyhow::bail!("Command '{cmd_name}' is not in the allowed list");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_config_default() {
        let config = ExecConfig::default();

        assert_eq!(config.default_shell, PathBuf::from("/bin/sh"));
        assert_eq!(config.timeout_secs, 3600);
        assert!(config.working_dir.is_none());
        assert!(config.allowed_commands.is_none());
        assert!(!config.blocked_commands.is_empty());
    }

    #[test]
    fn test_exec_config_builder() {
        let config = ExecConfig::new()
            .with_shell("/bin/bash")
            .with_timeout_secs(600)
            .with_working_dir("/tmp")
            .with_env("LANG", "en_US.UTF-8")
            .with_allowed_commands(vec!["ls".to_string(), "cat".to_string()])
            .with_blocked_command("dangerous_cmd");

        assert_eq!(config.default_shell, PathBuf::from("/bin/bash"));
        assert_eq!(config.timeout_secs, 600);
        assert_eq!(config.working_dir, Some(PathBuf::from("/tmp")));
        assert_eq!(config.env.get("LANG"), Some(&"en_US.UTF-8".to_string()));
        assert!(config.allowed_commands.is_some());
        assert!(config
            .blocked_commands
            .contains(&"dangerous_cmd".to_string()));
    }

    #[test]
    fn test_exec_config_timeout() {
        let mut config = ExecConfig::default();
        assert_eq!(config.timeout(), Some(Duration::from_secs(3600)));

        config.timeout_secs = 0;
        assert!(config.timeout().is_none());

        config.timeout_secs = 300;
        assert_eq!(config.timeout(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_validate_command_blocked() {
        let config = ExecConfig::default();
        let executor = CommandExecutor::new(config);

        // Test blocked commands
        assert!(executor.validate_command("rm -rf /").is_err());
        assert!(executor.validate_command("rm -fr /home").is_err());
        assert!(executor.validate_command("sudo mkfs /dev/sda").is_err());
        assert!(executor
            .validate_command("dd if=/dev/zero of=/dev/sda")
            .is_err());

        // Test command chaining attempts
        assert!(executor.validate_command("ls; rm -rf /").is_err());
        assert!(executor.validate_command("ls && rm -rf /").is_err());
        assert!(executor.validate_command("ls || rm -rf /").is_err());
        assert!(executor.validate_command("ls `rm -rf /`").is_err());
        assert!(executor.validate_command("ls $(rm -rf /)").is_err());

        // Test allowed commands (no whitelist configured)
        assert!(executor.validate_command("ls -la").is_ok());
        assert!(executor.validate_command("cat /etc/passwd").is_ok());
        assert!(executor.validate_command("echo hello").is_ok());
    }

    #[test]
    fn test_validate_command_whitelist() {
        let config = ExecConfig::new().with_allowed_commands(vec![
            "ls".to_string(),
            "cat".to_string(),
            "echo".to_string(),
        ]);
        let executor = CommandExecutor::new(config);

        // Test allowed commands
        assert!(executor.validate_command("ls -la").is_ok());
        assert!(executor.validate_command("cat /etc/passwd").is_ok());
        assert!(executor.validate_command("echo hello world").is_ok());

        // Test disallowed commands
        assert!(executor.validate_command("rm -rf /").is_err());
        assert!(executor
            .validate_command("wget http://example.com")
            .is_err());
        assert!(executor
            .validate_command("curl http://example.com")
            .is_err());

        // Test that command chaining is blocked even with allowed commands
        assert!(executor.validate_command("ls; rm -rf /").is_err());
        assert!(executor
            .validate_command("cat /etc/passwd && rm -rf /")
            .is_err());
    }

    #[test]
    fn test_validate_command_combined() {
        // Both whitelist and blocklist
        let config = ExecConfig::new()
            .with_allowed_commands(vec!["ls".to_string(), "echo".to_string()])
            .with_blocked_command("dangerous");
        let executor = CommandExecutor::new(config);

        // Allowed and not blocked
        assert!(executor.validate_command("ls -la").is_ok());
        assert!(executor.validate_command("echo hello").is_ok());

        // Not allowed
        assert!(executor.validate_command("cat file.txt").is_err());

        // Command chaining always blocked with allowlist
        assert!(executor.validate_command("ls; echo test").is_err());
    }

    #[test]
    fn test_validate_command_empty() {
        let config = ExecConfig::default();
        let executor = CommandExecutor::new(config);

        // Empty command should be allowed (shell will handle it)
        assert!(executor.validate_command("").is_ok());
    }

    #[test]
    fn test_validate_command_whitespace() {
        let config = ExecConfig::new().with_allowed_commands(vec!["ls".to_string()]);
        let executor = CommandExecutor::new(config);

        // Commands with various whitespace
        assert!(executor.validate_command("ls").is_ok());
        assert!(executor.validate_command("ls   -la").is_ok());
    }

    #[test]
    fn test_default_blocked_commands() {
        let blocked = default_blocked_commands();

        // The new blocklist blocks command names, not full patterns
        assert!(blocked.contains(&"rm".to_string()));
        assert!(blocked.contains(&"mkfs".to_string()));
        assert!(blocked.contains(&"dd".to_string()));
        assert!(blocked.contains(&"sudo".to_string()));
    }

    #[test]
    fn test_command_executor_creation() {
        let config = ExecConfig::default();
        let _executor = CommandExecutor::new(config);
        // Just verify it creates without panic
    }

    #[test]
    fn test_exec_config_serialization() {
        let config = ExecConfig::new()
            .with_shell("/bin/bash")
            .with_timeout_secs(1800)
            .with_env("LANG", "C.UTF-8");

        // Test serialization
        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("/bin/bash"));
        assert!(yaml.contains("1800"));

        // Test deserialization
        let deserialized: ExecConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.default_shell, PathBuf::from("/bin/bash"));
        assert_eq!(deserialized.timeout_secs, 1800);
        assert_eq!(deserialized.env.get("LANG"), Some(&"C.UTF-8".to_string()));
    }

    #[test]
    fn test_command_injection_prevention() {
        let config = ExecConfig::default();
        let executor = CommandExecutor::new(config);

        // Test various command injection techniques
        assert!(executor.validate_command("ls; rm -rf /").is_err());
        assert!(executor.validate_command("ls && rm -rf /").is_err());
        assert!(executor.validate_command("ls || rm -rf /").is_err());
        assert!(executor.validate_command("ls `whoami`").is_err());
        assert!(executor.validate_command("ls $(whoami)").is_err());
        assert!(executor.validate_command("cat file > /dev/sda").is_err());
        assert!(executor.validate_command("cat file >> /dev/sda").is_err());

        // Variable expansion attempts
        assert!(executor.validate_command("echo ${PATH}").is_err());
        assert!(executor.validate_command("echo $HOME").is_err());

        // Process substitution
        assert!(executor.validate_command("cat <(ls)").is_err());
        assert!(executor.validate_command("cat >(cat)").is_err());
    }

    #[test]
    fn test_blocklist_normalization() {
        let config = ExecConfig::default();
        let executor = CommandExecutor::new(config);

        // Case variations should be caught
        assert!(executor.validate_command("RM -rf /").is_err());
        assert!(executor.validate_command("Rm -rf /").is_err());
        assert!(executor.validate_command("rM -rf /").is_err());

        // With extra spaces
        assert!(executor.validate_command("rm  -rf  /").is_err());

        // SUDO variations
        assert!(executor.validate_command("SUDO apt-get install").is_err());
        assert!(executor.validate_command("SuDo apt-get install").is_err());
    }

    #[test]
    fn test_allowlist_exact_match() {
        let config =
            ExecConfig::new().with_allowed_commands(vec!["ls".to_string(), "cat".to_string()]);
        let executor = CommandExecutor::new(config);

        // Exact command names should work
        assert!(executor.validate_command("ls -la").is_ok());
        assert!(executor.validate_command("cat file.txt").is_ok());

        // Similar but not exact should fail
        assert!(executor.validate_command("lsof").is_err());
        assert!(executor.validate_command("catch").is_err());
    }

    #[test]
    fn test_dangerous_env_vars() {
        // This test would need to be an integration test to fully validate
        // For now, we document the expected behavior:
        // LD_PRELOAD, LD_LIBRARY_PATH, BASH_ENV, ENV should be blocked

        let dangerous_vars = DANGEROUS_ENV_VARS;
        assert!(dangerous_vars.contains(&"LD_PRELOAD"));
        assert!(dangerous_vars.contains(&"LD_LIBRARY_PATH"));
        assert!(dangerous_vars.contains(&"BASH_ENV"));
        assert!(dangerous_vars.contains(&"ENV"));
        assert!(dangerous_vars.contains(&"PROMPT_COMMAND"));
    }

    #[test]
    fn test_default_blocked_patterns() {
        let blocked = default_blocked_commands();

        // Critical commands should be blocked
        assert!(blocked.contains(&"rm".to_string()));
        assert!(blocked.contains(&"sudo".to_string()));
        assert!(blocked.contains(&"mkfs".to_string()));
        assert!(blocked.contains(&"dd".to_string()));

        // System modification
        assert!(blocked.contains(&"reboot".to_string()));
        assert!(blocked.contains(&"shutdown".to_string()));

        // Package managers
        assert!(blocked.contains(&"apt".to_string()));
        assert!(blocked.contains(&"yum".to_string()));
    }

    #[test]
    fn test_pipe_handling() {
        let config = ExecConfig::default();
        let executor = CommandExecutor::new(config);

        // Single pipe should be logged but might be allowed
        // This behavior depends on the security requirements
        // For now, we test that double pipe is definitely blocked
        assert!(executor.validate_command("ls || rm -rf /").is_err());
    }
}

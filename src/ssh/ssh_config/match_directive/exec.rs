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
use std::process::{Command, Stdio};
use std::time::Duration;

use super::MatchContext;

/// Maximum timeout for exec commands
const EXEC_TIMEOUT_SECS: u64 = 5;

/// Execute a command for Match exec condition
pub fn execute_match_command(command: &str, context: &MatchContext) -> Result<bool> {
    validate_exec_command(command)?;
    let expanded_command = expand_variables(command, &context.variables);
    tracing::debug!("Executing Match exec command: {}", expanded_command);
    let mut shell = shell_command(&expanded_command);
    shell
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: setpgid only changes the child process group between fork
        // and exec; it touches no Rust-managed memory.
        unsafe {
            shell.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }

    let mut child = match shell.spawn() {
        Ok(child) => child,
        Err(error) => {
            tracing::debug!("Failed to spawn Match exec shell: {error}");
            return Ok(false);
        }
    };
    let started = std::time::Instant::now();
    let timeout = Duration::from_secs(EXEC_TIMEOUT_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                tracing::warn!(
                    "Match exec command exceeded timeout of {}s; terminating process group",
                    EXEC_TIMEOUT_SECS
                );
                kill_match_process(&mut child);
                return Ok(false);
            }
            Err(error) => {
                tracing::debug!("Failed while waiting for Match exec shell: {error}");
                kill_match_process(&mut child);
                return Ok(false);
            }
        }
    }
}

/// Preserve the legacy non-shell Match exec behavior outside config-dump.
///
/// Normal runtime configuration is resolved repeatedly by several getters, so
/// the explicitly authorized OpenSSH shell behavior must not leak out of the
/// host-aware `-G` preprocessing path.
pub(super) fn execute_match_command_direct(command: &str, context: &MatchContext) -> Result<bool> {
    validate_direct_exec_command(command)?;
    let expanded_command = expand_variables(command, &context.variables);
    let parts = shell_words::split(&expanded_command)
        .with_context(|| format!("Failed to parse Match exec command: {expanded_command}"))?;
    let Some((program, args)) = parts.split_first() else {
        anyhow::bail!("Empty Match exec command");
    };

    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in &context.variables {
        command.env(format!("SSH_MATCH_{}", key.to_uppercase()), value);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: setpgid only changes the child process group between fork
        // and exec; it touches no Rust-managed memory.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            tracing::debug!("Failed to spawn Match exec command '{program}': {error}");
            return Ok(false);
        }
    };
    let started = std::time::Instant::now();
    let timeout = Duration::from_secs(EXEC_TIMEOUT_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                tracing::warn!(
                    "Match exec command exceeded timeout of {}s; terminating process group",
                    EXEC_TIMEOUT_SECS
                );
                kill_match_process(&mut child);
                return Ok(false);
            }
            Err(error) => {
                tracing::debug!("Failed while waiting for Match exec command: {error}");
                kill_match_process(&mut child);
                return Ok(false);
            }
        }
    }
}

fn validate_direct_exec_command(command: &str) -> Result<()> {
    const MAX_COMMAND_LENGTH: usize = 1024;
    if command.len() > MAX_COMMAND_LENGTH {
        anyhow::bail!(
            "Match exec command is too long ({} bytes). Maximum allowed is {} bytes.",
            command.len(),
            MAX_COMMAND_LENGTH
        );
    }
    if command
        .chars()
        .any(|character| character.is_control() && character != '\t')
    {
        anyhow::bail!("Match exec command contains a control character");
    }

    const DANGEROUS_PATTERNS: &[&str] = &[
        "rm ", "rm\t", "rm-", "rmdir", "dd ", "dd\t", "mkfs", "format", "fdisk", ">", "<", "|",
        ";", "&&", "||", "&", "`", "$(", "${", "\\n", "\\r", "../", "..\\", "~/.", "~root",
    ];
    if let Some(pattern) = DANGEROUS_PATTERNS
        .iter()
        .find(|pattern| command.contains(**pattern))
    {
        anyhow::bail!("Match exec command contains potentially dangerous pattern '{pattern}'");
    }

    let parts = shell_words::split(command).context("Failed to parse Match exec command")?;
    let first_word = parts.first().map_or("", String::as_str);
    const BLOCKED_COMMANDS: &[&str] = &[
        "sh", "bash", "zsh", "ksh", "csh", "fish", "python", "python2", "python3", "perl", "ruby",
        "php", "node", "nc", "netcat", "ncat", "socat", "wget", "curl", "fetch", "chmod", "chown",
        "chgrp",
    ];
    if let Some(blocked) = BLOCKED_COMMANDS
        .iter()
        .find(|blocked| first_word == **blocked || first_word.ends_with(&format!("/{blocked}")))
    {
        anyhow::bail!("Match exec command uses blocked executable '{blocked}'");
    }
    Ok(())
}

#[cfg(unix)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("/bin/sh");
    shell.arg("-c").arg(command);
    shell
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("cmd.exe");
    shell.arg("/C").arg(command);
    shell
}

#[cfg(not(any(unix, windows)))]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("sh");
    shell.arg("-c").arg(command);
    shell
}

#[cfg(unix)]
fn kill_match_process(child: &mut std::process::Child) {
    let pid = child.id();
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: a negative pid targets the process group created in pre_exec.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
fn kill_match_process(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Validate an exec command for security
pub fn validate_exec_command(command: &str) -> Result<()> {
    const MAX_COMMAND_LENGTH: usize = 8192;
    if command.len() > MAX_COMMAND_LENGTH {
        anyhow::bail!(
            "Match exec command is too long ({} bytes). Maximum allowed is {} bytes.",
            command.len(),
            MAX_COMMAND_LENGTH
        );
    }

    if command
        .chars()
        .any(|character| character.is_control() && character != '\t')
    {
        anyhow::bail!("Match exec command contains a control character");
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
                if next_ch == '%' {
                    result.push('%');
                    chars.next();
                    continue;
                }
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
    fn validation_preserves_shell_grammar_and_bounds_untrusted_size() {
        // Match exec is trusted configuration and OpenSSH evaluates it with a
        // shell. Operators, substitutions, and redirections are grammar rather
        // than input to a command allowlist.
        for command in [
            "test -f /tmp/file",
            "printf x | grep x",
            "false || true",
            "value=$(printf x); test \"$value\" = x",
            "printf x > /tmp/match-exec-output",
        ] {
            assert!(validate_exec_command(command).is_ok(), "{command}");
        }
        assert!(validate_exec_command(&"x".repeat(8192)).is_ok());
        assert!(validate_exec_command(&"x".repeat(8193)).is_err());
        assert!(validate_exec_command("printf x\nprintf y").is_err());
        assert!(validate_exec_command("printf \0").is_err());
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
    #[cfg(unix)]
    fn shell_operators_and_substitutions_follow_openssh_semantics() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();
        assert!(
            execute_match_command(
                "value=$(printf shell); test \"$value\" = shell && true",
                &context,
            )
            .unwrap()
        );
        assert!(execute_match_command("false || true", &context).unwrap());
        assert!(!execute_match_command("true && false", &context).unwrap());
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
    fn timeout_kills_descendant_process_group() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("descendant-survived");
        let context = MatchContext::new("example.com".to_string(), None).unwrap();
        let command = format!("(sleep 6; printf x > '{}') & sleep 10", marker.display());

        assert!(!execute_match_command(&command, &context).unwrap());
        std::thread::sleep(Duration::from_secs(2));
        assert!(
            !marker.exists(),
            "a timed-out Match exec descendant escaped the killed process group"
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
    fn test_exec_uses_platform_shell_on_windows() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();
        assert!(execute_match_command("exit /B 0", &context).unwrap());
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

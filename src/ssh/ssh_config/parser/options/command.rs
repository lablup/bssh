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

//! SSH command execution options parsing
//!
//! Handles command execution and automation options including
//! LocalCommand, RemoteCommand, KnownHostsCommand, and other automation features.

use crate::ssh::ssh_config::parser::helpers::parse_yes_no;
use crate::ssh::ssh_config::security::validate_executable_string;
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::{Context, Result};

/// Parse command execution-related SSH configuration options
pub(super) fn parse_command_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "permitlocalcommand" => {
            if args.is_empty() {
                anyhow::bail!("PermitLocalCommand requires a value at line {line_number}");
            }
            host.permit_local_command = Some(parse_yes_no(&args[0], line_number)?);
        }
        "localcommand" => {
            if args.is_empty() {
                anyhow::bail!("LocalCommand requires a value at line {line_number}");
            }
            let command = args.join(" ");
            // Security: Validate the command to prevent injection attacks
            // LocalCommand supports token substitution: %h, %H, %n, %p, %r, %u
            // These tokens are safe and will be substituted by the client
            validate_command_with_tokens(&command, "LocalCommand", line_number)?;
            host.local_command = Some(command);
        }
        "remotecommand" => {
            if args.is_empty() {
                anyhow::bail!("RemoteCommand requires a value at line {line_number}");
            }
            let command = args.join(" ");

            // Security: Warn about potentially dangerous patterns even though it runs remotely
            // This helps prevent lateral movement attacks
            validate_remote_command_warnings(&command, line_number);

            host.remote_command = Some(command);
        }
        "knownhostscommand" => {
            if args.is_empty() {
                anyhow::bail!("KnownHostsCommand requires a value at line {line_number}");
            }
            let command = args.join(" ");
            // Security: Validate the command as it will be executed locally
            // KnownHostsCommand supports %h and %H token substitution
            validate_command_with_tokens(&command, "KnownHostsCommand", line_number)?;
            host.known_hosts_command = Some(command);
        }
        "forkafterauthentication" => {
            if args.is_empty() {
                anyhow::bail!("ForkAfterAuthentication requires a value at line {line_number}");
            }
            host.fork_after_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "sessiontype" => {
            if args.is_empty() {
                anyhow::bail!("SessionType requires a value at line {line_number}");
            }
            let value = args[0].to_lowercase();
            // Validate allowed values: none, subsystem, default
            match value.as_str() {
                "none" | "subsystem" | "default" => {
                    host.session_type = Some(value);
                }
                _ => {
                    anyhow::bail!(
                        "Invalid SessionType value '{value}' at line {line_number} (expected: none, subsystem, or default)"
                    );
                }
            }
        }
        "stdinnull" => {
            if args.is_empty() {
                anyhow::bail!("StdinNull requires a value at line {line_number}");
            }
            host.stdin_null = Some(parse_yes_no(&args[0], line_number)?);
        }
        _ => unreachable!("Unexpected keyword in parse_command_option: {}", keyword),
    }

    Ok(())
}

/// Validate and warn about potentially dangerous RemoteCommand patterns
///
/// RemoteCommand executes on the remote host, so we don't block commands
/// but we warn about suspicious patterns that could indicate attacks.
fn validate_remote_command_warnings(command: &str, line_number: usize) {
    let lower_command = command.to_lowercase();

    // Warn about potential lateral movement attempts
    if lower_command.contains("ssh ")
        || lower_command.contains("scp ")
        || lower_command.contains("rsync ")
    {
        tracing::warn!(
            "RemoteCommand at line {} contains SSH/SCP/rsync command '{}'. \
             This could be used for lateral movement attacks. \
             Ensure this is intentional and the remote host is trusted.",
            line_number,
            command.split_whitespace().next().unwrap_or("")
        );
    }

    // Warn about download/upload commands
    if lower_command.contains("curl ")
        || lower_command.contains("wget ")
        || lower_command.contains("nc ")
        || lower_command.contains("netcat ")
    {
        tracing::warn!(
            "RemoteCommand at line {} contains network command '{}'. \
             This could download malware or exfiltrate data from the remote host. \
             Ensure this is intentional.",
            line_number,
            command.split_whitespace().next().unwrap_or("")
        );
    }

    // Warn about privilege escalation attempts
    if lower_command.contains("sudo ")
        || lower_command.contains("su ")
        || lower_command.contains("doas ")
        || lower_command.contains("pkexec ")
    {
        tracing::warn!(
            "RemoteCommand at line {} contains privilege escalation command '{}'. \
             Verify that elevated privileges are necessary and properly authorized.",
            line_number,
            command.split_whitespace().next().unwrap_or("")
        );
    }

    // Warn about system modification commands
    if lower_command.contains("chmod ")
        || lower_command.contains("chown ")
        || lower_command.contains("usermod ")
        || lower_command.contains("adduser ")
        || lower_command.contains("useradd ")
    {
        tracing::warn!(
            "RemoteCommand at line {} modifies system configuration with '{}'. \
             Ensure these changes are authorized and necessary.",
            line_number,
            command.split_whitespace().next().unwrap_or("")
        );
    }
}

/// Validate command strings that support token substitution
///
/// This function validates commands while allowing SSH token substitution patterns.
/// Supported tokens:
/// - %h - remote hostname (from config)
/// - %H - remote hostname (as specified on command line)
/// - %n - original hostname
/// - %p - remote port
/// - %r - remote username
/// - %u - local username
/// - %% - literal %
///
/// The actual token substitution is performed by the SSH client, not the parser.
fn validate_command_with_tokens(
    command: &str,
    option_name: &str,
    line_number: usize,
) -> Result<()> {
    // First, check if the command is empty or just whitespace
    if command.trim().is_empty() {
        anyhow::bail!("{option_name} cannot be empty at line {line_number}");
    }

    // Security: Check for excessive token usage that could cause DoS
    // Count the number of tokens (excluding %%)
    let token_count = command.matches("%h").count()
        + command.matches("%H").count()
        + command.matches("%n").count()
        + command.matches("%p").count()
        + command.matches("%r").count()
        + command.matches("%u").count();

    const MAX_TOKENS: usize = 50; // Reasonable limit for token expansion
    if token_count > MAX_TOKENS {
        anyhow::bail!(
            "Security violation: {option_name} contains excessive token usage ({token_count} tokens) at line {line_number}. \
             Maximum allowed is {MAX_TOKENS} tokens to prevent resource exhaustion."
        );
    }

    // Check command length after potential expansion (worst case)
    // Assume each token could expand to 255 chars (max hostname/username length)
    const MAX_EXPANDED_LENGTH: usize = 8192; // 8KB reasonable limit
    let potential_length = command.len() + (token_count * 255);
    if potential_length > MAX_EXPANDED_LENGTH {
        anyhow::bail!(
            "Security violation: {option_name} could expand to {potential_length} bytes at line {line_number}. \
             Maximum allowed expanded length is {MAX_EXPANDED_LENGTH} bytes."
        );
    }

    // Validate tokens before substitution
    // We need to check for invalid tokens (% followed by invalid char)
    let chars: Vec<char> = command.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            if i + 1 < chars.len() {
                let next_char = chars[i + 1];
                match next_char {
                    'h' | 'H' | 'n' | 'p' | 'r' | 'u' | '%' => {
                        // Valid token, skip both characters
                        i += 2;
                    }
                    _ => {
                        anyhow::bail!(
                            "Invalid token '%{next_char}' in {option_name} at line {line_number}. \
                             Valid tokens are: %h, %H, %n, %p, %r, %u, %%"
                        );
                    }
                }
            } else {
                // % at end of string
                anyhow::bail!(
                    "Incomplete token '%' at end of {option_name} at line {line_number}. \
                     Valid tokens are: %h, %H, %n, %p, %r, %u, %%"
                );
            }
        } else {
            i += 1;
        }
    }

    // Create a temporary command with tokens replaced for validation
    // Replace valid tokens with safe placeholder strings
    let mut sanitized = command.to_string();

    // Replace %% with a temporary marker to avoid issues
    sanitized = sanitized.replace("%%", "__DOUBLE_PERCENT__");

    // Replace all valid tokens with safe placeholders
    let tokens = [
        ("%h", "HOSTNAME"),
        ("%H", "HOSTNAME"),
        ("%n", "ORIGINAL"),
        ("%p", "22"),
        ("%r", "USER"),
        ("%u", "LOCALUSER"),
    ];

    for (token, replacement) in tokens.iter() {
        sanitized = sanitized.replace(token, replacement);
    }

    // Restore the %% marker as a single % for accurate validation
    sanitized = sanitized.replace("__DOUBLE_PERCENT__", "%");

    // Now validate the sanitized command for injection attacks
    validate_executable_string(&sanitized, option_name, line_number).with_context(|| {
        format!("Security validation failed for {option_name} at line {line_number}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_command_with_tokens_valid() {
        // Valid commands with tokens
        assert!(validate_command_with_tokens(
            "rsync -av ~/project/ %h:~/project/",
            "LocalCommand",
            1
        )
        .is_ok());

        assert!(validate_command_with_tokens(
            "notify-send \"Connected to %h on port %p\"",
            "LocalCommand",
            1
        )
        .is_ok());

        assert!(validate_command_with_tokens(
            "/usr/local/bin/fetch-host-key %H",
            "KnownHostsCommand",
            1
        )
        .is_ok());

        // Command with escaped percent
        assert!(validate_command_with_tokens(
            "echo \"Progress: 50%% complete\"",
            "LocalCommand",
            1
        )
        .is_ok());
    }

    #[test]
    fn test_validate_command_with_tokens_invalid() {
        // Invalid token
        assert!(validate_command_with_tokens("echo %x", "LocalCommand", 1).is_err());

        // Command with dangerous characters (after token substitution)
        assert!(validate_command_with_tokens("echo test; rm -rf /", "LocalCommand", 1).is_err());

        // Command injection attempt
        assert!(validate_command_with_tokens("echo $(whoami)", "LocalCommand", 1).is_err());

        // Empty command
        assert!(validate_command_with_tokens("", "LocalCommand", 1).is_err());

        // Command with pipe
        assert!(validate_command_with_tokens("ls | grep test", "LocalCommand", 1).is_err());
    }

    #[test]
    fn test_validate_command_token_rate_limiting() {
        // Excessive token usage (DoS prevention)
        let many_tokens = "%h".repeat(100); // 100 tokens
        assert!(validate_command_with_tokens(&many_tokens, "LocalCommand", 1).is_err());

        // Under both token count and expansion size limits
        let ok_tokens = format!("echo {}", "%h ".repeat(20)); // 20 tokens, expands to ~5KB
        assert!(validate_command_with_tokens(&ok_tokens, "LocalCommand", 1).is_ok());

        // Token count OK but would expand to huge size
        let huge_expansion = format!("{} {}", "%h".repeat(30), "x".repeat(1000));
        assert!(validate_command_with_tokens(&huge_expansion, "LocalCommand", 1).is_err());

        // Exactly at token limit (50 tokens) but would exceed size after expansion
        let at_limit = "%p ".repeat(50);
        assert!(validate_command_with_tokens(&at_limit, "LocalCommand", 1).is_err());

        // Just over token limit (51 tokens)
        let over_limit = "%p ".repeat(51);
        assert!(validate_command_with_tokens(&over_limit, "LocalCommand", 1).is_err());
    }

    #[test]
    fn test_parse_permit_local_command() {
        let mut config = SshHostConfig::default();

        // Test yes values
        assert!(
            parse_command_option(&mut config, "permitlocalcommand", &["yes".to_string()], 1)
                .is_ok()
        );
        assert_eq!(config.permit_local_command, Some(true));

        // Test no values
        assert!(
            parse_command_option(&mut config, "permitlocalcommand", &["no".to_string()], 1).is_ok()
        );
        assert_eq!(config.permit_local_command, Some(false));

        // Test invalid value
        assert!(
            parse_command_option(&mut config, "permitlocalcommand", &["maybe".to_string()], 1)
                .is_err()
        );

        // Test missing value
        assert!(parse_command_option(&mut config, "permitlocalcommand", &[], 1).is_err());
    }

    #[test]
    fn test_parse_session_type() {
        let mut config = SshHostConfig::default();

        // Valid values
        for value in ["none", "subsystem", "default"] {
            assert!(
                parse_command_option(&mut config, "sessiontype", &[value.to_string()], 1).is_ok()
            );
            assert_eq!(config.session_type, Some(value.to_string()));
        }

        // Case insensitive
        assert!(parse_command_option(&mut config, "sessiontype", &["NONE".to_string()], 1).is_ok());
        assert_eq!(config.session_type, Some("none".to_string()));

        // Invalid value
        assert!(
            parse_command_option(&mut config, "sessiontype", &["invalid".to_string()], 1).is_err()
        );

        // Missing value
        assert!(parse_command_option(&mut config, "sessiontype", &[], 1).is_err());
    }

    #[test]
    fn test_parse_remote_command() {
        let mut config = SshHostConfig::default();

        // Simple command
        assert!(parse_command_option(
            &mut config,
            "remotecommand",
            &["ls".to_string(), "-la".to_string()],
            1
        )
        .is_ok());
        assert_eq!(config.remote_command, Some("ls -la".to_string()));

        // Complex command (no validation for remote commands)
        assert!(parse_command_option(
            &mut config,
            "remotecommand",
            &[
                "tmux".to_string(),
                "attach".to_string(),
                "-t".to_string(),
                "dev".to_string(),
                "||".to_string(),
                "tmux".to_string(),
                "new".to_string()
            ],
            1
        )
        .is_ok());
        assert_eq!(
            config.remote_command,
            Some("tmux attach -t dev || tmux new".to_string())
        );

        // Missing value
        assert!(parse_command_option(&mut config, "remotecommand", &[], 1).is_err());
    }
}

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
            // LocalCommand accepts the default OpenSSH client token set plus %T.
            // Expanded values are checked again at the runtime shell boundary.
            validate_command_with_tokens(&command, "LocalCommand", line_number)?;
            host.local_command = Some(command);
        }
        "remotecommand" => {
            if args.is_empty() {
                anyhow::bail!("RemoteCommand requires a value at line {line_number}");
            }
            let command = args.join(" ");
            if command.trim().is_empty() {
                anyhow::bail!("RemoteCommand cannot be empty at line {line_number}");
            }

            validate_default_percent_tokens(&command, "RemoteCommand", line_number, 16 * 1024)?;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PercentTokenSet {
    Default,
    LocalCommand,
    KnownHostsCommand,
}

impl PercentTokenSet {
    fn accepts(self, token: char) -> bool {
        let default = matches!(
            token,
            '%' | 'C' | 'd' | 'h' | 'i' | 'j' | 'k' | 'L' | 'l' | 'n' | 'p' | 'r' | 'u'
        );
        default
            || matches!((self, token), (Self::LocalCommand, 'T'))
            || matches!(
                (self, token),
                (Self::KnownHostsCommand, 'f' | 'H' | 'I' | 'K' | 't')
            )
    }

    fn description(self) -> &'static str {
        match self {
            Self::Default => "%%, %C, %d, %h, %i, %j, %k, %L, %l, %n, %p, %r, %u",
            Self::LocalCommand => "%%, %C, %d, %h, %i, %j, %k, %L, %l, %n, %p, %r, %T, %u",
            Self::KnownHostsCommand => {
                "%%, %C, %d, %f, %H, %h, %I, %i, %j, %K, %k, %L, %l, %n, %p, %r, %t, %u"
            }
        }
    }
}

/// Validate the OpenSSH default client percent-token set without applying
/// local-shell restrictions. RemoteCommand and SetEnv both use this set.
pub(super) fn validate_default_percent_tokens(
    value: &str,
    option_name: &str,
    line_number: usize,
    max_bytes: usize,
) -> Result<()> {
    validate_percent_tokens(
        value,
        option_name,
        line_number,
        PercentTokenSet::Default,
        max_bytes,
    )
}

fn validate_percent_tokens(
    value: &str,
    option_name: &str,
    line_number: usize,
    token_set: PercentTokenSet,
    max_bytes: usize,
) -> Result<()> {
    if value.len() > max_bytes {
        anyhow::bail!("{option_name} exceeds the {max_bytes}-byte limit at line {line_number}");
    }

    const MAX_TOKENS: usize = 50;
    let mut token_count = 0;
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            continue;
        }
        let token = chars.next().ok_or_else(|| {
            anyhow::anyhow!(
                "Incomplete token '%' at end of {option_name} at line {line_number}; valid tokens are {}",
                token_set.description()
            )
        })?;
        if !token_set.accepts(token) {
            anyhow::bail!(
                "Invalid token '%{token}' in {option_name} at line {line_number}; valid tokens are {}",
                token_set.description()
            );
        }
        if token != '%' {
            token_count += 1;
            if token_count > MAX_TOKENS {
                anyhow::bail!(
                    "Security violation: {option_name} contains excessive token usage ({token_count} tokens) at line {line_number}. Maximum allowed is {MAX_TOKENS} tokens."
                );
            }
        }
    }
    Ok(())
}

fn sanitize_known_hosts_environment(
    command: &str,
    option_name: &str,
    line_number: usize,
) -> Result<String> {
    let argv = shell_words::split(command).with_context(|| {
        format!("Invalid argument quoting in {option_name} at line {line_number}")
    })?;
    let Some(program) = argv.first() else {
        anyhow::bail!("{option_name} cannot be empty at line {line_number}");
    };
    if program.contains('$') {
        anyhow::bail!(
            "Security violation: {option_name} does not expand environment variables in argv[0] at line {line_number}"
        );
    }

    let mut sanitized = String::with_capacity(command.len());
    let mut chars = command.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '$' {
            sanitized.push(character);
            continue;
        }
        if chars.next() != Some('{') {
            anyhow::bail!(
                "Security violation: {option_name} contains invalid '$' expansion at line {line_number}"
            );
        }
        let mut name = String::new();
        let mut closed = false;
        for character in chars.by_ref() {
            if character == '}' {
                closed = true;
                break;
            }
            name.push(character);
        }
        if !closed || !valid_environment_name(&name) {
            anyhow::bail!(
                "Security violation: {option_name} contains an invalid environment expansion at line {line_number}"
            );
        }
        sanitized.push_str("ENVIRONMENT");
    }
    Ok(sanitized)
}

fn valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

/// Validate a locally executed command after replacing its accepted tokens
/// with inert placeholders. Runtime expansion performs a second validation at
/// the actual local-shell boundary.
fn validate_command_with_tokens(
    command: &str,
    option_name: &str,
    line_number: usize,
) -> Result<()> {
    if command.trim().is_empty() {
        anyhow::bail!("{option_name} cannot be empty at line {line_number}");
    }
    let token_set = if option_name == "LocalCommand" {
        PercentTokenSet::LocalCommand
    } else {
        PercentTokenSet::KnownHostsCommand
    };
    validate_percent_tokens(command, option_name, line_number, token_set, 16 * 1024)?;

    let mut sanitized = if option_name == "KnownHostsCommand" {
        sanitize_known_hosts_environment(command, option_name, line_number)?
    } else {
        command.to_string()
    };
    sanitized = sanitized.replace("%%", "__DOUBLE_PERCENT__");
    let tokens = [
        ("%C", "CONNECTIONHASH"),
        ("%d", "HOME"),
        ("%f", "FINGERPRINT"),
        ("%H", "KNOWNHOST"),
        ("%h", "HOSTNAME"),
        ("%I", "REASON"),
        ("%i", "1000"),
        ("%j", "JUMPHOST"),
        ("%K", "HOSTKEY"),
        ("%k", "HOSTKEYALIAS"),
        ("%L", "LOCALHOSTSHORT"),
        ("%l", "LOCALHOST"),
        ("%n", "ORIGINAL"),
        ("%p", "22"),
        ("%r", "USER"),
        ("%T", "NONE"),
        ("%t", "HOSTKEYTYPE"),
        ("%u", "LOCALUSER"),
    ];
    for (token, replacement) in tokens {
        sanitized = sanitized.replace(token, replacement);
    }
    sanitized = sanitized.replace("__DOUBLE_PERCENT__", "%");

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
        assert!(
            validate_command_with_tokens("rsync -av ~/project/ %h:~/project/", "LocalCommand", 1)
                .is_ok()
        );

        assert!(
            validate_command_with_tokens(
                "notify-send \"Connected to %h on port %p\"",
                "LocalCommand",
                1
            )
            .is_ok()
        );

        assert!(
            validate_command_with_tokens(
                "/usr/local/bin/fetch-host-key %H",
                "KnownHostsCommand",
                1
            )
            .is_ok()
        );

        assert!(
            validate_command_with_tokens(
                "echo %C %d %h %i %j %k %L %l %n %p %r %T %u %%",
                "LocalCommand",
                1,
            )
            .is_ok()
        );

        // Command with escaped percent
        assert!(
            validate_command_with_tokens("echo \"Progress: 50%% complete\"", "LocalCommand", 1)
                .is_ok()
        );
    }

    #[test]
    fn test_validate_command_with_tokens_invalid() {
        // Invalid token, and %H is KnownHostsCommand-only.
        assert!(validate_command_with_tokens("echo %x", "LocalCommand", 1).is_err());
        assert!(validate_command_with_tokens("echo %H", "LocalCommand", 1).is_err());

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

        // Actual post-expansion bounds are enforced with concrete runtime
        // values; the parser bounds the raw command without guessing lengths.
        let under_raw_limit = format!("{} {}", "%h".repeat(30), "x".repeat(1000));
        assert!(validate_command_with_tokens(&under_raw_limit, "LocalCommand", 1).is_ok());
        let over_raw_limit = "x".repeat(16 * 1024 + 1);
        assert!(validate_command_with_tokens(&over_raw_limit, "LocalCommand", 1).is_err());

        // Exactly at the token limit remains valid.
        let at_limit = "%p ".repeat(50);
        assert!(validate_command_with_tokens(&at_limit, "LocalCommand", 1).is_ok());

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
        assert!(
            parse_command_option(
                &mut config,
                "remotecommand",
                &["ls".to_string(), "-la".to_string()],
                1
            )
            .is_ok()
        );
        assert_eq!(config.remote_command, Some("ls -la".to_string()));

        // Complex command (no validation for remote commands)
        assert!(
            parse_command_option(
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
            .is_ok()
        );
        assert_eq!(
            config.remote_command,
            Some("tmux attach -t dev || tmux new".to_string())
        );

        let default_tokens = "echo %% %C %d %h %i %j %k %L %l %n %p %r %u";
        assert!(
            parse_command_option(
                &mut config,
                "remotecommand",
                &[default_tokens.to_string()],
                1,
            )
            .is_ok()
        );
        for invalid in ["echo %H", "echo %T"] {
            assert!(
                parse_command_option(&mut config, "remotecommand", &[invalid.to_string()], 1,)
                    .is_err()
            );
        }

        // Missing value
        assert!(parse_command_option(&mut config, "remotecommand", &[], 1).is_err());
    }
}

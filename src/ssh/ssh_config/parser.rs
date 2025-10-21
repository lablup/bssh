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

//! SSH configuration parsing functionality with Include and Match support
//!
//! This module implements a 2-pass parsing strategy:
//! - Pass 1: Resolve all Include directives and build the complete configuration
//! - Pass 2: Parse Host and Match blocks with their configurations

use super::include::{combine_included_files, resolve_includes};
use super::match_directive::{MatchBlock, MatchCondition};
use super::security::{secure_validate_path, validate_control_path, validate_executable_string};
use super::types::{ConfigBlock, SshHostConfig};
use anyhow::{Context, Result};
use std::path::Path;

/// Parse SSH configuration content with Include and Match support
pub(super) fn parse(content: &str) -> Result<Vec<SshHostConfig>> {
    // For synchronous parsing without file path, we can't resolve includes
    // This maintains backward compatibility for tests and simple usage
    parse_without_includes(content)
}

/// Parse SSH configuration from a file with full Include support
pub(super) async fn parse_from_file(path: &Path, content: &str) -> Result<Vec<SshHostConfig>> {
    // Pass 1: Resolve all Include directives
    let included_files = resolve_includes(path, content)
        .await
        .with_context(|| format!("Failed to resolve includes for {}", path.display()))?;

    // Combine all included files into a single configuration
    let combined_content = combine_included_files(&included_files);

    // Pass 2: Parse the combined configuration
    parse_without_includes(&combined_content)
}

/// Parse SSH configuration content without Include resolution
fn parse_without_includes(content: &str) -> Result<Vec<SshHostConfig>> {
    // Security: Set reasonable limits to prevent DoS attacks
    const MAX_LINE_LENGTH: usize = 8192; // 8KB per line should be more than enough
    const MAX_VALUE_LENGTH: usize = 4096; // 4KB for individual values

    let mut configs = Vec::new();
    let mut current_config: Option<SshHostConfig> = None;
    let mut current_match: Option<MatchBlock> = None;
    let mut line_number = 0;
    let mut in_match_block = false;

    for line in content.lines() {
        line_number += 1;

        // Skip source file comments added by include resolution
        if line.starts_with("# Source:") {
            continue;
        }

        // Security: Check line length to prevent DoS
        if line.len() > MAX_LINE_LENGTH {
            anyhow::bail!(
                "Line {} exceeds maximum length of {} bytes",
                line_number,
                MAX_LINE_LENGTH
            );
        }

        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Get lowercase version of line for keyword detection
        let lower_line = line.to_lowercase();

        // Check for Include directive (should have been resolved in pass 1)
        if lower_line.starts_with("include") {
            // In direct parsing mode, we skip Include directives
            tracing::debug!(
                "Skipping Include directive at line {} (not in file mode)",
                line_number
            );
            continue;
        }

        // Check for Match directive
        if lower_line.starts_with("match ")
            || lower_line.starts_with("match\t")
            || lower_line == "match"
            || lower_line.starts_with("match=")
        {
            // Save previous config if any
            if let Some(config) = current_config.take() {
                configs.push(config);
            }
            if let Some(match_block) = current_match.take() {
                configs.push(match_block.config);
            }

            // Parse Match conditions
            let conditions = MatchCondition::parse_match_line(line, line_number)?;

            // Create new Match block
            let mut match_block = MatchBlock::new(line_number);
            match_block.conditions = conditions.clone();

            // Create config for this Match block
            let config = SshHostConfig {
                block_type: Some(ConfigBlock::Match(conditions)),
                ..Default::default()
            };
            match_block.config = config;

            current_match = Some(match_block);
            current_config = None;
            in_match_block = true;
            continue;
        }

        // Check for Host directive (must be "host" not "hostname" etc.)
        if lower_line.starts_with("host ")
            || lower_line.starts_with("host\t")
            || lower_line == "host"
            || (lower_line.starts_with("host=") && !lower_line.starts_with("hostname="))
        {
            // Save previous config if any
            if let Some(config) = current_config.take() {
                configs.push(config);
            }
            if let Some(match_block) = current_match.take() {
                configs.push(match_block.config);
            }

            // Parse Host patterns
            let patterns = parse_host_line(line, line_number)?;

            // Create new Host config
            let config = SshHostConfig {
                host_patterns: patterns.clone(),
                block_type: Some(ConfigBlock::Host(patterns)),
                ..Default::default()
            };

            current_config = Some(config);
            current_match = None;
            in_match_block = false;
            continue;
        }

        // Parse configuration option
        let (keyword, args) = parse_config_line(line, line_number, MAX_VALUE_LENGTH)?;

        if keyword.is_empty() {
            continue;
        }

        // Apply option to current config block
        if in_match_block {
            if let Some(ref mut match_block) = current_match {
                parse_option(&mut match_block.config, &keyword, &args, line_number)
                    .with_context(|| format!("Error at line {line_number}: {line}"))?;
            }
        } else if let Some(ref mut config) = current_config {
            parse_option(config, &keyword, &args, line_number)
                .with_context(|| format!("Error at line {line_number}: {line}"))?;
        } else {
            // Global option outside any block
            // In OpenSSH, these set defaults but we're ignoring them for now
            tracing::debug!(
                "Ignoring global option '{}' at line {}",
                keyword,
                line_number
            );
        }
    }

    // Don't forget the last config
    if let Some(config) = current_config {
        configs.push(config);
    }
    if let Some(match_block) = current_match {
        configs.push(match_block.config);
    }

    Ok(configs)
}

/// Parse a Host directive line
fn parse_host_line(line: &str, line_number: usize) -> Result<Vec<String>> {
    let line = line.trim();

    // Support both "Host pattern" and "Host=pattern" syntax
    let patterns_str = if let Some(pos) = line.find('=') {
        // Host=pattern syntax
        if line[..pos].trim().to_lowercase() != "host" {
            anyhow::bail!("Invalid Host directive at line {}", line_number);
        }
        line[pos + 1..].trim()
    } else {
        // Host pattern syntax
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() || parts[0].to_lowercase() != "host" {
            anyhow::bail!("Invalid Host directive at line {}", line_number);
        }
        if parts.len() < 2 {
            anyhow::bail!(
                "Host directive requires at least one pattern at line {}",
                line_number
            );
        }
        // Join all parts after "Host"
        line[parts[0].len()..].trim()
    };

    if patterns_str.is_empty() {
        anyhow::bail!(
            "Host directive requires at least one pattern at line {}",
            line_number
        );
    }

    // Split into individual patterns
    let patterns: Vec<String> = patterns_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    Ok(patterns)
}

/// Parse a configuration line into keyword and arguments
fn parse_config_line(
    line: &str,
    line_number: usize,
    max_value_length: usize,
) -> Result<(String, Vec<String>)> {
    let line = line.trim();

    // Determine if using equals syntax
    let eq_pos = line.find('=');
    let uses_equals_syntax = if let Some(pos) = eq_pos {
        // Has equals sign - extract first word to check
        let prefix = &line[..pos];
        let first_word = prefix
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_lowercase();
        // Host and Match never use equals syntax
        !matches!(first_word.as_str(), "host" | "match")
    } else {
        false
    };

    let (keyword, args) = if let Some(pos) = eq_pos.filter(|_| uses_equals_syntax) {
        // Option=Value syntax
        let key_part = line[..pos].trim();
        let value_part = &line[pos + 1..];

        if key_part.is_empty() {
            return Ok((String::new(), vec![]));
        }

        let trimmed_value = value_part.trim();

        // Security: Check value length
        if trimmed_value.len() > max_value_length {
            anyhow::bail!(
                "Value at line {} exceeds maximum length of {} bytes",
                line_number,
                max_value_length
            );
        }

        let args = if trimmed_value.is_empty() {
            vec![]
        } else {
            // Special handling for comma-separated options
            match key_part.to_lowercase().as_str() {
                "ciphers"
                | "macs"
                | "hostkeyalgorithms"
                | "kexalgorithms"
                | "preferredauthentications"
                | "protocol" => trimmed_value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                _ => vec![trimmed_value.to_string()],
            }
        };

        (key_part.to_lowercase(), args)
    } else {
        // Option Value syntax (space-separated)
        let mut parts = line.split_whitespace();
        let keyword = parts.next().unwrap_or("").to_lowercase();
        let args: Vec<String> = parts.map(|s| s.to_string()).collect();
        (keyword, args)
    };

    Ok((keyword, args))
}

/// Parse a configuration option for a host
pub(super) fn parse_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "hostname" => {
            if args.is_empty() {
                anyhow::bail!("HostName requires a value at line {line_number}");
            }
            host.hostname = Some(args[0].clone());
        }
        "user" => {
            if args.is_empty() {
                anyhow::bail!("User requires a value at line {line_number}");
            }
            host.user = Some(args[0].clone());
        }
        "port" => {
            if args.is_empty() {
                anyhow::bail!("Port requires a value at line {line_number}");
            }
            let port: u16 = args[0].parse().with_context(|| {
                format!("Invalid port number '{}' at line {}", args[0], line_number)
            })?;
            host.port = Some(port);
        }
        "identityfile" => {
            if args.is_empty() {
                anyhow::bail!("IdentityFile requires a value at line {line_number}");
            }
            let path = secure_validate_path(&args[0], "identity", line_number)
                .with_context(|| format!("Invalid IdentityFile path at line {line_number}"))?;
            host.identity_files.push(path);
        }
        "identitiesonly" => {
            if args.is_empty() {
                anyhow::bail!("IdentitiesOnly requires a value at line {line_number}");
            }
            // Parse yes/no and store in identity_files behavior (implicit)
            let value = parse_yes_no(&args[0], line_number)?;
            if value {
                // When IdentitiesOnly is yes, clear default identity files
                // This is handled during resolution
            }
        }
        "proxyjump" => {
            if args.is_empty() {
                anyhow::bail!("ProxyJump requires a value at line {line_number}");
            }
            host.proxy_jump = Some(args.join(" "));
        }
        "proxycommand" => {
            if args.is_empty() {
                anyhow::bail!("ProxyCommand requires a value at line {line_number}");
            }
            let command = args.join(" ");
            validate_executable_string(&command, "ProxyCommand", line_number)?;
            host.proxy_command = Some(command);
        }
        "stricthostkeychecking" => {
            if args.is_empty() {
                anyhow::bail!("StrictHostKeyChecking requires a value at line {line_number}");
            }
            host.strict_host_key_checking = Some(args[0].clone());
        }
        "userknownhostsfile" => {
            if args.is_empty() {
                anyhow::bail!("UserKnownHostsFile requires a value at line {line_number}");
            }
            let path =
                secure_validate_path(&args[0], "known_hosts", line_number).with_context(|| {
                    format!("Invalid UserKnownHostsFile path at line {line_number}")
                })?;
            host.user_known_hosts_file = Some(path);
        }
        "globalknownhostsfile" => {
            if args.is_empty() {
                anyhow::bail!("GlobalKnownHostsFile requires a value at line {line_number}");
            }
            let path =
                secure_validate_path(&args[0], "known_hosts", line_number).with_context(|| {
                    format!("Invalid GlobalKnownHostsFile path at line {line_number}")
                })?;
            host.global_known_hosts_file = Some(path);
        }
        "forwardagent" => {
            if args.is_empty() {
                anyhow::bail!("ForwardAgent requires a value at line {line_number}");
            }
            host.forward_agent = Some(parse_yes_no(&args[0], line_number)?);
        }
        "forwardx11" => {
            if args.is_empty() {
                anyhow::bail!("ForwardX11 requires a value at line {line_number}");
            }
            host.forward_x11 = Some(parse_yes_no(&args[0], line_number)?);
        }
        "serveraliveinterval" => {
            if args.is_empty() {
                anyhow::bail!("ServerAliveInterval requires a value at line {line_number}");
            }
            let interval: u32 = args[0].parse().with_context(|| {
                format!(
                    "Invalid ServerAliveInterval value '{}' at line {}",
                    args[0], line_number
                )
            })?;
            host.server_alive_interval = Some(interval);
        }
        "serveralivecountmax" => {
            if args.is_empty() {
                anyhow::bail!("ServerAliveCountMax requires a value at line {line_number}");
            }
            let count: u32 = args[0].parse().with_context(|| {
                format!(
                    "Invalid ServerAliveCountMax value '{}' at line {}",
                    args[0], line_number
                )
            })?;
            host.server_alive_count_max = Some(count);
        }
        "connecttimeout" => {
            if args.is_empty() {
                anyhow::bail!("ConnectTimeout requires a value at line {line_number}");
            }
            let timeout: u32 = args[0].parse().with_context(|| {
                format!(
                    "Invalid ConnectTimeout value '{}' at line {}",
                    args[0], line_number
                )
            })?;
            host.connect_timeout = Some(timeout);
        }
        "connectionattempts" => {
            if args.is_empty() {
                anyhow::bail!("ConnectionAttempts requires a value at line {line_number}");
            }
            let attempts: u32 = args[0].parse().with_context(|| {
                format!(
                    "Invalid ConnectionAttempts value '{}' at line {}",
                    args[0], line_number
                )
            })?;
            host.connection_attempts = Some(attempts);
        }
        "batchmode" => {
            if args.is_empty() {
                anyhow::bail!("BatchMode requires a value at line {line_number}");
            }
            host.batch_mode = Some(parse_yes_no(&args[0], line_number)?);
        }
        "compression" => {
            if args.is_empty() {
                anyhow::bail!("Compression requires a value at line {line_number}");
            }
            host.compression = Some(parse_yes_no(&args[0], line_number)?);
        }
        "tcpkeepalive" => {
            if args.is_empty() {
                anyhow::bail!("TCPKeepAlive requires a value at line {line_number}");
            }
            host.tcp_keep_alive = Some(parse_yes_no(&args[0], line_number)?);
        }
        "preferredauthentications" => {
            if args.is_empty() {
                anyhow::bail!("PreferredAuthentications requires a value at line {line_number}");
            }
            host.preferred_authentications = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "pubkeyauthentication" => {
            if args.is_empty() {
                anyhow::bail!("PubkeyAuthentication requires a value at line {line_number}");
            }
            host.pubkey_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "passwordauthentication" => {
            if args.is_empty() {
                anyhow::bail!("PasswordAuthentication requires a value at line {line_number}");
            }
            host.password_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "kbdinteractiveauthentication" => {
            if args.is_empty() {
                anyhow::bail!(
                    "KbdInteractiveAuthentication requires a value at line {line_number}"
                );
            }
            host.keyboard_interactive_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "gssapiauthentication" => {
            if args.is_empty() {
                anyhow::bail!("GSSAPIAuthentication requires a value at line {line_number}");
            }
            host.gssapi_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "hostkeyalgorithms" => {
            if args.is_empty() {
                anyhow::bail!("HostKeyAlgorithms requires a value at line {line_number}");
            }
            host.host_key_algorithms = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "kexalgorithms" => {
            if args.is_empty() {
                anyhow::bail!("KexAlgorithms requires a value at line {line_number}");
            }
            host.kex_algorithms = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "ciphers" => {
            if args.is_empty() {
                anyhow::bail!("Ciphers requires a value at line {line_number}");
            }
            host.ciphers = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "macs" => {
            if args.is_empty() {
                anyhow::bail!("MACs requires a value at line {line_number}");
            }
            host.macs = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "sendenv" => {
            if args.is_empty() {
                anyhow::bail!("SendEnv requires a value at line {line_number}");
            }
            host.send_env.extend(args.iter().map(|s| s.to_string()));
        }
        "setenv" => {
            if args.is_empty() {
                anyhow::bail!("SetEnv requires at least one name=value pair at line {line_number}");
            }
            // SetEnv can have multiple name=value pairs
            // If we have a single arg (from equals syntax), it might contain multiple pairs
            let pairs: Vec<&str> = if args.len() == 1 && args[0].contains('=') {
                // Single arg from equals syntax - might have multiple name=value pairs
                args[0].split_whitespace().collect()
            } else {
                // Multiple args from space syntax - convert to &str references
                args.iter().map(String::as_str).collect()
            };

            for pair in pairs {
                if let Some(eq_pos) = pair.find('=') {
                    let name = pair[..eq_pos].to_string();
                    let value = pair[eq_pos + 1..].to_string();
                    host.set_env.insert(name, value);
                } else {
                    anyhow::bail!(
                        "Invalid SetEnv format '{pair}' at line {line_number} (expected name=value)"
                    );
                }
            }
        }
        "localforward" => {
            if args.is_empty() {
                anyhow::bail!("LocalForward requires a value at line {line_number}");
            }
            host.local_forward.push(args.join(" "));
        }
        "remoteforward" => {
            if args.is_empty() {
                anyhow::bail!("RemoteForward requires a value at line {line_number}");
            }
            host.remote_forward.push(args.join(" "));
        }
        "dynamicforward" => {
            if args.is_empty() {
                anyhow::bail!("DynamicForward requires a value at line {line_number}");
            }
            host.dynamic_forward.push(args.join(" "));
        }
        "requesttty" => {
            if args.is_empty() {
                anyhow::bail!("RequestTTY requires a value at line {line_number}");
            }
            host.request_tty = Some(args[0].clone());
        }
        "escapechar" => {
            if args.is_empty() {
                anyhow::bail!("EscapeChar requires a value at line {line_number}");
            }
            host.escape_char = Some(args[0].clone());
        }
        "loglevel" => {
            if args.is_empty() {
                anyhow::bail!("LogLevel requires a value at line {line_number}");
            }
            host.log_level = Some(args[0].clone());
        }
        "syslogfacility" => {
            if args.is_empty() {
                anyhow::bail!("SyslogFacility requires a value at line {line_number}");
            }
            host.syslog_facility = Some(args[0].clone());
        }
        "protocol" => {
            if args.is_empty() {
                anyhow::bail!("Protocol requires a value at line {line_number}");
            }
            host.protocol = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "addressfamily" => {
            if args.is_empty() {
                anyhow::bail!("AddressFamily requires a value at line {line_number}");
            }
            host.address_family = Some(args[0].clone());
        }
        "bindaddress" => {
            if args.is_empty() {
                anyhow::bail!("BindAddress requires a value at line {line_number}");
            }
            host.bind_address = Some(args[0].clone());
        }
        "clearallforwardings" => {
            if args.is_empty() {
                anyhow::bail!("ClearAllForwardings requires a value at line {line_number}");
            }
            host.clear_all_forwardings = Some(parse_yes_no(&args[0], line_number)?);
        }
        "controlmaster" => {
            if args.is_empty() {
                anyhow::bail!("ControlMaster requires a value at line {line_number}");
            }
            host.control_master = Some(args[0].clone());
        }
        "controlpath" => {
            if args.is_empty() {
                anyhow::bail!("ControlPath requires a value at line {line_number}");
            }
            let path = args[0].clone();
            // ControlPath has different validation - it allows SSH substitution patterns
            validate_control_path(&path, line_number)?;
            host.control_path = Some(path);
        }
        "controlpersist" => {
            if args.is_empty() {
                anyhow::bail!("ControlPersist requires a value at line {line_number}");
            }
            host.control_persist = Some(args[0].clone());
        }
        _ => {
            // Unknown option - log a warning but continue
            tracing::warn!(
                "Unknown SSH config option '{}' at line {}",
                keyword,
                line_number
            );
        }
    }

    Ok(())
}

/// Parse yes/no boolean values from SSH configuration
pub(super) fn parse_yes_no(value: &str, line_number: usize) -> Result<bool> {
    match value.to_lowercase().as_str() {
        "yes" | "true" | "1" => Ok(true),
        "no" | "false" | "0" => Ok(false),
        _ => {
            anyhow::bail!("Invalid yes/no value '{value}' at line {line_number} (expected yes/no)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yes_no_values() {
        assert!(parse_yes_no("yes", 1).unwrap());
        assert!(parse_yes_no("true", 1).unwrap());
        assert!(parse_yes_no("1", 1).unwrap());
        assert!(!parse_yes_no("no", 1).unwrap());
        assert!(!parse_yes_no("false", 1).unwrap());
        assert!(!parse_yes_no("0", 1).unwrap());
        assert!(parse_yes_no("invalid", 1).is_err());
    }

    #[test]
    fn test_parse_single_host() {
        let content = r#"
Host example.com
    User testuser
    Port 2222
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
        assert_eq!(hosts[0].port, Some(2222));
    }

    #[test]
    fn test_parse_match_block() {
        let content = r#"
Match host *.example.com user admin
    ForwardAgent yes
    Port 2222

Host web.example.com
    User webuser
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 2);

        // First should be the Match block
        match &hosts[0].block_type {
            Some(ConfigBlock::Match(conditions)) => {
                assert_eq!(conditions.len(), 2);
            }
            _ => panic!("Expected Match block"),
        }
        assert_eq!(hosts[0].forward_agent, Some(true));
        assert_eq!(hosts[0].port, Some(2222));

        // Second should be the Host block
        assert_eq!(hosts[1].host_patterns, vec!["web.example.com"]);
        assert_eq!(hosts[1].user, Some("webuser".to_string()));
    }

    #[test]
    fn test_parse_multiple_patterns() {
        let content = r#"
Host web*.example.com *.test.com
    User webuser
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(
            hosts[0].host_patterns,
            vec!["web*.example.com", "*.test.com"]
        );
        assert_eq!(hosts[0].user, Some("webuser".to_string()));
    }

    #[test]
    fn test_parse_comments_and_empty_lines() {
        let content = r#"
# This is a comment
Host example.com
    # Another comment
    User testuser

    Port 2222

# Final comment
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
        assert_eq!(hosts[0].port, Some(2222));
    }

    #[test]
    fn test_parse_equals_syntax() {
        // Test Option=Value syntax
        let content = r#"
Host example.com
    User=testuser
    Port=2222
    HostName=actual.example.com
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
        assert_eq!(hosts[0].port, Some(2222));
        assert_eq!(hosts[0].hostname, Some("actual.example.com".to_string()));
    }

    #[test]
    fn test_parse_mixed_syntax() {
        // Test mixing both syntaxes in same config
        let content = r#"
Host example.com
    User testuser
    Port=2222
    HostName = actual.example.com
    ForwardAgent yes
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
        assert_eq!(hosts[0].port, Some(2222));
        assert_eq!(hosts[0].hostname, Some("actual.example.com".to_string()));
        assert_eq!(hosts[0].forward_agent, Some(true));
    }

    #[test]
    fn test_parse_match_all() {
        let content = r#"
Match all
    ServerAliveInterval 60
    ServerAliveCountMax 3
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);

        match &hosts[0].block_type {
            Some(ConfigBlock::Match(conditions)) => {
                assert_eq!(conditions.len(), 1);
                assert_eq!(conditions[0], MatchCondition::All);
            }
            _ => panic!("Expected Match block"),
        }
        assert_eq!(hosts[0].server_alive_interval, Some(60));
        assert_eq!(hosts[0].server_alive_count_max, Some(3));
    }

    #[test]
    fn test_parse_match_with_exec() {
        let content = r#"
Match exec "test -f /tmp/vpn"
    ProxyJump vpn-gateway
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);

        match &hosts[0].block_type {
            Some(ConfigBlock::Match(conditions)) => {
                assert_eq!(conditions.len(), 1);
                match &conditions[0] {
                    MatchCondition::Exec(cmd) => {
                        assert_eq!(cmd, "test -f /tmp/vpn");
                    }
                    _ => panic!("Expected Exec condition"),
                }
            }
            _ => panic!("Expected Match block"),
        }
        assert_eq!(hosts[0].proxy_jump, Some("vpn-gateway".to_string()));
    }

    #[test]
    fn test_parse_include_directive_skipped() {
        // Include directives should be skipped in direct parse mode
        let content = r#"
Include ~/.ssh/config.d/*

Host example.com
    User testuser
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
    }

    #[test]
    fn test_parse_global_options_ignored() {
        // Global options should be ignored for now
        let content = r#"
User globaluser
Port 22

Host example.com
    User hostuser

Host *.example.org
    Port 2222
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].user, Some("hostuser".to_string()));
        assert_eq!(hosts[0].port, None); // Global port not inherited
        assert_eq!(hosts[1].port, Some(2222));
        assert_eq!(hosts[1].user, None); // Global user not inherited
    }

    #[test]
    fn test_parse_case_insensitive_keywords() {
        // Test that keywords are case-insensitive
        let content = r#"
Host example.com
    USER=testuser
    Port=2222
    hostname=server.com
    FORWARDAGENT=yes
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
        assert_eq!(hosts[0].port, Some(2222));
        assert_eq!(hosts[0].hostname, Some("server.com".to_string()));
        assert_eq!(hosts[0].forward_agent, Some(true));
    }

    // Additional tests for edge cases
    #[test]
    fn test_parse_very_long_line() {
        // Test line length limit enforcement
        let long_line = "User=".to_string() + &"a".repeat(9000);
        let content = format!("Host example.com\n    {}", long_line);
        let result = parse(&content);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum length"));
    }

    #[test]
    fn test_parse_very_long_value() {
        // Test value length limit enforcement
        let long_value = "a".repeat(5000);
        let content = format!("Host example.com\n    User={}", long_value);
        let result = parse(&content);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum length"));
    }

    // Integration tests for Include + Match scenarios
    #[tokio::test]
    async fn test_include_with_match_blocks() {
        use crate::ssh::ssh_config::types::ConfigBlock;
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // Create an included file with Match blocks
        let include_file = temp_dir.path().join("match_rules.conf");
        let include_content = r#"
Match host *.prod.example.com user admin
    ForwardAgent yes
    Port 2222

Match localuser developer
    RequestTTY yes
"#;
        fs::write(&include_file, include_content).unwrap();

        // Create main config that includes the Match rules
        let main_config = temp_dir.path().join("config");
        let main_content = format!(
            r#"
Include {}

Host example.com
    User testuser
    Port 22
"#,
            include_file.display()
        );
        fs::write(&main_config, &main_content).unwrap();

        // Parse the configuration
        let config = crate::ssh::ssh_config::SshConfig::load_from_file(&main_config)
            .await
            .unwrap();

        // Should have 3 blocks: Include directive inserts files at Include location
        // Expected order (per SSH spec): Included files first, then rest of main config
        assert_eq!(config.hosts.len(), 3);

        // First should be Match host + user from included file (inserted at Include location)
        match &config.hosts[0].block_type {
            Some(ConfigBlock::Match(conditions)) => {
                assert_eq!(conditions.len(), 2);
            }
            _ => panic!("Expected Match block at index 0"),
        }
        assert_eq!(config.hosts[0].forward_agent, Some(true));
        assert_eq!(config.hosts[0].port, Some(2222));

        // Second should be Match localuser from included file
        match &config.hosts[1].block_type {
            Some(ConfigBlock::Match(conditions)) => {
                assert_eq!(conditions.len(), 1);
            }
            _ => panic!("Expected Match block at index 1"),
        }
        assert_eq!(config.hosts[1].request_tty, Some("yes".to_string()));

        // Third is the Host block from main config (after Include directive)
        assert_eq!(config.hosts[2].host_patterns, vec!["example.com"]);
        assert_eq!(config.hosts[2].user, Some("testuser".to_string()));
        assert_eq!(config.hosts[2].port, Some(22));
    }

    #[tokio::test]
    async fn test_nested_includes_with_match() {
        use crate::ssh::ssh_config::match_directive::MatchCondition;
        use crate::ssh::ssh_config::types::ConfigBlock;
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // Create a deeply included file with Host config
        let deep_include = temp_dir.path().join("deep.conf");
        fs::write(
            &deep_include,
            r#"
Host deep.example.com
    User deepuser
    Port 3333
"#,
        )
        .unwrap();

        // Create a middle include with Match and Include
        let middle_include = temp_dir.path().join("middle.conf");
        fs::write(
            &middle_include,
            format!(
                r#"
Match host *.dev.example.com
    ForwardAgent no
    Port 2222

Include {}
"#,
                deep_include.display()
            ),
        )
        .unwrap();

        // Create main config
        let main_config = temp_dir.path().join("config");
        fs::write(
            &main_config,
            format!(
                r#"
Host *.example.com
    User defaultuser

Include {}

Match all
    ServerAliveInterval 60
"#,
                middle_include.display()
            ),
        )
        .unwrap();

        // Parse the configuration
        let config = crate::ssh::ssh_config::SshConfig::load_from_file(&main_config)
            .await
            .unwrap();

        // Should have 4 blocks in SSH spec order
        assert_eq!(config.hosts.len(), 4);

        // Verify the order and content
        assert_eq!(config.hosts[0].host_patterns, vec!["*.example.com"]);
        assert_eq!(config.hosts[0].user, Some("defaultuser".to_string()));

        match &config.hosts[1].block_type {
            Some(ConfigBlock::Match(_)) => {
                assert_eq!(config.hosts[1].forward_agent, Some(false));
                assert_eq!(config.hosts[1].port, Some(2222));
            }
            _ => panic!("Expected Match block"),
        }

        assert_eq!(config.hosts[2].host_patterns, vec!["deep.example.com"]);
        assert_eq!(config.hosts[2].user, Some("deepuser".to_string()));

        match &config.hosts[3].block_type {
            Some(ConfigBlock::Match(conditions)) => {
                assert_eq!(conditions.len(), 1);
                assert_eq!(conditions[0], MatchCondition::All);
            }
            _ => panic!("Expected Match all block"),
        }
        assert_eq!(config.hosts[3].server_alive_interval, Some(60));
    }

    #[test]
    fn test_match_resolution_with_host() {
        use crate::ssh::ssh_config::types::ConfigBlock;

        // Test that Match conditions are properly evaluated alongside Host patterns
        let content = r#"
Host *.example.com
    User defaultuser
    Port 22

Match host web*.example.com user admin
    Port 8080
    ForwardAgent yes

Host db.example.com
    User dbuser
    Port 5432
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 3);

        // Verify Host block
        assert_eq!(hosts[0].host_patterns, vec!["*.example.com"]);
        assert_eq!(hosts[0].user, Some("defaultuser".to_string()));

        // Verify Match block
        match &hosts[1].block_type {
            Some(ConfigBlock::Match(conditions)) => {
                assert_eq!(conditions.len(), 2);
            }
            _ => panic!("Expected Match block"),
        }
        assert_eq!(hosts[1].port, Some(8080));
        assert_eq!(hosts[1].forward_agent, Some(true));

        // Verify specific Host block
        assert_eq!(hosts[2].host_patterns, vec!["db.example.com"]);
        assert_eq!(hosts[2].user, Some("dbuser".to_string()));
        assert_eq!(hosts[2].port, Some(5432));
    }
}

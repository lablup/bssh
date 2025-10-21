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

//! SSH configuration parsing functionality
//!
//! This module handles parsing of SSH configuration files, converting the text format
//! into structured configuration objects while performing security validation.

use super::security::{secure_validate_path, validate_control_path, validate_executable_string};
use super::types::SshHostConfig;
use anyhow::{Context, Result};

/// Parse SSH configuration content
pub(super) fn parse(content: &str) -> Result<Vec<SshHostConfig>> {
    let mut hosts = Vec::new();
    let mut current_host: Option<SshHostConfig> = None;
    let mut line_number = 0;

    for line in content.lines() {
        line_number += 1;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split line into keyword and arguments
        // Support both "Option Value" and "Option=Value" syntax
        let (keyword, args) = if let Some(eq_pos) = line.find('=') {
            // Option=Value syntax
            let key_part = line[..eq_pos].trim();
            let value_part = line[eq_pos + 1..].trim();

            // Extract keyword (first word before =)
            let keyword = key_part.split_whitespace().next().unwrap_or("");

            // For values, split by whitespace to maintain consistency with space-separated syntax
            let args: Vec<&str> = if value_part.is_empty() {
                vec![]
            } else {
                value_part.split_whitespace().collect()
            };

            (keyword.to_lowercase(), args)
        } else {
            // Option Value syntax (space-separated)
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let keyword = parts[0].to_lowercase();
            let args = parts[1..].to_vec();

            (keyword, args)
        };

        if keyword.is_empty() {
            continue;
        }

        match keyword.as_str() {
            "host" => {
                // Save previous host config
                if let Some(host) = current_host.take() {
                    hosts.push(host);
                }

                // Start new host config
                if args.is_empty() {
                    anyhow::bail!(
                        "Host directive requires at least one pattern at line {line_number}"
                    );
                }

                let host_config = SshHostConfig {
                    host_patterns: args.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                };
                current_host = Some(host_config);
            }
            _ => {
                // Configuration option
                if let Some(ref mut host) = current_host {
                    parse_option(host, &keyword, &args, line_number)
                        .with_context(|| format!("Error at line {line_number}: {line}"))?;
                } else if keyword != "host" {
                    // Global options outside of any Host block are ignored for now
                    // In a full SSH config parser, these would set global defaults
                    tracing::debug!(
                        "Ignoring global option '{}' at line {}",
                        keyword,
                        line_number
                    );
                }
            }
        }
    }

    // Don't forget the last host
    if let Some(host) = current_host {
        hosts.push(host);
    }

    Ok(hosts)
}

/// Parse a configuration option for a host
pub(super) fn parse_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[&str],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "hostname" => {
            if args.is_empty() {
                anyhow::bail!("HostName requires a value at line {line_number}");
            }
            host.hostname = Some(args[0].to_string());
        }
        "user" => {
            if args.is_empty() {
                anyhow::bail!("User requires a value at line {line_number}");
            }
            host.user = Some(args[0].to_string());
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
            let path = secure_validate_path(args[0], "identity", line_number)
                .with_context(|| format!("Invalid IdentityFile path at line {line_number}"))?;
            host.identity_files.push(path);
        }
        "identitiesonly" => {
            if args.is_empty() {
                anyhow::bail!("IdentitiesOnly requires a value at line {line_number}");
            }
            // Parse yes/no and store in identity_files behavior (implicit)
            let value = parse_yes_no(args[0], line_number)?;
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
            host.strict_host_key_checking = Some(args[0].to_string());
        }
        "userknownhostsfile" => {
            if args.is_empty() {
                anyhow::bail!("UserKnownHostsFile requires a value at line {line_number}");
            }
            let path =
                secure_validate_path(args[0], "known_hosts", line_number).with_context(|| {
                    format!("Invalid UserKnownHostsFile path at line {line_number}")
                })?;
            host.user_known_hosts_file = Some(path);
        }
        "globalknownhostsfile" => {
            if args.is_empty() {
                anyhow::bail!("GlobalKnownHostsFile requires a value at line {line_number}");
            }
            let path =
                secure_validate_path(args[0], "known_hosts", line_number).with_context(|| {
                    format!("Invalid GlobalKnownHostsFile path at line {line_number}")
                })?;
            host.global_known_hosts_file = Some(path);
        }
        "forwardagent" => {
            if args.is_empty() {
                anyhow::bail!("ForwardAgent requires a value at line {line_number}");
            }
            host.forward_agent = Some(parse_yes_no(args[0], line_number)?);
        }
        "forwardx11" => {
            if args.is_empty() {
                anyhow::bail!("ForwardX11 requires a value at line {line_number}");
            }
            host.forward_x11 = Some(parse_yes_no(args[0], line_number)?);
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
            host.batch_mode = Some(parse_yes_no(args[0], line_number)?);
        }
        "compression" => {
            if args.is_empty() {
                anyhow::bail!("Compression requires a value at line {line_number}");
            }
            host.compression = Some(parse_yes_no(args[0], line_number)?);
        }
        "tcpkeepalive" => {
            if args.is_empty() {
                anyhow::bail!("TCPKeepAlive requires a value at line {line_number}");
            }
            host.tcp_keep_alive = Some(parse_yes_no(args[0], line_number)?);
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
            host.pubkey_authentication = Some(parse_yes_no(args[0], line_number)?);
        }
        "passwordauthentication" => {
            if args.is_empty() {
                anyhow::bail!("PasswordAuthentication requires a value at line {line_number}");
            }
            host.password_authentication = Some(parse_yes_no(args[0], line_number)?);
        }
        "kbdinteractiveauthentication" => {
            if args.is_empty() {
                anyhow::bail!(
                    "KbdInteractiveAuthentication requires a value at line {line_number}"
                );
            }
            host.keyboard_interactive_authentication = Some(parse_yes_no(args[0], line_number)?);
        }
        "gssapiauthentication" => {
            if args.is_empty() {
                anyhow::bail!("GSSAPIAuthentication requires a value at line {line_number}");
            }
            host.gssapi_authentication = Some(parse_yes_no(args[0], line_number)?);
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
            if args.len() < 2 {
                anyhow::bail!("SetEnv requires name=value at line {line_number}");
            }
            for arg in args {
                if let Some(eq_pos) = arg.find('=') {
                    let name = arg[..eq_pos].to_string();
                    let value = arg[eq_pos + 1..].to_string();
                    host.set_env.insert(name, value);
                } else {
                    anyhow::bail!(
                        "Invalid SetEnv format '{arg}' at line {line_number} (expected name=value)"
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
            host.request_tty = Some(args[0].to_string());
        }
        "escapechar" => {
            if args.is_empty() {
                anyhow::bail!("EscapeChar requires a value at line {line_number}");
            }
            host.escape_char = Some(args[0].to_string());
        }
        "loglevel" => {
            if args.is_empty() {
                anyhow::bail!("LogLevel requires a value at line {line_number}");
            }
            host.log_level = Some(args[0].to_string());
        }
        "syslogfacility" => {
            if args.is_empty() {
                anyhow::bail!("SyslogFacility requires a value at line {line_number}");
            }
            host.syslog_facility = Some(args[0].to_string());
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
            host.address_family = Some(args[0].to_string());
        }
        "bindaddress" => {
            if args.is_empty() {
                anyhow::bail!("BindAddress requires a value at line {line_number}");
            }
            host.bind_address = Some(args[0].to_string());
        }
        "clearallforwardings" => {
            if args.is_empty() {
                anyhow::bail!("ClearAllForwardings requires a value at line {line_number}");
            }
            host.clear_all_forwardings = Some(parse_yes_no(args[0], line_number)?);
        }
        "controlmaster" => {
            if args.is_empty() {
                anyhow::bail!("ControlMaster requires a value at line {line_number}");
            }
            host.control_master = Some(args[0].to_string());
        }
        "controlpath" => {
            if args.is_empty() {
                anyhow::bail!("ControlPath requires a value at line {line_number}");
            }
            let path = args[0].to_string();
            // ControlPath has different validation - it allows SSH substitution patterns
            validate_control_path(&path, line_number)?;
            host.control_path = Some(path);
        }
        "controlpersist" => {
            if args.is_empty() {
                anyhow::bail!("ControlPersist requires a value at line {line_number}");
            }
            host.control_persist = Some(args[0].to_string());
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
    fn test_parse_equals_with_spaces() {
        // Test Option = Value syntax (spaces around equals)
        let content = r#"
Host example.com
    User = testuser
    Port = 2222
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
        assert_eq!(hosts[0].port, Some(2222));
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
    fn test_parse_equals_with_boolean() {
        // Test yes/no values with equals syntax
        let content = r#"
Host example.com
    ForwardAgent=yes
    ForwardX11=no
    Compression = yes
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].forward_agent, Some(true));
        assert_eq!(hosts[0].forward_x11, Some(false));
        assert_eq!(hosts[0].compression, Some(true));
    }

    #[test]
    fn test_parse_equals_with_comma_separated() {
        // Test comma-separated values with equals syntax
        let content = r#"
Host example.com
    Ciphers=aes128-ctr,aes192-ctr,aes256-ctr
    MACs = hmac-sha2-256,hmac-sha2-512
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(
            hosts[0].ciphers,
            vec!["aes128-ctr", "aes192-ctr", "aes256-ctr"]
        );
        assert_eq!(hosts[0].macs, vec!["hmac-sha2-256", "hmac-sha2-512"]);
    }
}

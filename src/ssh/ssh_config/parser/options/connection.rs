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

//! SSH connection options parsing
//!
//! Handles connection-related configuration options including keepalive
//! settings, timeouts, compression, and network settings.

use crate::ssh::ssh_config::parser::helpers::parse_yes_no;
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::{Context, Result};

/// Parse connection-related SSH configuration options
pub(super) fn parse_connection_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
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
        "bindinterface" => {
            if args.is_empty() {
                anyhow::bail!("BindInterface requires a value at line {line_number}");
            }
            // Security: Validate network interface name to prevent injection attacks
            let interface = &args[0];
            if interface.is_empty() {
                anyhow::bail!("BindInterface cannot be empty at line {line_number}");
            }
            // Network interface names on Linux/macOS are typically:
            // - eth0, eth1, etc. (Linux)
            // - en0, en1, etc. (macOS)
            // - lo, lo0 (loopback)
            // - wlan0, wlp3s0, etc. (wireless)
            // - docker0, br0, tun0, tap0, etc. (virtual interfaces)
            // - bond0, team0, etc. (bonded interfaces)
            // - vlan interfaces like eth0.100
            // Maximum length is typically 15 characters on Linux (IFNAMSIZ - 1)
            if interface.len() > 15 {
                anyhow::bail!(
                    "BindInterface '{}' at line {} exceeds maximum interface name length of 15 characters",
                    interface,
                    line_number
                );
            }

            // Only allow alphanumeric, dots, hyphens, underscores, and colons (for aliases like eth0:1)
            if !interface
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':')
            {
                anyhow::bail!(
                    "BindInterface '{}' at line {} contains invalid characters. \
                     Network interface names can only contain alphanumeric characters, dots, hyphens, underscores, and colons",
                    interface,
                    line_number
                );
            }

            // Additional validation: interface name shouldn't start with a dot or hyphen
            if interface.starts_with('.') || interface.starts_with('-') {
                anyhow::bail!(
                    "BindInterface '{}' at line {} cannot start with a dot or hyphen",
                    interface,
                    line_number
                );
            }

            // Prevent potential path traversal or command injection
            if interface.contains("..") || interface.contains("/") || interface.contains("\\") {
                anyhow::bail!(
                    "BindInterface '{}' at line {} contains dangerous characters that could be used for injection attacks",
                    interface,
                    line_number
                );
            }

            host.bind_interface = Some(interface.clone());
        }
        "ipqos" => {
            if args.is_empty() {
                anyhow::bail!("IPQoS requires a value at line {line_number}");
            }
            // IPQoS can have one or two values (interactive and bulk)
            // Valid values are: af11-af43, cs0-cs7, ef, lowdelay, throughput, reliability, or numeric (0-63)
            if args.len() > 2 {
                anyhow::bail!(
                    "IPQoS at line {} accepts at most 2 values (interactive and bulk), got {}",
                    line_number,
                    args.len()
                );
            }

            // Validate each QoS value
            let valid_qos_values = [
                "af11",
                "af12",
                "af13",
                "af21",
                "af22",
                "af23",
                "af31",
                "af32",
                "af33",
                "af41",
                "af42",
                "af43",
                "cs0",
                "cs1",
                "cs2",
                "cs3",
                "cs4",
                "cs5",
                "cs6",
                "cs7",
                "ef",
                "lowdelay",
                "throughput",
                "reliability",
                "none",
            ];

            for value in args {
                // Check if it's a known QoS value
                let lower_value = value.to_lowercase();
                if !valid_qos_values.contains(&lower_value.as_str()) {
                    // Check if it's a numeric value (0-63 for DSCP or 0-255 for ToS)
                    if let Ok(num) = value.parse::<u8>() {
                        if num > 63 && num != 0xff {
                            tracing::warn!(
                                "IPQoS value '{}' at line {} is outside typical DSCP range (0-63)",
                                value,
                                line_number
                            );
                        }
                    } else {
                        anyhow::bail!(
                            "IPQoS value '{}' at line {} is not a valid QoS identifier. \
                             Valid values are: af11-af43, cs0-cs7, ef, lowdelay, throughput, reliability, none, or numeric (0-63)",
                            value,
                            line_number
                        );
                    }
                }
            }

            // Limit total length to prevent memory exhaustion
            let combined = args.join(" ");
            if combined.len() > 100 {
                anyhow::bail!(
                    "IPQoS value at line {} is too long (max 100 characters)",
                    line_number
                );
            }

            host.ipqos = Some(combined);
        }
        "rekeylimit" => {
            if args.is_empty() {
                anyhow::bail!("RekeyLimit requires a value at line {line_number}");
            }
            // RekeyLimit can have one or two values (data limit and time limit)
            // Format: <data> [<time>]
            // Data: default, none, or number with optional suffix (K/M/G)
            // Time: none or number with optional suffix (s/m/h)

            if args.len() > 2 {
                anyhow::bail!(
                    "RekeyLimit at line {} accepts at most 2 values (data and time), got {}",
                    line_number,
                    args.len()
                );
            }

            // Validate data limit (first argument)
            let data_limit = &args[0];
            if data_limit != "default" && data_limit != "none" {
                // Parse size with optional suffix
                let valid_size = if let Some(stripped) = data_limit.strip_suffix(&['K', 'k'][..]) {
                    stripped.parse::<u64>().is_ok()
                } else if let Some(stripped) = data_limit.strip_suffix(&['M', 'm'][..]) {
                    stripped.parse::<u64>().is_ok()
                } else if let Some(stripped) = data_limit.strip_suffix(&['G', 'g'][..]) {
                    stripped.parse::<u64>().is_ok()
                } else {
                    // Plain number (bytes)
                    data_limit.parse::<u64>().is_ok()
                };

                if !valid_size {
                    anyhow::bail!(
                        "RekeyLimit data limit '{}' at line {} is invalid. \
                         Use 'default', 'none', or a number with optional suffix (K/M/G)",
                        data_limit,
                        line_number
                    );
                }

                // Prevent absurdly large values that could cause issues
                if data_limit.len() > 20 {
                    anyhow::bail!(
                        "RekeyLimit data limit at line {} is too long (max 20 characters)",
                        line_number
                    );
                }
            }

            // Validate time limit (second argument, if present)
            if args.len() > 1 {
                let time_limit = &args[1];
                if time_limit != "none" {
                    // Parse time with optional suffix
                    let valid_time =
                        if let Some(stripped) = time_limit.strip_suffix(&['s', 'S'][..]) {
                            stripped.parse::<u64>().is_ok()
                        } else if let Some(stripped) = time_limit.strip_suffix(&['m', 'M'][..]) {
                            stripped.parse::<u64>().is_ok()
                        } else if let Some(stripped) = time_limit.strip_suffix(&['h', 'H'][..]) {
                            stripped.parse::<u64>().is_ok()
                        } else {
                            // Plain number (seconds)
                            time_limit.parse::<u64>().is_ok()
                        };

                    if !valid_time {
                        anyhow::bail!(
                            "RekeyLimit time limit '{}' at line {} is invalid. \
                             Use 'none' or a number with optional suffix (s/m/h)",
                            time_limit,
                            line_number
                        );
                    }

                    // Prevent absurdly large values
                    if time_limit.len() > 20 {
                        anyhow::bail!(
                            "RekeyLimit time limit at line {} is too long (max 20 characters)",
                            line_number
                        );
                    }
                }
            }

            // Limit total length to prevent memory exhaustion
            let combined = args.join(" ");
            if combined.len() > 50 {
                anyhow::bail!(
                    "RekeyLimit value at line {} is too long (max 50 characters total)",
                    line_number
                );
            }

            host.rekey_limit = Some(combined);
        }
        _ => unreachable!("Unexpected keyword in parse_connection_option: {}", keyword),
    }

    Ok(())
}

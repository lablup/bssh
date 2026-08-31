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
use crate::ssh::ssh_config::{IpQosPolicy, RekeyLimit};
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
            if attempts == 0 {
                anyhow::bail!("ConnectionAttempts must be at least 1 at line {line_number}");
            }
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
            let interface = &args[0];
            if interface.is_empty() {
                anyhow::bail!("BindInterface cannot be empty at line {line_number}");
            }
            host.bind_interface = Some(interface.clone());
        }
        "ipqos" => {
            if args.is_empty() {
                anyhow::bail!("IPQoS requires a value at line {line_number}");
            }
            if args.iter().any(|value| value.len() > 20) {
                anyhow::bail!("IPQoS value at line {line_number} is too long");
            }
            host.ipqos = Some(IpQosPolicy::parse(args).map_err(|error| {
                anyhow::anyhow!("Invalid IPQoS value at line {line_number}: {error}")
            })?);
        }
        "rekeylimit" => {
            if args.is_empty() {
                anyhow::bail!("RekeyLimit requires a value at line {line_number}");
            }
            if args.iter().any(|value| value.len() > 20) || args.join(" ").len() > 50 {
                anyhow::bail!(
                    "RekeyLimit value at line {line_number} is too long (max 50 characters total)"
                );
            }
            let policy = RekeyLimit::parse(args)
                .with_context(|| format!("Invalid RekeyLimit value at line {line_number}"))?;
            if policy.data_is_capped() {
                tracing::warn!(
                    "RekeyLimit data policy at line {line_number} exceeds russh's 1 GiB \
                     nonce-safety ceiling and will be capped"
                );
            }
            host.rekey_limit = Some(policy);
        }
        _ => unreachable!("Unexpected keyword in parse_connection_option: {}", keyword),
    }

    Ok(())
}

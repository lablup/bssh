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

//! Host and port parsing utilities

use anyhow::{Context, Result};

use super::host::JumpHost;

/// Parse a single jump host specification
///
/// Handles the format: `[user@]hostname[:port]`
/// * IPv6 addresses are supported: `[::1]:2222` or `user@[::1]:2222`
/// * Port parsing is disambiguated from IPv6 colons
pub fn parse_single_jump_host(host_spec: &str) -> Result<JumpHost> {
    // Handle empty specification
    if host_spec.is_empty() {
        anyhow::bail!("Empty jump host specification");
    }

    // Split on '@' to separate user from host:port
    let parts: Vec<&str> = host_spec.splitn(2, '@').collect();
    let (user, host_port) = if parts.len() == 2 {
        (Some(parts[0].to_string()), parts[1])
    } else {
        (None, parts[0])
    };

    // Validate and sanitize username if provided
    let user = if let Some(username) = user {
        Some(crate::utils::sanitize_username(&username).with_context(|| {
            format!("Invalid username in jump host specification: '{host_spec}'")
        })?)
    } else {
        None
    };

    // Parse host:port
    let (host, port) = parse_host_port(host_port)
        .with_context(|| format!("Invalid host:port specification: '{host_port}'"))?;

    // Sanitize hostname to prevent injection
    let host = crate::utils::sanitize_hostname(&host)
        .with_context(|| format!("Invalid hostname in jump host specification: '{host}'"))?;

    Ok(JumpHost::new(host, user, port))
}

/// Parse host:port specification with IPv6 support
///
/// Handles various formats:
/// * `hostname` -> (hostname, None)
/// * `hostname:port` -> (hostname, Some(port))
/// * `[::1]` -> (::1, None)
/// * `[::1]:port` -> (::1, Some(port))
pub fn parse_host_port(host_port: &str) -> Result<(String, Option<u16>)> {
    if host_port.is_empty() {
        anyhow::bail!("Empty host specification");
    }

    // Handle IPv6 addresses in brackets
    if host_port.starts_with('[') {
        // Find the closing bracket
        if let Some(bracket_end) = host_port.find(']') {
            let ipv6_addr = &host_port[1..bracket_end];
            if ipv6_addr.is_empty() {
                anyhow::bail!("Empty IPv6 address in brackets");
            }

            let remaining = &host_port[bracket_end + 1..];
            if remaining.is_empty() {
                // Just [ipv6]
                return Ok((ipv6_addr.to_string(), None));
            } else if let Some(port_str) = remaining.strip_prefix(':') {
                // [ipv6]:port
                if port_str.is_empty() {
                    anyhow::bail!("Empty port specification after IPv6 address");
                }
                let port = port_str
                    .parse::<u16>()
                    .with_context(|| format!("Invalid port number: '{port_str}'"))?;
                if port == 0 {
                    anyhow::bail!("Port number cannot be zero");
                }
                return Ok((ipv6_addr.to_string(), Some(port)));
            } else {
                anyhow::bail!("Invalid characters after IPv6 address: '{remaining}'");
            }
        } else {
            anyhow::bail!("Unclosed bracket in IPv6 address");
        }
    }

    // Handle regular hostname[:port] format
    // Find the last colon to handle IPv6 addresses without brackets
    if let Some(colon_pos) = host_port.rfind(':') {
        let host_part = &host_port[..colon_pos];
        let port_part = &host_port[colon_pos + 1..];

        if host_part.is_empty() {
            anyhow::bail!("Empty hostname");
        }

        if port_part.is_empty() {
            anyhow::bail!("Empty port specification");
        }

        // Try to parse as port number
        match port_part.parse::<u16>() {
            Ok(port) => {
                if port == 0 {
                    anyhow::bail!("Port number cannot be zero");
                }
                Ok((host_part.to_string(), Some(port)))
            }
            Err(e) => {
                // Check if this looks like a port number (all digits)
                if port_part.chars().all(|c| c.is_ascii_digit()) {
                    // It's clearly intended to be a port but invalid
                    anyhow::bail!("Invalid port number: '{port_part}' ({e})");
                } else {
                    // Not a port, treat entire string as hostname (might be IPv6)
                    Ok((host_port.to_string(), None))
                }
            }
        }
    } else {
        // No colon found, entire string is hostname
        Ok((host_port.to_string(), None))
    }
}

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

use anyhow::{Context, Result};
use std::fmt;

/// A single jump host specification
///
/// Represents one hop in a jump host chain, parsed from OpenSSH ProxyJump syntax.
/// Supports the format: `[user@]hostname[:port]`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JumpHost {
    /// Username for SSH authentication (None means use current user or config default)
    pub user: Option<String>,
    /// Hostname or IP address of the jump host
    pub host: String,
    /// SSH port (None means use default port 22 or config default)
    pub port: Option<u16>,
}

impl JumpHost {
    /// Create a new jump host specification
    pub fn new(host: String, user: Option<String>, port: Option<u16>) -> Self {
        Self { user, host, port }
    }

    /// Get the effective username (provided or current user)
    pub fn effective_user(&self) -> String {
        self.user.clone().unwrap_or_else(whoami::username)
    }

    /// Get the effective port (provided or default SSH port)
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(22)
    }

    /// Convert to a connection string for display purposes
    pub fn to_connection_string(&self) -> String {
        match (&self.user, &self.port) {
            (Some(user), Some(port)) => format!("{}@{}:{}", user, self.host, port),
            (Some(user), None) => format!("{}@{}", user, self.host),
            (None, Some(port)) => format!("{}:{}", self.host, port),
            (None, None) => self.host.clone(),
        }
    }
}

impl fmt::Display for JumpHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_connection_string())
    }
}

/// Parse jump host specifications from OpenSSH ProxyJump format
///
/// Supports the OpenSSH -J syntax:
/// * Single host: `hostname`, `user@hostname`, `hostname:port`, `user@hostname:port`
/// * Multiple hosts: Comma-separated list of the above
///
/// # Examples
/// ```rust
/// use bssh::jump::parse_jump_hosts;
///
/// // Single jump host
/// let jumps = parse_jump_hosts("bastion.example.com").unwrap();
/// assert_eq!(jumps.len(), 1);
/// assert_eq!(jumps[0].host, "bastion.example.com");
///
/// // With user and port
/// let jumps = parse_jump_hosts("admin@jump.example.com:2222").unwrap();
/// assert_eq!(jumps[0].user, Some("admin".to_string()));
/// assert_eq!(jumps[0].port, Some(2222));
///
/// // Multiple jump hosts
/// let jumps = parse_jump_hosts("jump1@host1,user@host2:2222").unwrap();
/// assert_eq!(jumps.len(), 2);
/// ```
pub fn parse_jump_hosts(jump_spec: &str) -> Result<Vec<JumpHost>> {
    if jump_spec.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut jump_hosts = Vec::new();

    for host_spec in jump_spec.split(',') {
        let host_spec = host_spec.trim();
        if host_spec.is_empty() {
            continue;
        }

        let jump_host = parse_single_jump_host(host_spec)
            .with_context(|| format!("Failed to parse jump host specification: '{host_spec}'"))?;
        jump_hosts.push(jump_host);
    }

    if jump_hosts.is_empty() {
        anyhow::bail!(
            "No valid jump hosts found in specification: '{}'",
            jump_spec
        );
    }

    Ok(jump_hosts)
}

/// Parse a single jump host specification
///
/// Handles the format: `[user@]hostname[:port]`
/// * IPv6 addresses are supported: `[::1]:2222` or `user@[::1]:2222`
/// * Port parsing is disambiguated from IPv6 colons
fn parse_single_jump_host(host_spec: &str) -> Result<JumpHost> {
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
fn parse_host_port(host_port: &str) -> Result<(String, Option<u16>)> {
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
                anyhow::bail!("Invalid characters after IPv6 address: '{}'", remaining);
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
                    anyhow::bail!("Invalid port number: '{}' ({})", port_part, e);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_jump_host_hostname_only() {
        let result = parse_single_jump_host("example.com").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, None);
        assert_eq!(result.port, None);
    }

    #[test]
    fn test_parse_single_jump_host_with_user() {
        let result = parse_single_jump_host("admin@example.com").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, Some("admin".to_string()));
        assert_eq!(result.port, None);
    }

    #[test]
    fn test_parse_single_jump_host_with_port() {
        let result = parse_single_jump_host("example.com:2222").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, None);
        assert_eq!(result.port, Some(2222));
    }

    #[test]
    fn test_parse_single_jump_host_with_user_and_port() {
        let result = parse_single_jump_host("admin@example.com:2222").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, Some("admin".to_string()));
        assert_eq!(result.port, Some(2222));
    }

    #[test]
    fn test_parse_single_jump_host_ipv6_brackets() {
        let result = parse_single_jump_host("[::1]").unwrap();
        assert_eq!(result.host, "::1");
        assert_eq!(result.user, None);
        assert_eq!(result.port, None);
    }

    #[test]
    fn test_parse_single_jump_host_ipv6_with_port() {
        let result = parse_single_jump_host("[::1]:2222").unwrap();
        assert_eq!(result.host, "::1");
        assert_eq!(result.user, None);
        assert_eq!(result.port, Some(2222));
    }

    #[test]
    fn test_parse_single_jump_host_ipv6_with_user_and_port() {
        let result = parse_single_jump_host("admin@[::1]:2222").unwrap();
        assert_eq!(result.host, "::1");
        assert_eq!(result.user, Some("admin".to_string()));
        assert_eq!(result.port, Some(2222));
    }

    #[test]
    fn test_parse_jump_hosts_multiple() {
        let result = parse_jump_hosts("jump1@host1,user@host2:2222,host3").unwrap();
        assert_eq!(result.len(), 3);

        assert_eq!(result[0].host, "host1");
        assert_eq!(result[0].user, Some("jump1".to_string()));
        assert_eq!(result[0].port, None);

        assert_eq!(result[1].host, "host2");
        assert_eq!(result[1].user, Some("user".to_string()));
        assert_eq!(result[1].port, Some(2222));

        assert_eq!(result[2].host, "host3");
        assert_eq!(result[2].user, None);
        assert_eq!(result[2].port, None);
    }

    #[test]
    fn test_parse_jump_hosts_whitespace_handling() {
        let result = parse_jump_hosts(" host1 , user@host2:2222 , host3 ").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].host, "host1");
        assert_eq!(result[1].host, "host2");
        assert_eq!(result[2].host, "host3");
    }

    #[test]
    fn test_parse_jump_hosts_empty_string() {
        let result = parse_jump_hosts("").unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_jump_hosts_only_commas() {
        let result = parse_jump_hosts(",,");
        assert!(result.is_err()); // Should error since no valid jump hosts found
    }

    #[test]
    fn test_parse_single_jump_host_errors() {
        // Empty specification
        assert!(parse_single_jump_host("").is_err());

        // Empty username
        assert!(parse_single_jump_host("@host").is_err());

        // Empty hostname
        assert!(parse_single_jump_host("user@").is_err());

        // Empty port
        assert!(parse_single_jump_host("host:").is_err());

        // Zero port
        assert!(parse_single_jump_host("host:0").is_err());

        // Invalid port (too large)
        assert!(parse_single_jump_host("host:99999").is_err());

        // Unclosed IPv6 bracket
        assert!(parse_single_jump_host("[::1").is_err());

        // Empty IPv6 address
        assert!(parse_single_jump_host("[]").is_err());
    }

    #[test]
    fn test_jump_host_display() {
        let host = JumpHost::new("example.com".to_string(), None, None);
        assert_eq!(format!("{host}"), "example.com");

        let host = JumpHost::new("example.com".to_string(), Some("user".to_string()), None);
        assert_eq!(format!("{host}"), "user@example.com");

        let host = JumpHost::new("example.com".to_string(), None, Some(2222));
        assert_eq!(format!("{host}"), "example.com:2222");

        let host = JumpHost::new(
            "example.com".to_string(),
            Some("user".to_string()),
            Some(2222),
        );
        assert_eq!(format!("{host}"), "user@example.com:2222");
    }

    #[test]
    fn test_jump_host_effective_values() {
        let host = JumpHost::new("example.com".to_string(), None, None);
        assert_eq!(host.effective_port(), 22);
        assert!(!host.effective_user().is_empty()); // Should return current user

        let host = JumpHost::new(
            "example.com".to_string(),
            Some("testuser".to_string()),
            Some(2222),
        );
        assert_eq!(host.effective_port(), 2222);
        assert_eq!(host.effective_user(), "testuser");
    }
}

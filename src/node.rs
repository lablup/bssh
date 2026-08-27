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

use std::fmt;
use std::net::Ipv6Addr;

use anyhow::{Context, Result};

/// Parsed components of a `[user@]host[:port]` node specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeSpec<'a> {
    pub user: Option<&'a str>,
    pub host: &'a str,
    pub port: Option<u16>,
}

/// Parse a node specification while preserving IPv6 address boundaries.
///
/// IPv6 literals must use brackets because an unbracketed trailing numeric
/// segment is indistinguishable from a port. The returned host never includes
/// the brackets, so callers can pass `(host, port)` directly to a resolver.
pub fn parse_node_spec(node_str: &str) -> Result<NodeSpec<'_>> {
    let (user, host_part) = if let Some((user, host)) = node_str.split_once('@') {
        (Some(user), host)
    } else {
        (None, node_str)
    };

    if let Some(bracketed) = host_part.strip_prefix('[') {
        let closing = bracketed
            .find(']')
            .context("Bracketed IPv6 address is missing a closing ']'")?;
        let host = &bracketed[..closing];
        host.parse::<Ipv6Addr>()
            .context("Invalid bracketed IPv6 address")?;

        let suffix = &bracketed[closing + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            let port_str = suffix
                .strip_prefix(':')
                .context("Unexpected text after bracketed IPv6 address")?;
            Some(port_str.parse::<u16>().context("Invalid port number")?)
        };

        return Ok(NodeSpec { user, host, port });
    }

    if host_part.parse::<Ipv6Addr>().is_ok() {
        anyhow::bail!("IPv6 address literals must be enclosed in brackets, for example '[::1]'");
    }

    let (host, port) = if let Some((host, port_str)) = host_part.rsplit_once(':') {
        let port = port_str.parse::<u16>().context("Invalid port number")?;
        (host, Some(port))
    } else {
        (host_part, None)
    };

    Ok(NodeSpec { user, host, port })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub host: String,
    /// Host name as supplied before ssh_config `HostName` expansion.
    pub original_host: String,
    pub port: u16,
    pub username: String,
}

impl Node {
    pub fn new(host: String, port: u16, username: String) -> Self {
        let original_host = host.clone();
        Self {
            host,
            original_host,
            port,
            username,
        }
    }

    #[must_use]
    pub fn with_original_host(mut self, original_host: String) -> Self {
        self.original_host = original_host;
        self
    }

    /// Host name used to match ssh_config and expand ProxyCommand `%n`.
    pub fn config_host(&self) -> &str {
        &self.original_host
    }

    pub fn parse(node_str: &str, default_user: Option<&str>) -> Result<Self> {
        // Parse formats:
        // - host
        // - host:port
        // - user@host
        // - user@host:port

        let spec = parse_node_spec(node_str)?;

        let username = spec
            .user
            .or(default_user)
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .or_else(|_| std::env::var("LOGNAME"))
                    .unwrap_or_else(|_| whoami::username().unwrap_or_else(|_| "user".to_string()))
            });

        Ok(Node {
            host: spec.host.to_string(),
            original_host: spec.host.to_string(),
            port: spec.port.unwrap_or(22),
            username,
        })
    }

    pub fn address(&self) -> String {
        if self.host.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.parse::<Ipv6Addr>().is_ok() {
            write!(f, "{}@[{}]:{}", self.username, self.host, self.port)
        } else {
            write!(f, "{}@{}:{}", self.username, self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_only() {
        let node = Node::parse("example.com", None).unwrap();
        assert_eq!(node.host, "example.com");
        assert_eq!(node.port, 22);
    }

    #[test]
    fn test_parse_host_with_port() {
        let node = Node::parse("example.com:2222", None).unwrap();
        assert_eq!(node.host, "example.com");
        assert_eq!(node.port, 2222);
    }

    #[test]
    fn test_parse_user_and_host() {
        let node = Node::parse("admin@example.com", None).unwrap();
        assert_eq!(node.username, "admin");
        assert_eq!(node.host, "example.com");
        assert_eq!(node.port, 22);
    }

    #[test]
    fn test_parse_full_format() {
        let node = Node::parse("admin@example.com:2222", None).unwrap();
        assert_eq!(node.username, "admin");
        assert_eq!(node.host, "example.com");
        assert_eq!(node.port, 2222);
    }

    #[test]
    fn test_parse_bracketed_ipv6_forms() {
        let node = Node::parse("[::1]", Some("default_user")).unwrap();
        assert_eq!(node.host, "::1");
        assert_eq!(node.port, 22);
        assert_eq!(node.username, "default_user");
        assert_eq!(node.address(), "[::1]:22");
        assert_eq!(node.to_string(), "default_user@[::1]:22");

        let node = Node::parse("admin@[2001:db8::1]:2222", None).unwrap();
        assert_eq!(node.host, "2001:db8::1");
        assert_eq!(node.port, 2222);
        assert_eq!(node.username, "admin");
    }

    #[test]
    fn test_parse_unbracketed_ipv6_explains_required_syntax() {
        let error = Node::parse("::1", None).unwrap_err();
        assert!(error.to_string().contains("must be enclosed in brackets"));
    }

    #[test]
    fn test_parse_with_default_user() {
        let node = Node::parse("example.com", Some("default_user")).unwrap();
        assert_eq!(node.username, "default_user");
    }

    #[test]
    fn test_parse_uses_current_user_when_no_default() {
        // When no user is specified, it should use current user from environment
        let node = Node::parse("example.com", None).unwrap();
        // Should not be "root" unless the current user is actually root
        let current_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| whoami::username().unwrap_or_else(|_| "user".to_string()));
        assert_eq!(node.username, current_user);
        // Specifically verify it doesn't default to root when we're not root
        if current_user != "root" {
            assert_ne!(node.username, "root");
        }
    }
}

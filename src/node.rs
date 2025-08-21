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

#[derive(Debug, Clone)]
pub struct Node {
    pub host: String,
    pub port: u16,
    pub username: String,
}

impl Node {
    pub fn new(host: String, port: u16, username: String) -> Self {
        Self {
            host,
            port,
            username,
        }
    }

    pub fn parse(node_str: &str, default_user: Option<&str>) -> Result<Self> {
        // Parse formats:
        // - host
        // - host:port
        // - user@host
        // - user@host:port

        let (user_part, host_part) = if let Some(at_pos) = node_str.find('@') {
            let user = &node_str[..at_pos];
            let rest = &node_str[at_pos + 1..];
            (Some(user), rest)
        } else {
            (None, node_str)
        };

        let (host, port) = if let Some(colon_pos) = host_part.rfind(':') {
            let host = &host_part[..colon_pos];
            let port_str = &host_part[colon_pos + 1..];
            let port = port_str.parse::<u16>().context("Invalid port number")?;
            (host, port)
        } else {
            (host_part, 22)
        };

        let username = user_part
            .or(default_user)
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "root".to_string())
            });

        Ok(Node {
            host: host.to_string(),
            port,
            username,
        })
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}:{}", self.username, self.host, self.port)
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
    fn test_parse_with_default_user() {
        let node = Node::parse("example.com", Some("default_user")).unwrap();
        assert_eq!(node.username, "default_user");
    }
}

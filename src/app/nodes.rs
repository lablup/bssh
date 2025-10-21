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

//! Node resolution and filtering functionality

use anyhow::{Context, Result};
use bssh::{cli::Cli, config::Config, node::Node, ssh::SshConfig};
use glob::Pattern;

/// Parse a node string with SSH config integration
pub fn parse_node_with_ssh_config(node_str: &str, ssh_config: &SshConfig) -> Result<Node> {
    // Security: Validate the node string to prevent injection attacks
    if node_str.is_empty() {
        anyhow::bail!("Node string cannot be empty");
    }

    // Check for dangerous characters that could cause issues
    if node_str.contains(';')
        || node_str.contains('&')
        || node_str.contains('|')
        || node_str.contains('`')
        || node_str.contains('$')
        || node_str.contains('\n')
    {
        anyhow::bail!("Node string contains invalid characters");
    }

    // First parse the raw node string to extract user, host, port from CLI
    let (user_part, host_part) = if let Some(at_pos) = node_str.find('@') {
        let user = &node_str[..at_pos];
        let rest = &node_str[at_pos + 1..];
        (Some(user), rest)
    } else {
        (None, node_str)
    };

    let (raw_host, cli_port) = if let Some(colon_pos) = host_part.rfind(':') {
        let host = &host_part[..colon_pos];
        let port_str = &host_part[colon_pos + 1..];
        let port = port_str.parse::<u16>().context("Invalid port number")?;
        (host, Some(port))
    } else {
        (host_part, None)
    };

    // Security: Validate hostname
    let validated_host = bssh::security::validate_hostname(raw_host)
        .with_context(|| format!("Invalid hostname in node: {raw_host}"))?;

    // Security: Validate username if provided
    if let Some(user) = user_part {
        bssh::security::validate_username(user)
            .with_context(|| format!("Invalid username in node: {user}"))?;
    }

    // Now resolve using SSH config with CLI taking precedence
    let effective_hostname = ssh_config.get_effective_hostname(&validated_host);
    let effective_user = if let Some(user) = user_part {
        user.to_string()
    } else if let Some(ssh_user) = ssh_config.get_effective_user(raw_host, None) {
        ssh_user
    } else {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| {
                // Try to get current user from system
                #[cfg(unix)]
                {
                    whoami::username()
                }
                #[cfg(not(unix))]
                {
                    "user".to_string()
                }
            })
    };
    let effective_port = ssh_config.get_effective_port(raw_host, cli_port);

    Ok(Node::new(
        effective_hostname,
        effective_port,
        effective_user,
    ))
}

/// Resolve nodes from CLI arguments and configuration
pub async fn resolve_nodes(
    cli: &Cli,
    config: &Config,
    ssh_config: &SshConfig,
) -> Result<(Vec<Node>, Option<String>)> {
    let mut nodes = Vec::new();
    let mut cluster_name = None;

    // Handle SSH compatibility mode (single host)
    if cli.is_ssh_mode() {
        let (user, host, port) = cli
            .parse_destination()
            .ok_or_else(|| anyhow::anyhow!("Invalid destination format"))?;

        // Resolve using SSH config with CLI taking precedence
        let effective_hostname = ssh_config.get_effective_hostname(&host);
        let effective_user = if let Some(u) = user {
            u
        } else if let Some(cli_user) = cli.get_effective_user() {
            cli_user
        } else if let Some(ssh_user) = ssh_config.get_effective_user(&host, None) {
            ssh_user
        } else if let Ok(env_user) = std::env::var("USER") {
            env_user
        } else {
            "root".to_string()
        };
        let effective_port =
            ssh_config.get_effective_port(&host, port.or_else(|| cli.get_effective_port()));

        let node = Node::new(effective_hostname, effective_port, effective_user);
        nodes.push(node);
    } else if let Some(hosts) = &cli.hosts {
        // Parse hosts from CLI
        for host_str in hosts {
            // Split by comma if a single argument contains multiple hosts
            for single_host in host_str.split(',') {
                let node = parse_node_with_ssh_config(single_host.trim(), ssh_config)?;
                nodes.push(node);
            }
        }
    } else if let Some(cli_cluster_name) = &cli.cluster {
        // Get nodes from cluster configuration
        nodes = config.resolve_nodes(cli_cluster_name)?;
        cluster_name = Some(cli_cluster_name.clone());
    } else {
        // Check if Backend.AI environment is detected (automatic cluster)
        if config.clusters.contains_key("bai_auto") {
            // Automatically use Backend.AI cluster when no explicit cluster is specified
            nodes = config.resolve_nodes("bai_auto")?;
            cluster_name = Some("bai_auto".to_string());
        }
    }

    // Apply host filter if destination is used as a filter pattern
    if let Some(filter) = cli.get_host_filter() {
        nodes = filter_nodes(nodes, filter)?;
        if nodes.is_empty() {
            anyhow::bail!("No hosts matched the filter pattern: {filter}");
        }
    }

    Ok((nodes, cluster_name))
}

/// Filter nodes based on a pattern (supports wildcards)
pub fn filter_nodes(nodes: Vec<Node>, pattern: &str) -> Result<Vec<Node>> {
    // Security: Validate pattern length to prevent DoS
    const MAX_PATTERN_LENGTH: usize = 256;
    if pattern.len() > MAX_PATTERN_LENGTH {
        anyhow::bail!("Filter pattern too long (max {MAX_PATTERN_LENGTH} characters)");
    }

    // Security: Validate pattern for dangerous constructs
    if pattern.is_empty() {
        anyhow::bail!("Filter pattern cannot be empty");
    }

    // Security: Prevent excessive wildcard usage that could cause DoS
    let wildcard_count = pattern.chars().filter(|c| *c == '*' || *c == '?').count();
    const MAX_WILDCARDS: usize = 10;
    if wildcard_count > MAX_WILDCARDS {
        anyhow::bail!("Filter pattern contains too many wildcards (max {MAX_WILDCARDS})");
    }

    // Security: Check for potential path traversal attempts
    if pattern.contains("..") || pattern.contains("//") {
        anyhow::bail!("Filter pattern contains invalid sequences");
    }

    // Security: Sanitize pattern - only allow safe characters for hostnames
    // Allow alphanumeric, dots, hyphens, underscores, wildcards, and brackets
    let valid_chars = pattern.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '.'
            || c == '-'
            || c == '_'
            || c == '@'
            || c == ':'
            || c == '*'
            || c == '?'
            || c == '['
            || c == ']'
    });

    if !valid_chars {
        anyhow::bail!("Filter pattern contains invalid characters for hostname matching");
    }

    // If pattern contains wildcards, use glob matching
    if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
        // Security: Compile pattern with timeout to prevent ReDoS attacks
        let glob_pattern =
            Pattern::new(pattern).with_context(|| format!("Invalid filter pattern: {pattern}"))?;

        // Performance: Use HashSet for O(1) lookups if we need to check many nodes
        let mut matched_nodes = Vec::with_capacity(nodes.len());

        for node in nodes {
            // Security: Limit matching to prevent excessive computation
            let host_matches = glob_pattern.matches(&node.host);
            let full_matches = if !host_matches {
                glob_pattern.matches(&node.to_string())
            } else {
                true
            };

            if host_matches || full_matches {
                matched_nodes.push(node);
            }
        }

        Ok(matched_nodes)
    } else {
        // Exact match: check hostname, full node string, or partial match
        // Performance: Pre-compute pattern once for contains check
        Ok(nodes
            .into_iter()
            .filter(|node| {
                node.host == pattern || node.to_string() == pattern || node.host.contains(pattern)
            })
            .collect())
    }
}

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
use bssh::{cli::Cli, config::Config, hostlist, node::Node, ssh::SshConfig};
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
                whoami::username().unwrap_or_else(|_| "user".to_string())
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
        // Parse hosts from CLI with hostlist expression expansion
        for host_str in hosts {
            // Expand hostlist expressions (e.g., node[1-5], rack[1-2]-node[1-3])
            let expanded_hosts = hostlist::expander::expand_host_specs(host_str)
                .with_context(|| format!("Failed to expand host expression: {host_str}"))?;

            for single_host in expanded_hosts {
                let node = parse_node_with_ssh_config(&single_host, ssh_config)?;
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
        // Expand hostlist expressions in filter pattern (e.g., --filter "node[1-5]")
        nodes = filter_nodes_with_hostlist(nodes, filter)?;
        if nodes.is_empty() {
            anyhow::bail!("No hosts matched the filter pattern: {filter}");
        }
    }

    // Apply host exclusion patterns (--exclude option)
    if let Some(exclude_patterns) = cli.get_exclude_patterns() {
        let node_count_before = nodes.len();
        // Expand hostlist expressions in exclusion patterns
        nodes = exclude_nodes_with_hostlist(nodes, exclude_patterns)?;
        if nodes.is_empty() {
            let patterns_str = exclude_patterns.join(", ");
            anyhow::bail!(
                "All {node_count_before} hosts were excluded by pattern(s): {patterns_str}"
            );
        }
    }

    Ok((nodes, cluster_name))
}

/// Check if a pattern matches a node (hostname or full node string)
fn pattern_matches_node(pattern: &Pattern, node: &Node) -> bool {
    pattern.matches(&node.host) || pattern.matches(&node.to_string())
}

/// Exclude nodes based on patterns (supports wildcards)
///
/// Takes a list of nodes and exclusion patterns, returning nodes that don't match
/// any of the exclusion patterns. Patterns support wildcards like 'db*', '*-backup'.
pub fn exclude_nodes(nodes: Vec<Node>, patterns: &[String]) -> Result<Vec<Node>> {
    if patterns.is_empty() {
        return Ok(nodes);
    }

    // Compile all exclusion patterns
    let mut compiled_patterns = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        // Security: Validate pattern length to prevent DoS
        const MAX_PATTERN_LENGTH: usize = 256;
        if pattern.len() > MAX_PATTERN_LENGTH {
            anyhow::bail!("Exclusion pattern too long (max {MAX_PATTERN_LENGTH} characters)");
        }

        // Security: Validate pattern for dangerous constructs
        if pattern.is_empty() {
            anyhow::bail!("Exclusion pattern cannot be empty");
        }

        // Security: Prevent excessive wildcard usage that could cause DoS
        let wildcard_count = pattern.chars().filter(|c| *c == '*' || *c == '?').count();
        const MAX_WILDCARDS: usize = 10;
        if wildcard_count > MAX_WILDCARDS {
            anyhow::bail!("Exclusion pattern contains too many wildcards (max {MAX_WILDCARDS})");
        }

        // Security: Check for potential path traversal attempts
        if pattern.contains("..") || pattern.contains("//") {
            anyhow::bail!("Exclusion pattern contains invalid sequences");
        }

        // Security: Sanitize pattern - only allow safe characters for hostnames
        // Also allow '!' for negation patterns like [!abc] in glob
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
                || c == '!'
        });

        if !valid_chars {
            anyhow::bail!("Exclusion pattern contains invalid characters for hostname matching");
        }

        // Compile the pattern
        let glob_pattern = Pattern::new(pattern)
            .with_context(|| format!("Invalid exclusion pattern: {pattern}"))?;
        compiled_patterns.push((pattern.clone(), glob_pattern));
    }

    // Filter out nodes that match any exclusion pattern
    let filtered: Vec<Node> = nodes
        .into_iter()
        .filter(|node| {
            // Keep node if it doesn't match any exclusion pattern
            !compiled_patterns.iter().any(|(raw_pattern, glob_pattern)| {
                // For patterns without wildcards, also do exact/contains matching
                if !raw_pattern.contains('*')
                    && !raw_pattern.contains('?')
                    && !raw_pattern.contains('[')
                {
                    node.host == *raw_pattern
                        || node.to_string() == *raw_pattern
                        || node.host.contains(raw_pattern.as_str())
                } else {
                    pattern_matches_node(glob_pattern, node)
                }
            })
        })
        .collect();

    Ok(filtered)
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
    // Allow alphanumeric, dots, hyphens, underscores, wildcards, brackets, and '!' for negation
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
            || c == '!'
    });

    if !valid_chars {
        anyhow::bail!("Filter pattern contains invalid characters for hostname matching");
    }

    // If pattern contains wildcards, use glob matching
    if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
        // Compile the glob pattern (DoS protection via length/wildcard limits above)
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

/// Filter nodes with hostlist expression support
///
/// If the pattern contains hostlist expressions (e.g., node[1-5]),
/// expands the pattern and filters to matching nodes.
/// Otherwise, falls back to standard glob/exact matching.
pub fn filter_nodes_with_hostlist(nodes: Vec<Node>, pattern: &str) -> Result<Vec<Node>> {
    // Security: Basic validation
    if pattern.is_empty() {
        anyhow::bail!("Filter pattern cannot be empty");
    }

    // Check if this looks like a hostlist expression
    if hostlist::is_hostlist_expression(pattern) {
        // Expand the hostlist expression
        let expanded_patterns = hostlist::expander::expand_host_specs(pattern)
            .with_context(|| format!("Failed to expand filter pattern: {pattern}"))?;

        // Create a set of expanded patterns for efficient lookup
        let pattern_set: std::collections::HashSet<&str> =
            expanded_patterns.iter().map(|s| s.as_str()).collect();

        // Filter nodes that match any expanded pattern
        let filtered: Vec<Node> = nodes
            .into_iter()
            .filter(|node| {
                pattern_set.contains(node.host.as_str())
                    || pattern_set.contains(node.to_string().as_str())
            })
            .collect();

        Ok(filtered)
    } else {
        // Fall back to standard filter_nodes for glob patterns
        filter_nodes(nodes, pattern)
    }
}

/// Exclude nodes with hostlist expression support
///
/// Expands any hostlist expressions in exclusion patterns before matching.
pub fn exclude_nodes_with_hostlist(nodes: Vec<Node>, patterns: &[String]) -> Result<Vec<Node>> {
    if patterns.is_empty() {
        return Ok(nodes);
    }

    // Expand all patterns and collect into a set of hostnames to exclude
    let mut expanded_patterns = Vec::new();
    let mut glob_patterns = Vec::new();

    for pattern in patterns {
        if hostlist::is_hostlist_expression(pattern) {
            // Expand hostlist expression
            let expanded = hostlist::expander::expand_host_specs(pattern)
                .with_context(|| format!("Failed to expand exclusion pattern: {pattern}"))?;
            expanded_patterns.extend(expanded);
        } else {
            // Keep as a glob pattern for later matching
            glob_patterns.push(pattern.clone());
        }
    }

    // Create a set of expanded patterns for O(1) lookup
    let expanded_set: std::collections::HashSet<&str> =
        expanded_patterns.iter().map(|s| s.as_str()).collect();

    // First filter by expanded hostlist patterns
    let mut filtered: Vec<Node> = nodes
        .into_iter()
        .filter(|node| {
            !expanded_set.contains(node.host.as_str())
                && !expanded_set.contains(node.to_string().as_str())
        })
        .collect();

    // Then apply glob patterns using existing exclude_nodes
    if !glob_patterns.is_empty() {
        filtered = exclude_nodes(filtered, &glob_patterns)?;
    }

    Ok(filtered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bssh::hostlist::is_hostlist_expression;

    fn create_test_nodes() -> Vec<Node> {
        vec![
            Node::new("web1.example.com".to_string(), 22, "admin".to_string()),
            Node::new("web2.example.com".to_string(), 22, "admin".to_string()),
            Node::new("db1.example.com".to_string(), 22, "admin".to_string()),
            Node::new("db2.example.com".to_string(), 22, "admin".to_string()),
            Node::new(
                "cache-backup.example.com".to_string(),
                22,
                "admin".to_string(),
            ),
        ]
    }

    #[test]
    fn test_exclude_single_host_exact() {
        let nodes = create_test_nodes();
        let patterns = vec!["web1.example.com".to_string()];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 4);
        assert!(!result.iter().any(|n| n.host == "web1.example.com"));
    }

    #[test]
    fn test_exclude_multiple_hosts() {
        let nodes = create_test_nodes();
        let patterns = vec![
            "web1.example.com".to_string(),
            "db1.example.com".to_string(),
        ];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 3);
        assert!(!result.iter().any(|n| n.host == "web1.example.com"));
        assert!(!result.iter().any(|n| n.host == "db1.example.com"));
    }

    #[test]
    fn test_exclude_with_wildcard_prefix() {
        let nodes = create_test_nodes();
        let patterns = vec!["db*".to_string()];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 3);
        assert!(!result.iter().any(|n| n.host.starts_with("db")));
    }

    #[test]
    fn test_exclude_with_wildcard_suffix() {
        let nodes = create_test_nodes();
        let patterns = vec!["*-backup*".to_string()];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 4);
        assert!(!result.iter().any(|n| n.host.contains("-backup")));
    }

    #[test]
    fn test_exclude_with_question_mark_wildcard() {
        let nodes = create_test_nodes();
        let patterns = vec!["web?.example.com".to_string()];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 3);
        assert!(!result.iter().any(|n| n.host.starts_with("web")));
    }

    #[test]
    fn test_exclude_multiple_patterns_with_wildcards() {
        let nodes = create_test_nodes();
        let patterns = vec!["web*".to_string(), "db*".to_string()];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host, "cache-backup.example.com");
    }

    #[test]
    fn test_exclude_empty_patterns() {
        let nodes = create_test_nodes();
        let patterns: Vec<String> = vec![];
        let result = exclude_nodes(nodes.clone(), &patterns).unwrap();

        assert_eq!(result.len(), nodes.len());
    }

    #[test]
    fn test_exclude_no_matches() {
        let nodes = create_test_nodes();
        let patterns = vec!["nonexistent*".to_string()];
        let result = exclude_nodes(nodes.clone(), &patterns).unwrap();

        assert_eq!(result.len(), nodes.len());
    }

    #[test]
    fn test_exclude_all_hosts_returns_empty() {
        let nodes = create_test_nodes();
        let patterns = vec!["*".to_string()];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_exclude_pattern_too_long() {
        let nodes = create_test_nodes();
        let long_pattern = "a".repeat(300);
        let patterns = vec![long_pattern];
        let result = exclude_nodes(nodes, &patterns);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_exclude_empty_pattern() {
        let nodes = create_test_nodes();
        let patterns = vec!["".to_string()];
        let result = exclude_nodes(nodes, &patterns);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_exclude_too_many_wildcards() {
        let nodes = create_test_nodes();
        let patterns = vec!["*a*b*c*d*e*f*g*h*i*j*k*".to_string()];
        let result = exclude_nodes(nodes, &patterns);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("too many wildcards"));
    }

    #[test]
    fn test_exclude_invalid_characters() {
        let nodes = create_test_nodes();
        let patterns = vec!["host;rm -rf /".to_string()];
        let result = exclude_nodes(nodes, &patterns);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid characters"));
    }

    #[test]
    fn test_exclude_path_traversal_attempt() {
        let nodes = create_test_nodes();
        let patterns = vec!["../etc/passwd".to_string()];
        let result = exclude_nodes(nodes, &patterns);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid sequences"));
    }

    #[test]
    fn test_exclude_partial_hostname_match() {
        let nodes = create_test_nodes();
        // "web" should match "web1.example.com" and "web2.example.com" via contains
        let patterns = vec!["web".to_string()];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 3);
        assert!(!result.iter().any(|n| n.host.contains("web")));
    }

    #[test]
    fn test_filter_and_exclude_combined() {
        // Test that filter and exclude work correctly when used together
        let nodes = create_test_nodes();

        // First filter to only web and db nodes
        let filtered = filter_nodes(nodes, "*.example.com").unwrap();
        assert_eq!(filtered.len(), 5);

        // Then exclude db nodes
        let patterns = vec!["db*".to_string()];
        let result = exclude_nodes(filtered, &patterns).unwrap();

        assert_eq!(result.len(), 3);
        assert!(!result.iter().any(|n| n.host.starts_with("db")));
    }

    #[test]
    fn test_exclude_with_bracket_pattern() {
        // Test bracket character range patterns
        let nodes = create_test_nodes();
        // [12] should match db1 and db2 but not other nodes
        let patterns = vec!["db[12].example.com".to_string()];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 3);
        assert!(!result.iter().any(|n| n.host == "db1.example.com"));
        assert!(!result.iter().any(|n| n.host == "db2.example.com"));
        assert!(result.iter().any(|n| n.host == "web1.example.com"));
    }

    #[test]
    fn test_filter_with_bracket_pattern() {
        // Test bracket patterns work for filter_nodes as well
        let nodes = create_test_nodes();
        let result = filter_nodes(nodes, "web[12].example.com").unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|n| n.host == "web1.example.com"));
        assert!(result.iter().any(|n| n.host == "web2.example.com"));
    }

    #[test]
    fn test_exclude_with_bracket_negation_pattern() {
        // Test negation bracket patterns [!...]
        let nodes = vec![
            Node::new("web1.example.com".to_string(), 22, "admin".to_string()),
            Node::new("web2.example.com".to_string(), 22, "admin".to_string()),
            Node::new("web3.example.com".to_string(), 22, "admin".to_string()),
            Node::new("weba.example.com".to_string(), 22, "admin".to_string()),
        ];
        // [!12] should match web3 and weba (anything that is NOT 1 or 2)
        let patterns = vec!["web[!12].example.com".to_string()];
        let result = exclude_nodes(nodes, &patterns).unwrap();

        // Should keep web1 and web2 (they DON'T match the exclusion pattern)
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|n| n.host == "web1.example.com"));
        assert!(result.iter().any(|n| n.host == "web2.example.com"));
    }

    // ==================== Hostlist Expression Tests ====================

    #[test]
    fn test_is_hostlist_expression_numeric_range() {
        // Numeric ranges should be detected as hostlist
        assert!(is_hostlist_expression("node[1-5]"));
        assert!(is_hostlist_expression("node[01-05]"));
        assert!(is_hostlist_expression("node[1,2,3]"));
        assert!(is_hostlist_expression("node[1-3,5-7]"));
        assert!(is_hostlist_expression("rack[1-2]-node[1-3]"));
    }

    #[test]
    fn test_is_hostlist_expression_glob_pattern() {
        // Glob patterns should NOT be detected as hostlist
        assert!(!is_hostlist_expression("web*"));
        assert!(!is_hostlist_expression("web[abc]"));
        assert!(!is_hostlist_expression("web[a-z]"));
        assert!(!is_hostlist_expression("web[!12]"));
        assert!(!is_hostlist_expression("simple.host.com"));
    }

    #[test]
    fn test_filter_nodes_with_hostlist_range() {
        let nodes = vec![
            Node::new("node1".to_string(), 22, "admin".to_string()),
            Node::new("node2".to_string(), 22, "admin".to_string()),
            Node::new("node3".to_string(), 22, "admin".to_string()),
            Node::new("node4".to_string(), 22, "admin".to_string()),
            Node::new("node5".to_string(), 22, "admin".to_string()),
        ];

        // Filter to nodes 1-3 using hostlist expression
        let result = filter_nodes_with_hostlist(nodes, "node[1-3]").unwrap();

        assert_eq!(result.len(), 3);
        assert!(result.iter().any(|n| n.host == "node1"));
        assert!(result.iter().any(|n| n.host == "node2"));
        assert!(result.iter().any(|n| n.host == "node3"));
        assert!(!result.iter().any(|n| n.host == "node4"));
        assert!(!result.iter().any(|n| n.host == "node5"));
    }

    #[test]
    fn test_filter_nodes_with_hostlist_comma_separated() {
        let nodes = vec![
            Node::new("node1".to_string(), 22, "admin".to_string()),
            Node::new("node2".to_string(), 22, "admin".to_string()),
            Node::new("node3".to_string(), 22, "admin".to_string()),
            Node::new("node4".to_string(), 22, "admin".to_string()),
            Node::new("node5".to_string(), 22, "admin".to_string()),
        ];

        // Filter to specific nodes using hostlist expression
        let result = filter_nodes_with_hostlist(nodes, "node[1,3,5]").unwrap();

        assert_eq!(result.len(), 3);
        assert!(result.iter().any(|n| n.host == "node1"));
        assert!(result.iter().any(|n| n.host == "node3"));
        assert!(result.iter().any(|n| n.host == "node5"));
    }

    #[test]
    fn test_filter_nodes_with_hostlist_falls_back_to_glob() {
        let nodes = create_test_nodes();

        // Glob pattern (not a hostlist) should still work
        let result = filter_nodes_with_hostlist(nodes, "web*").unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|n| n.host.starts_with("web")));
    }

    #[test]
    fn test_exclude_nodes_with_hostlist_range() {
        let nodes = vec![
            Node::new("node1".to_string(), 22, "admin".to_string()),
            Node::new("node2".to_string(), 22, "admin".to_string()),
            Node::new("node3".to_string(), 22, "admin".to_string()),
            Node::new("node4".to_string(), 22, "admin".to_string()),
            Node::new("node5".to_string(), 22, "admin".to_string()),
        ];

        // Exclude nodes 2-4 using hostlist expression
        let patterns = vec!["node[2-4]".to_string()];
        let result = exclude_nodes_with_hostlist(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|n| n.host == "node1"));
        assert!(result.iter().any(|n| n.host == "node5"));
    }

    #[test]
    fn test_exclude_nodes_with_hostlist_mixed_patterns() {
        let nodes = vec![
            Node::new("node1".to_string(), 22, "admin".to_string()),
            Node::new("node2".to_string(), 22, "admin".to_string()),
            Node::new("node3".to_string(), 22, "admin".to_string()),
            Node::new("web1".to_string(), 22, "admin".to_string()),
            Node::new("web2".to_string(), 22, "admin".to_string()),
        ];

        // Mix hostlist and glob patterns
        let patterns = vec!["node[1-2]".to_string(), "web*".to_string()];
        let result = exclude_nodes_with_hostlist(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host, "node3");
    }

    #[test]
    fn test_exclude_nodes_with_hostlist_falls_back_to_glob() {
        let nodes = create_test_nodes();

        // Pure glob pattern (not a hostlist) should still work
        let patterns = vec!["db*".to_string()];
        let result = exclude_nodes_with_hostlist(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 3);
        assert!(!result.iter().any(|n| n.host.starts_with("db")));
    }

    #[test]
    fn test_filter_nodes_with_hostlist_zero_padded() {
        let nodes = vec![
            Node::new("node01".to_string(), 22, "admin".to_string()),
            Node::new("node02".to_string(), 22, "admin".to_string()),
            Node::new("node03".to_string(), 22, "admin".to_string()),
            Node::new("node04".to_string(), 22, "admin".to_string()),
            Node::new("node05".to_string(), 22, "admin".to_string()),
        ];

        // Filter using zero-padded hostlist expression
        let result = filter_nodes_with_hostlist(nodes, "node[01-03]").unwrap();

        assert_eq!(result.len(), 3);
        assert!(result.iter().any(|n| n.host == "node01"));
        assert!(result.iter().any(|n| n.host == "node02"));
        assert!(result.iter().any(|n| n.host == "node03"));
    }

    #[test]
    fn test_exclude_nodes_with_hostlist_cartesian_product() {
        let nodes = vec![
            Node::new("rack1-node1".to_string(), 22, "admin".to_string()),
            Node::new("rack1-node2".to_string(), 22, "admin".to_string()),
            Node::new("rack2-node1".to_string(), 22, "admin".to_string()),
            Node::new("rack2-node2".to_string(), 22, "admin".to_string()),
            Node::new("rack3-node1".to_string(), 22, "admin".to_string()),
        ];

        // Exclude using cartesian product hostlist expression
        let patterns = vec!["rack[1-2]-node[1-2]".to_string()];
        let result = exclude_nodes_with_hostlist(nodes, &patterns).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host, "rack3-node1");
    }
}

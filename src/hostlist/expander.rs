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

//! Hostlist expansion implementation
//!
//! This module expands parsed host patterns into lists of hostnames
//! using cartesian product for multiple range expressions.

use super::error::HostlistError;
use super::parser::{parse_host_pattern, PatternSegment};

/// Maximum number of hosts that can be generated from a single pattern
const MAX_EXPANSION_SIZE: usize = 100_000;

/// Expand a hostlist expression into a list of hostnames
///
/// # Arguments
///
/// * `expr` - The hostlist expression to expand
///
/// # Returns
///
/// A vector of expanded hostnames.
///
/// # Examples
///
/// ```rust
/// use bssh::hostlist::expand_hostlist;
///
/// // Simple range
/// let hosts = expand_hostlist("node[1-3]").unwrap();
/// assert_eq!(hosts, vec!["node1", "node2", "node3"]);
///
/// // Zero-padded
/// let hosts = expand_hostlist("server[01-03]").unwrap();
/// assert_eq!(hosts, vec!["server01", "server02", "server03"]);
///
/// // Cartesian product
/// let hosts = expand_hostlist("rack[1-2]-node[1-2]").unwrap();
/// assert_eq!(hosts, vec!["rack1-node1", "rack1-node2", "rack2-node1", "rack2-node2"]);
/// ```
pub fn expand_hostlist(expr: &str) -> Result<Vec<String>, HostlistError> {
    if expr.is_empty() {
        return Ok(Vec::new());
    }

    let pattern = parse_host_pattern(expr)?;

    // Check expansion size before generating
    let expansion_count = pattern.expansion_count();
    if expansion_count > MAX_EXPANSION_SIZE {
        return Err(HostlistError::RangeTooLarge {
            expression: expr.to_string(),
            count: expansion_count,
            limit: MAX_EXPANSION_SIZE,
        });
    }

    // If no ranges, just concatenate literals
    if !pattern.has_ranges() {
        let host: String = pattern
            .segments
            .iter()
            .filter_map(|s| match s {
                PatternSegment::Literal(lit) => Some(lit.as_str()),
                PatternSegment::Range(_) => None,
            })
            .collect();
        return Ok(if host.is_empty() {
            Vec::new()
        } else {
            vec![host]
        });
    }

    // Expand using cartesian product
    expand_segments(&pattern.segments)
}

/// Expand pattern segments into a list of hostnames using cartesian product
fn expand_segments(segments: &[PatternSegment]) -> Result<Vec<String>, HostlistError> {
    if segments.is_empty() {
        return Ok(vec![String::new()]);
    }

    // Start with a single empty string
    let mut results = vec![String::new()];

    for segment in segments {
        match segment {
            PatternSegment::Literal(lit) => {
                // Append literal to all current results
                for result in &mut results {
                    result.push_str(lit);
                }
            }
            PatternSegment::Range(range_expr) => {
                // Expand with all values from the range
                let values = range_expr.values();

                // Use checked multiplication to prevent integer overflow
                let new_capacity = results.len().checked_mul(values.len()).ok_or_else(|| {
                    HostlistError::RangeTooLarge {
                        expression: "cartesian product".to_string(),
                        count: usize::MAX,
                        limit: MAX_EXPANSION_SIZE,
                    }
                })?;

                if new_capacity > MAX_EXPANSION_SIZE {
                    return Err(HostlistError::RangeTooLarge {
                        expression: "cartesian product".to_string(),
                        count: new_capacity,
                        limit: MAX_EXPANSION_SIZE,
                    });
                }

                let mut new_results = Vec::with_capacity(new_capacity);

                for result in &results {
                    for value in &values {
                        let formatted = range_expr.format_value(*value);
                        let mut new_result = result.clone();
                        new_result.push_str(&formatted);
                        new_results.push(new_result);
                    }
                }

                results = new_results;
            }
        }
    }

    Ok(results)
}

/// Expand a host specification that may include user@ prefix and :port suffix
///
/// This function handles the full host specification format:
/// `[user@]hostpattern[:port]`
///
/// # Arguments
///
/// * `spec` - The full host specification
///
/// # Returns
///
/// A vector of expanded host specifications preserving user and port.
///
/// # Examples
///
/// ```rust
/// use bssh::hostlist::expander::expand_host_spec;
///
/// let hosts = expand_host_spec("admin@web[1-2].example.com:22").unwrap();
/// assert_eq!(hosts, vec![
///     "admin@web1.example.com:22",
///     "admin@web2.example.com:22"
/// ]);
/// ```
pub fn expand_host_spec(spec: &str) -> Result<Vec<String>, HostlistError> {
    if spec.is_empty() {
        return Ok(Vec::new());
    }

    // Parse user prefix
    let (user_prefix, rest) = if let Some(at_pos) = spec.find('@') {
        // Check if @ is before any [ to avoid matching @ in expressions
        let bracket_pos = spec.find('[');
        if bracket_pos.is_none() || at_pos < bracket_pos.unwrap() {
            let user = &spec[..=at_pos]; // includes @
            let rest = &spec[at_pos + 1..];
            (Some(user.to_string()), rest)
        } else {
            (None, spec)
        }
    } else {
        (None, spec)
    };

    // Parse port suffix (find last : that's not inside brackets)
    let (host_pattern, port_suffix) = parse_port_suffix(rest)?;

    // Expand the host pattern
    let expanded_hosts = expand_hostlist(host_pattern)?;

    // Reconstruct with user and port
    let results: Vec<String> = expanded_hosts
        .into_iter()
        .map(|host| {
            let mut result = String::new();
            if let Some(ref user) = user_prefix {
                result.push_str(user);
            }
            result.push_str(&host);
            if let Some(ref port) = port_suffix {
                result.push_str(port);
            }
            result
        })
        .collect();

    Ok(results)
}

/// Parse port suffix from a host pattern, being careful about brackets
fn parse_port_suffix(spec: &str) -> Result<(&str, Option<String>), HostlistError> {
    // Find the last : that's not inside brackets
    let mut bracket_depth = 0;
    let mut last_colon_outside = None;

    for (i, ch) in spec.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => {
                if bracket_depth > 0 {
                    bracket_depth -= 1;
                }
            }
            ':' if bracket_depth == 0 => {
                last_colon_outside = Some(i);
            }
            _ => {}
        }
    }

    if let Some(colon_pos) = last_colon_outside {
        let potential_port = &spec[colon_pos + 1..];
        // Check if it looks like a port (all digits)
        if !potential_port.is_empty() && potential_port.chars().all(|c| c.is_ascii_digit()) {
            let host_pattern = &spec[..colon_pos];
            let port_suffix = Some(format!(":{}", potential_port));
            return Ok((host_pattern, port_suffix));
        }
    }

    Ok((spec, None))
}

/// Expand multiple comma-separated host specifications
///
/// # Arguments
///
/// * `specs` - Comma-separated host specifications
///
/// # Returns
///
/// A vector of all expanded host specifications, deduplicated.
pub fn expand_host_specs(specs: &str) -> Result<Vec<String>, HostlistError> {
    use super::split_patterns;

    if specs.is_empty() {
        return Ok(Vec::new());
    }

    let patterns = split_patterns(specs)?;
    let mut all_hosts = Vec::new();

    for pattern in patterns {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }

        let expanded = expand_host_spec(pattern)?;
        all_hosts.extend(expanded);
    }

    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for host in all_hosts {
        if seen.insert(host.clone()) {
            result.push(host);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Basic expansion tests
    #[test]
    fn test_expand_simple_range() {
        let hosts = expand_hostlist("node[1-3]").unwrap();
        assert_eq!(hosts, vec!["node1", "node2", "node3"]);
    }

    #[test]
    fn test_expand_zero_padded_range() {
        let hosts = expand_hostlist("node[01-05]").unwrap();
        assert_eq!(
            hosts,
            vec!["node01", "node02", "node03", "node04", "node05"]
        );
    }

    #[test]
    fn test_expand_comma_separated() {
        let hosts = expand_hostlist("node[1,3,5]").unwrap();
        assert_eq!(hosts, vec!["node1", "node3", "node5"]);
    }

    #[test]
    fn test_expand_mixed_range() {
        let hosts = expand_hostlist("node[1-3,7,9-10]").unwrap();
        assert_eq!(
            hosts,
            vec!["node1", "node2", "node3", "node7", "node9", "node10"]
        );
    }

    #[test]
    fn test_expand_cartesian_product() {
        let hosts = expand_hostlist("rack[1-2]-node[1-3]").unwrap();
        assert_eq!(
            hosts,
            vec![
                "rack1-node1",
                "rack1-node2",
                "rack1-node3",
                "rack2-node1",
                "rack2-node2",
                "rack2-node3"
            ]
        );
    }

    #[test]
    fn test_expand_with_domain() {
        let hosts = expand_hostlist("web[1-3].example.com").unwrap();
        assert_eq!(
            hosts,
            vec!["web1.example.com", "web2.example.com", "web3.example.com"]
        );
    }

    #[test]
    fn test_expand_no_range() {
        let hosts = expand_hostlist("simple.host.com").unwrap();
        assert_eq!(hosts, vec!["simple.host.com"]);
    }

    #[test]
    fn test_expand_empty() {
        let hosts = expand_hostlist("").unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_expand_single_value_range() {
        let hosts = expand_hostlist("node[5]").unwrap();
        assert_eq!(hosts, vec!["node5"]);
    }

    #[test]
    fn test_expand_three_digit_padding() {
        let hosts = expand_hostlist("node[001-003]").unwrap();
        assert_eq!(hosts, vec!["node001", "node002", "node003"]);
    }

    // Host spec expansion tests
    #[test]
    fn test_expand_host_spec_with_user() {
        let hosts = expand_host_spec("admin@node[1-2]").unwrap();
        assert_eq!(hosts, vec!["admin@node1", "admin@node2"]);
    }

    #[test]
    fn test_expand_host_spec_with_port() {
        let hosts = expand_host_spec("node[1-2]:22").unwrap();
        assert_eq!(hosts, vec!["node1:22", "node2:22"]);
    }

    #[test]
    fn test_expand_host_spec_full() {
        let hosts = expand_host_spec("admin@web[1-2].example.com:22").unwrap();
        assert_eq!(
            hosts,
            vec!["admin@web1.example.com:22", "admin@web2.example.com:22"]
        );
    }

    #[test]
    fn test_expand_host_spec_no_expansion() {
        let hosts = expand_host_spec("user@host.com:2222").unwrap();
        assert_eq!(hosts, vec!["user@host.com:2222"]);
    }

    #[test]
    fn test_expand_host_specs_multiple() {
        let hosts = expand_host_specs("web[1-2],db[1-2]").unwrap();
        assert_eq!(hosts, vec!["web1", "web2", "db1", "db2"]);
    }

    #[test]
    fn test_expand_host_specs_with_user_port() {
        let hosts = expand_host_specs("admin@web[1-2]:22,root@db[1-2]:3306").unwrap();
        assert_eq!(
            hosts,
            vec![
                "admin@web1:22",
                "admin@web2:22",
                "root@db1:3306",
                "root@db2:3306"
            ]
        );
    }

    #[test]
    fn test_expand_host_specs_deduplication() {
        let hosts = expand_host_specs("node[1-3],node[2-4]").unwrap();
        assert_eq!(hosts, vec!["node1", "node2", "node3", "node4"]);
    }

    // Error cases
    #[test]
    fn test_expand_too_large() {
        // This would produce 1000 * 1000 = 1,000,000 hosts
        let result = expand_hostlist("a[1-1000]-b[1-1000]");
        assert!(matches!(result, Err(HostlistError::RangeTooLarge { .. })));
    }

    #[test]
    fn test_expand_empty_bracket() {
        let result = expand_hostlist("node[]");
        assert!(matches!(result, Err(HostlistError::EmptyBracket { .. })));
    }

    #[test]
    fn test_expand_reversed_range() {
        let result = expand_hostlist("node[5-1]");
        assert!(matches!(result, Err(HostlistError::ReversedRange { .. })));
    }

    #[test]
    fn test_expand_invalid_number() {
        let result = expand_hostlist("node[a-z]");
        assert!(matches!(result, Err(HostlistError::InvalidNumber { .. })));
    }

    // Edge cases
    #[test]
    fn test_expand_large_but_valid_range() {
        let hosts = expand_hostlist("node[1-1000]").unwrap();
        assert_eq!(hosts.len(), 1000);
        assert_eq!(hosts[0], "node1");
        assert_eq!(hosts[999], "node1000");
    }

    #[test]
    fn test_expand_prefix_only() {
        let hosts = expand_hostlist("prefix-[1-2]").unwrap();
        assert_eq!(hosts, vec!["prefix-1", "prefix-2"]);
    }

    #[test]
    fn test_expand_suffix_only() {
        let hosts = expand_hostlist("[1-2]-suffix").unwrap();
        assert_eq!(hosts, vec!["1-suffix", "2-suffix"]);
    }

    #[test]
    fn test_expand_range_only() {
        let hosts = expand_hostlist("[1-3]").unwrap();
        assert_eq!(hosts, vec!["1", "2", "3"]);
    }

    #[test]
    fn test_expand_complex_domain() {
        let hosts = expand_hostlist("app[1-2].prod.us-east-1.example.com").unwrap();
        assert_eq!(
            hosts,
            vec![
                "app1.prod.us-east-1.example.com",
                "app2.prod.us-east-1.example.com"
            ]
        );
    }

    #[test]
    fn test_port_suffix_parsing() {
        // Test that port suffix is correctly separated
        let (host, port) = parse_port_suffix("node[1-3]:22").unwrap();
        assert_eq!(host, "node[1-3]");
        assert_eq!(port, Some(":22".to_string()));

        // No port
        let (host, port) = parse_port_suffix("node[1-3]").unwrap();
        assert_eq!(host, "node[1-3]");
        assert_eq!(port, None);

        // Domain with port
        let (host, port) = parse_port_suffix("node[1-3].example.com:2222").unwrap();
        assert_eq!(host, "node[1-3].example.com");
        assert_eq!(port, Some(":2222".to_string()));
    }
}

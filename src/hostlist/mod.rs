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

//! Hostlist expression support for pdsh-style range expansion
//!
//! This module provides parsing and expansion of hostlist expressions,
//! allowing compact specification of multiple hosts using range notation.
//!
//! # Syntax
//!
//! The hostlist expression syntax supports:
//! - Simple range: `node[1-5]` -> `node1, node2, node3, node4, node5`
//! - Zero-padded range: `node[01-05]` -> `node01, node02, node03, node04, node05`
//! - Comma-separated values: `node[1,3,5]` -> `node1, node3, node5`
//! - Mixed ranges and values: `node[1-3,7,9-10]` -> 7 hosts
//! - Multiple ranges (cartesian product): `rack[1-2]-node[1-3]` -> 6 hosts
//! - Domain suffix: `web[1-3].example.com` -> 3 hosts
//! - File input: `^/path/to/file` -> read hosts from file
//!
//! # Examples
//!
//! ```rust
//! use bssh::hostlist::expand_hostlist;
//!
//! // Simple range expansion
//! let hosts = expand_hostlist("node[1-3]").unwrap();
//! assert_eq!(hosts, vec!["node1", "node2", "node3"]);
//!
//! // Zero-padded expansion
//! let hosts = expand_hostlist("server[01-03]").unwrap();
//! assert_eq!(hosts, vec!["server01", "server02", "server03"]);
//!
//! // Multiple ranges (cartesian product)
//! let hosts = expand_hostlist("rack[1-2]-node[1-2]").unwrap();
//! assert_eq!(hosts, vec!["rack1-node1", "rack1-node2", "rack2-node1", "rack2-node2"]);
//! ```

mod error;
pub mod expander;
mod parser;

pub use error::HostlistError;
pub use expander::{expand_host_spec, expand_host_specs, expand_hostlist};
pub use parser::{parse_host_pattern, parse_hostfile, HostPattern};

/// Check if a pattern is a hostlist expression (contains numeric range brackets)
///
/// Hostlist expressions have brackets containing numeric ranges like [1-5], [01-05], [1,2,3]
/// Glob patterns have brackets containing characters like [abc], [a-z], [!xyz]
pub fn is_hostlist_expression(pattern: &str) -> bool {
    // A hostlist expression has [...] with numbers/ranges inside
    if !pattern.contains('[') || !pattern.contains(']') {
        return false;
    }

    // Find bracket content and check if it looks like a hostlist range
    let mut in_bracket = false;
    let mut bracket_content = String::new();

    for ch in pattern.chars() {
        match ch {
            '[' if !in_bracket => {
                in_bracket = true;
                bracket_content.clear();
            }
            ']' if in_bracket => {
                // Check if bracket content looks like a hostlist range
                if looks_like_hostlist_range(&bracket_content) {
                    return true;
                }
                in_bracket = false;
            }
            _ if in_bracket => {
                bracket_content.push(ch);
            }
            _ => {}
        }
    }

    false
}

/// Check if bracket content looks like a hostlist numeric range
pub fn looks_like_hostlist_range(content: &str) -> bool {
    if content.is_empty() {
        return false;
    }

    // Hostlist ranges are numeric: 1-5, 01-05, 1,2,3, 1-3,5-7
    // Glob patterns have letters: abc, a-z, !xyz
    for part in content.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Check if it's a range (contains -)
        if part.contains('-') {
            let parts: Vec<&str> = part.splitn(2, '-').collect();
            if parts.len() == 2 {
                // Both parts should be numeric for hostlist
                if parts[0].chars().all(|c| c.is_ascii_digit())
                    && parts[1].chars().all(|c| c.is_ascii_digit())
                {
                    return true;
                }
            }
        } else {
            // Single value should be numeric for hostlist
            if part.chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }

    false
}

/// Expand a comma-separated list of host patterns
///
/// This function handles multiple patterns separated by commas,
/// expanding each pattern and deduplicating the results.
///
/// # Arguments
///
/// * `expr` - A comma-separated list of host patterns
///
/// # Returns
///
/// A vector of expanded hostnames, deduplicated and in order.
///
/// # Examples
///
/// ```rust
/// use bssh::hostlist::expand_hostlist_patterns;
///
/// let hosts = expand_hostlist_patterns("web[1-2],db[1-2]").unwrap();
/// assert_eq!(hosts, vec!["web1", "web2", "db1", "db2"]);
/// ```
pub fn expand_hostlist_patterns(expr: &str) -> Result<Vec<String>, HostlistError> {
    if expr.is_empty() {
        return Ok(Vec::new());
    }

    // Handle file input with ^ prefix
    if let Some(path) = expr.strip_prefix('^') {
        return parse_hostfile(std::path::Path::new(path));
    }

    // Split by comma, but be careful about commas inside brackets
    let patterns = split_patterns(expr)?;

    let mut all_hosts = Vec::new();
    for pattern in patterns {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }

        // Handle file input within comma-separated list
        if let Some(path) = pattern.strip_prefix('^') {
            let file_hosts = parse_hostfile(std::path::Path::new(path))?;
            all_hosts.extend(file_hosts);
        } else {
            let expanded = expand_hostlist(pattern)?;
            all_hosts.extend(expanded);
        }
    }

    // Deduplicate while preserving order
    deduplicate_hosts(all_hosts)
}

/// Split a hostlist expression by commas, respecting bracket boundaries
fn split_patterns(expr: &str) -> Result<Vec<String>, HostlistError> {
    let mut patterns = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0;

    for ch in expr.chars() {
        match ch {
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                if bracket_depth == 0 {
                    return Err(HostlistError::UnmatchedBracket {
                        expression: expr.to_string(),
                    });
                }
                bracket_depth -= 1;
                current.push(ch);
            }
            ',' if bracket_depth == 0 => {
                if !current.is_empty() {
                    patterns.push(current);
                    current = String::new();
                }
            }
            _ => current.push(ch),
        }
    }

    if bracket_depth != 0 {
        return Err(HostlistError::UnclosedBracket {
            expression: expr.to_string(),
        });
    }

    if !current.is_empty() {
        patterns.push(current);
    }

    Ok(patterns)
}

/// Deduplicate hosts while preserving original order
fn deduplicate_hosts(hosts: Vec<String>) -> Result<Vec<String>, HostlistError> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    for host in hosts {
        if seen.insert(host.clone()) {
            result.push(host);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_hostlist_patterns_empty() {
        let result = expand_hostlist_patterns("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_expand_hostlist_patterns_single() {
        let result = expand_hostlist_patterns("node[1-3]").unwrap();
        assert_eq!(result, vec!["node1", "node2", "node3"]);
    }

    #[test]
    fn test_expand_hostlist_patterns_multiple() {
        let result = expand_hostlist_patterns("web[1-2],db[1-2]").unwrap();
        assert_eq!(result, vec!["web1", "web2", "db1", "db2"]);
    }

    #[test]
    fn test_expand_hostlist_patterns_with_whitespace() {
        let result = expand_hostlist_patterns("web[1-2], db[1-2]").unwrap();
        assert_eq!(result, vec!["web1", "web2", "db1", "db2"]);
    }

    #[test]
    fn test_expand_hostlist_patterns_deduplication() {
        let result = expand_hostlist_patterns("node[1-3],node[2-4]").unwrap();
        assert_eq!(result, vec!["node1", "node2", "node3", "node4"]);
    }

    #[test]
    fn test_split_patterns_simple() {
        let patterns = split_patterns("a,b,c").unwrap();
        assert_eq!(patterns, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_split_patterns_with_brackets() {
        let patterns = split_patterns("node[1,2,3],web[1-3]").unwrap();
        assert_eq!(patterns, vec!["node[1,2,3]", "web[1-3]"]);
    }

    #[test]
    fn test_split_patterns_unclosed_bracket() {
        let result = split_patterns("node[1-3");
        assert!(result.is_err());
    }

    #[test]
    fn test_split_patterns_unmatched_bracket() {
        let result = split_patterns("node]1-3[");
        assert!(result.is_err());
    }
}

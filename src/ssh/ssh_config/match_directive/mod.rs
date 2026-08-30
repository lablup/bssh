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

//! Match directive support for SSH configuration
//!
//! This module handles the Match directive which provides conditional configuration
//! based on various criteria like hostname, username, and command execution results.

use anyhow::Result;
use std::collections::HashMap;

use super::pattern::matches_host_pattern;

mod exec;

// Re-export exec functions
#[allow(unused_imports)]
pub use exec::{execute_match_command, expand_variables, validate_exec_command};

/// Match condition types supported by SSH
#[derive(Debug, Clone, PartialEq)]
pub enum MatchCondition {
    /// Match by hostname pattern
    Host(Vec<String>),
    /// Match by the destination name as written on the command line.
    OriginalHost(Vec<String>),
    /// Match by remote username
    User(Vec<String>),
    /// Match by local username
    LocalUser(Vec<String>),
    /// Match by command execution result
    Exec(String),
    /// Match all connections (always true)
    All,
    /// Negation of one Match attribute.
    Negated(Box<MatchCondition>),
}

/// A Match block with its conditions and configuration
#[derive(Debug, Clone)]
pub struct MatchBlock {
    /// Conditions that must all be satisfied (AND logic)
    pub conditions: Vec<MatchCondition>,
    /// Configuration options within this Match block
    pub config: super::types::SshHostConfig,
    /// Line number where this Match block starts (for debugging)
    #[allow(dead_code)]
    pub line_number: usize,
}

impl MatchBlock {
    /// Create a new Match block
    pub fn new(line_number: usize) -> Self {
        Self {
            conditions: Vec::new(),
            config: super::types::SshHostConfig::default(),
            line_number,
        }
    }

    /// Check if all conditions match for the given context
    pub fn matches(&self, context: &MatchContext) -> Result<bool> {
        // All conditions must match (AND logic)
        for condition in &self.conditions {
            if !condition.matches(context)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Context for evaluating Match conditions
#[derive(Debug, Clone)]
pub struct MatchContext {
    /// The hostname being connected to
    pub hostname: String,
    /// The destination name before applying `HostName`.
    pub original_hostname: String,
    /// The remote username (if specified)
    pub remote_user: Option<String>,
    /// The local username
    pub local_user: String,
    /// Additional context variables for exec commands
    pub variables: HashMap<String, String>,
}

impl MatchContext {
    /// Create a new match context
    pub fn new(hostname: String, remote_user: Option<String>) -> Result<Self> {
        Self::with_original_hostname(hostname.clone(), hostname, remote_user)
    }

    /// Create a context whose effective and original host names differ.
    pub fn with_original_hostname(
        hostname: String,
        original_hostname: String,
        remote_user: Option<String>,
    ) -> Result<Self> {
        // Get local username
        let local_user = whoami::username().unwrap_or_else(|_| "user".to_string());

        let mut variables = HashMap::new();
        variables.insert("h".to_string(), hostname.clone());
        variables.insert("host".to_string(), hostname.clone());
        variables.insert("l".to_string(), local_user.clone());
        variables.insert("localuser".to_string(), local_user.clone());

        if let Some(ref user) = remote_user {
            variables.insert("u".to_string(), user.clone());
            variables.insert("user".to_string(), user.clone());
        }

        Ok(Self {
            hostname,
            original_hostname,
            remote_user,
            local_user,
            variables,
        })
    }
}

impl MatchCondition {
    /// Parse a Match directive line into conditions
    pub fn parse_match_line(line: &str, line_number: usize) -> Result<Vec<MatchCondition>> {
        let line = line.trim();

        // Remove "Match" keyword (case-insensitive)
        let conditions_str = if line.to_lowercase().starts_with("match ") {
            &line[6..]
        } else if let Some(pos) = line.find('=') {
            // Match=conditions syntax
            if line[..pos].trim().to_lowercase() == "match" {
                line[pos + 1..].trim()
            } else {
                anyhow::bail!("Invalid Match directive at line {line_number}");
            }
        } else {
            anyhow::bail!("Invalid Match directive at line {line_number}");
        };

        if conditions_str.is_empty() {
            anyhow::bail!("Match directive requires conditions at line {line_number}");
        }
        let conditions_str = conditions_str
            .find(" #")
            .map_or(conditions_str, |comment| &conditions_str[..comment]);

        // Parse conditions
        let mut conditions = Vec::new();
        let mut parts = conditions_str.split_whitespace();

        while let Some(token) = parts.next() {
            let (keyword, attached_pattern) = token
                .split_once('=')
                .map_or((token, None), |(keyword, value)| (keyword, Some(value)));
            let (negated, keyword) = keyword
                .strip_prefix('!')
                .map_or((false, keyword), |keyword| (true, keyword));
            let keyword_lower = keyword.to_lowercase();

            match keyword_lower.as_str() {
                "host" => {
                    let patterns = collect_patterns(attached_pattern, &mut parts)?;
                    if patterns.is_empty() {
                        anyhow::bail!("Match host requires patterns at line {line_number}");
                    }
                    push_condition(&mut conditions, MatchCondition::Host(patterns), negated);
                }
                "originalhost" => {
                    let patterns = collect_patterns(attached_pattern, &mut parts)?;
                    if patterns.is_empty() {
                        anyhow::bail!("Match originalhost requires patterns at line {line_number}");
                    }
                    push_condition(
                        &mut conditions,
                        MatchCondition::OriginalHost(patterns),
                        negated,
                    );
                }
                "user" => {
                    let patterns = collect_patterns(attached_pattern, &mut parts)?;
                    if patterns.is_empty() {
                        anyhow::bail!("Match user requires patterns at line {line_number}");
                    }
                    push_condition(&mut conditions, MatchCondition::User(patterns), negated);
                }
                "localuser" => {
                    let patterns = collect_patterns(attached_pattern, &mut parts)?;
                    if patterns.is_empty() {
                        anyhow::bail!("Match localuser requires patterns at line {line_number}");
                    }
                    push_condition(
                        &mut conditions,
                        MatchCondition::LocalUser(patterns),
                        negated,
                    );
                }
                "exec" => {
                    // Exec condition takes the rest of the line as command
                    let remaining: Vec<&str> = parts.collect();
                    if remaining.is_empty() {
                        anyhow::bail!("Match exec requires a command at line {line_number}");
                    }

                    // Check if the command is quoted
                    let exec_part = conditions_str
                        [conditions_str.to_lowercase().find("exec").unwrap() + 4..]
                        .trim();
                    let command = if exec_part.starts_with('"') && exec_part.ends_with('"') {
                        // Remove quotes
                        exec_part[1..exec_part.len() - 1].to_string()
                    } else {
                        remaining.join(" ")
                    };

                    push_condition(&mut conditions, MatchCondition::Exec(command), negated);
                    break; // Exec consumes the rest of the line
                }
                "all" => {
                    push_condition(&mut conditions, MatchCondition::All, negated);
                }
                _ => {
                    anyhow::bail!("Unknown Match condition '{keyword}' at line {line_number}");
                }
            }
        }

        if conditions.is_empty() {
            anyhow::bail!("Match directive requires at least one condition at line {line_number}");
        }

        Ok(conditions)
    }

    /// Check if this condition matches the given context
    pub fn matches(&self, context: &MatchContext) -> Result<bool> {
        match self {
            MatchCondition::Host(patterns) => Ok(matches_host_pattern(&context.hostname, patterns)),
            MatchCondition::OriginalHost(patterns) => {
                Ok(matches_host_pattern(&context.original_hostname, patterns))
            }
            MatchCondition::User(patterns) => {
                // Check if remote username matches any of the patterns
                if let Some(ref user) = context.remote_user {
                    return Ok(matches_host_pattern(user, patterns));
                }
                Ok(false)
            }
            MatchCondition::LocalUser(patterns) => {
                // Check if local username matches any of the patterns
                Ok(matches_host_pattern(&context.local_user, patterns))
            }
            MatchCondition::Exec(command) => {
                // Execute the command and check exit status
                execute_match_command(command, context)
            }
            MatchCondition::All => {
                // Always matches
                Ok(true)
            }
            MatchCondition::Negated(condition) => Ok(!condition.matches(context)?),
        }
    }
}

fn push_condition(conditions: &mut Vec<MatchCondition>, condition: MatchCondition, negated: bool) {
    conditions.push(if negated {
        MatchCondition::Negated(Box::new(condition))
    } else {
        condition
    });
}

/// Collect patterns until the next keyword
fn collect_patterns(
    attached: Option<&str>,
    parts: &mut std::str::SplitWhitespace,
) -> Result<Vec<String>> {
    let mut patterns: Vec<String> = attached
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .split(',')
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // Peek at upcoming parts to collect patterns
    let remaining: Vec<&str> = parts.clone().collect();

    for part in remaining {
        // Stop if we hit another Match keyword
        let lower = part
            .split_once('=')
            .map_or(part, |(keyword, _)| keyword)
            .trim_start_matches('!')
            .to_lowercase();
        if matches!(
            lower.as_str(),
            "host" | "originalhost" | "user" | "localuser" | "exec" | "all"
        ) {
            break;
        }

        patterns.extend(
            part.split(',')
                .filter(|pattern| !pattern.is_empty())
                .map(str::to_string),
        );
        // Consume the part from the iterator
        parts.next();
    }

    Ok(patterns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_match_conditions() {
        // Test host condition
        let conditions = MatchCondition::parse_match_line("Match host *.example.com", 1).unwrap();
        assert_eq!(conditions.len(), 1);
        match &conditions[0] {
            MatchCondition::Host(patterns) => assert_eq!(patterns, &["*.example.com"]),
            _ => panic!("Expected Host condition"),
        }

        // Test multiple conditions
        let conditions =
            MatchCondition::parse_match_line("Match host *.example.com user admin", 1).unwrap();
        assert_eq!(conditions.len(), 2);

        // Test all condition
        let conditions = MatchCondition::parse_match_line("Match all", 1).unwrap();
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0], MatchCondition::All);

        // Test exec condition
        let conditions =
            MatchCondition::parse_match_line("Match exec \"test -f /tmp/vpn\"", 1).unwrap();
        assert_eq!(conditions.len(), 1);
        match &conditions[0] {
            MatchCondition::Exec(cmd) => assert_eq!(cmd, "test -f /tmp/vpn"),
            _ => panic!("Expected Exec condition"),
        }
    }

    #[test]
    fn test_match_host_condition() {
        let context =
            MatchContext::new("web1.example.com".to_string(), Some("testuser".to_string()))
                .unwrap();

        let condition = MatchCondition::Host(vec!["*.example.com".to_string()]);
        assert!(condition.matches(&context).unwrap());

        let condition = MatchCondition::Host(vec!["*.test.com".to_string()]);
        assert!(!condition.matches(&context).unwrap());
    }

    #[test]
    fn test_match_user_condition() {
        let context =
            MatchContext::new("example.com".to_string(), Some("admin".to_string())).unwrap();

        let condition = MatchCondition::User(vec!["admin".to_string()]);
        assert!(condition.matches(&context).unwrap());

        let condition = MatchCondition::User(vec!["root".to_string()]);
        assert!(!condition.matches(&context).unwrap());

        // Test with no remote user
        let context_no_user = MatchContext::new("example.com".to_string(), None).unwrap();

        let condition = MatchCondition::User(vec!["admin".to_string()]);
        assert!(!condition.matches(&context_no_user).unwrap());
    }

    #[test]
    fn test_match_localuser_condition() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();

        let local_user = whoami::username().unwrap();
        let condition = MatchCondition::LocalUser(vec![local_user.clone()]);
        assert!(condition.matches(&context).unwrap());

        let condition = MatchCondition::LocalUser(vec!["nonexistentuser12345".to_string()]);
        assert!(!condition.matches(&context).unwrap());
    }

    #[test]
    fn test_match_all_condition() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();

        let condition = MatchCondition::All;
        assert!(condition.matches(&context).unwrap());
    }

    #[test]
    fn test_match_block() {
        let mut block = MatchBlock::new(10);
        block
            .conditions
            .push(MatchCondition::Host(vec!["*.example.com".to_string()]));
        block
            .conditions
            .push(MatchCondition::User(vec!["admin".to_string()]));

        // Test matching context
        let context =
            MatchContext::new("web.example.com".to_string(), Some("admin".to_string())).unwrap();
        assert!(block.matches(&context).unwrap());

        // Test non-matching context (wrong user)
        let context =
            MatchContext::new("web.example.com".to_string(), Some("guest".to_string())).unwrap();
        assert!(!block.matches(&context).unwrap());

        // Test non-matching context (wrong host)
        let context =
            MatchContext::new("web.test.com".to_string(), Some("admin".to_string())).unwrap();
        assert!(!block.matches(&context).unwrap());
    }

    #[test]
    fn test_match_host_with_negation() {
        // A negated pattern vetoes a positive wildcard match.
        let context_internal =
            MatchContext::new("web.internal.com".to_string(), Some("testuser".to_string()))
                .unwrap();
        let context_external = MatchContext::new("web.example.com".to_string(), None).unwrap();

        // Negation pattern should NOT match internal hosts
        let condition = MatchCondition::Host(vec!["*".to_string(), "!*.internal.com".to_string()]);
        assert!(!condition.matches(&context_internal).unwrap());
        // But SHOULD match external hosts
        assert!(condition.matches(&context_external).unwrap());

        // Test wildcard negation
        let condition = MatchCondition::Host(vec!["*".to_string(), "!db*.example.com".to_string()]);
        let context_db = MatchContext::new("db1.example.com".to_string(), None).unwrap();
        let context_web = MatchContext::new("web.example.com".to_string(), None).unwrap();

        assert!(!condition.matches(&context_db).unwrap());
        assert!(condition.matches(&context_web).unwrap());

        // Test exact negation
        let condition =
            MatchCondition::Host(vec!["*".to_string(), "!production.example.com".to_string()]);
        let context_prod = MatchContext::new("production.example.com".to_string(), None).unwrap();
        let context_staging = MatchContext::new("staging.example.com".to_string(), None).unwrap();

        assert!(!condition.matches(&context_prod).unwrap());
        assert!(condition.matches(&context_staging).unwrap());
    }

    #[test]
    fn test_match_user_multiple_patterns() {
        let context =
            MatchContext::new("example.com".to_string(), Some("admin".to_string())).unwrap();

        // Test multiple user patterns (comma or space separated)
        let condition = MatchCondition::User(vec!["admin".to_string(), "root".to_string()]);
        assert!(condition.matches(&context).unwrap());

        let condition = MatchCondition::User(vec!["root".to_string(), "operator".to_string()]);
        assert!(!condition.matches(&context).unwrap());
    }

    #[test]
    fn test_match_localuser_with_wildcards() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();

        let local_user = whoami::username().unwrap();

        // Test wildcard pattern
        if local_user.len() > 2 {
            let pattern = format!("{}*", &local_user[..2]);
            let condition = MatchCondition::LocalUser(vec![pattern]);
            assert!(condition.matches(&context).unwrap());
        }

        // Test negation
        let condition =
            MatchCondition::LocalUser(vec!["*".to_string(), "!nonexistent*".to_string()]);
        assert!(condition.matches(&context).unwrap());
    }

    #[test]
    fn test_parse_match_complex_conditions() {
        // Test parsing with multiple complex conditions
        let conditions = MatchCondition::parse_match_line(
            "Match host *.example.com,!db*.example.com user admin,root",
            1,
        )
        .unwrap();
        assert_eq!(conditions.len(), 2);

        // Test exec with variables
        let conditions =
            MatchCondition::parse_match_line("Match exec \"test -f /tmp/%h.lock\"", 1).unwrap();
        assert_eq!(conditions.len(), 1);
        match &conditions[0] {
            MatchCondition::Exec(cmd) => assert!(cmd.contains("%h")),
            _ => panic!("Expected Exec condition"),
        }
    }

    #[test]
    fn test_match_block_all_conditions() {
        // Test Match all alone (should match everything)
        let mut block = MatchBlock::new(10);
        block.conditions.push(MatchCondition::All);

        let context1 = MatchContext::new("anything.com".to_string(), None).unwrap();
        let context2 =
            MatchContext::new("example.com".to_string(), Some("admin".to_string())).unwrap();

        // All condition should match any context
        assert!(block.matches(&context1).unwrap());
        assert!(block.matches(&context2).unwrap());

        // Test that All with other conditions uses AND logic
        // (Per SSH spec, 'all' should typically be alone, but if combined, all conditions must match)
        let mut block2 = MatchBlock::new(10);
        block2.conditions.push(MatchCondition::All);
        block2
            .conditions
            .push(MatchCondition::Host(vec!["*.example.com".to_string()]));

        let context_match = MatchContext::new("web.example.com".to_string(), None).unwrap();
        let context_nomatch = MatchContext::new("web.other.com".to_string(), None).unwrap();

        // Should match only if both All (always true) AND Host pattern match
        assert!(block2.matches(&context_match).unwrap());
        assert!(!block2.matches(&context_nomatch).unwrap());
    }
}

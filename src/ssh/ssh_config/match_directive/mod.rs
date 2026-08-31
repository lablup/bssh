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

use anyhow::{Context, Result};
use sha1::{Digest, Sha1};
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
    /// Match the explicit final configuration pass.
    Final,
    /// Match the canonical/final pass without requesting it.
    Canonical,
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
        Ok(self.evaluate(context)?.matched)
    }

    /// Evaluate conditions in source order and carry the separately parsed
    /// positive-`final` request bit.
    pub(crate) fn evaluate(&self, context: &MatchContext) -> Result<MatchEvaluation> {
        // OpenSSH records a positive `final` attribute while parsing the whole
        // Match line, even when an earlier runtime predicate is false. A
        // negated `!final` never requests the extra pass.
        let requests_final = self
            .conditions
            .iter()
            .any(MatchCondition::requests_final_pass);
        for condition in &self.conditions {
            if !condition.matches(context)? {
                return Ok(MatchEvaluation {
                    matched: false,
                    requests_final,
                });
            }
        }
        Ok(MatchEvaluation {
            matched: true,
            requests_final,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MatchEvaluation {
    pub(crate) matched: bool,
    pub(crate) requests_final: bool,
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
    /// Whether this is OpenSSH's requested final configuration pass.
    pub final_pass: bool,
    /// Host-aware `-G` preprocessing is the only path authorized to use
    /// OpenSSH-compatible shell evaluation for trusted configuration.
    exec_policy: ExecPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ExecPolicy {
    #[default]
    Direct,
    TrustedShell,
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
        let local_user = whoami::username().unwrap_or_else(|_| "user".to_string());
        let remote_user = remote_user.or_else(|| Some(local_user.clone()));
        let local_host = whoami::hostname().unwrap_or_else(|_| "localhost".to_string());
        let local_host_short = local_host
            .split('.')
            .next()
            .unwrap_or(&local_host)
            .to_string();
        let local_home = dirs::home_dir()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        let mut variables = HashMap::new();
        variables.insert("h".to_string(), hostname.clone());
        variables.insert("host".to_string(), hostname.clone());
        variables.insert("n".to_string(), original_hostname.clone());
        variables.insert("u".to_string(), local_user.clone());
        variables.insert("l".to_string(), local_host.clone());
        variables.insert("L".to_string(), local_host_short);
        variables.insert("d".to_string(), local_home);
        variables.insert("i".to_string(), local_uid());
        variables.insert("p".to_string(), "22".to_string());
        variables.insert("k".to_string(), original_hostname.clone());
        variables.insert("j".to_string(), String::new());
        variables.insert("localuser".to_string(), local_user.clone());

        if let Some(ref user) = remote_user {
            variables.insert("r".to_string(), user.clone());
            variables.insert("user".to_string(), user.clone());
        }

        Ok(Self {
            hostname,
            original_hostname,
            remote_user,
            local_user,
            variables,
            final_pass: false,
            exec_policy: ExecPolicy::Direct,
        })
    }

    pub fn with_final_pass(mut self, final_pass: bool) -> Self {
        self.final_pass = final_pass;
        self
    }

    pub(super) fn with_trusted_shell_exec(mut self) -> Self {
        self.exec_policy = ExecPolicy::TrustedShell;
        self
    }

    pub(super) fn with_config(mut self, config: &super::types::SshHostConfig) -> Self {
        let port = config.port.unwrap_or(22).to_string();
        let key_alias = config
            .host_key_alias
            .clone()
            .unwrap_or_else(|| self.original_hostname.clone());
        let jump = config.proxy_jump.clone().unwrap_or_default();
        self.variables.insert("p".to_string(), port.clone());
        self.variables.insert("k".to_string(), key_alias);
        self.variables.insert("j".to_string(), jump.clone());

        let mut digest = Sha1::new();
        digest.update(self.variables["l"].as_bytes());
        digest.update(self.hostname.as_bytes());
        digest.update(port.as_bytes());
        digest.update(self.variables["r"].as_bytes());
        digest.update(jump.as_bytes());
        self.variables.insert(
            "C".to_string(),
            digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
        self
    }
}

#[cfg(unix)]
fn local_uid() -> String {
    // SAFETY: getuid has no arguments, dereferences no pointers, and cannot fail.
    unsafe { libc::getuid() }.to_string()
}

#[cfg(not(unix))]
fn local_uid() -> String {
    "0".to_string()
}

impl MatchCondition {
    /// Parse a Match directive line into conditions
    pub fn parse_match_line(line: &str, line_number: usize) -> Result<Vec<MatchCondition>> {
        let line = line.trim();
        let boundary = line
            .char_indices()
            .find(|(_, ch)| ch.is_whitespace() || *ch == '=');
        let Some((index, delimiter)) = boundary else {
            anyhow::bail!("Invalid Match directive at line {line_number}");
        };
        if !line[..index].eq_ignore_ascii_case("match") {
            anyhow::bail!("Invalid Match directive at line {line_number}");
        }
        let remainder = line[index + delimiter.len_utf8()..].trim_start();
        let tokens = super::value::tokenize(remainder, line_number)?;
        if tokens.is_empty() {
            anyhow::bail!("Match directive requires conditions at line {line_number}");
        }
        let mut conditions = Vec::new();
        let mut position = 0usize;
        while position < tokens.len() {
            let token = tokens[position].as_str();
            position += 1;
            let (keyword, attached_pattern) = token
                .split_once('=')
                .map_or((token, None), |(keyword, value)| (keyword, Some(value)));
            let (negated, keyword) = keyword
                .strip_prefix('!')
                .map_or((false, keyword), |keyword| (true, keyword));
            let keyword_lower = keyword.to_lowercase();

            match keyword_lower.as_str() {
                "host" => {
                    let patterns = collect_patterns(attached_pattern, &tokens, &mut position);
                    if patterns.is_empty() {
                        anyhow::bail!("Match host requires patterns at line {line_number}");
                    }
                    push_condition(&mut conditions, MatchCondition::Host(patterns), negated);
                }
                "originalhost" => {
                    let patterns = collect_patterns(attached_pattern, &tokens, &mut position);
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
                    let patterns = collect_patterns(attached_pattern, &tokens, &mut position);
                    if patterns.is_empty() {
                        anyhow::bail!("Match user requires patterns at line {line_number}");
                    }
                    push_condition(&mut conditions, MatchCondition::User(patterns), negated);
                }
                "localuser" => {
                    let patterns = collect_patterns(attached_pattern, &tokens, &mut position);
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
                    let command = attached_pattern
                        .filter(|command| !command.is_empty())
                        .map(str::to_string)
                        .or_else(|| {
                            let command = tokens.get(position).cloned();
                            position += usize::from(command.is_some());
                            command
                        })
                        .with_context(|| {
                            format!("Match exec requires a command at line {line_number}")
                        })?;
                    push_condition(&mut conditions, MatchCondition::Exec(command), negated);
                }
                "all" => {
                    push_condition(&mut conditions, MatchCondition::All, negated);
                }
                "final" => {
                    push_condition(&mut conditions, MatchCondition::Final, negated);
                }
                "canonical" => {
                    push_condition(&mut conditions, MatchCondition::Canonical, negated);
                }
                _ => {
                    anyhow::bail!("Unknown Match condition '{keyword}' at line {line_number}");
                }
            }
        }

        if conditions.is_empty() {
            anyhow::bail!("Match directive requires at least one condition at line {line_number}");
        }
        if conditions.iter().any(|condition| {
            matches!(condition, MatchCondition::All)
                || matches!(condition, MatchCondition::Negated(inner) if matches!(inner.as_ref(), MatchCondition::All))
        }) && (conditions.len() != 1 || !matches!(conditions[0], MatchCondition::All))
        {
            anyhow::bail!("Match all must appear alone and non-negated at line {line_number}");
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
            MatchCondition::Exec(command) => match context.exec_policy {
                ExecPolicy::Direct => exec::execute_match_command_direct(command, context),
                ExecPolicy::TrustedShell => execute_match_command(command, context),
            },
            MatchCondition::All => {
                // Always matches
                Ok(true)
            }
            MatchCondition::Final | MatchCondition::Canonical => Ok(context.final_pass),
            MatchCondition::Negated(condition) => Ok(!condition.matches(context)?),
        }
    }

    pub(crate) fn requests_final_pass(&self) -> bool {
        matches!(self, MatchCondition::Final)
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
    tokens: &[String],
    position: &mut usize,
) -> Vec<String> {
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

    while let Some(part) = tokens.get(*position) {
        let lower = part
            .as_str()
            .split_once('=')
            .map_or(part.as_str(), |(keyword, _)| keyword)
            .trim_start_matches('!')
            .to_lowercase();
        if matches!(
            lower.as_str(),
            "host" | "originalhost" | "user" | "localuser" | "exec" | "all" | "final" | "canonical"
        ) {
            break;
        }

        patterns.extend(
            part.split(',')
                .filter(|pattern| !pattern.is_empty())
                .map(str::to_string),
        );
        *position += 1;
    }
    patterns
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

        let conditions = MatchCondition::parse_match_line("Match all\t# comment", 1).unwrap();
        assert_eq!(conditions, [MatchCondition::All]);

        let conditions = MatchCondition::parse_match_line("Match exec=\"test x = x\"", 1).unwrap();
        assert_eq!(conditions, [MatchCondition::Exec("test x = x".to_string())]);

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
    fn match_all_must_be_standalone_and_non_negated() {
        assert!(MatchCondition::parse_match_line("Match all", 1).is_ok());
        assert!(MatchCondition::parse_match_line("Match all user deploy", 1).is_err());
        assert!(MatchCondition::parse_match_line("Match !all", 1).is_err());
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

    #[test]
    #[cfg(unix)]
    fn trusted_shell_policy_is_explicit_and_negated_exec_is_preserved() {
        let direct = MatchContext::new("example.com".to_string(), None).unwrap();
        let shell = direct.clone().with_trusted_shell_exec();
        let shell_expression = MatchCondition::Exec("false || true".to_string());
        assert!(shell_expression.matches(&direct).is_err());
        assert!(shell_expression.matches(&shell).unwrap());

        let negated_false =
            MatchCondition::Negated(Box::new(MatchCondition::Exec("false".to_string())));
        let negated_true =
            MatchCondition::Negated(Box::new(MatchCondition::Exec("true".to_string())));
        assert!(negated_false.matches(&shell).unwrap());
        assert!(!negated_true.matches(&shell).unwrap());
    }

    #[test]
    fn only_positive_final_requests_the_second_pass() {
        let context = MatchContext::new("example.com".to_string(), None).unwrap();
        let positive_after_false = MatchBlock {
            conditions: vec![
                MatchCondition::Host(vec!["no-match".to_string()]),
                MatchCondition::Final,
            ],
            config: super::super::types::SshHostConfig::default(),
            line_number: 1,
        };
        let evaluation = positive_after_false.evaluate(&context).unwrap();
        assert!(!evaluation.matched);
        assert!(evaluation.requests_final);

        let negated = MatchBlock {
            conditions: vec![MatchCondition::Negated(Box::new(MatchCondition::Final))],
            config: super::super::types::SshHostConfig::default(),
            line_number: 1,
        };
        let evaluation = negated.evaluate(&context).unwrap();
        assert!(evaluation.matched);
        assert!(!evaluation.requests_final);
    }
}

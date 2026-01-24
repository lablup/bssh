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

//! Filter policy engine.
//!
//! This module implements the core policy evaluation logic for file transfer filtering.
//! Policies consist of ordered rules that are evaluated in sequence until a match is found.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use super::{FilterResult, Operation, TransferFilter};
use crate::server::config::{FilterAction, FilterConfig, FilterRule as FilterRuleConfig};
use crate::server::filter::path::PrefixMatcher;
use crate::server::filter::pattern::GlobMatcher;

/// Trait for path matchers.
///
/// Implement this trait to create custom pattern matching logic for filter rules.
pub trait Matcher: Send + Sync + fmt::Debug {
    /// Check if the given path matches this matcher's pattern.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path to check
    ///
    /// # Returns
    ///
    /// `true` if the path matches the pattern, `false` otherwise.
    fn matches(&self, path: &Path) -> bool;

    /// Clone the matcher into a boxed trait object.
    fn clone_box(&self) -> Box<dyn Matcher>;

    /// Returns a description of the pattern for logging/debugging.
    fn pattern_description(&self) -> String;
}

impl Clone for Box<dyn Matcher> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// A single filter rule.
///
/// Rules combine a matcher with an action and optional constraints on
/// which operations and users the rule applies to.
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// Rule name (for logging and debugging).
    pub name: Option<String>,

    /// Pattern matcher for file paths.
    pub matcher: Box<dyn Matcher>,

    /// Action to take when the rule matches.
    pub action: FilterResult,

    /// Operations this rule applies to.
    /// If `None`, the rule applies to all operations.
    pub operations: Option<Vec<Operation>>,

    /// Users this rule applies to.
    /// If `None`, the rule applies to all users.
    pub users: Option<Vec<String>>,
}

impl FilterRule {
    /// Create a new filter rule with just a matcher and action.
    pub fn new(matcher: Box<dyn Matcher>, action: FilterResult) -> Self {
        Self {
            name: None,
            matcher,
            action,
            operations: None,
            users: None,
        }
    }

    /// Set the rule name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Limit the rule to specific operations.
    pub fn with_operations(mut self, operations: Vec<Operation>) -> Self {
        self.operations = Some(operations);
        self
    }

    /// Limit the rule to specific users.
    pub fn with_users(mut self, users: Vec<String>) -> Self {
        self.users = Some(users);
        self
    }

    /// Check if this rule applies to the given operation.
    fn applies_to_operation(&self, operation: Operation) -> bool {
        match &self.operations {
            Some(ops) => ops.contains(&operation),
            None => true,
        }
    }

    /// Check if this rule applies to the given user.
    fn applies_to_user(&self, user: &str) -> bool {
        match &self.users {
            Some(users) => users.iter().any(|u| u == user),
            None => true,
        }
    }

    /// Check if this rule matches the given path, operation, and user.
    pub fn matches(&self, path: &Path, operation: Operation, user: &str) -> bool {
        self.applies_to_operation(operation)
            && self.applies_to_user(user)
            && self.matcher.matches(path)
    }
}

/// Filter policy engine.
///
/// The policy engine evaluates an ordered list of rules against file operations.
/// Rules are evaluated in order, and the first matching rule determines the action.
/// If no rules match, the default action is used.
#[derive(Debug, Clone)]
pub struct FilterPolicy {
    /// Ordered list of filter rules.
    rules: Vec<FilterRule>,

    /// Default action when no rules match.
    default_action: FilterResult,

    /// Whether filtering is enabled.
    enabled: bool,
}

impl Default for FilterPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterPolicy {
    /// Create a new empty filter policy with Allow as the default action.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: FilterResult::Allow,
            enabled: true,
        }
    }

    /// Set the default action for when no rules match.
    pub fn with_default(mut self, action: FilterResult) -> Self {
        self.default_action = action;
        self
    }

    /// Set whether filtering is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Add a rule to the policy.
    ///
    /// Rules are evaluated in the order they are added.
    pub fn add_rule(mut self, rule: FilterRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Add multiple rules to the policy.
    pub fn add_rules(mut self, rules: impl IntoIterator<Item = FilterRule>) -> Self {
        self.rules.extend(rules);
        self
    }

    /// Get the number of rules in this policy.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get the default action.
    pub fn default_action(&self) -> FilterResult {
        self.default_action
    }

    /// Create a policy from configuration.
    ///
    /// Parses the filter configuration and creates matchers for each rule.
    pub fn from_config(config: &FilterConfig) -> Result<Self> {
        let mut policy = Self::new().with_enabled(config.enabled);

        if let Some(ref default) = config.default_action {
            policy.default_action = match default {
                FilterAction::Allow => FilterResult::Allow,
                FilterAction::Deny => FilterResult::Deny,
                FilterAction::Log => FilterResult::Log,
            };
        }

        for rule_config in &config.rules {
            let rule = Self::rule_from_config(rule_config)?;
            policy.rules.push(rule);
        }

        Ok(policy)
    }

    /// Create a rule from configuration.
    fn rule_from_config(config: &FilterRuleConfig) -> Result<FilterRule> {
        // Create matcher based on config
        let matcher: Box<dyn Matcher> = if let Some(ref pattern) = config.pattern.as_ref() {
            Box::new(
                GlobMatcher::new(pattern)
                    .with_context(|| format!("Invalid glob pattern: {}", pattern))?,
            )
        } else if let Some(ref prefix) = config.path_prefix.as_ref() {
            Box::new(PrefixMatcher::new(prefix.as_str()))
        } else {
            anyhow::bail!("Filter rule must have either 'pattern' or 'path_prefix'");
        };

        // Convert action
        let action = match config.action {
            FilterAction::Allow => FilterResult::Allow,
            FilterAction::Deny => FilterResult::Deny,
            FilterAction::Log => FilterResult::Log,
        };

        // Parse operations if specified
        let operations: Option<Vec<Operation>> = config.operations.as_ref().map(|ops: &Vec<String>| {
            ops.iter()
                .filter_map(|op: &String| {
                    op.parse::<Operation>()
                        .map_err(|e| {
                            tracing::warn!("Unknown operation '{}' in filter config: {}", op, e);
                            e
                        })
                        .ok()
                })
                .collect()
        });

        Ok(FilterRule {
            name: config.name.clone(),
            matcher,
            action,
            operations,
            users: config.users.clone(),
        })
    }
}

impl TransferFilter for FilterPolicy {
    fn check(&self, path: &Path, operation: Operation, user: &str) -> FilterResult {
        if !self.enabled {
            return FilterResult::Allow;
        }

        for rule in &self.rules {
            if rule.matches(path, operation, user) {
                tracing::debug!(
                    rule_name = ?rule.name,
                    path = %path.display(),
                    operation = %operation,
                    user = %user,
                    action = %rule.action,
                    pattern = %rule.matcher.pattern_description(),
                    "Filter rule matched"
                );
                return rule.action;
            }
        }

        tracing::trace!(
            path = %path.display(),
            operation = %operation,
            user = %user,
            action = %self.default_action,
            "No filter rule matched, using default action"
        );

        self.default_action
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// A thread-safe, shared filter policy.
///
/// Use this when you need to share a filter policy across multiple handlers.
#[derive(Debug, Clone)]
pub struct SharedFilterPolicy {
    inner: Arc<FilterPolicy>,
}

impl SharedFilterPolicy {
    /// Create a new shared filter policy.
    pub fn new(policy: FilterPolicy) -> Self {
        Self {
            inner: Arc::new(policy),
        }
    }

    /// Get a reference to the inner policy.
    pub fn policy(&self) -> &FilterPolicy {
        &self.inner
    }
}

impl TransferFilter for SharedFilterPolicy {
    fn check(&self, path: &Path, operation: Operation, user: &str) -> FilterResult {
        self.inner.check(path, operation, user)
    }

    fn check_with_dest(
        &self,
        src: &Path,
        dest: &Path,
        operation: Operation,
        user: &str,
    ) -> FilterResult {
        self.inner.check_with_dest(src, dest, operation, user)
    }

    fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }
}

impl From<FilterPolicy> for SharedFilterPolicy {
    fn from(policy: FilterPolicy) -> Self {
        SharedFilterPolicy::new(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::filter::path::ExactMatcher;

    #[test]
    fn test_filter_rule_creation() {
        let rule = FilterRule::new(
            Box::new(GlobMatcher::new("*.key").unwrap()),
            FilterResult::Deny,
        )
        .with_name("block-keys")
        .with_operations(vec![Operation::Download, Operation::Upload]);

        assert_eq!(rule.name, Some("block-keys".to_string()));
        assert_eq!(rule.action, FilterResult::Deny);
        assert_eq!(
            rule.operations,
            Some(vec![Operation::Download, Operation::Upload])
        );
    }

    #[test]
    fn test_rule_matches_operation() {
        let rule = FilterRule::new(
            Box::new(GlobMatcher::new("*").unwrap()),
            FilterResult::Deny,
        )
        .with_operations(vec![Operation::Upload]);

        assert!(rule.applies_to_operation(Operation::Upload));
        assert!(!rule.applies_to_operation(Operation::Download));
    }

    #[test]
    fn test_rule_matches_user() {
        let rule = FilterRule::new(
            Box::new(GlobMatcher::new("*").unwrap()),
            FilterResult::Deny,
        )
        .with_users(vec!["alice".to_string(), "bob".to_string()]);

        assert!(rule.applies_to_user("alice"));
        assert!(rule.applies_to_user("bob"));
        assert!(!rule.applies_to_user("charlie"));
    }

    #[test]
    fn test_policy_default_allow() {
        let policy = FilterPolicy::new();

        assert_eq!(
            policy.check(Path::new("/any/path"), Operation::Upload, "user"),
            FilterResult::Allow
        );
    }

    #[test]
    fn test_policy_default_deny() {
        let policy = FilterPolicy::new().with_default(FilterResult::Deny);

        assert_eq!(
            policy.check(Path::new("/any/path"), Operation::Upload, "user"),
            FilterResult::Deny
        );
    }

    #[test]
    fn test_policy_rule_matching() {
        let policy = FilterPolicy::new()
            .add_rule(FilterRule::new(
                Box::new(GlobMatcher::new("*.key").unwrap()),
                FilterResult::Deny,
            ))
            .add_rule(FilterRule::new(
                Box::new(GlobMatcher::new("*.log").unwrap()),
                FilterResult::Log,
            ));

        assert_eq!(
            policy.check(Path::new("/etc/secret.key"), Operation::Download, "user"),
            FilterResult::Deny
        );
        assert_eq!(
            policy.check(Path::new("/var/log/app.log"), Operation::Download, "user"),
            FilterResult::Log
        );
        assert_eq!(
            policy.check(Path::new("/home/user/file.txt"), Operation::Download, "user"),
            FilterResult::Allow
        );
    }

    #[test]
    fn test_policy_first_match_wins() {
        let policy = FilterPolicy::new()
            .add_rule(FilterRule::new(
                Box::new(GlobMatcher::new("*.key").unwrap()),
                FilterResult::Allow,
            ))
            .add_rule(FilterRule::new(
                Box::new(GlobMatcher::new("*").unwrap()),
                FilterResult::Deny,
            ));

        // *.key matches first, so Allow
        assert_eq!(
            policy.check(Path::new("/etc/secret.key"), Operation::Download, "user"),
            FilterResult::Allow
        );
    }

    #[test]
    fn test_policy_with_user_restriction() {
        let policy = FilterPolicy::new()
            .add_rule(
                FilterRule::new(
                    Box::new(PrefixMatcher::new("/admin")),
                    FilterResult::Deny,
                )
                .with_users(vec!["guest".to_string()]),
            )
            .with_default(FilterResult::Allow);

        // Guest user is denied
        assert_eq!(
            policy.check(Path::new("/admin/config"), Operation::Download, "guest"),
            FilterResult::Deny
        );
        // Admin user is allowed
        assert_eq!(
            policy.check(Path::new("/admin/config"), Operation::Download, "admin"),
            FilterResult::Allow
        );
    }

    #[test]
    fn test_policy_with_operation_restriction() {
        let policy = FilterPolicy::new()
            .add_rule(
                FilterRule::new(
                    Box::new(GlobMatcher::new("*.log").unwrap()),
                    FilterResult::Deny,
                )
                .with_operations(vec![Operation::Delete]),
            )
            .with_default(FilterResult::Allow);

        // Delete is denied
        assert_eq!(
            policy.check(Path::new("/var/app.log"), Operation::Delete, "user"),
            FilterResult::Deny
        );
        // Download is allowed
        assert_eq!(
            policy.check(Path::new("/var/app.log"), Operation::Download, "user"),
            FilterResult::Allow
        );
    }

    #[test]
    fn test_policy_disabled() {
        let policy = FilterPolicy::new()
            .with_enabled(false)
            .with_default(FilterResult::Deny)
            .add_rule(FilterRule::new(
                Box::new(GlobMatcher::new("*").unwrap()),
                FilterResult::Deny,
            ));

        // When disabled, always allow
        assert_eq!(
            policy.check(Path::new("/any/path"), Operation::Upload, "user"),
            FilterResult::Allow
        );
        assert!(!policy.is_enabled());
    }

    #[test]
    fn test_shared_filter_policy() {
        let policy = FilterPolicy::new().add_rule(FilterRule::new(
            Box::new(GlobMatcher::new("*.key").unwrap()),
            FilterResult::Deny,
        ));

        let shared = SharedFilterPolicy::new(policy);

        assert_eq!(
            shared.check(Path::new("/etc/secret.key"), Operation::Download, "user"),
            FilterResult::Deny
        );
        assert_eq!(
            shared.check(Path::new("/home/file.txt"), Operation::Download, "user"),
            FilterResult::Allow
        );
    }

    #[test]
    fn test_exact_matcher() {
        let policy = FilterPolicy::new().add_rule(FilterRule::new(
            Box::new(ExactMatcher::new("/etc/passwd")),
            FilterResult::Deny,
        ));

        assert_eq!(
            policy.check(Path::new("/etc/passwd"), Operation::Download, "user"),
            FilterResult::Deny
        );
        assert_eq!(
            policy.check(Path::new("/etc/passwd.bak"), Operation::Download, "user"),
            FilterResult::Allow
        );
    }
}

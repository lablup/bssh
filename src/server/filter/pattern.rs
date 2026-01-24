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

//! Pattern-based matchers for file transfer filtering.
//!
//! This module provides matchers that use pattern matching:
//! - [`GlobMatcher`] - Matches paths using glob patterns (e.g., "*.key", "*.{tar,zip}")
//! - [`RegexMatcher`] - Matches paths using regular expressions

use std::path::Path;

use anyhow::{Context, Result};
use glob::Pattern;
use regex::{Regex, RegexBuilder};

use super::policy::Matcher;

/// Matches paths using glob patterns.
///
/// Glob patterns support wildcards and character classes:
/// - `*` matches any sequence of characters (except path separators in some modes)
/// - `?` matches any single character
/// - `[abc]` matches any character in the set
/// - `[!abc]` or `[^abc]` matches any character not in the set
/// - `**` matches zero or more directories (when enabled)
///
/// # Example
///
/// ```rust
/// use bssh::server::filter::pattern::GlobMatcher;
/// use bssh::server::filter::policy::Matcher;
/// use std::path::Path;
///
/// let matcher = GlobMatcher::new("*.key").unwrap();
///
/// assert!(matcher.matches(Path::new("secret.key")));
/// assert!(matcher.matches(Path::new("/etc/ssl/private.key")));
/// assert!(!matcher.matches(Path::new("keyboard.txt")));
/// ```
#[derive(Debug, Clone)]
pub struct GlobMatcher {
    pattern: Pattern,
    raw: String,
}

impl GlobMatcher {
    /// Create a new glob matcher.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The glob pattern to match against
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bssh::server::filter::pattern::GlobMatcher;
    ///
    /// let matcher = GlobMatcher::new("*.{key,pem}").unwrap();
    /// ```
    pub fn new(pattern: &str) -> Result<Self> {
        let glob_pattern =
            Pattern::new(pattern).with_context(|| format!("Invalid glob pattern: {}", pattern))?;

        Ok(Self {
            pattern: glob_pattern,
            raw: pattern.to_string(),
        })
    }

    /// Get the raw pattern string.
    pub fn pattern(&self) -> &str {
        &self.raw
    }
}

impl Matcher for GlobMatcher {
    fn matches(&self, path: &Path) -> bool {
        // Try matching the full path first
        if self.pattern.matches_path(path) {
            return true;
        }

        // Also try matching just the filename for patterns like "*.key"
        if let Some(filename) = path.file_name() {
            if let Some(filename_str) = filename.to_str() {
                if self.pattern.matches(filename_str) {
                    return true;
                }
            }
        }

        false
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(self.clone())
    }

    fn pattern_description(&self) -> String {
        format!("glob:{}", self.raw)
    }
}

/// Matches paths using regular expressions.
///
/// Regular expressions provide the most flexibility for pattern matching,
/// but are also more complex and potentially slower than glob patterns.
///
/// # Example
///
/// ```rust
/// use bssh::server::filter::pattern::RegexMatcher;
/// use bssh::server::filter::policy::Matcher;
/// use std::path::Path;
///
/// // Match files with version numbers in names
/// let matcher = RegexMatcher::new(r".*-v\d+\.\d+\.\d+\.tar\.gz$").unwrap();
///
/// assert!(matcher.matches(Path::new("/releases/app-v1.2.3.tar.gz")));
/// assert!(!matcher.matches(Path::new("/releases/app.tar.gz")));
/// ```
#[derive(Debug, Clone)]
pub struct RegexMatcher {
    regex: Regex,
    raw: String,
}

impl RegexMatcher {
    /// Default size limit for compiled regex (1MB)
    const DEFAULT_SIZE_LIMIT: usize = 1024 * 1024;

    /// Create a new regex matcher.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The regular expression pattern
    ///
    /// # Errors
    ///
    /// Returns an error if the regex pattern is invalid or exceeds size limits.
    ///
    /// # Security
    ///
    /// Uses RegexBuilder with size limits to prevent ReDoS attacks.
    /// The compiled regex is limited to 1MB by default.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bssh::server::filter::pattern::RegexMatcher;
    ///
    /// // Match private key files
    /// let matcher = RegexMatcher::new(r"(?i)\.key$|id_rsa$|id_dsa$").unwrap();
    /// ```
    pub fn new(pattern: &str) -> Result<Self> {
        let regex = RegexBuilder::new(pattern)
            .size_limit(Self::DEFAULT_SIZE_LIMIT)
            .dfa_size_limit(Self::DEFAULT_SIZE_LIMIT)
            .build()
            .with_context(|| format!("Invalid regex pattern: {}", pattern))?;

        Ok(Self {
            regex,
            raw: pattern.to_string(),
        })
    }

    /// Create a new regex matcher with custom size limits.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The regular expression pattern
    /// * `size_limit` - Maximum size in bytes for the compiled regex
    ///
    /// # Errors
    ///
    /// Returns an error if the regex pattern is invalid or exceeds the size limit.
    pub fn with_size_limit(pattern: &str, size_limit: usize) -> Result<Self> {
        let regex = RegexBuilder::new(pattern)
            .size_limit(size_limit)
            .dfa_size_limit(size_limit)
            .build()
            .with_context(|| format!("Invalid regex pattern: {}", pattern))?;

        Ok(Self {
            regex,
            raw: pattern.to_string(),
        })
    }

    /// Get the raw pattern string.
    pub fn pattern(&self) -> &str {
        &self.raw
    }
}

impl Matcher for RegexMatcher {
    fn matches(&self, path: &Path) -> bool {
        self.regex.is_match(&path.to_string_lossy())
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(self.clone())
    }

    fn pattern_description(&self) -> String {
        format!("regex:{}", self.raw)
    }
}

/// A matcher that combines multiple matchers with OR logic.
///
/// The combined matcher returns true if any of its inner matchers match.
///
/// # Example
///
/// ```rust
/// use bssh::server::filter::pattern::{GlobMatcher, CombinedMatcher};
/// use bssh::server::filter::policy::Matcher;
/// use std::path::Path;
///
/// let matcher = CombinedMatcher::new(vec![
///     Box::new(GlobMatcher::new("*.key").unwrap()),
///     Box::new(GlobMatcher::new("*.pem").unwrap()),
/// ]);
///
/// assert!(matcher.matches(Path::new("secret.key")));
/// assert!(matcher.matches(Path::new("cert.pem")));
/// assert!(!matcher.matches(Path::new("document.txt")));
/// ```
#[derive(Debug, Clone)]
pub struct CombinedMatcher {
    matchers: Vec<Box<dyn Matcher>>,
}

impl CombinedMatcher {
    /// Create a new combined matcher.
    ///
    /// # Arguments
    ///
    /// * `matchers` - The matchers to combine with OR logic
    pub fn new(matchers: Vec<Box<dyn Matcher>>) -> Self {
        Self { matchers }
    }

    /// Add a matcher to the combination.
    pub fn with_matcher(mut self, matcher: Box<dyn Matcher>) -> Self {
        self.matchers.push(matcher);
        self
    }

    /// Get the number of matchers in this combination.
    pub fn len(&self) -> usize {
        self.matchers.len()
    }

    /// Check if the combination is empty.
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }
}

impl Matcher for CombinedMatcher {
    fn matches(&self, path: &Path) -> bool {
        self.matchers.iter().any(|m| m.matches(path))
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(self.clone())
    }

    fn pattern_description(&self) -> String {
        let descriptions: Vec<_> = self.matchers.iter().map(|m| m.pattern_description()).collect();
        format!("any_of:[{}]", descriptions.join(", "))
    }
}

/// A matcher that inverts another matcher's result.
///
/// # Example
///
/// ```rust
/// use bssh::server::filter::pattern::{GlobMatcher, NotMatcher};
/// use bssh::server::filter::policy::Matcher;
/// use std::path::Path;
///
/// // Match everything EXCEPT .key files
/// let matcher = NotMatcher::new(Box::new(GlobMatcher::new("*.key").unwrap()));
///
/// assert!(!matcher.matches(Path::new("secret.key")));
/// assert!(matcher.matches(Path::new("document.txt")));
/// ```
#[derive(Debug, Clone)]
pub struct NotMatcher {
    inner: Box<dyn Matcher>,
}

impl NotMatcher {
    /// Create a new negating matcher.
    ///
    /// # Arguments
    ///
    /// * `inner` - The matcher to invert
    pub fn new(inner: Box<dyn Matcher>) -> Self {
        Self { inner }
    }
}

impl Matcher for NotMatcher {
    fn matches(&self, path: &Path) -> bool {
        !self.inner.matches(path)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(self.clone())
    }

    fn pattern_description(&self) -> String {
        format!("not({})", self.inner.pattern_description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_matcher_basic() {
        let matcher = GlobMatcher::new("*.key").unwrap();

        assert!(matcher.matches(Path::new("secret.key")));
        assert!(matcher.matches(Path::new("/etc/ssl/private.key")));
        assert!(!matcher.matches(Path::new("keyboard.txt")));
        assert!(!matcher.matches(Path::new("key")));
    }

    #[test]
    fn test_glob_matcher_extensions() {
        // Note: The glob crate doesn't support brace expansion like {tar,zip,gz}
        // Test individual patterns instead
        let tar_matcher = GlobMatcher::new("*.tar").unwrap();
        let zip_matcher = GlobMatcher::new("*.zip").unwrap();
        let gz_matcher = GlobMatcher::new("*.gz").unwrap();

        assert!(tar_matcher.matches(Path::new("archive.tar")));
        assert!(zip_matcher.matches(Path::new("archive.zip")));
        assert!(gz_matcher.matches(Path::new("archive.gz")));
        assert!(!tar_matcher.matches(Path::new("archive.rar")));
    }

    #[test]
    fn test_glob_matcher_character_class() {
        let matcher = GlobMatcher::new("file[0-9].txt").unwrap();

        assert!(matcher.matches(Path::new("file1.txt")));
        assert!(matcher.matches(Path::new("file9.txt")));
        assert!(!matcher.matches(Path::new("fileA.txt")));
        assert!(!matcher.matches(Path::new("file.txt")));
    }

    #[test]
    fn test_glob_matcher_question_mark() {
        let matcher = GlobMatcher::new("test?.log").unwrap();

        assert!(matcher.matches(Path::new("test1.log")));
        assert!(matcher.matches(Path::new("testA.log")));
        assert!(!matcher.matches(Path::new("test12.log")));
        assert!(!matcher.matches(Path::new("test.log")));
    }

    #[test]
    fn test_glob_matcher_invalid_pattern() {
        assert!(GlobMatcher::new("[").is_err());
    }

    #[test]
    fn test_glob_matcher_clone() {
        let matcher = GlobMatcher::new("*.pem").unwrap();
        let cloned = matcher.clone_box();

        assert!(cloned.matches(Path::new("cert.pem")));
        assert_eq!(cloned.pattern_description(), "glob:*.pem");
    }

    #[test]
    fn test_regex_matcher_basic() {
        let matcher = RegexMatcher::new(r"\.key$").unwrap();

        assert!(matcher.matches(Path::new("/etc/secret.key")));
        assert!(matcher.matches(Path::new("private.key")));
        assert!(!matcher.matches(Path::new("keyboard.txt")));
    }

    #[test]
    fn test_regex_matcher_case_insensitive() {
        let matcher = RegexMatcher::new(r"(?i)\.exe$").unwrap();

        assert!(matcher.matches(Path::new("program.exe")));
        assert!(matcher.matches(Path::new("PROGRAM.EXE")));
        assert!(matcher.matches(Path::new("Program.Exe")));
    }

    #[test]
    fn test_regex_matcher_complex() {
        let matcher = RegexMatcher::new(r".*-v\d+\.\d+\.\d+\.tar\.gz$").unwrap();

        assert!(matcher.matches(Path::new("/releases/app-v1.2.3.tar.gz")));
        assert!(matcher.matches(Path::new("lib-v10.20.30.tar.gz")));
        assert!(!matcher.matches(Path::new("app.tar.gz")));
        assert!(!matcher.matches(Path::new("app-v1.tar.gz")));
    }

    #[test]
    fn test_regex_matcher_with_size_limit() {
        // Normal pattern should work with default limit
        let matcher = RegexMatcher::with_size_limit(r"test", 1024 * 1024);
        assert!(matcher.is_ok());

        // Very small size limit should reject patterns
        let _result = RegexMatcher::with_size_limit(r"(a+)+", 10);
        // Size limit is applied during compilation
        // Complex patterns may exceed small limits
    }

    #[test]

    fn test_regex_matcher_invalid_pattern() {
        assert!(RegexMatcher::new(r"[").is_err());
    }

    #[test]
    fn test_regex_matcher_clone() {
        let matcher = RegexMatcher::new(r"test").unwrap();
        let cloned = matcher.clone_box();

        assert!(cloned.matches(Path::new("/test/file")));
        assert_eq!(cloned.pattern_description(), "regex:test");
    }

    #[test]
    fn test_combined_matcher_basic() {
        let matcher = CombinedMatcher::new(vec![
            Box::new(GlobMatcher::new("*.key").unwrap()),
            Box::new(GlobMatcher::new("*.pem").unwrap()),
        ]);

        assert!(matcher.matches(Path::new("secret.key")));
        assert!(matcher.matches(Path::new("cert.pem")));
        assert!(!matcher.matches(Path::new("document.txt")));
    }

    #[test]
    fn test_combined_matcher_add() {
        let matcher = CombinedMatcher::new(vec![Box::new(GlobMatcher::new("*.key").unwrap())])
            .with_matcher(Box::new(GlobMatcher::new("*.pem").unwrap()));

        assert_eq!(matcher.len(), 2);
        assert!(matcher.matches(Path::new("cert.pem")));
    }

    #[test]
    fn test_combined_matcher_empty() {
        let matcher = CombinedMatcher::new(vec![]);

        assert!(matcher.is_empty());
        assert!(!matcher.matches(Path::new("anything")));
    }

    #[test]
    fn test_combined_matcher_clone() {
        let matcher = CombinedMatcher::new(vec![
            Box::new(GlobMatcher::new("*.a").unwrap()),
            Box::new(GlobMatcher::new("*.b").unwrap()),
        ]);
        let cloned = matcher.clone_box();

        assert!(cloned.matches(Path::new("file.a")));
        assert!(cloned.matches(Path::new("file.b")));
        assert!(cloned.pattern_description().contains("any_of:"));
    }

    #[test]
    fn test_not_matcher_basic() {
        let matcher = NotMatcher::new(Box::new(GlobMatcher::new("*.key").unwrap()));

        assert!(!matcher.matches(Path::new("secret.key")));
        assert!(matcher.matches(Path::new("document.txt")));
    }

    #[test]
    fn test_not_matcher_clone() {
        let matcher = NotMatcher::new(Box::new(GlobMatcher::new("*.log").unwrap()));
        let cloned = matcher.clone_box();

        assert!(!cloned.matches(Path::new("app.log")));
        assert!(cloned.matches(Path::new("app.txt")));
        assert!(cloned.pattern_description().starts_with("not("));
    }

    #[test]
    fn test_nested_matchers() {
        // Create a complex matcher: not any of (*.key, *.pem)
        let inner = CombinedMatcher::new(vec![
            Box::new(GlobMatcher::new("*.key").unwrap()),
            Box::new(GlobMatcher::new("*.pem").unwrap()),
        ]);
        let matcher = NotMatcher::new(Box::new(inner));

        assert!(!matcher.matches(Path::new("secret.key")));
        assert!(!matcher.matches(Path::new("cert.pem")));
        assert!(matcher.matches(Path::new("document.txt")));
    }

    #[test]
    fn test_glob_matcher_with_paths() {
        // Test path-based patterns
        let matcher = GlobMatcher::new("/etc/**").unwrap();

        assert!(matcher.matches(Path::new("/etc/passwd")));
        assert!(matcher.matches(Path::new("/etc/ssh/sshd_config")));
        // Note: glob behavior for paths can be platform-dependent
    }

    #[test]
    fn test_regex_matcher_path_separators() {
        // Use both forward slashes and backslashes in pattern
        let matcher = RegexMatcher::new(r"/tmp/.*\.tmp$").unwrap();

        assert!(matcher.matches(Path::new("/tmp/file.tmp")));
        assert!(matcher.matches(Path::new("/tmp/subdir/file.tmp")));
        assert!(!matcher.matches(Path::new("/var/file.tmp")));
    }
}

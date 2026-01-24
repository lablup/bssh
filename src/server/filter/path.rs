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

//! Path-based matchers for file transfer filtering.
//!
//! This module provides matchers that work with file path structure:
//! - [`PrefixMatcher`] - Matches paths that start with a given prefix
//! - [`ExactMatcher`] - Matches paths that exactly equal a given path
//! - [`ComponentMatcher`] - Matches paths containing a specific component
//! - [`ExtensionMatcher`] - Matches paths by file extension
//!
//! # Security Considerations
//!
//! ## Path Traversal
//!
//! These matchers operate on the paths as provided. For security-sensitive
//! filtering, callers should normalize paths before matching to prevent
//! bypass via path traversal sequences like `..` or symlinks.
//!
//! Use [`normalize_path`] to remove `.` and `..` components logically, or
//! use `std::fs::canonicalize` if the path exists on the filesystem and you
//! need symlink resolution.
//!
//! ## Example: Secure Usage
//!
//! ```rust
//! use std::path::Path;
//! use bssh::server::filter::path::{normalize_path, PrefixMatcher};
//! use bssh::server::filter::policy::Matcher;
//!
//! let matcher = PrefixMatcher::new("/etc");
//! let user_path = Path::new("/var/../etc/passwd");
//!
//! // Without normalization - BYPASS!
//! assert!(!matcher.matches(user_path)); // Does NOT match /etc
//!
//! // With normalization - SECURE
//! let normalized = normalize_path(user_path);
//! assert!(matcher.matches(&normalized)); // Correctly matches /etc
//! ```

use std::path::{Component, Path, PathBuf};

use super::policy::Matcher;

/// Normalizes a path by resolving `.` and `..` components logically.
///
/// This function does NOT access the filesystem, so:
/// - It works on non-existent paths
/// - It does NOT resolve symlinks
/// - It normalizes paths purely based on their string representation
///
/// For paths where symlink resolution is needed, use `std::fs::canonicalize`
/// instead (but note that it requires the path to exist).
///
/// # Security Note
///
/// This function should be called on user-provided paths BEFORE passing them
/// to matchers, to prevent path traversal attacks.
///
/// # Examples
///
/// ```rust
/// use std::path::Path;
/// use bssh::server::filter::path::normalize_path;
///
/// assert_eq!(normalize_path(Path::new("/etc/../var")), Path::new("/var"));
/// assert_eq!(normalize_path(Path::new("/etc/./passwd")), Path::new("/etc/passwd"));
/// assert_eq!(normalize_path(Path::new("foo/../bar")), Path::new("bar"));
/// ```
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    
    for component in path.components() {
        match component {
            Component::Prefix(p) => result.push(p.as_os_str()),
            Component::RootDir => result.push(Component::RootDir.as_os_str()),
            Component::CurDir => {} // Skip "."
            Component::ParentDir => {
                // Pop if we can, otherwise keep ".." for relative paths
                if result.parent().is_some() && result != Path::new("/") {
                    result.pop();
                } else if !result.is_absolute() {
                    result.push("..");
                }
                // If at root, ignore ".."
            }
            Component::Normal(name) => result.push(name),
        }
    }
    
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

/// Matches paths that start with a given prefix.
///
/// This matcher is useful for blocking or allowing entire directory trees.
///
/// # Security Warning
///
/// This matcher operates on paths as provided. To prevent path traversal
/// attacks, normalize the input path using [`normalize_path`] before matching.
///
/// ```rust
/// use std::path::Path;
/// use bssh::server::filter::path::{normalize_path, PrefixMatcher};
/// use bssh::server::filter::policy::Matcher;
///
/// let matcher = PrefixMatcher::new("/etc");
/// let attack_path = Path::new("/var/../etc/shadow");
///
/// // Normalize to prevent bypass
/// let safe_path = normalize_path(attack_path);
/// assert!(matcher.matches(&safe_path)); // Now correctly blocked
/// ```
///
/// # Example
///
/// ```rust
/// use bssh::server::filter::path::PrefixMatcher;
/// use bssh::server::filter::policy::Matcher;
/// use std::path::Path;
///
/// let matcher = PrefixMatcher::new("/etc");
///
/// assert!(matcher.matches(Path::new("/etc/passwd")));
/// assert!(matcher.matches(Path::new("/etc/ssh/sshd_config")));
/// assert!(!matcher.matches(Path::new("/home/user")));
/// assert!(!matcher.matches(Path::new("/etcetera/file"))); // Not a true prefix
/// ```
#[derive(Debug, Clone)]
pub struct PrefixMatcher {
    prefix: PathBuf,
}

impl PrefixMatcher {
    /// Create a new prefix matcher.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The path prefix to match against
    pub fn new(prefix: impl Into<PathBuf>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// Get the prefix being matched.
    pub fn prefix(&self) -> &Path {
        &self.prefix
    }
}

impl Matcher for PrefixMatcher {
    fn matches(&self, path: &Path) -> bool {
        path.starts_with(&self.prefix)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(self.clone())
    }

    fn pattern_description(&self) -> String {
        format!("prefix:{}", self.prefix.display())
    }
}

/// Matches paths that exactly equal a given path.
///
/// This matcher is useful for blocking or allowing specific files.
///
/// # Example
///
/// ```rust
/// use bssh::server::filter::path::ExactMatcher;
/// use bssh::server::filter::policy::Matcher;
/// use std::path::Path;
///
/// let matcher = ExactMatcher::new("/etc/shadow");
///
/// assert!(matcher.matches(Path::new("/etc/shadow")));
/// assert!(!matcher.matches(Path::new("/etc/shadow.bak")));
/// assert!(!matcher.matches(Path::new("/etc/passwd")));
/// ```
#[derive(Debug, Clone)]
pub struct ExactMatcher {
    path: PathBuf,
}

impl ExactMatcher {
    /// Create a new exact path matcher.
    ///
    /// # Arguments
    ///
    /// * `path` - The exact path to match
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Get the path being matched.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Matcher for ExactMatcher {
    fn matches(&self, path: &Path) -> bool {
        path == self.path
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(self.clone())
    }

    fn pattern_description(&self) -> String {
        format!("exact:{}", self.path.display())
    }
}

/// Matches paths that contain a specific component.
///
/// This matcher is useful for blocking hidden files/directories (those starting with .)
/// or specific directory names regardless of where they appear in the path.
///
/// # Example
///
/// ```rust
/// use bssh::server::filter::path::ComponentMatcher;
/// use bssh::server::filter::policy::Matcher;
/// use std::path::Path;
///
/// let matcher = ComponentMatcher::new(".git");
///
/// assert!(matcher.matches(Path::new("/project/.git/config")));
/// assert!(matcher.matches(Path::new("/home/user/.git")));
/// assert!(!matcher.matches(Path::new("/home/user/git")));
/// ```
#[derive(Debug, Clone)]
pub struct ComponentMatcher {
    component: String,
}

impl ComponentMatcher {
    /// Create a new component matcher.
    ///
    /// # Arguments
    ///
    /// * `component` - The path component to search for
    pub fn new(component: impl Into<String>) -> Self {
        Self {
            component: component.into(),
        }
    }

    /// Get the component being matched.
    pub fn component(&self) -> &str {
        &self.component
    }
}

impl Matcher for ComponentMatcher {
    fn matches(&self, path: &Path) -> bool {
        path.components().any(|c| {
            c.as_os_str()
                .to_str()
                .map(|s| s == self.component)
                .unwrap_or(false)
        })
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(self.clone())
    }

    fn pattern_description(&self) -> String {
        format!("component:{}", self.component)
    }
}

/// Matches paths based on file extension.
///
/// This is a convenience matcher for filtering by file type.
/// It's similar to a glob pattern like "*.ext" but more efficient.
///
/// # Example
///
/// ```rust
/// use bssh::server::filter::path::ExtensionMatcher;
/// use bssh::server::filter::policy::Matcher;
/// use std::path::Path;
///
/// let matcher = ExtensionMatcher::new("exe");
///
/// assert!(matcher.matches(Path::new("/uploads/malware.exe")));
/// assert!(matcher.matches(Path::new("/Downloads/SETUP.EXE"))); // Case insensitive
/// assert!(!matcher.matches(Path::new("/home/user/document.pdf")));
/// ```
#[derive(Debug, Clone)]
pub struct ExtensionMatcher {
    extension: String,
}

impl ExtensionMatcher {
    /// Create a new extension matcher.
    ///
    /// The extension should not include the leading dot.
    ///
    /// # Arguments
    ///
    /// * `extension` - The file extension to match (without the dot)
    pub fn new(extension: impl Into<String>) -> Self {
        Self {
            extension: extension.into().to_lowercase(),
        }
    }

    /// Get the extension being matched.
    pub fn extension(&self) -> &str {
        &self.extension
    }
}

impl Matcher for ExtensionMatcher {
    fn matches(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase() == self.extension)
            .unwrap_or(false)
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(self.clone())
    }

    fn pattern_description(&self) -> String {
        format!("extension:*.{}", self.extension)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_matcher_basic() {
        let matcher = PrefixMatcher::new("/etc");

        assert!(matcher.matches(Path::new("/etc/passwd")));
        assert!(matcher.matches(Path::new("/etc/ssh/sshd_config")));
        assert!(matcher.matches(Path::new("/etc")));
        assert!(!matcher.matches(Path::new("/home/user")));
        assert!(!matcher.matches(Path::new("/etcetera/file"))); // Not a prefix match
    }

    #[test]
    fn test_prefix_matcher_with_trailing_slash() {
        let matcher = PrefixMatcher::new("/etc/");

        assert!(matcher.matches(Path::new("/etc/passwd")));
        // Note: Path::starts_with normalizes paths, so /etc starts_with /etc/ is true
        // because it checks component by component, not byte by byte
        assert!(matcher.matches(Path::new("/etc/")));
    }

    #[test]
    fn test_prefix_matcher_clone() {
        let matcher = PrefixMatcher::new("/tmp");
        let cloned = matcher.clone_box();

        assert!(cloned.matches(Path::new("/tmp/file")));
        assert_eq!(cloned.pattern_description(), "prefix:/tmp");
    }

    #[test]
    fn test_exact_matcher_basic() {
        let matcher = ExactMatcher::new("/etc/shadow");

        assert!(matcher.matches(Path::new("/etc/shadow")));
        assert!(!matcher.matches(Path::new("/etc/shadow.bak")));
        assert!(!matcher.matches(Path::new("/etc/passwd")));
        assert!(!matcher.matches(Path::new("/etc")));
    }

    #[test]
    fn test_exact_matcher_clone() {
        let matcher = ExactMatcher::new("/etc/passwd");
        let cloned = matcher.clone_box();

        assert!(cloned.matches(Path::new("/etc/passwd")));
        assert_eq!(cloned.pattern_description(), "exact:/etc/passwd");
    }

    #[test]
    fn test_component_matcher_basic() {
        let matcher = ComponentMatcher::new(".git");

        assert!(matcher.matches(Path::new("/project/.git/config")));
        assert!(matcher.matches(Path::new("/home/user/.git")));
        assert!(matcher.matches(Path::new("/.git")));
        assert!(!matcher.matches(Path::new("/home/user/git")));
        assert!(!matcher.matches(Path::new("/home/user/.gitconfig")));
    }

    #[test]
    fn test_component_matcher_hidden_files() {
        let matcher = ComponentMatcher::new(".ssh");

        assert!(matcher.matches(Path::new("/home/user/.ssh/authorized_keys")));
        assert!(matcher.matches(Path::new("/.ssh")));
        assert!(!matcher.matches(Path::new("/home/user/ssh")));
    }

    #[test]
    fn test_component_matcher_clone() {
        let matcher = ComponentMatcher::new(".svn");
        let cloned = matcher.clone_box();

        assert!(cloned.matches(Path::new("/project/.svn/entries")));
        assert_eq!(cloned.pattern_description(), "component:.svn");
    }

    #[test]
    fn test_extension_matcher_basic() {
        let matcher = ExtensionMatcher::new("exe");

        assert!(matcher.matches(Path::new("/uploads/malware.exe")));
        assert!(matcher.matches(Path::new("/Downloads/SETUP.EXE"))); // Case insensitive
        assert!(!matcher.matches(Path::new("/home/user/document.pdf")));
        assert!(!matcher.matches(Path::new("/no/extension")));
    }

    #[test]
    fn test_extension_matcher_common_types() {
        let key_matcher = ExtensionMatcher::new("key");
        let pem_matcher = ExtensionMatcher::new("pem");

        assert!(key_matcher.matches(Path::new("/etc/secret.key")));
        assert!(pem_matcher.matches(Path::new("/etc/ssl/cert.pem")));
        assert!(!key_matcher.matches(Path::new("/keyboard.txt")));
    }

    #[test]
    fn test_extension_matcher_no_extension() {
        let matcher = ExtensionMatcher::new("txt");

        assert!(!matcher.matches(Path::new("/bin/bash")));
        assert!(!matcher.matches(Path::new("/etc/passwd")));
    }

    #[test]
    fn test_extension_matcher_clone() {
        let matcher = ExtensionMatcher::new("zip");
        let cloned = matcher.clone_box();

        assert!(cloned.matches(Path::new("/downloads/archive.zip")));
        assert_eq!(cloned.pattern_description(), "extension:*.zip");
    }

    #[test]
    fn test_extension_matcher_double_extension() {
        let matcher = ExtensionMatcher::new("gz");

        // Only matches the final extension
        assert!(matcher.matches(Path::new("/backup/archive.tar.gz")));
        assert!(!matcher.matches(Path::new("/backup/archive.tar")));
    }

    #[test]
    fn test_matcher_combinations() {
        // Test that different matchers work independently
        let prefix = PrefixMatcher::new("/tmp");
        let exact = ExactMatcher::new("/etc/passwd");
        let component = ComponentMatcher::new(".cache");
        let extension = ExtensionMatcher::new("log");

        let test_path = Path::new("/tmp/app/.cache/debug.log");

        assert!(prefix.matches(test_path));
        assert!(!exact.matches(test_path));
        assert!(component.matches(test_path));
        assert!(extension.matches(test_path));
    }
}

    #[test]
    fn test_normalize_path_removes_dot() {
        assert_eq!(normalize_path(Path::new("/etc/./passwd")), Path::new("/etc/passwd"));
        assert_eq!(normalize_path(Path::new("./foo/./bar")), Path::new("foo/bar"));
    }

    #[test]
    fn test_normalize_path_resolves_parent() {
        assert_eq!(normalize_path(Path::new("/etc/../var")), Path::new("/var"));
        assert_eq!(normalize_path(Path::new("/etc/ssh/../passwd")), Path::new("/etc/passwd"));
        assert_eq!(normalize_path(Path::new("/a/b/c/../../d")), Path::new("/a/d"));
    }

    #[test]
    fn test_normalize_path_traversal_at_root() {
        // At root, .. should be ignored
        assert_eq!(normalize_path(Path::new("/../etc/passwd")), Path::new("/etc/passwd"));
        assert_eq!(normalize_path(Path::new("/../../etc")), Path::new("/etc"));
    }

    #[test]
    fn test_normalize_path_relative() {
        assert_eq!(normalize_path(Path::new("foo/../bar")), Path::new("bar"));
        assert_eq!(normalize_path(Path::new("../foo")), Path::new("../foo"));
    }

    #[test]
    fn test_normalize_path_empty() {
        assert_eq!(normalize_path(Path::new("")), Path::new("."));
        assert_eq!(normalize_path(Path::new(".")), Path::new("."));
    }

    #[test]
    fn test_normalize_path_security() {
        // This is the key security test: path traversal should be normalized
        let matcher = PrefixMatcher::new("/etc");
        
        // Without normalization, this would NOT match /etc (attack succeeds)
        let attack_path = Path::new("/var/../etc/passwd");
        assert!(!matcher.matches(attack_path)); // Raw path doesn't match
        
        // With normalization, it correctly matches /etc (attack blocked)
        let normalized = normalize_path(attack_path);
        assert!(matcher.matches(&normalized)); // Normalized path matches
        assert_eq!(normalized, Path::new("/etc/passwd"));
    }

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

//! File transfer filtering infrastructure.
//!
//! This module provides a policy-based system for controlling file transfers
//! in SFTP and SCP operations. It allows administrators to:
//!
//! - Allow or deny file transfers based on path patterns
//! - Log specific file operations for auditing
//! - Apply different rules per user or operation type
//!
//! # Architecture
//!
//! The filtering system is built around three main concepts:
//!
//! 1. **Operations** - Types of file operations (upload, download, delete, etc.)
//! 2. **Matchers** - Pattern matching against file paths (glob, prefix, regex)
//! 3. **Policies** - Ordered sets of rules that determine allow/deny/log actions
//!
//! # Example
//!
//! ```rust
//! use bssh::server::filter::{FilterPolicy, FilterResult, Operation};
//! use bssh::server::filter::pattern::GlobMatcher;
//! use bssh::server::filter::policy::FilterRule;
//! use std::path::Path;
//!
//! // Create a policy that blocks *.key files
//! let policy = FilterPolicy::new()
//!     .with_default(FilterResult::Allow)
//!     .add_rule(FilterRule {
//!         name: Some("block-keys".to_string()),
//!         matcher: Box::new(GlobMatcher::new("*.key").unwrap()),
//!         action: FilterResult::Deny,
//!         operations: None,
//!         users: None,
//!     });
//!
//! // Check if operation is allowed
//! let result = policy.check(Path::new("/etc/secret.key"), Operation::Download, "alice");
//! assert_eq!(result, FilterResult::Deny);
//! ```

pub mod path;
pub mod pattern;
pub mod policy;

use std::fmt;
use std::path::Path;

pub use self::path::{
    normalize_path, ComponentMatcher, ExactMatcher, ExtensionMatcher, MultiExtensionMatcher,
    PrefixMatcher, SizeMatcher,
};
pub use self::pattern::{
    AllMatcher, CombinedMatcher, CompositeMatcher, GlobMatcher, NotMatcher, RegexMatcher,
};
pub use self::policy::{FilterPolicy, FilterRule, Matcher, SharedFilterPolicy};

/// File transfer operation type.
///
/// Represents the type of file operation being performed. Used by filter rules
/// to apply different policies for different operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Upload a file to the server
    Upload,
    /// Download a file from the server
    Download,
    /// Delete a file
    Delete,
    /// Rename or move a file
    Rename,
    /// Create a directory
    CreateDir,
    /// List directory contents
    ListDir,
    /// Read file attributes
    Stat,
    /// Modify file attributes
    SetStat,
    /// Create a symbolic link
    Symlink,
    /// Read a symbolic link target
    ReadLink,
}

impl Operation {
    /// Returns all available operations.
    pub fn all() -> &'static [Operation] {
        &[
            Operation::Upload,
            Operation::Download,
            Operation::Delete,
            Operation::Rename,
            Operation::CreateDir,
            Operation::ListDir,
            Operation::Stat,
            Operation::SetStat,
            Operation::Symlink,
            Operation::ReadLink,
        ]
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Upload => write!(f, "upload"),
            Operation::Download => write!(f, "download"),
            Operation::Delete => write!(f, "delete"),
            Operation::Rename => write!(f, "rename"),
            Operation::CreateDir => write!(f, "createdir"),
            Operation::ListDir => write!(f, "listdir"),
            Operation::Stat => write!(f, "stat"),
            Operation::SetStat => write!(f, "setstat"),
            Operation::Symlink => write!(f, "symlink"),
            Operation::ReadLink => write!(f, "readlink"),
        }
    }
}

impl std::str::FromStr for Operation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "upload" => Ok(Operation::Upload),
            "download" => Ok(Operation::Download),
            "delete" => Ok(Operation::Delete),
            "rename" => Ok(Operation::Rename),
            "createdir" | "mkdir" => Ok(Operation::CreateDir),
            "listdir" | "readdir" => Ok(Operation::ListDir),
            "stat" => Ok(Operation::Stat),
            "setstat" => Ok(Operation::SetStat),
            "symlink" => Ok(Operation::Symlink),
            "readlink" => Ok(Operation::ReadLink),
            _ => Err(format!("unknown operation: {}", s)),
        }
    }
}

/// Result of filter check.
///
/// Determines what action should be taken for a file operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterResult {
    /// Allow the operation to proceed
    #[default]
    Allow,
    /// Deny the operation
    Deny,
    /// Allow the operation but log it
    Log,
}

impl fmt::Display for FilterResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterResult::Allow => write!(f, "allow"),
            FilterResult::Deny => write!(f, "deny"),
            FilterResult::Log => write!(f, "log"),
        }
    }
}

/// Trait for file transfer filters.
///
/// Implement this trait to create custom file transfer filtering logic.
/// The default implementation provides basic path and operation filtering.
pub trait TransferFilter: Send + Sync {
    /// Check if an operation is allowed on a given path.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path being operated on
    /// * `operation` - The type of operation
    /// * `user` - The username performing the operation
    ///
    /// # Returns
    ///
    /// A `FilterResult` indicating whether to allow, deny, or log the operation.
    fn check(&self, path: &Path, operation: Operation, user: &str) -> FilterResult;

    /// Check if an operation involving source and destination paths is allowed.
    ///
    /// Used for rename, copy, and symlink operations that involve two paths.
    /// The default implementation checks both paths and returns the most restrictive result.
    ///
    /// # Arguments
    ///
    /// * `src` - The source file path
    /// * `dest` - The destination file path
    /// * `operation` - The type of operation
    /// * `user` - The username performing the operation
    ///
    /// # Returns
    ///
    /// A `FilterResult` indicating whether to allow, deny, or log the operation.
    fn check_with_dest(
        &self,
        src: &Path,
        dest: &Path,
        operation: Operation,
        user: &str,
    ) -> FilterResult {
        let src_result = self.check(src, operation, user);
        let dest_result = self.check(dest, operation, user);

        // Return most restrictive result
        match (src_result, dest_result) {
            (FilterResult::Deny, _) | (_, FilterResult::Deny) => FilterResult::Deny,
            (FilterResult::Log, _) | (_, FilterResult::Log) => FilterResult::Log,
            _ => FilterResult::Allow,
        }
    }

    /// Returns true if filtering is enabled.
    fn is_enabled(&self) -> bool {
        true
    }
}

/// A no-op filter that allows all operations.
///
/// Used when filtering is disabled or not configured.
#[derive(Debug, Clone, Default)]
pub struct NoOpFilter;

impl TransferFilter for NoOpFilter {
    fn check(&self, _path: &Path, _operation: Operation, _user: &str) -> FilterResult {
        FilterResult::Allow
    }

    fn is_enabled(&self) -> bool {
        false
    }
}

/// Trait for size-aware file transfer filters.
///
/// This extends the basic `TransferFilter` trait to include file size
/// in the filtering decision. Use this when you need to filter based
/// on file size (e.g., block uploads larger than 100MB).
///
/// # Example
///
/// ```rust
/// use bssh::server::filter::{FilterResult, Operation, SizeAwareFilter, TransferFilter};
/// use bssh::server::filter::path::SizeMatcher;
/// use std::path::Path;
///
/// struct MaxUploadSizeFilter {
///     max_bytes: u64,
/// }
///
/// impl TransferFilter for MaxUploadSizeFilter {
///     fn check(&self, _path: &Path, _operation: Operation, _user: &str) -> FilterResult {
///         // Without size info, we allow by default
///         FilterResult::Allow
///     }
/// }
///
/// impl SizeAwareFilter for MaxUploadSizeFilter {
///     fn check_with_size(
///         &self,
///         _path: &Path,
///         size: u64,
///         operation: Operation,
///         _user: &str,
///     ) -> FilterResult {
///         if operation == Operation::Upload && size > self.max_bytes {
///             FilterResult::Deny
///         } else {
///             FilterResult::Allow
///         }
///     }
/// }
/// ```
pub trait SizeAwareFilter: TransferFilter {
    /// Check if an operation is allowed, taking file size into account.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path being operated on
    /// * `size` - The file size in bytes
    /// * `operation` - The type of operation
    /// * `user` - The username performing the operation
    ///
    /// # Returns
    ///
    /// A `FilterResult` indicating whether to allow, deny, or log the operation.
    fn check_with_size(
        &self,
        path: &Path,
        size: u64,
        operation: Operation,
        user: &str,
    ) -> FilterResult;

    /// Check a two-path operation with size information.
    ///
    /// Used for rename/copy operations where both source and destination
    /// are considered.
    fn check_with_size_dest(
        &self,
        src: &Path,
        src_size: u64,
        dest: &Path,
        operation: Operation,
        user: &str,
    ) -> FilterResult {
        let src_result = self.check_with_size(src, src_size, operation, user);
        let dest_result = self.check(dest, operation, user);

        match (src_result, dest_result) {
            (FilterResult::Deny, _) | (_, FilterResult::Deny) => FilterResult::Deny,
            (FilterResult::Log, _) | (_, FilterResult::Log) => FilterResult::Log,
            _ => FilterResult::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_display() {
        assert_eq!(Operation::Upload.to_string(), "upload");
        assert_eq!(Operation::Download.to_string(), "download");
        assert_eq!(Operation::Delete.to_string(), "delete");
        assert_eq!(Operation::Rename.to_string(), "rename");
        assert_eq!(Operation::CreateDir.to_string(), "createdir");
        assert_eq!(Operation::ListDir.to_string(), "listdir");
    }

    #[test]
    fn test_operation_parse() {
        assert_eq!("upload".parse::<Operation>().unwrap(), Operation::Upload);
        assert_eq!(
            "DOWNLOAD".parse::<Operation>().unwrap(),
            Operation::Download
        );
        assert_eq!("mkdir".parse::<Operation>().unwrap(), Operation::CreateDir);
        assert_eq!("readdir".parse::<Operation>().unwrap(), Operation::ListDir);
        assert!("invalid".parse::<Operation>().is_err());
    }

    #[test]
    fn test_filter_result_default() {
        assert_eq!(FilterResult::default(), FilterResult::Allow);
    }

    #[test]
    fn test_filter_result_display() {
        assert_eq!(FilterResult::Allow.to_string(), "allow");
        assert_eq!(FilterResult::Deny.to_string(), "deny");
        assert_eq!(FilterResult::Log.to_string(), "log");
    }

    #[test]
    fn test_noop_filter() {
        let filter = NoOpFilter;
        assert!(!filter.is_enabled());
        assert_eq!(
            filter.check(Path::new("/any/path"), Operation::Upload, "user"),
            FilterResult::Allow
        );
    }

    #[test]
    fn test_check_with_dest_deny_takes_precedence() {
        struct DenyDownload;
        impl TransferFilter for DenyDownload {
            fn check(&self, path: &Path, _operation: Operation, _user: &str) -> FilterResult {
                if path.to_string_lossy().contains("secret") {
                    FilterResult::Deny
                } else {
                    FilterResult::Allow
                }
            }
        }

        let filter = DenyDownload;

        // Both paths allowed
        assert_eq!(
            filter.check_with_dest(
                Path::new("/safe/src"),
                Path::new("/safe/dest"),
                Operation::Rename,
                "user"
            ),
            FilterResult::Allow
        );

        // Source path denied
        assert_eq!(
            filter.check_with_dest(
                Path::new("/secret/src"),
                Path::new("/safe/dest"),
                Operation::Rename,
                "user"
            ),
            FilterResult::Deny
        );

        // Destination path denied
        assert_eq!(
            filter.check_with_dest(
                Path::new("/safe/src"),
                Path::new("/secret/dest"),
                Operation::Rename,
                "user"
            ),
            FilterResult::Deny
        );
    }

    #[test]
    fn test_check_with_dest_log_priority() {
        struct LogSensitive;
        impl TransferFilter for LogSensitive {
            fn check(&self, path: &Path, _operation: Operation, _user: &str) -> FilterResult {
                if path.to_string_lossy().contains("sensitive") {
                    FilterResult::Log
                } else {
                    FilterResult::Allow
                }
            }
        }

        let filter = LogSensitive;

        // Source is sensitive, should log
        assert_eq!(
            filter.check_with_dest(
                Path::new("/sensitive/src"),
                Path::new("/safe/dest"),
                Operation::Rename,
                "user"
            ),
            FilterResult::Log
        );

        // Destination is sensitive, should log
        assert_eq!(
            filter.check_with_dest(
                Path::new("/safe/src"),
                Path::new("/sensitive/dest"),
                Operation::Rename,
                "user"
            ),
            FilterResult::Log
        );
    }

    #[test]
    fn test_operation_all() {
        let all_ops = Operation::all();

        // Should contain all 10 operations
        assert_eq!(all_ops.len(), 10);

        // Verify all operations are included
        assert!(all_ops.contains(&Operation::Upload));
        assert!(all_ops.contains(&Operation::Download));
        assert!(all_ops.contains(&Operation::Delete));
        assert!(all_ops.contains(&Operation::Rename));
        assert!(all_ops.contains(&Operation::CreateDir));
        assert!(all_ops.contains(&Operation::ListDir));
        assert!(all_ops.contains(&Operation::Stat));
        assert!(all_ops.contains(&Operation::SetStat));
        assert!(all_ops.contains(&Operation::Symlink));
        assert!(all_ops.contains(&Operation::ReadLink));
    }

    #[test]
    fn test_operation_display_all() {
        // Test all operations have a string representation
        assert_eq!(Operation::Stat.to_string(), "stat");
        assert_eq!(Operation::SetStat.to_string(), "setstat");
        assert_eq!(Operation::Symlink.to_string(), "symlink");
        assert_eq!(Operation::ReadLink.to_string(), "readlink");
    }

    #[test]
    fn test_operation_parse_all_variants() {
        // Test parsing all valid variants
        assert_eq!("stat".parse::<Operation>().unwrap(), Operation::Stat);
        assert_eq!("setstat".parse::<Operation>().unwrap(), Operation::SetStat);
        assert_eq!("symlink".parse::<Operation>().unwrap(), Operation::Symlink);
        assert_eq!(
            "readlink".parse::<Operation>().unwrap(),
            Operation::ReadLink
        );

        // Test case insensitivity
        assert_eq!("STAT".parse::<Operation>().unwrap(), Operation::Stat);
        assert_eq!("SetStat".parse::<Operation>().unwrap(), Operation::SetStat);
    }

    #[test]
    fn test_noop_filter_default() {
        let filter = NoOpFilter::default();
        assert!(!filter.is_enabled());
    }

    #[test]
    fn test_noop_filter_clone() {
        let filter = NoOpFilter;
        let cloned = filter.clone();
        assert!(!cloned.is_enabled());
    }
}

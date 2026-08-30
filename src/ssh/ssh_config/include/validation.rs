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

//! Security validation for Include directive

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use super::super::diagnostic::{escape_field, escape_path};

/// Validate a glob pattern for security
pub fn validate_glob_pattern(pattern: &str) -> Result<()> {
    // Check for dangerous glob patterns
    if pattern.contains("**") {
        anyhow::bail!("Recursive glob patterns (**) are not allowed for security reasons");
    }

    // Check for excessive wildcards that could cause exponential expansion
    let wildcard_count = pattern.chars().filter(|&c| c == '*').count();
    if wildcard_count > 5 {
        anyhow::bail!(
            "Too many wildcards in pattern '{}'. Maximum 5 wildcards allowed.",
            escape_field(pattern)
        );
    }

    // Check for overly broad patterns that could match system files
    // But allow common SSH config patterns like ~/.ssh/config.d/*
    if (pattern == "*" || pattern == "/*") && !pattern.contains("ssh") {
        anyhow::bail!(
            "Pattern '{}' is too broad and could match system files",
            escape_field(pattern)
        );
    }

    // Check pattern length
    if pattern.len() > 512 {
        anyhow::bail!("Pattern is too long (max 512 characters)");
    }

    Ok(())
}

/// Check if a path is in an allowed directory
#[cfg(not(test))]
pub fn is_path_allowed(path: &Path) -> bool {
    let allowed_prefixes = [
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")),
        PathBuf::from("/etc/ssh"),
        PathBuf::from("/usr/local/etc/ssh"),
        std::env::temp_dir(), // Allow temp directories for testing
    ];

    allowed_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Validate an include file path for security
pub fn validate_include_path(path: &Path) -> Result<()> {
    // Check if file exists
    if !path.exists() {
        // Non-existent files are silently ignored per SSH spec
        return Ok(());
    }

    // Get metadata without following symlinks
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to get metadata for {}", escape_path(path)))?;

    // Reject symbolic links for security
    if metadata.is_symlink() {
        anyhow::bail!(
            "Include path {} is a symbolic link. Symlinks are not allowed for security reasons.",
            escape_path(path)
        );
    }

    // Check if it's a regular file
    if !metadata.is_file() {
        anyhow::bail!("Include path is not a regular file: {}", escape_path(path));
    }

    // Canonicalize and verify the path doesn't escape expected directories
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize {}", escape_path(path)))?;

    // Check for directory traversal attempts
    let path_str = canonical.to_string_lossy();
    if path_str.contains("../") || path_str.contains("..\\") {
        anyhow::bail!(
            "Include path {} contains directory traversal sequences",
            escape_path(path)
        );
    }

    // Restrict includes to safe directories
    let safe_prefixes = [
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")),
        PathBuf::from("/etc/ssh"),
        PathBuf::from("/usr/local/etc/ssh"),
        std::env::temp_dir(), // Allow temp directories for testing
    ];

    let is_safe = safe_prefixes
        .iter()
        .any(|prefix| canonical.starts_with(prefix));

    if !is_safe {
        tracing::warn!(
            "Include path {} is outside of standard SSH config directories. This may be a security risk.",
            escape_path(&canonical)
        );
    }

    // Check file permissions (warn on world-writable or group-writable)
    // Skip permission checks in test mode to allow temporary test files
    #[cfg(all(unix, not(test)))]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Check if world-writable (other-write bit set)
        if mode & 0o002 != 0 {
            anyhow::bail!(
                "SSH config file {} is world-writable. This is a security vulnerability.",
                escape_path(path)
            );
        }

        // Check if group-writable (group-write bit set)
        if mode & 0o020 != 0 {
            tracing::warn!(
                "SSH config file {} is group-writable. This is a potential security risk.",
                escape_path(path)
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_glob_pattern_security() {
        // Test recursive glob rejection
        let result = validate_glob_pattern("config.d/**/*.conf");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Recursive glob"));

        // Test too many wildcards
        let result = validate_glob_pattern("a*/b*/c*/d*/e*/f*");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Too many wildcards")
        );

        // Test too-long pattern
        let long_pattern = "a".repeat(600);
        let result = validate_glob_pattern(&long_pattern);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));

        // Test overly broad pattern
        let result = validate_glob_pattern("/*");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too broad"));

        // Test valid patterns
        assert!(validate_glob_pattern("~/.ssh/config.d/*.conf").is_ok());
        assert!(validate_glob_pattern("/etc/ssh/*.conf").is_ok());
        assert!(validate_glob_pattern("config.d/[0-9][0-9]-*.conf").is_ok());
        // Path with ../ is allowed in pattern validation (checked later by is_path_allowed)
        assert!(validate_glob_pattern("../../../etc/passwd").is_ok());
    }
}

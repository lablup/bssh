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

//! Path validation and security checks

use anyhow::{Context, Result};
use std::path::PathBuf;

use super::checks;
use crate::ssh::ssh_config::path::expand_path_internal;

/// Securely validate and expand a file path to prevent path traversal attacks
///
/// # Security Features
/// - Prevents directory traversal with ../ sequences
/// - Validates paths after expansion and canonicalization
/// - Checks file permissions on Unix systems (warns if identity files are world-readable)
/// - Ensures paths don't point to sensitive system files
/// - Handles both absolute and relative paths correctly
/// - Supports safe tilde expansion
///
/// # Arguments
/// * `path` - The file path to validate (may contain ~/ and environment variables)
/// * `path_type` - The type of path for security context ("identity", "known_hosts", or "other")
/// * `line_number` - Line number for error reporting
///
/// # Returns
/// * `Ok(PathBuf)` if the path is safe and valid
/// * `Err(anyhow::Error)` if the path is unsafe or invalid
pub fn secure_validate_path(path: &str, path_type: &str, line_number: usize) -> Result<PathBuf> {
    // First expand the path using the existing logic
    let expanded_path = expand_path_internal(path)
        .with_context(|| format!("Failed to expand path '{path}' at line {line_number}"))?;

    // Convert to string for analysis
    let path_str = expanded_path.to_string_lossy();

    // Check for directory traversal sequences
    if path_str.contains("../") || path_str.contains("..\\") {
        anyhow::bail!(
            "Security violation: {path_type} path contains directory traversal sequence '..' at line {line_number}. \
             Path traversal attacks are not allowed."
        );
    }

    // Check for null bytes and other dangerous characters
    if path_str.contains('\0') {
        anyhow::bail!(
            "Security violation: {path_type} path contains null byte at line {line_number}. \
             This could be used for path truncation attacks."
        );
    }

    // Try to canonicalize the path to resolve any remaining relative components
    let canonical_path = if expanded_path.exists() {
        match expanded_path.canonicalize() {
            Ok(canonical) => canonical,
            Err(e) => {
                tracing::debug!(
                    "Could not canonicalize {} path '{}' at line {}: {}. Using expanded path as-is.",
                    path_type, path_str, line_number, e
                );
                expanded_path.clone()
            }
        }
    } else {
        // For non-existent files, just ensure the parent directory is safe
        expanded_path.clone()
    };

    // Re-check for traversal in the canonical path
    let canonical_str = canonical_path.to_string_lossy();
    if canonical_str.contains("..") {
        // This might be legitimate (like a directory literally named "..something")
        // but we need to be very careful about parent directory references
        if canonical_str.split('/').any(|component| component == "..")
            || canonical_str.split('\\').any(|component| component == "..")
        {
            anyhow::bail!(
                "Security violation: Canonicalized {path_type} path '{canonical_str}' contains parent directory references at line {line_number}. \
                 This could indicate a path traversal attempt."
            );
        }
    }

    // Additional security checks based on path type
    match path_type {
        "identity" => {
            checks::validate_identity_file_security(&canonical_path, line_number)?;
        }
        "known_hosts" => {
            checks::validate_known_hosts_file_security(&canonical_path, line_number)?;
        }
        _ => {
            // General path validation for other file types
            checks::validate_general_file_security(&canonical_path, line_number)?;
        }
    }

    Ok(canonical_path)
}

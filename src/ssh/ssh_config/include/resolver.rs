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

//! Pattern resolution for Include directive

use anyhow::{Context, Result};
use std::path::PathBuf;

use super::super::path::expand_path_internal;
#[cfg(not(test))]
use super::validation::is_path_allowed;
use super::validation::{validate_glob_pattern, validate_include_path};
use crate::ssh::ssh_config::include::IncludeContext;

/// Parse an Include directive line
pub fn parse_include_line(line: &str) -> Option<Vec<&str>> {
    // Support both "Include pattern" and "Include=pattern" syntax
    let line = line.trim();

    // Check if it starts with Include directive (case-insensitive)
    if !line.to_lowercase().starts_with("include") {
        return None;
    }

    // Extract the patterns part
    let patterns_part = if let Some(pos) = line.find('=') {
        // Include=pattern syntax
        line[pos + 1..].trim()
    } else {
        // Include pattern syntax
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 || parts[0].to_lowercase() != "include" {
            return None;
        }
        // Join all parts after "Include" keyword
        line[parts[0].len()..].trim()
    };

    if patterns_part.is_empty() {
        return None;
    }

    // Split multiple patterns (space-separated)
    let patterns: Vec<&str> = patterns_part.split_whitespace().collect();

    if patterns.is_empty() {
        None
    } else {
        Some(patterns)
    }
}

/// Resolve a single include pattern to a list of files
pub async fn resolve_include_pattern(
    pattern: &str,
    context: &IncludeContext,
) -> Result<Vec<PathBuf>> {
    // Validate pattern for security before expansion
    validate_glob_pattern(pattern)?;

    // Expand environment variables and tilde
    let expanded = expand_path_internal(pattern)?;

    // Make relative paths relative to the config directory
    let search_path = if expanded.is_relative() {
        context.base_dir.join(&expanded)
    } else {
        expanded
    };

    // Convert to string for glob
    let pattern_str = search_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 in path: {:?}", search_path))?;

    // Additional validation after expansion
    validate_glob_pattern(pattern_str)?;

    // Limit glob results to prevent resource exhaustion
    const MAX_GLOB_RESULTS: usize = 100;
    let mut files = Vec::new();

    // Use glob with options to control behavior
    let glob_options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,   // Don't match / with *
        require_literal_leading_dot: true, // Don't match hidden files with *
    };

    for entry in glob::glob_with(pattern_str, glob_options)
        .with_context(|| format!("Invalid glob pattern: {}", pattern_str))?
    {
        if files.len() >= MAX_GLOB_RESULTS {
            anyhow::bail!(
                "Glob pattern '{}' matched too many files (>{MAX_GLOB_RESULTS}). \
                 Please use a more specific pattern.",
                pattern
            );
        }

        match entry {
            Ok(path) => {
                // Additional security: ensure resolved path doesn't escape expected directories
                // Skip this check in test mode
                #[cfg(not(test))]
                {
                    let canonical = match path.canonicalize() {
                        Ok(c) => c,
                        Err(_) if !path.exists() => continue, // Skip non-existent files
                        Err(e) => {
                            tracing::debug!("Failed to canonicalize {}: {}", path.display(), e);
                            continue;
                        }
                    };

                    // Verify the canonical path is still under an allowed directory
                    if !is_path_allowed(&canonical) {
                        tracing::warn!(
                            "Glob result {} escapes allowed directories, skipping",
                            path.display()
                        );
                        continue;
                    }
                }

                // Skip directories and symlinks
                match std::fs::symlink_metadata(&path) {
                    Ok(metadata) => {
                        if metadata.is_file() && !metadata.is_symlink() {
                            // Security check: validate the path
                            if validate_include_path(&path).is_ok() {
                                files.push(path);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to get metadata for {}: {}", path.display(), e);
                    }
                }
            }
            Err(e) => {
                // Log glob errors but continue
                tracing::warn!("Error processing glob pattern '{}': {}", pattern_str, e);
            }
        }
    }

    // Sort files in lexical order (as per SSH spec)
    files.sort();

    // If no files matched and pattern doesn't contain wildcards, it might be an error
    if files.is_empty() && !pattern.contains('*') && !pattern.contains('?') {
        tracing::debug!(
            "Include pattern '{}' matched no files (this may be intentional)",
            pattern
        );
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_parse_include_line() {
        // Test space syntax
        assert_eq!(
            parse_include_line("Include ~/.ssh/config.d/*"),
            Some(vec!["~/.ssh/config.d/*"])
        );

        // Test equals syntax
        assert_eq!(
            parse_include_line("Include=~/.ssh/config.d/*"),
            Some(vec!["~/.ssh/config.d/*"])
        );

        // Test multiple patterns
        assert_eq!(
            parse_include_line("Include /etc/ssh/config.d/* ~/.ssh/extra/*"),
            Some(vec!["/etc/ssh/config.d/*", "~/.ssh/extra/*"])
        );

        // Test case insensitivity
        assert_eq!(
            parse_include_line("include ~/.ssh/config.d/*"),
            Some(vec!["~/.ssh/config.d/*"])
        );

        // Test non-include lines
        assert_eq!(parse_include_line("Host example.com"), None);
        assert_eq!(parse_include_line("User testuser"), None);
    }

    #[tokio::test]
    async fn test_resolve_include_pattern_glob() {
        use crate::ssh::ssh_config::include::IncludeContext;

        let temp_dir = TempDir::new().unwrap();

        // Create test config files
        let config_dir = temp_dir.path().join("config.d");
        fs::create_dir(&config_dir).unwrap();

        fs::write(config_dir.join("01-first.conf"), "Host first\n").unwrap();
        fs::write(config_dir.join("02-second.conf"), "Host second\n").unwrap();
        fs::write(config_dir.join("03-third.conf"), "Host third\n").unwrap();

        // Create context
        let main_config = temp_dir.path().join("config");
        fs::write(&main_config, "").unwrap();
        let context = IncludeContext::new(&main_config);

        // Resolve glob pattern
        let pattern = format!("{}/*.conf", config_dir.display());
        let files = resolve_include_pattern(&pattern, &context).await.unwrap();

        // Should have 3 files in lexical order
        assert_eq!(files.len(), 3);
        assert!(files[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("01-first"));
        assert!(files[1]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("02-second"));
        assert!(files[2]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("03-third"));
    }

    #[tokio::test]
    async fn test_include_with_tilde_expansion() {
        // Test that tilde expansion is handled
        let patterns = parse_include_line("Include ~/.ssh/config.d/*.conf");
        assert!(patterns.is_some());

        let patterns = patterns.unwrap();
        assert_eq!(patterns.len(), 1);
        assert!(patterns[0].starts_with("~/"));
    }
}

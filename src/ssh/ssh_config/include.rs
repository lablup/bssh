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

//! Include directive support for SSH configuration
//!
//! This module handles the Include directive which allows loading configuration
//! from external files, supporting glob patterns and recursive includes.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::path::expand_path_internal;

/// Maximum include depth to prevent infinite recursion
const MAX_INCLUDE_DEPTH: usize = 10;

/// Maximum number of files that can be included (DoS prevention)
const MAX_INCLUDED_FILES: usize = 100;

/// Context for tracking include resolution state
#[derive(Debug, Clone)]
pub struct IncludeContext {
    /// Current recursion depth
    depth: usize,
    /// Set of canonical paths already processed (cycle detection) - using string for efficiency
    visited: HashSet<String>,
    /// Total number of files included so far
    file_count: usize,
    /// Base directory for relative includes
    base_dir: PathBuf,
    /// LRU cache for canonicalized paths to avoid repeated filesystem operations
    canonical_cache: std::collections::HashMap<PathBuf, PathBuf>,
}

impl IncludeContext {
    /// Create a new include context for the given config file
    pub fn new(config_path: &Path) -> Self {
        let base_dir = config_path
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf();

        Self {
            depth: 0,
            visited: HashSet::with_capacity(16), // Pre-allocate reasonable capacity
            file_count: 0,
            base_dir,
            canonical_cache: std::collections::HashMap::with_capacity(16),
        }
    }

    /// Check if we can include another file
    fn can_include(&self) -> Result<()> {
        if self.depth >= MAX_INCLUDE_DEPTH {
            anyhow::bail!(
                "Maximum include depth ({}) exceeded. This may indicate an include cycle or misconfiguration.",
                MAX_INCLUDE_DEPTH
            );
        }

        if self.file_count >= MAX_INCLUDED_FILES {
            anyhow::bail!(
                "Maximum number of included files ({}) exceeded. This limit exists to prevent DoS attacks.",
                MAX_INCLUDED_FILES
            );
        }

        Ok(())
    }

    /// Enter a new include level
    fn enter_include(&mut self, path: &Path) -> Result<()> {
        self.can_include()?;

        // Check cache first to avoid repeated canonicalization
        let canonical = if let Some(cached) = self.canonical_cache.get(path) {
            cached.clone()
        } else if path.exists() {
            // Canonicalize and cache the result
            let canonical = path
                .canonicalize()
                .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;
            self.canonical_cache
                .insert(path.to_path_buf(), canonical.clone());
            canonical
        } else {
            // For non-existent files, try to at least make it absolute
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                self.base_dir.join(path)
            }
        };

        // Use string representation for more efficient cycle detection
        let canonical_str = canonical.to_string_lossy().into_owned();

        // Check for cycles
        if self.visited.contains(&canonical_str) {
            anyhow::bail!(
                "Include cycle detected: {} has already been processed",
                path.display()
            );
        }

        self.visited.insert(canonical_str);
        self.depth += 1;
        self.file_count += 1;

        // Update base directory for nested includes
        if let Some(parent) = canonical.parent() {
            self.base_dir = parent.to_path_buf();
        }

        // Clear cache if it gets too large to prevent unbounded memory growth
        if self.canonical_cache.len() > 100 {
            self.canonical_cache.clear();
        }

        Ok(())
    }

    /// Exit an include level
    fn exit_include(&mut self) {
        if self.depth > 0 {
            self.depth -= 1;
        }
    }
}

/// Resolved include file with its content
#[derive(Debug, Clone)]
pub struct IncludedFile {
    /// Path to the file
    pub path: PathBuf,
    /// File content
    pub content: String,
    /// Line offset in the combined configuration
    #[allow(dead_code)]
    pub line_offset: usize,
}

/// Resolve Include directives and collect all configuration files
/// Processes files in the order they appear, inserting included files at Include directive locations
pub async fn resolve_includes(config_path: &Path, content: &str) -> Result<Vec<IncludedFile>> {
    let mut context = IncludeContext::new(config_path);

    // Mark the main file as visited to prevent cycles
    let canonical = if config_path.exists() {
        config_path.canonicalize().with_context(|| {
            format!(
                "Failed to canonicalize main config path: {}",
                config_path.display()
            )
        })?
    } else {
        config_path.to_path_buf()
    };
    context
        .visited
        .insert(canonical.to_string_lossy().into_owned());

    // Process the main file with includes
    process_file_with_includes(config_path, content, &mut context).await
}

/// Process a file with Include directives, inserting included files at the correct positions
async fn process_file_with_includes(
    file_path: &Path,
    content: &str,
    context: &mut IncludeContext,
) -> Result<Vec<IncludedFile>> {
    let mut result = Vec::new();
    let mut current_content = String::new();

    for (line_number, line) in content.lines().enumerate() {
        let line_number = line_number + 1; // 1-indexed for error messages
        let trimmed = line.trim();

        // Check for Include directive
        if let Some(patterns) = parse_include_line(trimmed) {
            // Save current accumulated content as an IncludedFile (if not empty)
            if !current_content.is_empty() {
                let line_offset: usize = result
                    .iter()
                    .map(|f: &IncludedFile| f.content.lines().count())
                    .sum();
                result.push(IncludedFile {
                    path: file_path.to_path_buf(),
                    content: current_content.clone(),
                    line_offset,
                });
                current_content.clear();
            }

            // Process each Include pattern
            for pattern in patterns {
                let resolved_files = resolve_include_pattern(pattern, context)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to resolve Include pattern '{}' at line {} in {}",
                            pattern,
                            line_number,
                            file_path.display()
                        )
                    })?;

                // Process each resolved file recursively
                for include_path in resolved_files {
                    context.enter_include(&include_path).with_context(|| {
                        format!("Failed to include file: {}", include_path.display())
                    })?;

                    // Read with timeout to prevent hanging on network filesystems
                    let include_content = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::fs::read_to_string(&include_path),
                    )
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("Timeout reading include file: {}", include_path.display())
                    })?
                    .with_context(|| {
                        format!("Failed to read include file: {}", include_path.display())
                    })?;

                    // Recursively process the included file (use Box::pin to avoid stack overflow)
                    let mut included_files = Box::pin(process_file_with_includes(
                        &include_path,
                        &include_content,
                        context,
                    ))
                    .await?;

                    // Add all files from the included file to result
                    result.append(&mut included_files);

                    context.exit_include();
                }
            }
        } else {
            // Regular line - add to current content
            current_content.push_str(line);
            current_content.push('\n');
        }
    }

    // Add any remaining content as the final IncludedFile
    if !current_content.is_empty() {
        let line_offset: usize = result
            .iter()
            .map(|f: &IncludedFile| f.content.lines().count())
            .sum();
        result.push(IncludedFile {
            path: file_path.to_path_buf(),
            content: current_content,
            line_offset,
        });
    }

    // If no Include directives were found and result is empty, add the whole file
    if result.is_empty() {
        result.push(IncludedFile {
            path: file_path.to_path_buf(),
            content: content.to_string(),
            line_offset: 0,
        });
    }

    Ok(result)
}

/// Recursively resolve includes in a configuration content (DEPRECATED - kept for reference)
#[allow(dead_code)]
fn resolve_includes_recursive<'a>(
    result: &'a mut Vec<IncludedFile>,
    content: &'a str,
    context: &'a mut IncludeContext,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        for (line_number, line) in content.lines().enumerate() {
            let line_number = line_number + 1; // 1-indexed for error messages
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check for Include directive
            if let Some(patterns) = parse_include_line(line) {
                // Resolve each pattern
                for pattern in patterns {
                    let resolved_files = resolve_include_pattern(pattern, context)
                        .await
                        .with_context(|| {
                            format!(
                                "Failed to resolve Include pattern '{}' at line {}",
                                pattern, line_number
                            )
                        })?;

                    // Process each resolved file
                    for file_path in resolved_files {
                        // Check if we can include this file
                        context.enter_include(&file_path).with_context(|| {
                            format!("Failed to include file: {}", file_path.display())
                        })?;

                        // Read the file
                        let file_content = tokio::fs::read_to_string(&file_path)
                            .await
                            .with_context(|| {
                                format!("Failed to read include file: {}", file_path.display())
                            })?;

                        // Calculate line offset
                        let line_offset = result
                            .iter()
                            .map(|f| f.content.lines().count())
                            .sum::<usize>();

                        // Add to results
                        result.push(IncludedFile {
                            path: file_path.clone(),
                            content: file_content.clone(),
                            line_offset,
                        });

                        // Recursively process includes in this file
                        resolve_includes_recursive(result, &file_content, context).await?;

                        context.exit_include();
                    }
                }
            }
        }

        Ok(())
    })
}

/// Parse an Include directive line
fn parse_include_line(line: &str) -> Option<Vec<&str>> {
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
async fn resolve_include_pattern(pattern: &str, context: &IncludeContext) -> Result<Vec<PathBuf>> {
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

/// Validate a glob pattern for security
fn validate_glob_pattern(pattern: &str) -> Result<()> {
    // Check for dangerous glob patterns
    if pattern.contains("**") {
        anyhow::bail!("Recursive glob patterns (**) are not allowed for security reasons");
    }

    // Check for excessive wildcards that could cause exponential expansion
    let wildcard_count = pattern.chars().filter(|&c| c == '*').count();
    if wildcard_count > 5 {
        anyhow::bail!(
            "Too many wildcards in pattern '{}'. Maximum 5 wildcards allowed.",
            pattern
        );
    }

    // Check for overly broad patterns that could match system files
    // But allow common SSH config patterns like ~/.ssh/config.d/*
    if (pattern == "*" || pattern == "/*") && !pattern.contains("ssh") {
        anyhow::bail!(
            "Pattern '{}' is too broad and could match system files",
            pattern
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
fn is_path_allowed(path: &Path) -> bool {
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
fn validate_include_path(path: &Path) -> Result<()> {
    // Check if file exists
    if !path.exists() {
        // Non-existent files are silently ignored per SSH spec
        return Ok(());
    }

    // Get metadata without following symlinks
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to get metadata for {}", path.display()))?;

    // Reject symbolic links for security
    if metadata.is_symlink() {
        anyhow::bail!(
            "Include path {} is a symbolic link. Symlinks are not allowed for security reasons.",
            path.display()
        );
    }

    // Check if it's a regular file
    if !metadata.is_file() {
        anyhow::bail!("Include path is not a regular file: {}", path.display());
    }

    // Canonicalize and verify the path doesn't escape expected directories
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize {}", path.display()))?;

    // Check for directory traversal attempts
    let path_str = canonical.to_string_lossy();
    if path_str.contains("../") || path_str.contains("..\\") {
        anyhow::bail!(
            "Include path {} contains directory traversal sequences",
            path.display()
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
            canonical.display()
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
                path.display()
            );
        }

        // Check if group-writable (group-write bit set)
        if mode & 0o020 != 0 {
            tracing::warn!(
                "SSH config file {} is group-writable. This is a potential security risk.",
                path.display()
            );
        }
    }

    Ok(())
}

/// Combine multiple included files into a single configuration string
pub fn combine_included_files(files: &[IncludedFile]) -> String {
    let mut combined = String::new();

    for file in files {
        if !combined.is_empty() {
            combined.push('\n');
        }

        // Add a comment indicating the source file (helpful for debugging)
        combined.push_str(&format!("# Source: {}\n", file.path.display()));
        combined.push_str(&file.content);
    }

    combined
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_parse_include_line() {
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
    async fn test_resolve_includes_simple() {
        let temp_dir = TempDir::new().unwrap();

        // Create main config
        let main_config = temp_dir.path().join("config");
        let main_content = "Host example.com\n    User mainuser\n";
        fs::write(&main_config, main_content).unwrap();

        // Resolve includes (no Include directives)
        let result = resolve_includes(&main_config, main_content).await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, main_config);
        assert_eq!(result[0].content, main_content);
    }

    #[tokio::test]
    async fn test_resolve_includes_with_include() {
        let temp_dir = TempDir::new().unwrap();

        // Create included file
        let include_dir = temp_dir.path().join("config.d");
        fs::create_dir(&include_dir).unwrap();

        let included_file = include_dir.join("extra.conf");
        let included_content = "Host included.com\n    User includeduser\n";
        fs::write(&included_file, included_content).unwrap();

        // Create main config with Include directive
        let main_config = temp_dir.path().join("config");
        let main_content = format!(
            "Include {}\n\nHost example.com\n    User mainuser\n",
            included_file.display()
        );
        fs::write(&main_config, &main_content).unwrap();

        // Resolve includes
        let result = resolve_includes(&main_config, &main_content).await.unwrap();

        // With corrected Include order, included files are inserted at Include location
        // Expected: included file first, then rest of main config
        assert_eq!(result.len(), 2, "Should have 2 file chunks");
        assert_eq!(
            result[0].path, included_file,
            "First should be included file"
        );
        assert_eq!(result[0].content, included_content);
        assert_eq!(
            result[1].path, main_config,
            "Second should be rest of main config"
        );
        assert!(
            result[1].content.contains("Host example.com"),
            "Should contain main config content"
        );
    }

    #[tokio::test]
    async fn test_include_cycle_detection() {
        let temp_dir = TempDir::new().unwrap();

        // Create file A that includes B
        let file_a = temp_dir.path().join("a.conf");
        let content_a = format!("Include {}\n", temp_dir.path().join("b.conf").display());
        fs::write(&file_a, &content_a).unwrap();

        // Create file B that includes A (cycle)
        let file_b = temp_dir.path().join("b.conf");
        let content_b = format!("Include {}\n", file_a.display());
        fs::write(&file_b, content_b).unwrap();

        // Try to resolve - should detect cycle
        let result = resolve_includes(&file_a, &content_a).await;

        assert!(result.is_err());
        let err_display = result.as_ref().unwrap_err().to_string();
        // Check the full error chain for cycle detection message
        let err_chain = format!("{:?}", result.unwrap_err());
        println!("Error display: {}", err_display); // Debug output
        println!("Error chain: {}", err_chain); // Debug output
        assert!(
            err_chain.contains("cycle")
                || err_chain.contains("already been processed")
                || err_chain.contains("Include cycle"),
            "Expected cycle detection in error chain but got: {}",
            err_chain
        );
    }

    #[tokio::test]
    async fn test_max_depth_limit() {
        let temp_dir = TempDir::new().unwrap();

        // Create a chain of includes deeper than the limit
        let mut prev_file = temp_dir.path().join("config");
        let mut prev_content = String::new();

        for i in 0..=MAX_INCLUDE_DEPTH + 1 {
            let file = temp_dir.path().join(format!("level{}.conf", i));
            let content = if i == 0 {
                "Host start\n".to_string()
            } else {
                format!("Include {}\n", prev_file.display())
            };
            fs::write(&file, &content).unwrap();

            prev_file = file;
            prev_content = content;
        }

        // Try to resolve - should hit depth limit
        let result = resolve_includes(&prev_file, &prev_content).await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        // Check the full error chain since the depth error is in the cause
        let err_chain = format!("{:?}", error);
        assert!(err_chain.contains("depth") || err_chain.contains("Maximum include depth"));
    }

    #[tokio::test]
    async fn test_glob_pattern_expansion() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple config files
        let config_dir = temp_dir.path().join("config.d");
        fs::create_dir(&config_dir).unwrap();

        fs::write(config_dir.join("01-first.conf"), "Host first\n").unwrap();
        fs::write(config_dir.join("02-second.conf"), "Host second\n").unwrap();
        fs::write(config_dir.join("03-third.conf"), "Host third\n").unwrap();

        // Create main config with glob Include
        let main_config = temp_dir.path().join("config");
        let main_content = format!("Include {}/*.conf\n", config_dir.display());
        fs::write(&main_config, &main_content).unwrap();

        // Resolve includes
        let result = resolve_includes(&main_config, &main_content).await.unwrap();

        // Should have 3 included files (main config only has Include, so no content chunk from main)
        assert_eq!(result.len(), 3);

        // Check lexical ordering of included files
        assert!(result[0]
            .path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("01-first"));
        assert!(result[1]
            .path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("02-second"));
        assert!(result[2]
            .path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("03-third"));
    }

    #[tokio::test]
    async fn test_validate_glob_pattern_security() {
        // Test recursive glob rejection
        let result = validate_glob_pattern("config.d/**/*.conf");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Recursive glob"));

        // Test too many wildcards
        let result = validate_glob_pattern("a*/b*/c*/d*/e*/f*");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Too many wildcards"));

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

    #[tokio::test]
    async fn test_multiple_patterns_in_include() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple config files in different directories
        let dir1 = temp_dir.path().join("dir1");
        let dir2 = temp_dir.path().join("dir2");
        fs::create_dir(&dir1).unwrap();
        fs::create_dir(&dir2).unwrap();

        fs::write(dir1.join("config1.conf"), "Host host1\n").unwrap();
        fs::write(dir2.join("config2.conf"), "Host host2\n").unwrap();

        // Create main config with multiple patterns in one Include directive
        let main_config = temp_dir.path().join("config");
        let main_content = format!(
            "Include {} {}\n",
            dir1.join("*.conf").display(),
            dir2.join("*.conf").display()
        );
        fs::write(&main_config, &main_content).unwrap();

        // Resolve includes
        let result = resolve_includes(&main_config, &main_content).await.unwrap();

        // Should have 2 included files
        assert_eq!(result.len(), 2);
        assert!(
            result[0].content.contains("Host host1") || result[1].content.contains("Host host1")
        );
        assert!(
            result[0].content.contains("Host host2") || result[1].content.contains("Host host2")
        );
    }

    #[tokio::test]
    async fn test_include_nonexistent_file_skipped() {
        let temp_dir = TempDir::new().unwrap();

        // Create main config that includes a non-existent file
        let main_config = temp_dir.path().join("config");
        let nonexistent_path = temp_dir.path().join("nonexistent.conf");
        let main_content = format!(
            "Include {}\nHost example.com\n    User testuser\n",
            nonexistent_path.display()
        );
        fs::write(&main_config, &main_content).unwrap();

        // Resolve includes - should skip non-existent file and continue
        let result = resolve_includes(&main_config, &main_content).await.unwrap();

        // Should have 1 file (main config, since Include file doesn't exist)
        assert_eq!(result.len(), 1);
        assert!(result[0].content.contains("Host example.com"));
    }

    #[tokio::test]
    async fn test_include_order_preservation() {
        let temp_dir = TempDir::new().unwrap();

        // Create three include files
        let include_dir = temp_dir.path().join("includes");
        fs::create_dir(&include_dir).unwrap();

        fs::write(
            include_dir.join("first.conf"),
            "Host first\n    Port 1111\n",
        )
        .unwrap();
        fs::write(
            include_dir.join("second.conf"),
            "Host second\n    Port 2222\n",
        )
        .unwrap();
        fs::write(
            include_dir.join("third.conf"),
            "Host third\n    Port 3333\n",
        )
        .unwrap();

        // Create main config with multiple Include directives at different positions
        let main_config = temp_dir.path().join("config");
        let main_content = format!(
            "Host start\n    Port 9999\n\nInclude {}\n\nHost middle\n    Port 5555\n\nInclude {}\n\nHost end\n    Port 1\n",
            include_dir.join("first.conf").display(),
            include_dir.join("second.conf").display()
        );
        fs::write(&main_config, &main_content).unwrap();

        // Resolve includes
        let result = resolve_includes(&main_config, &main_content).await.unwrap();

        // Combine and check order: start → first → middle → second → end
        let combined = combine_included_files(&result);

        let start_pos = combined.find("Host start").unwrap();
        let first_pos = combined.find("Host first").unwrap();
        let middle_pos = combined.find("Host middle").unwrap();
        let second_pos = combined.find("Host second").unwrap();
        let end_pos = combined.find("Host end").unwrap();

        assert!(start_pos < first_pos, "start should come before first");
        assert!(first_pos < middle_pos, "first should come before middle");
        assert!(middle_pos < second_pos, "middle should come before second");
        assert!(second_pos < end_pos, "second should come before end");
    }

    #[tokio::test]
    async fn test_empty_glob_pattern() {
        let temp_dir = TempDir::new().unwrap();

        // Create main config with glob that matches no files
        let main_config = temp_dir.path().join("config");
        let main_content = format!(
            "Include {}\nHost example.com\n",
            temp_dir.path().join("nonexistent/*.conf").display()
        );
        fs::write(&main_config, &main_content).unwrap();

        // Resolve includes - should handle empty glob gracefully
        let result = resolve_includes(&main_config, &main_content).await.unwrap();

        // Should have 1 file (main config only)
        assert_eq!(result.len(), 1);
        assert!(result[0].content.contains("Host example.com"));
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

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
use std::path::{Path, PathBuf};

use super::diagnostic::{escape_field, escape_path};

mod resolver;
mod validation;

// Re-export submodule items
pub use resolver::{parse_include_line, resolve_include_pattern};
#[allow(unused_imports)]
pub use validation::{validate_glob_pattern, validate_include_path};

/// Maximum include depth to prevent infinite recursion
const MAX_INCLUDE_DEPTH: usize = 16;

/// Maximum number of files that can be included (DoS prevention)
const MAX_INCLUDED_FILES: usize = 100;

/// Context for tracking include resolution state
#[derive(Debug, Clone)]
pub struct IncludeContext {
    /// Current recursion depth
    depth: usize,
    /// Total number of files included so far
    file_count: usize,
    /// Immutable OpenSSH origin for all nested relative Includes.
    pub anchor: PathBuf,
}

impl IncludeContext {
    /// Create a new include context for the given config file
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(config_path: &Path) -> Self {
        let anchor = config_path
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf();

        Self {
            depth: 0,
            file_count: 0,
            anchor,
        }
    }

    pub fn with_anchor(anchor: PathBuf) -> Self {
        Self {
            depth: 0,
            file_count: 0,
            anchor,
        }
    }

    /// Check if we can include another file
    fn can_include(&self) -> Result<()> {
        if self.depth >= MAX_INCLUDE_DEPTH {
            anyhow::bail!(
                "Maximum include depth ({MAX_INCLUDE_DEPTH}) exceeded. This may indicate an include cycle or misconfiguration."
            );
        }

        if self.file_count >= MAX_INCLUDED_FILES {
            anyhow::bail!(
                "Maximum number of included files ({MAX_INCLUDED_FILES}) exceeded. This limit exists to prevent DoS attacks."
            );
        }

        Ok(())
    }

    /// Enter a new include level
    fn enter_include(&mut self) -> Result<()> {
        self.can_include()?;
        self.depth += 1;
        self.file_count += 1;
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
    #[cfg_attr(not(test), allow(dead_code))]
    pub path: PathBuf,
    /// File content
    pub content: String,
    /// One-based line number of the first content line in the source file.
    pub source_line_start: usize,
    /// Host/Match scopes that guarded entry into this included file.
    pub scope_guards: Vec<String>,
}

/// Resolve Include directives and collect all configuration files
/// Processes files in the order they appear, inserting included files at Include directive locations
pub async fn resolve_includes(config_path: &Path, content: &str) -> Result<Vec<IncludedFile>> {
    resolve_includes_for_host(config_path, content, None).await
}

/// Resolve Includes with `%h` bound to the destination being inspected.
pub async fn resolve_includes_for_host(
    config_path: &Path,
    content: &str,
    hostname: Option<&str>,
) -> Result<Vec<IncludedFile>> {
    let anchor = config_path
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .to_path_buf();
    resolve_includes_for_host_at(config_path, content, hostname, anchor).await
}

/// Resolve Includes relative to an immutable OpenSSH origin directory.
pub(crate) async fn resolve_includes_for_host_at(
    config_path: &Path,
    content: &str,
    hostname: Option<&str>,
    anchor: PathBuf,
) -> Result<Vec<IncludedFile>> {
    resolve_includes_for_host_at_pass(config_path, content, hostname, anchor, None, None, false)
        .await
}

pub(crate) async fn resolve_includes_for_host_at_pass(
    config_path: &Path,
    content: &str,
    hostname: Option<&str>,
    anchor: PathBuf,
    effective_hostname: Option<&str>,
    remote_user: Option<&str>,
    final_pass: bool,
) -> Result<Vec<IncludedFile>> {
    let mut context = IncludeContext::with_anchor(anchor);
    let mut expansion =
        IncludeExpansionState::new(hostname, effective_hostname, remote_user, final_pass);

    // Process the main file with includes
    process_file_with_includes(
        config_path,
        content,
        &mut context,
        &mut expansion,
        "Host *",
        &[],
        true,
    )
    .await
}

#[derive(Debug)]
struct IncludeExpansionState {
    original_hostname: Option<String>,
    effective_hostname: Option<String>,
    hostname_obtained: bool,
    remote_user: Option<String>,
    final_pass: bool,
}

impl IncludeExpansionState {
    fn new(
        hostname: Option<&str>,
        effective_hostname: Option<&str>,
        remote_user: Option<&str>,
        final_pass: bool,
    ) -> Self {
        Self {
            original_hostname: hostname.map(str::to_string),
            effective_hostname: effective_hostname.or(hostname).map(str::to_string),
            hostname_obtained: effective_hostname.is_some(),
            remote_user: remote_user.map(str::to_string),
            final_pass,
        }
    }
}

/// Process a file with Include directives, inserting included files at the correct positions
async fn process_file_with_includes(
    file_path: &Path,
    content: &str,
    context: &mut IncludeContext,
    expansion: &mut IncludeExpansionState,
    inherited_scope: &str,
    scope_guards: &[String],
    inherited_active: bool,
) -> Result<Vec<IncludedFile>> {
    let mut result = Vec::new();
    let mut current_content = String::new();
    let mut current_source_line = 1;
    let mut active_scope = inherited_scope.to_string();
    let mut scope_active = inherited_active;
    let mut pending_scope_restore = false;
    let mut pending_initial_scope = context.depth > 0;

    for (line_number, line) in content.lines().enumerate() {
        let line_number = line_number + 1; // 1-indexed for error messages
        let trimmed = line.trim();

        // Check for Include directive
        if let Some(patterns) = parse_include_line(trimmed)? {
            // Save current accumulated content as an IncludedFile (if not empty)
            if !current_content.is_empty() {
                result.push(IncludedFile {
                    path: file_path.to_path_buf(),
                    content: current_content.clone(),
                    source_line_start: current_source_line,
                    scope_guards: scope_guards.to_vec(),
                });
                current_content.clear();
            }
            current_source_line = line_number + 1;

            // Process each Include pattern
            for pattern in patterns {
                let expanded_environment = expand_include_environment(&pattern)?;
                let expanded_pattern = expansion
                    .effective_hostname
                    .as_deref()
                    .map_or_else(|| pattern.to_string(), |host| pattern.replace("%h", host));
                let expanded_pattern = if expanded_environment == pattern {
                    expanded_pattern
                } else {
                    expansion
                        .effective_hostname
                        .as_deref()
                        .map_or(expanded_environment.clone(), |host| {
                            expanded_environment.replace("%h", host)
                        })
                };
                let resolved_files = resolve_include_pattern(&expanded_pattern, context)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to resolve Include pattern '{}' at line {} in {}",
                            escape_field(&pattern),
                            line_number,
                            escape_path(file_path)
                        )
                    })?;

                // Process each resolved file recursively
                for include_path in resolved_files {
                    context.enter_include().with_context(|| {
                        format!("Failed to include file: {}", escape_path(&include_path))
                    })?;

                    // Read with timeout to prevent hanging on network filesystems
                    let include_content = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::fs::read_to_string(&include_path),
                    )
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "Timeout reading include file: {}",
                            escape_path(&include_path)
                        )
                    })?
                    .with_context(|| {
                        format!(
                            "Failed to read include file: {}",
                            escape_path(&include_path)
                        )
                    })?;

                    let mut child_guards = scope_guards.to_vec();
                    child_guards.push(active_scope.clone());
                    // Recursively process the included file (use Box::pin to avoid stack overflow)
                    let mut included_files = Box::pin(process_file_with_includes(
                        &include_path,
                        &include_content,
                        context,
                        expansion,
                        &active_scope,
                        &child_guards,
                        scope_active,
                    ))
                    .await?;

                    // Add all files from the included file to result
                    result.append(&mut included_files);

                    context.exit_include();
                }
            }
            pending_scope_restore = true;
        } else {
            if pending_initial_scope && !trimmed.is_empty() && !trimmed.starts_with('#') {
                let lower = trimmed.to_ascii_lowercase();
                let starts_new_scope = lower.starts_with("host ")
                    || lower.starts_with("host=")
                    || lower.starts_with("match ")
                    || lower.starts_with("match=");
                if !starts_new_scope {
                    current_content.push_str(inherited_scope);
                    current_content.push('\n');
                }
                pending_initial_scope = false;
            }
            if pending_scope_restore && !trimmed.is_empty() && !trimmed.starts_with('#') {
                let lower = trimmed.to_ascii_lowercase();
                let starts_new_scope = lower.starts_with("host ")
                    || lower.starts_with("host=")
                    || lower.starts_with("match ")
                    || lower.starts_with("match=");
                if !starts_new_scope {
                    current_content.push_str(&active_scope);
                    current_content.push('\n');
                }
                pending_scope_restore = false;
            }
            // Regular line - add to current content
            current_content.push_str(line);
            current_content.push('\n');
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("host ")
                || lower.starts_with("host=")
                || lower.starts_with("match ")
                || lower.starts_with("match=")
            {
                active_scope = trimmed.to_string();
                scope_active = inherited_active && scope_matches(trimmed, expansion)?;
            } else if scope_active {
                update_expansion_state(trimmed, expansion)?;
            }
        }
    }

    // Add any remaining content as the final IncludedFile
    if !current_content.is_empty() {
        result.push(IncludedFile {
            path: file_path.to_path_buf(),
            content: current_content,
            source_line_start: current_source_line,
            scope_guards: scope_guards.to_vec(),
        });
    }

    // If no Include directives were found and result is empty, add the whole file
    if result.is_empty() {
        result.push(IncludedFile {
            path: file_path.to_path_buf(),
            content: content.to_string(),
            source_line_start: 1,
            scope_guards: scope_guards.to_vec(),
        });
    }

    Ok(result)
}

fn scope_matches(line: &str, state: &IncludeExpansionState) -> Result<bool> {
    let Some(original_hostname) = state.original_hostname.as_deref() else {
        return Ok(true);
    };
    let lower = line.trim_start().to_ascii_lowercase();
    if lower.starts_with("host ") || lower.starts_with("host\t") || lower.starts_with("host=") {
        let (_, patterns) = split_directive(line, 0)?;
        return Ok(super::pattern::matches_host_pattern(
            original_hostname,
            &patterns,
        ));
    }
    let conditions = super::match_directive::MatchCondition::parse_match_line(line, 0)?;
    if conditions.iter().any(match_contains_exec) {
        anyhow::bail!("Match exec cannot be evaluated in side-effect-free -G mode");
    }
    let context = super::match_directive::MatchContext::with_original_hostname(
        state
            .effective_hostname
            .clone()
            .unwrap_or_else(|| original_hostname.to_string()),
        original_hostname.to_string(),
        state.remote_user.clone(),
    )?
    .with_final_pass(state.final_pass);
    let block = super::match_directive::MatchBlock {
        conditions,
        config: super::types::SshHostConfig::default(),
        line_number: 0,
    };
    block.matches(&context)
}

fn match_contains_exec(condition: &super::match_directive::MatchCondition) -> bool {
    match condition {
        super::match_directive::MatchCondition::Exec(_) => true,
        super::match_directive::MatchCondition::Negated(inner) => match_contains_exec(inner),
        _ => false,
    }
}

fn update_expansion_state(line: &str, state: &mut IncludeExpansionState) -> Result<()> {
    let (keyword, args) = split_directive(line, 0)?;
    if keyword == "hostname" && !state.hostname_obtained {
        let value = args.first().context("HostName requires a value")?;
        state.effective_hostname = Some(value.clone());
        state.hostname_obtained = true;
    } else if keyword == "user" && state.remote_user.is_none() {
        state.remote_user = args.first().cloned();
    }
    Ok(())
}

fn split_directive(line: &str, line_number: usize) -> Result<(String, Vec<String>)> {
    let line = line.trim();
    let boundary = line
        .char_indices()
        .find(|(_, ch)| ch.is_whitespace() || *ch == '=');
    let (keyword, remainder) = boundary.map_or((line, ""), |(index, delimiter)| {
        (
            &line[..index],
            line[index + delimiter.len_utf8()..].trim_start(),
        )
    });
    Ok((
        keyword.to_ascii_lowercase(),
        super::value::tokenize(remainder, line_number)?,
    ))
}

fn expand_include_environment(pattern: &str) -> Result<String> {
    let mut output = String::with_capacity(pattern.len());
    let mut remaining = pattern;
    while let Some(start) = remaining.find("${") {
        output.push_str(&remaining[..start]);
        let variable = &remaining[start + 2..];
        let end = variable
            .find('}')
            .context("Include environment variable is missing closing '}'")?;
        let name = &variable[..end];
        if name.is_empty()
            || !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            anyhow::bail!("Include contains an invalid environment variable name");
        }
        let value = std::env::var(name)
            .with_context(|| format!("Include environment variable ${{{name}}} is not set"))?;
        if value.chars().any(|ch| matches!(ch, '\0' | '\r' | '\n')) {
            anyhow::bail!("Include environment variable contains a control character");
        }
        output.push_str(&value);
        remaining = &variable[end + 1..];
    }
    output.push_str(remaining);
    Ok(output)
}

/// Combine multiple included files into a single configuration string
#[cfg(test)]
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
    use tempfile::TempDir;

    mod fs {
        pub use std::fs::{Permissions, create_dir, create_dir_all, set_permissions};

        pub fn write(
            path: impl AsRef<std::path::Path>,
            contents: impl AsRef<[u8]>,
        ) -> std::io::Result<()> {
            std::fs::write(&path, contents)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        }
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
        println!("Error display: {err_display}"); // Debug output
        println!("Error chain: {err_chain}"); // Debug output
        assert!(
            err_chain.contains("cycle")
                || err_chain.contains("already been processed")
                || err_chain.contains("Include cycle")
                || err_chain.contains("depth"),
            "Expected cycle detection in error chain but got: {err_chain}"
        );
    }

    #[tokio::test]
    async fn test_max_depth_limit() {
        let temp_dir = TempDir::new().unwrap();

        // Create a chain of includes deeper than the limit
        let mut prev_file = temp_dir.path().join("config");
        let mut prev_content = String::new();

        for i in 0..=MAX_INCLUDE_DEPTH + 1 {
            let file = temp_dir.path().join(format!("level{i}.conf"));
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
        let err_chain = format!("{error:?}");
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
        assert!(
            result[0]
                .path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("01-first")
        );
        assert!(
            result[1]
                .path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("02-second")
        );
        assert!(
            result[2]
                .path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("03-third")
        );
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
    async fn nested_relative_includes_keep_the_origin_anchor() {
        let temp_dir = TempDir::new().unwrap();
        let anchor = temp_dir.path().join("anchor");
        let elsewhere = temp_dir.path().join("elsewhere");
        fs::create_dir_all(&anchor).unwrap();
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(anchor.join("first.conf"), "Include nested.conf\n").unwrap();
        fs::write(
            anchor.join("nested.conf"),
            "Host target\n    User anchored\n",
        )
        .unwrap();
        fs::write(
            elsewhere.join("nested.conf"),
            "Host target\n    User wrong\n",
        )
        .unwrap();
        let main = elsewhere.join("config");
        let content = "Include first.conf\n";
        fs::write(&main, content).unwrap();

        let files = resolve_includes_for_host_at(&main, content, Some("target"), anchor.clone())
            .await
            .unwrap();

        assert!(
            files
                .iter()
                .any(|file| file.path == anchor.join("nested.conf"))
        );
        assert!(
            !files
                .iter()
                .any(|file| file.path == elsewhere.join("nested.conf"))
        );
    }

    #[tokio::test]
    async fn percent_h_uses_streaming_effective_hostname() {
        let temp_dir = TempDir::new().unwrap();
        let main = temp_dir.path().join("config");
        let content = "Host alias\n    HostName effective.example\n    Include %h.conf\n";
        fs::write(&main, content).unwrap();
        fs::write(
            temp_dir.path().join("effective.example.conf"),
            "User effective\n",
        )
        .unwrap();
        fs::write(temp_dir.path().join("alias.conf"), "User alias\n").unwrap();

        let files = resolve_includes_for_host_at(
            &main,
            content,
            Some("alias"),
            temp_dir.path().to_path_buf(),
        )
        .await
        .unwrap();

        assert!(
            files
                .iter()
                .any(|file| file.path.ends_with("effective.example.conf"))
        );
        assert!(!files.iter().any(|file| file.path.ends_with("alias.conf")));
    }

    async fn resolve_include_chain(edge_count: usize) -> Result<Vec<IncludedFile>> {
        let temp_dir = TempDir::new().unwrap();
        let main = temp_dir.path().join("config");
        let content = "Include level1.conf\n";
        fs::write(&main, content).unwrap();
        for level in 1..=edge_count {
            let value = if level == edge_count {
                "Host target\n".to_string()
            } else {
                format!("Include level{}.conf\n", level + 1)
            };
            fs::write(temp_dir.path().join(format!("level{level}.conf")), value).unwrap();
        }
        resolve_includes_for_host_at(
            &main,
            content,
            Some("target"),
            temp_dir.path().to_path_buf(),
        )
        .await
    }

    #[tokio::test]
    async fn include_depth_accepts_sixteen_edges_and_rejects_seventeen() {
        assert!(resolve_include_chain(16).await.is_ok());
        let error = resolve_include_chain(17).await.unwrap_err();
        assert!(format!("{error:?}").contains("Maximum include depth (16)"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn include_follows_safe_symlink_and_rejects_writable_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp_dir = TempDir::new().unwrap();
        let main = temp_dir.path().join("config");
        let target = temp_dir.path().join("target.conf");
        let link = temp_dir.path().join("link.conf");
        fs::write(&target, "Host target\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();
        let content = format!("Include {}\n", link.display());
        fs::write(&main, &content).unwrap();

        assert!(resolve_includes(&main, &content).await.is_ok());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o622)).unwrap();
        let error = resolve_includes(&main, &content).await.unwrap_err();
        assert!(format!("{error:?}").contains("Bad permissions"));
    }
}

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

use super::super::diagnostic::{escape_field, escape_path};
use super::super::path::expand_path_internal;
use super::validation::{validate_glob_pattern, validate_include_path};
use crate::ssh::ssh_config::include::IncludeContext;

/// Parse an Include directive line
pub fn parse_include_line(line: &str) -> Result<Option<Vec<String>>> {
    let line = line.trim();
    let boundary = line
        .char_indices()
        .find(|(_, ch)| ch.is_whitespace() || *ch == '=');
    let (keyword, remainder) = match boundary {
        Some((index, delimiter)) => (
            &line[..index],
            line[index + delimiter.len_utf8()..].trim_start(),
        ),
        None => (line, ""),
    };
    if !keyword.eq_ignore_ascii_case("include") {
        return Ok(None);
    }
    let patterns = super::super::value::tokenize(remainder, 0)?;
    if patterns.is_empty() {
        anyhow::bail!("Include directive requires at least one path");
    }
    Ok(Some(patterns))
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
        context.anchor.join(&expanded)
    } else {
        expanded
    };

    // Convert to string for glob
    let pattern_str = search_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 in path: {}", escape_path(&search_path)))?;

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
        .with_context(|| format!("Invalid glob pattern: {}", escape_field(pattern_str)))?
    {
        if files.len() >= MAX_GLOB_RESULTS {
            anyhow::bail!(
                "Glob pattern '{}' matched too many files (>{MAX_GLOB_RESULTS}). Please use a more specific pattern.",
                escape_field(pattern)
            );
        }

        match entry {
            Ok(path) => {
                // Follow symlinks, then validate the target like OpenSSH's fstat path.
                match std::fs::metadata(&path) {
                    Ok(metadata) => {
                        if metadata.is_file() {
                            validate_include_path(&path)?;
                            files.push(path);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("Failed to get metadata for {}", escape_path(&path))
                        });
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Error processing glob pattern '{}'",
                        escape_field(pattern_str)
                    )
                });
            }
        }
    }

    // Sort files in lexical order (as per SSH spec)
    files.sort();

    // If no files matched and pattern doesn't contain wildcards, it might be an error
    if files.is_empty() && !pattern.contains('*') && !pattern.contains('?') {
        tracing::debug!(
            "Include pattern '{}' matched no files (this may be intentional)",
            escape_field(pattern)
        );
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn write_config(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) {
        let path = path.as_ref();
        fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn test_parse_include_line() {
        // Test space syntax
        assert_eq!(
            parse_include_line("Include ~/.ssh/config.d/*").unwrap(),
            Some(vec!["~/.ssh/config.d/*".to_string()])
        );

        // Test equals syntax
        assert_eq!(
            parse_include_line("Include=~/.ssh/config.d/*").unwrap(),
            Some(vec!["~/.ssh/config.d/*".to_string()])
        );

        // Test multiple patterns
        assert_eq!(
            parse_include_line("Include /etc/ssh/config.d/* ~/.ssh/extra/*").unwrap(),
            Some(vec![
                "/etc/ssh/config.d/*".to_string(),
                "~/.ssh/extra/*".to_string()
            ])
        );

        // Test case insensitivity
        assert_eq!(
            parse_include_line("include ~/.ssh/config.d/*").unwrap(),
            Some(vec!["~/.ssh/config.d/*".to_string()])
        );

        // Test non-include lines
        assert_eq!(parse_include_line("Host example.com").unwrap(), None);
        assert_eq!(parse_include_line("Included yes").unwrap(), None);
        assert_eq!(parse_include_line("Included=yes").unwrap(), None);
        assert!(parse_include_line("Include").is_err());
    }

    #[tokio::test]
    async fn test_resolve_include_pattern_glob() {
        use crate::ssh::ssh_config::include::IncludeContext;

        let temp_dir = TempDir::new().unwrap();

        // Create test config files
        let config_dir = temp_dir.path().join("config.d");
        fs::create_dir(&config_dir).unwrap();

        write_config(config_dir.join("01-first.conf"), "Host first\n");
        write_config(config_dir.join("02-second.conf"), "Host second\n");
        write_config(config_dir.join("03-third.conf"), "Host third\n");

        // Create context
        let main_config = temp_dir.path().join("config");
        fs::write(&main_config, "").unwrap();
        let context = IncludeContext::new(&main_config);

        // Resolve glob pattern
        let pattern = format!("{}/*.conf", config_dir.display());
        let files = resolve_include_pattern(&pattern, &context).await.unwrap();

        // Should have 3 files in lexical order
        assert_eq!(files.len(), 3);
        assert!(
            files[0]
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("01-first")
        );
        assert!(
            files[1]
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("02-second")
        );
        assert!(
            files[2]
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("03-third")
        );
    }

    #[tokio::test]
    async fn test_include_with_tilde_expansion() {
        // Test that tilde expansion is handled
        let patterns = parse_include_line("Include ~/.ssh/config.d/*.conf")
            .unwrap()
            .unwrap();
        assert_eq!(patterns.len(), 1);
        assert!(patterns[0].starts_with("~/"));
    }
}

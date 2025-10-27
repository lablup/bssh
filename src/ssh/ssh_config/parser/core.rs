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

//! Core SSH configuration parsing functionality
//!
//! This module contains the main parsing logic for SSH configurations,
//! including the 2-pass parsing strategy for Include and Match directives.

use crate::ssh::ssh_config::include::{combine_included_files, resolve_includes};
use crate::ssh::ssh_config::match_directive::{MatchBlock, MatchCondition};
use crate::ssh::ssh_config::types::{ConfigBlock, SshHostConfig};
use anyhow::{Context, Result};
use std::path::Path;

use super::options;

/// Parse SSH configuration content with Include and Match support
pub fn parse(content: &str) -> Result<Vec<SshHostConfig>> {
    // For synchronous parsing without file path, we can't resolve includes
    // This maintains backward compatibility for tests and simple usage
    parse_without_includes(content)
}

/// Parse SSH configuration from a file with full Include support
pub async fn parse_from_file(path: &Path, content: &str) -> Result<Vec<SshHostConfig>> {
    // Pass 1: Resolve all Include directives
    let included_files = resolve_includes(path, content)
        .await
        .with_context(|| format!("Failed to resolve includes for {}", path.display()))?;

    // Combine all included files into a single configuration
    let combined_content = combine_included_files(&included_files);

    // Pass 2: Parse the combined configuration
    parse_without_includes(&combined_content)
}

/// Parse SSH configuration content without Include resolution
pub(super) fn parse_without_includes(content: &str) -> Result<Vec<SshHostConfig>> {
    // Security: Set reasonable limits to prevent DoS attacks
    const MAX_LINE_LENGTH: usize = 8192; // 8KB per line should be more than enough
    const MAX_VALUE_LENGTH: usize = 4096; // 4KB for individual values

    let mut configs = Vec::new();
    let mut current_config: Option<SshHostConfig> = None;
    let mut current_match: Option<MatchBlock> = None;
    let mut line_number = 0;
    let mut in_match_block = false;

    for line in content.lines() {
        line_number += 1;

        // Skip source file comments added by include resolution
        if line.starts_with("# Source:") {
            continue;
        }

        // Security: Check line length to prevent DoS
        if line.len() > MAX_LINE_LENGTH {
            anyhow::bail!("Line {line_number} exceeds maximum length of {MAX_LINE_LENGTH} bytes");
        }

        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Get lowercase version of line for keyword detection
        let lower_line = line.to_lowercase();

        // Check for Include directive (should have been resolved in pass 1)
        if lower_line.starts_with("include") {
            // In direct parsing mode, we skip Include directives
            tracing::debug!(
                "Skipping Include directive at line {} (not in file mode)",
                line_number
            );
            continue;
        }

        // Check for Match directive
        if lower_line.starts_with("match ")
            || lower_line.starts_with("match\t")
            || lower_line == "match"
            || lower_line.starts_with("match=")
        {
            // Save previous config if any
            if let Some(config) = current_config.take() {
                configs.push(config);
            }
            if let Some(match_block) = current_match.take() {
                configs.push(match_block.config);
            }

            // Parse Match conditions
            let conditions = MatchCondition::parse_match_line(line, line_number)?;

            // Create new Match block
            let mut match_block = MatchBlock::new(line_number);
            match_block.conditions = conditions.clone();

            // Create config for this Match block
            let config = SshHostConfig {
                block_type: Some(ConfigBlock::Match(conditions)),
                ..Default::default()
            };
            match_block.config = config;

            current_match = Some(match_block);
            current_config = None;
            in_match_block = true;
            continue;
        }

        // Check for Host directive (must be "host" not "hostname" etc.)
        if lower_line.starts_with("host ")
            || lower_line.starts_with("host\t")
            || lower_line == "host"
            || (lower_line.starts_with("host=") && !lower_line.starts_with("hostname="))
        {
            // Save previous config if any
            if let Some(config) = current_config.take() {
                configs.push(config);
            }
            if let Some(match_block) = current_match.take() {
                configs.push(match_block.config);
            }

            // Parse Host patterns
            let patterns = parse_host_line(line, line_number)?;

            // Create new Host config
            let config = SshHostConfig {
                host_patterns: patterns.clone(),
                block_type: Some(ConfigBlock::Host(patterns)),
                ..Default::default()
            };

            current_config = Some(config);
            current_match = None;
            in_match_block = false;
            continue;
        }

        // Parse configuration option
        let (keyword, args) = parse_config_line(line, line_number, MAX_VALUE_LENGTH)?;

        if keyword.is_empty() {
            continue;
        }

        // Apply option to current config block
        if in_match_block {
            if let Some(ref mut match_block) = current_match {
                options::parse_option(&mut match_block.config, &keyword, &args, line_number)
                    .with_context(|| format!("Error at line {line_number}: {line}"))?;
            }
        } else if let Some(ref mut config) = current_config {
            options::parse_option(config, &keyword, &args, line_number)
                .with_context(|| format!("Error at line {line_number}: {line}"))?;
        } else {
            // Global option outside any block
            // In OpenSSH, these set defaults but we're ignoring them for now
            tracing::debug!(
                "Ignoring global option '{}' at line {}",
                keyword,
                line_number
            );
        }
    }

    // Don't forget the last config
    if let Some(config) = current_config {
        configs.push(config);
    }
    if let Some(match_block) = current_match {
        configs.push(match_block.config);
    }

    Ok(configs)
}

/// Parse a Host directive line
pub(super) fn parse_host_line(line: &str, line_number: usize) -> Result<Vec<String>> {
    let line = line.trim();

    // Support both "Host pattern" and "Host=pattern" syntax
    let patterns_str = if let Some(pos) = line.find('=') {
        // Host=pattern syntax
        if line[..pos].trim().to_lowercase() != "host" {
            anyhow::bail!("Invalid Host directive at line {line_number}");
        }
        line[pos + 1..].trim()
    } else {
        // Host pattern syntax
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() || parts[0].to_lowercase() != "host" {
            anyhow::bail!("Invalid Host directive at line {line_number}");
        }
        if parts.len() < 2 {
            anyhow::bail!("Host directive requires at least one pattern at line {line_number}");
        }
        // Join all parts after "Host"
        line[parts[0].len()..].trim()
    };

    if patterns_str.is_empty() {
        anyhow::bail!("Host directive requires at least one pattern at line {line_number}");
    }

    // Split into individual patterns
    let patterns: Vec<String> = patterns_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    Ok(patterns)
}

/// Parse a configuration line into keyword and arguments
pub(super) fn parse_config_line(
    line: &str,
    line_number: usize,
    max_value_length: usize,
) -> Result<(String, Vec<String>)> {
    let line = line.trim();

    // Determine if using equals syntax
    let eq_pos = line.find('=');
    let uses_equals_syntax = if let Some(pos) = eq_pos {
        // Has equals sign - extract first word to check
        let prefix = &line[..pos];
        let first_word = prefix
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_lowercase();
        // Host and Match never use equals syntax
        !matches!(first_word.as_str(), "host" | "match")
    } else {
        false
    };

    let (keyword, args) = if let Some(pos) = eq_pos.filter(|_| uses_equals_syntax) {
        // Option=Value syntax
        let key_part = line[..pos].trim();
        let value_part = &line[pos + 1..];

        if key_part.is_empty() {
            return Ok((String::new(), vec![]));
        }

        let trimmed_value = value_part.trim();

        // Security: Check value length
        if trimmed_value.len() > max_value_length {
            anyhow::bail!(
                "Value at line {line_number} exceeds maximum length of {max_value_length} bytes"
            );
        }

        let args = if trimmed_value.is_empty() {
            vec![]
        } else {
            // Special handling for comma-separated options
            match key_part.to_lowercase().as_str() {
                "ciphers"
                | "macs"
                | "hostkeyalgorithms"
                | "kexalgorithms"
                | "preferredauthentications"
                | "protocol" => trimmed_value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                _ => vec![trimmed_value.to_string()],
            }
        };

        (key_part.to_lowercase(), args)
    } else {
        // Option Value syntax (space-separated)
        let mut parts = line.split_whitespace();
        let keyword = parts.next().unwrap_or("").to_lowercase();
        let args: Vec<String> = parts.map(|s| s.to_string()).collect();
        (keyword, args)
    };

    Ok((keyword, args))
}

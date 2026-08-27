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

use crate::ssh::ssh_config::include::{IncludedFile, resolve_includes};
use crate::ssh::ssh_config::match_directive::{MatchBlock, MatchCondition};
use crate::ssh::ssh_config::resolver::merge_host_config;
use crate::ssh::ssh_config::types::{ConfigBlock, SshHostConfig};
use anyhow::{Context, Result};
use std::collections::HashSet;
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
    parse_included_files(&included_files)
}

/// Parse SSH configuration content without Include resolution
pub(super) fn parse_without_includes(content: &str) -> Result<Vec<SshHostConfig>> {
    parse_lines(
        content
            .lines()
            .enumerate()
            .map(|(index, line)| (None, index + 1, line)),
    )
}

/// Parse raw `-o Key=Value` arguments into a leading `Host *` overlay.
///
/// Keeping the overlay as a structured block lets the ordinary resolver apply
/// OpenSSH's first-obtained rule: CLI options are visited before file blocks,
/// while repeated `-o` scalars retain the first CLI value.
pub(crate) fn parse_cli_options(options: &[String]) -> Result<Option<SshHostConfig>> {
    const MAX_LINE_LENGTH: usize = 8192;
    const MAX_VALUE_LENGTH: usize = 4096;

    if options.is_empty() {
        return Ok(None);
    }

    let mut overlay = SshHostConfig {
        host_patterns: vec!["*".to_string()],
        block_type: Some(ConfigBlock::Host(vec!["*".to_string()])),
        ..Default::default()
    };
    let mut reported_diagnostics = HashSet::new();

    for (index, option) in options.iter().enumerate() {
        let option_number = index + 1;
        if option.contains(['\r', '\n']) {
            anyhow::bail!("-o option #{option_number} must be a single configuration line");
        }
        if option.len() > MAX_LINE_LENGTH {
            anyhow::bail!("-o option #{option_number} exceeds {MAX_LINE_LENGTH} bytes");
        }

        let (keyword, args) = parse_config_line(option, option_number, MAX_VALUE_LENGTH)
            .with_context(|| format!("Invalid -o option #{option_number}"))?;
        if keyword.is_empty() {
            anyhow::bail!("-o option #{option_number} has no keyword");
        }
        parse_option_first(
            &mut overlay,
            &keyword,
            &args,
            None,
            option_number,
            &mut reported_diagnostics,
        )
        .with_context(|| format!("Invalid -o option #{option_number} ({keyword})"))?;
    }

    Ok(Some(overlay))
}

fn parse_included_files(files: &[IncludedFile]) -> Result<Vec<SshHostConfig>> {
    parse_lines(files.iter().flat_map(|file| {
        file.content.lines().enumerate().map(move |(index, line)| {
            (
                Some(file.path.as_path()),
                file.source_line_start + index,
                line,
            )
        })
    }))
}

fn parse_lines<'a>(
    lines: impl IntoIterator<Item = (Option<&'a Path>, usize, &'a str)>,
) -> Result<Vec<SshHostConfig>> {
    // Security: Set reasonable limits to prevent DoS attacks
    const MAX_LINE_LENGTH: usize = 8192; // 8KB per line should be more than enough
    const MAX_VALUE_LENGTH: usize = 4096; // 4KB for individual values

    let mut configs = Vec::new();
    let mut current_config: Option<SshHostConfig> = None;
    let mut current_match: Option<MatchBlock> = None;
    let mut in_match_block = false;
    let mut reported_diagnostics = HashSet::new();

    for (source_path, line_number, line) in lines {
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
                parse_option_first(
                    &mut match_block.config,
                    &keyword,
                    &args,
                    source_path,
                    line_number,
                    &mut reported_diagnostics,
                )
                .with_context(|| format!("Error at line {line_number}: {line}"))?;
            }
        } else if let Some(ref mut config) = current_config {
            parse_option_first(
                config,
                &keyword,
                &args,
                source_path,
                line_number,
                &mut reported_diagnostics,
            )
            .with_context(|| format!("Error at line {line_number}: {line}"))?;
        } else {
            // OpenSSH treats options before the first Host/Match directive as
            // global defaults. Model that region as the first `Host *` block
            // so the resolver's first-obtained merge semantics apply without
            // losing the original directive order.
            let config = current_config.get_or_insert_with(|| SshHostConfig {
                host_patterns: vec!["*".to_string()],
                block_type: Some(ConfigBlock::Host(vec!["*".to_string()])),
                ..Default::default()
            });
            parse_option_first(
                config,
                &keyword,
                &args,
                source_path,
                line_number,
                &mut reported_diagnostics,
            )
            .with_context(|| format!("Error at line {line_number}: {line}"))?;
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

/// Parse one directive independently, then merge it into its surrounding
/// Host/Match block. This preserves OpenSSH's first-obtained rule even for
/// repeated directives separated by Include file boundaries, while additive
/// options continue to accumulate through the shared resolver merge logic.
fn parse_option_first(
    target: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    source_path: Option<&Path>,
    line_number: usize,
    reported_diagnostics: &mut HashSet<String>,
) -> Result<()> {
    let mut parsed = SshHostConfig::default();
    options::parse_option(
        &mut parsed,
        keyword,
        args,
        source_path,
        line_number,
        reported_diagnostics,
    )?;
    merge_host_config(target, &parsed);
    Ok(())
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
        // Only an equals sign immediately following the option name selects
        // Option=Value syntax. Values such as `ProxyCommand env FOO=bar`
        // must stay in the ordinary whitespace-separated form.
        let key_candidate = line[..pos].trim();
        let equals_follows_option =
            !key_candidate.is_empty() && !key_candidate.chars().any(char::is_whitespace);
        // Host and Match never use equals syntax
        equals_follows_option && !matches!(key_candidate.to_lowercase().as_str(), "host" | "match")
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

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

use crate::ssh::ssh_config::include::{
    IncludedFile, resolve_includes, resolve_includes_for_host_at_pass,
};
use crate::ssh::ssh_config::match_directive::{MatchBlock, MatchCondition};
use crate::ssh::ssh_config::resolver::merge_host_config;
use crate::ssh::ssh_config::types::{ConfigBlock, ConfigPass, SshHostConfig};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

use super::diagnostic::DiagnosticSource;
use super::options;
use crate::ssh::ssh_config::diagnostic::escape_path;

/// Parse SSH configuration content with Include and Match support
#[cfg(test)]
pub fn parse(content: &str) -> Result<Vec<SshHostConfig>> {
    let mut reported_diagnostics = HashSet::new();
    parse_with_diagnostics(content, &mut reported_diagnostics)
}

pub(crate) fn parse_with_diagnostics(
    content: &str,
    reported_diagnostics: &mut HashSet<String>,
) -> Result<Vec<SshHostConfig>> {
    // For synchronous parsing without file path, we can't resolve includes
    // This maintains backward compatibility for tests and simple usage
    parse_without_includes(content, reported_diagnostics).map(add_final_pass_configs)
}

/// Parse SSH configuration from a file with full Include support.
pub(crate) async fn parse_from_file_with_diagnostics(
    path: &Path,
    content: &str,
    reported_diagnostics: &mut HashSet<String>,
) -> Result<Vec<SshHostConfig>> {
    // Pass 1: Resolve all Include directives
    let included_files = resolve_includes(path, content)
        .await
        .with_context(|| format!("Failed to resolve includes for {}", escape_path(path)))?;
    parse_included_files(&included_files, reported_diagnostics).map(add_final_pass_configs)
}

fn add_final_pass_configs(mut configs: Vec<SshHostConfig>) -> Vec<SshHostConfig> {
    let canonicalization_present = configs.iter().any(|config| {
        config
            .unimplemented_options
            .get("canonicalizehostname")
            .and_then(|values| values.first())
            .is_some_and(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "yes" | "true" | "always"
                )
            })
    });
    if !super::super::resolver::requests_final_pass(&configs) && !canonicalization_present {
        return configs;
    }
    let mut final_pass = configs.clone();
    for config in &mut final_pass {
        config.pass = ConfigPass::FinalOnly;
    }
    configs.extend(final_pass);
    configs
}

/// Parse a config file while resolving host-dependent Include paths.
#[cfg(test)]
pub(crate) async fn parse_from_file_for_host_at_with_diagnostics(
    path: &Path,
    content: &str,
    hostname: &str,
    initial_hostname: Option<&str>,
    initial_user: Option<&str>,
    anchor: std::path::PathBuf,
    reported_diagnostics: &mut HashSet<String>,
) -> Result<Vec<SshHostConfig>> {
    let first_pass = parse_from_file_for_host_pass_at_with_diagnostics(
        path,
        content,
        hostname,
        initial_hostname,
        initial_user,
        anchor.clone(),
        false,
        true,
        reported_diagnostics,
    )
    .await?;
    if !super::super::resolver::requests_final_pass_for_host(&first_pass, hostname) {
        return Ok(first_pass);
    }
    let preliminary = super::super::resolver::find_host_config(&first_pass, hostname);
    let final_pass = parse_from_file_for_host_pass_at_with_diagnostics(
        path,
        content,
        hostname,
        preliminary.hostname.as_deref(),
        preliminary.user.as_deref(),
        anchor,
        true,
        true,
        reported_diagnostics,
    )
    .await?;
    let mut combined = first_pass;
    combined.extend(final_pass);
    Ok(combined)
}

/// Parse one OpenSSH configuration pass for a single top-level source.
///
/// Callers that combine user and system files must run every source for pass
/// one before invoking this function for the final pass on any source.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn parse_from_file_for_host_pass_at_with_diagnostics(
    path: &Path,
    content: &str,
    hostname: &str,
    initial_hostname: Option<&str>,
    initial_user: Option<&str>,
    anchor: std::path::PathBuf,
    final_pass: bool,
    allow_tilde: bool,
    reported_diagnostics: &mut HashSet<String>,
) -> Result<Vec<SshHostConfig>> {
    let included_files = resolve_includes_for_host_at_pass(
        path,
        content,
        Some(hostname),
        anchor,
        initial_hostname,
        initial_user,
        final_pass,
        allow_tilde,
    )
    .await
    .with_context(|| {
        let pass = if final_pass { "final-pass " } else { "" };
        format!("Failed to resolve {pass}includes for {}", escape_path(path))
    })?;
    let mut configs = parse_included_files(&included_files, reported_diagnostics)?;
    if final_pass {
        for config in &mut configs {
            config.pass = ConfigPass::FinalOnly;
        }
    }
    Ok(configs)
}

/// Parse SSH configuration content without Include resolution
pub(super) fn parse_without_includes(
    content: &str,
    reported_diagnostics: &mut HashSet<String>,
) -> Result<Vec<SshHostConfig>> {
    parse_lines(
        content
            .lines()
            .enumerate()
            .map(|(index, line)| (None, index + 1, line, &[][..], None, None, None)),
        reported_diagnostics,
    )
}

/// Parse raw `-o Key=Value` arguments into a leading `Host *` overlay.
///
/// Keeping the overlay as a structured block lets the ordinary resolver apply
/// OpenSSH's first-obtained rule: CLI options are visited before file blocks,
/// while repeated `-o` scalars retain the first CLI value.
pub(crate) fn parse_cli_options(
    options: &[String],
    reported_diagnostics: &mut HashSet<String>,
) -> Result<Option<SshHostConfig>> {
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
            DiagnosticSource::CliOption { option_number },
            reported_diagnostics,
        )
        .with_context(|| format!("Invalid -o option #{option_number} ({keyword})"))?;
    }

    Ok(Some(overlay))
}

fn parse_included_files(
    files: &[IncludedFile],
    reported_diagnostics: &mut HashSet<String>,
) -> Result<Vec<SshHostConfig>> {
    parse_lines(
        files.iter().flat_map(|file| {
            file.content.lines().enumerate().map(move |(index, line)| {
                (
                    Some(file.path.as_path()),
                    file.source_lines.get(index).copied().unwrap_or(index + 1),
                    line,
                    file.scope_guards.as_slice(),
                    file.precomputed_scope_active,
                    file.precomputed_matches.get(index).copied().flatten(),
                    file.precomputed_final_requests
                        .get(index)
                        .copied()
                        .flatten(),
                )
            })
        }),
        reported_diagnostics,
    )
}

fn parse_lines<'a>(
    lines: impl IntoIterator<
        Item = (
            Option<&'a Path>,
            usize,
            &'a str,
            &'a [String],
            Option<bool>,
            Option<bool>,
            Option<bool>,
        ),
    >,
    reported_diagnostics: &mut HashSet<String>,
) -> Result<Vec<SshHostConfig>> {
    // Security: Set reasonable limits to prevent DoS attacks
    const MAX_LINE_LENGTH: usize = 8192; // 8KB per line should be more than enough
    const MAX_VALUE_LENGTH: usize = 4096; // 4KB for individual values

    let mut configs = Vec::new();
    let mut current_config: Option<SshHostConfig> = None;
    let mut current_match: Option<MatchBlock> = None;
    let mut in_match_block = false;
    for (
        source_path,
        line_number,
        line,
        scope_guards,
        precomputed_scope_active,
        precomputed_match,
        precomputed_requests_final,
    ) in lines
    {
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

        // Check for exact Include directive (should have been resolved in pass 1).
        if super::super::include::parse_include_line(line)?.is_some() {
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
                precomputed_match,
                precomputed_requests_final,
                precomputed_scope_active,
                scope_guards: parse_scope_guards(scope_guards, line_number)?,
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
                precomputed_scope_active,
                scope_guards: parse_scope_guards(scope_guards, line_number)?,
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
                    DiagnosticSource::Config {
                        path: source_path,
                        line_number,
                    },
                    reported_diagnostics,
                )
                .with_context(|| format!("Error at line {line_number}: {line}"))?;
            }
        } else if let Some(ref mut config) = current_config {
            parse_option_first(
                config,
                &keyword,
                &args,
                DiagnosticSource::Config {
                    path: source_path,
                    line_number,
                },
                reported_diagnostics,
            )
            .with_context(|| format!("Error at line {line_number}: {line}"))?;
        } else {
            // OpenSSH treats options before the first Host/Match directive as
            // global defaults. Model that region as the first `Host *` block
            // so the resolver's first-obtained merge semantics apply without
            // losing the original directive order.
            if current_config.is_none() {
                current_config = Some(SshHostConfig {
                    host_patterns: vec!["*".to_string()],
                    block_type: Some(ConfigBlock::Host(vec!["*".to_string()])),
                    precomputed_scope_active,
                    scope_guards: parse_scope_guards(scope_guards, line_number)?,
                    ..Default::default()
                });
            }
            let config = current_config.as_mut().expect("config was initialized");
            parse_option_first(
                config,
                &keyword,
                &args,
                DiagnosticSource::Config {
                    path: source_path,
                    line_number,
                },
                reported_diagnostics,
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

fn parse_scope_guards(scopes: &[String], line_number: usize) -> Result<Vec<ConfigBlock>> {
    scopes
        .iter()
        .map(|scope| {
            let lower = scope.trim().to_ascii_lowercase();
            if lower.starts_with("host ") || lower.starts_with("host=") {
                parse_host_line(scope, line_number).map(ConfigBlock::Host)
            } else {
                MatchCondition::parse_match_line(scope, line_number).map(ConfigBlock::Match)
            }
        })
        .collect()
}

/// Parse one directive independently, then merge it into its surrounding
/// Host/Match block. This preserves OpenSSH's first-obtained rule even for
/// repeated directives separated by Include file boundaries, while additive
/// options continue to accumulate through the shared resolver merge logic.
fn parse_option_first(
    target: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    source: DiagnosticSource<'_>,
    reported_diagnostics: &mut HashSet<String>,
) -> Result<()> {
    let mut parsed = SshHostConfig::default();
    options::parse_option(&mut parsed, keyword, args, source, reported_diagnostics)?;
    merge_host_config(target, &parsed);
    Ok(())
}

/// Parse a Host directive line
pub(super) fn parse_host_line(line: &str, line_number: usize) -> Result<Vec<String>> {
    let (keyword, patterns) = parse_config_line(line, line_number, 4096)?;
    if keyword != "host" {
        anyhow::bail!("Invalid Host directive at line {line_number}");
    }
    if patterns.is_empty() {
        anyhow::bail!("Host directive requires at least one pattern at line {line_number}");
    }
    Ok(patterns)
}

/// Parse a configuration line into keyword and arguments
pub(super) fn parse_config_line(
    line: &str,
    line_number: usize,
    max_value_length: usize,
) -> Result<(String, Vec<String>)> {
    let line = line.trim();
    let boundary = line
        .char_indices()
        .find(|(_, ch)| ch.is_whitespace() || *ch == '=');
    let (keyword, remainder, equals) = match boundary {
        Some((index, delimiter)) => {
            let mut remainder = line[index + delimiter.len_utf8()..].trim_start();
            let mut equals = delimiter == '=';
            if !equals && let Some(after_equals) = remainder.strip_prefix('=') {
                remainder = after_equals.trim_start();
                equals = true;
            }
            (&line[..index], remainder, equals)
        }
        None => (line, "", false),
    };
    if keyword.is_empty() {
        return Ok((String::new(), Vec::new()));
    }
    if remainder.len() > max_value_length {
        anyhow::bail!(
            "Value at line {line_number} exceeds maximum length of {max_value_length} bytes"
        );
    }
    let keyword = keyword.to_ascii_lowercase();
    let mut args = super::super::value::tokenize(remainder, line_number)?;
    if equals
        && matches!(
            keyword.as_str(),
            "ciphers"
                | "macs"
                | "hostkeyalgorithms"
                | "kexalgorithms"
                | "preferredauthentications"
                | "protocol"
        )
    {
        args = args
            .iter()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .map(str::to_string)
            .collect();
    }
    Ok((keyword, args))
}

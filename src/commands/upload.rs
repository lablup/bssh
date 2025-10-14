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

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::path::Path;

use crate::executor::ParallelExecutor;
use crate::node::Node;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ui::OutputFormatter;
use crate::utils::fs::{format_bytes, resolve_source_files};

pub struct FileTransferParams<'a> {
    pub nodes: Vec<Node>,
    pub max_parallel: usize,
    pub key_path: Option<&'a Path>,
    pub strict_mode: StrictHostKeyChecking,
    pub use_agent: bool,
    pub use_password: bool,
    pub recursive: bool,
}

pub async fn upload_file(
    params: FileTransferParams<'_>,
    source: &Path,
    destination: &str,
) -> Result<()> {
    // Security: Validate the local source path
    let validated_source = crate::security::validate_local_path(source)
        .with_context(|| format!("Invalid source path: {source:?}"))?;

    // Security: Validate the remote destination path
    let validated_destination = crate::security::validate_remote_path(destination)
        .with_context(|| format!("Invalid destination path: {destination}"))?;

    // Collect all files matching the pattern
    let files = resolve_source_files(&validated_source, params.recursive)?;

    if files.is_empty() {
        anyhow::bail!("No files found matching pattern: {source:?}");
    }

    // Determine destination handling based on file count
    let is_dir_destination = validated_destination.ends_with('/') || files.len() > 1;

    // Display upload summary
    println!(
        "\n{} {} {} file(s) to {} nodes {}",
        "▶".cyan(),
        "Uploading".cyan().bold(),
        files.len().to_string().yellow(),
        params.nodes.len().to_string().yellow(),
        "(SFTP)".dimmed()
    );
    for file in &files {
        let size = std::fs::metadata(file)
            .map_or_else(|_| "unknown".to_string(), |m| format_bytes(m.len()));
        println!("  {} {} ({})", "•".dimmed(), file.display(), size.yellow());
    }
    println!(
        "{} {}\n",
        "Destination:".bold(),
        validated_destination.green()
    );

    let key_path_str = params.key_path.map(|p| p.to_string_lossy().to_string());
    let executor = ParallelExecutor::new_with_all_options(
        params.nodes.clone(),
        params.max_parallel,
        key_path_str.clone(),
        params.strict_mode,
        params.use_agent,
        params.use_password,
    );

    let mut total_success = 0;
    let mut total_failed = 0;

    // For recursive uploads, determine the base directory to preserve structure
    let base_dir = if params.recursive && source.is_dir() {
        Some(source)
    } else if params.recursive && !files.is_empty() {
        // For glob patterns with recursive, find common parent
        files.first().and_then(|f| f.parent())
    } else {
        None
    };

    // Upload each file
    for file in &files {
        let remote_path = if is_dir_destination {
            // If destination is a directory or multiple files
            if params.recursive {
                if let Some(base) = base_dir {
                    // Preserve directory structure for recursive uploads
                    let relative_path = file.strip_prefix(base).unwrap_or(file);
                    let remote_relative = relative_path.to_string_lossy();

                    // Create remote directory structure if needed
                    if let Some(parent) = relative_path.parent() {
                        if !parent.as_os_str().is_empty() {
                            let remote_dir = if validated_destination.ends_with('/') {
                                format!("{}{}", validated_destination, parent.display())
                            } else {
                                format!("{}/{}", validated_destination, parent.display())
                            };
                            // Create remote directory using SSH command
                            let mkdir_cmd = format!("mkdir -p '{remote_dir}'");
                            let _ = executor.execute(&mkdir_cmd).await;
                        }
                    }

                    if validated_destination.ends_with('/') {
                        format!("{validated_destination}{remote_relative}")
                    } else {
                        format!("{validated_destination}/{remote_relative}")
                    }
                } else {
                    // No base dir, just use filename
                    let filename = file
                        .file_name()
                        .ok_or_else(|| anyhow::anyhow!("Failed to get filename from {file:?}"))?
                        .to_string_lossy();
                    if validated_destination.ends_with('/') {
                        format!("{validated_destination}{filename}")
                    } else {
                        format!("{validated_destination}/{filename}")
                    }
                }
            } else {
                // Non-recursive: just append filename
                let filename = file
                    .file_name()
                    .ok_or_else(|| anyhow::anyhow!("Failed to get filename from {file:?}"))?
                    .to_string_lossy();
                if validated_destination.ends_with('/') {
                    format!("{validated_destination}{filename}")
                } else {
                    format!("{validated_destination}/{filename}")
                }
            }
        } else {
            // Single file to specific destination
            validated_destination.clone()
        };

        println!(
            "\n{} {} {} {} {}",
            "▶".cyan(),
            "Uploading".cyan(),
            file.display(),
            "→".dimmed(),
            remote_path.green()
        );
        let results = executor.upload_file(file, &remote_path).await?;

        // Print results for this file
        for result in &results {
            result.print_summary();
        }

        let success_count = results.iter().filter(|r| r.is_success()).count();
        let failed_count = results.len() - success_count;

        total_success += success_count;
        total_failed += failed_count;
    }

    println!(
        "{}",
        OutputFormatter::format_summary(total_success + total_failed, total_success, total_failed)
    );

    if total_failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

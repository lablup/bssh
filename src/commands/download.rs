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
use tokio::fs;

use crate::executor::{self, ParallelExecutor};
use crate::ssh::SshClient;
use crate::ui::OutputFormatter;

use super::upload::FileTransferParams;

pub async fn download_file(
    params: FileTransferParams<'_>,
    source: &str,
    destination: &Path,
) -> Result<()> {
    // Create destination directory if it doesn't exist
    if !destination.exists() {
        fs::create_dir_all(destination).await.with_context(|| {
            format!(
                "Failed to create destination directory: {}",
                destination.display()
            )
        })?;
    }

    let key_path_str = params.key_path.map(|p| p.to_string_lossy().to_string());
    let executor = ParallelExecutor::new_with_all_options(
        params.nodes.clone(),
        params.max_parallel,
        key_path_str.clone(),
        params.strict_mode,
        params.use_agent,
        params.use_password,
    );

    // Check if source contains glob pattern
    let has_glob = source.contains('*') || source.contains('?') || source.contains('[');

    // Check if source is a directory (for recursive download)
    let is_directory = if params.recursive && !has_glob {
        // Use a test command to check if source is a directory
        let test_cmd = format!("test -d '{source}' && echo 'dir' || echo 'file'");
        let test_results = executor.execute(&test_cmd).await?;
        test_results.iter().any(|r| {
            r.result
                .as_ref()
                .is_ok_and(|res| String::from_utf8_lossy(&res.output).trim() == "dir")
        })
    } else {
        false
    };

    if is_directory {
        // Recursive directory download using SFTP
        println!(
            "\n{} {} {} {} from {} nodes {}\n",
            "▶".cyan(),
            "Recursively downloading directory".cyan().bold(),
            source.green(),
            "from".dimmed(),
            params.nodes.len().to_string().yellow(),
            "(SFTP)".dimmed()
        );

        let mut total_success = 0;
        let mut total_failed = 0;

        // Download the entire directory from each node
        for node in &params.nodes {
            let node_dir = destination.join(node.to_string());

            println!(
                "\n{} {} {} {} {:?}",
                "▶".cyan(),
                "Downloading from".cyan(),
                node.to_string().bold(),
                "to".dimmed(),
                node_dir
            );

            // Use the download_dir_from_node function directly
            let result = executor::download_dir_from_node(
                node.clone(),
                source,
                &node_dir,
                key_path_str.as_deref(),
                params.strict_mode,
                params.use_agent,
                params.use_password,
            )
            .await;

            match result {
                Ok(_) => {
                    println!(
                        "  {} {}",
                        "●".green(),
                        "Successfully downloaded directory".green()
                    );
                    total_success += 1;
                }
                Err(e) => {
                    println!(
                        "  {} {} {}",
                        "●".red(),
                        "Failed to download directory:".red(),
                        e.to_string().dimmed()
                    );
                    total_failed += 1;
                }
            }
        }

        println!(
            "{}",
            OutputFormatter::format_summary(
                total_success + total_failed,
                total_success,
                total_failed
            )
        );

        if total_failed > 0 {
            std::process::exit(1);
        }
    } else if has_glob {
        println!(
            "Resolving glob pattern '{}' on {} nodes...",
            source,
            params.nodes.len()
        );

        // First, execute ls command with glob to find matching files on first node
        let test_node = params
            .nodes
            .first()
            .ok_or_else(|| anyhow::anyhow!("No nodes available"))?;
        let glob_command = format!("ls -1 {source} 2>/dev/null || true");

        let mut test_client = SshClient::new(
            test_node.host.clone(),
            test_node.port,
            test_node.username.clone(),
        );

        let glob_result = test_client
            .connect_and_execute_with_host_check(
                &glob_command,
                params.key_path,
                Some(params.strict_mode),
                params.use_agent,
                params.use_password,
                None, // Use default timeout for ls command
            )
            .await?;

        let remote_files: Vec<String> = String::from_utf8_lossy(&glob_result.output)
            .lines()
            .filter(|line| !line.is_empty())
            .map(std::string::ToString::to_string)
            .collect();

        if remote_files.is_empty() {
            anyhow::bail!("No files found matching pattern: {}", source);
        }

        println!(
            "\n{} {} {} file(s) matching pattern:",
            "▶".cyan(),
            "Found".bold(),
            remote_files.len().to_string().yellow()
        );
        for file in &remote_files {
            println!("  {} {}", "•".dimmed(), file.cyan());
        }
        println!("{} {}\n", "Destination:".bold(), destination.display());

        // Download each file
        let results = executor
            .download_files(remote_files.clone(), destination)
            .await?;

        // Print results
        let mut total_success = 0;
        let mut total_failed = 0;

        for result in &results {
            result.print_summary();
            if result.is_success() {
                total_success += 1;
            } else {
                total_failed += 1;
            }
        }

        println!(
            "{}",
            OutputFormatter::format_summary(
                total_success + total_failed,
                total_success,
                total_failed
            )
        );

        if total_failed > 0 {
            std::process::exit(1);
        }
    } else {
        // Single file download
        println!(
            "\n{} {} {} from {} nodes to {} {}\n",
            "▶".cyan(),
            "Downloading".cyan().bold(),
            source.green(),
            params.nodes.len().to_string().yellow(),
            destination.display(),
            "(SFTP)".dimmed()
        );

        let results = executor.download_file(source, destination).await?;

        // Print results
        for result in &results {
            result.print_summary();
        }

        // Print summary
        let success_count = results.iter().filter(|r| r.is_success()).count();
        let failed_count = results.len() - success_count;

        println!(
            "{}",
            OutputFormatter::format_summary(
                success_count + failed_count,
                success_count,
                failed_count
            )
        );

        if failed_count > 0 {
            std::process::exit(1);
        }
    }

    Ok(())
}

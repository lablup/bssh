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
use tokio::io::AsyncWriteExt;

use crate::executor::ExecutionResult;

pub async fn save_outputs_to_files(
    results: &[ExecutionResult],
    output_dir: &Path,
    command: &str,
) -> Result<()> {
    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir)
        .await
        .with_context(|| format!("Failed to create output directory: {output_dir:?}"))?;

    // Get timestamp for unique file naming
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");

    println!(
        "\n{} {} {:?}\n",
        "▶".cyan(),
        "Saving outputs to".cyan(),
        output_dir
    );

    for result in results {
        let node_name = result.node.host.replace([':', '/'], "_");

        match &result.result {
            Ok(cmd_result) => {
                // Save stdout if not empty
                if !cmd_result.output.is_empty() {
                    let stdout_file = output_dir.join(format!("{node_name}_{timestamp}.stdout"));
                    let mut file = fs::File::create(&stdout_file).await.with_context(|| {
                        format!("Failed to create stdout file: {stdout_file:?}")
                    })?;

                    // Write metadata header
                    let header = format!(
                        "# Command: {}\n# Host: {}\n# User: {}\n# Exit Status: {}\n# Timestamp: {}\n\n",
                        command,
                        result.node.host,
                        result.node.username,
                        cmd_result.exit_status,
                        timestamp
                    );
                    file.write_all(header.as_bytes()).await?;
                    file.write_all(&cmd_result.output).await?;
                    file.flush().await?;

                    println!(
                        "  {} Saved stdout for {} to {:?}",
                        "●".green(),
                        result.node.to_string().bold(),
                        stdout_file
                    );
                }

                // Save stderr if not empty
                if !cmd_result.stderr.is_empty() {
                    let stderr_file = output_dir.join(format!("{node_name}_{timestamp}.stderr"));
                    let mut file = fs::File::create(&stderr_file).await.with_context(|| {
                        format!("Failed to create stderr file: {stderr_file:?}")
                    })?;

                    // Write metadata header
                    let header = format!(
                        "# Command: {}\n# Host: {}\n# User: {}\n# Exit Status: {}\n# Timestamp: {}\n\n",
                        command,
                        result.node.host,
                        result.node.username,
                        cmd_result.exit_status,
                        timestamp
                    );
                    file.write_all(header.as_bytes()).await?;
                    file.write_all(&cmd_result.stderr).await?;
                    file.flush().await?;

                    println!(
                        "  {} Saved stderr for {} to {:?}",
                        "●".yellow(),
                        result.node.to_string().bold(),
                        stderr_file
                    );
                }

                // If both stdout and stderr are empty, create a marker file
                if cmd_result.output.is_empty() && cmd_result.stderr.is_empty() {
                    let empty_file = output_dir.join(format!("{node_name}_{timestamp}.empty"));
                    let mut file = fs::File::create(&empty_file).await.with_context(|| {
                        format!("Failed to create empty marker file: {empty_file:?}")
                    })?;

                    let content = format!(
                        "# Command: {}\n# Host: {}\n# User: {}\n# Exit Status: {}\n# Timestamp: {}\n\nCommand produced no output.\n",
                        command,
                        result.node.host,
                        result.node.username,
                        cmd_result.exit_status,
                        timestamp
                    );
                    file.write_all(content.as_bytes()).await?;
                    file.flush().await?;

                    println!(
                        "  ✓ Command produced no output for {} (created marker file)",
                        result.node
                    );
                }
            }
            Err(e) => {
                // Save error to a file
                let error_file = output_dir.join(format!("{node_name}_{timestamp}.error"));
                let mut file = fs::File::create(&error_file)
                    .await
                    .with_context(|| format!("Failed to create error file: {error_file:?}"))?;

                let content = format!(
                    "# Command: {}\n# Host: {}\n# User: {}\n# Timestamp: {}\n\nError: {}\n",
                    command, result.node.host, result.node.username, timestamp, e
                );
                file.write_all(content.as_bytes()).await?;
                file.flush().await?;

                println!(
                    "  {} Saved error for {} to {:?}",
                    "●".red(),
                    result.node.to_string().bold(),
                    error_file
                );
            }
        }
    }

    // Create a summary file
    let summary_file = output_dir.join(format!("summary_{timestamp}.txt"));
    let mut file = fs::File::create(&summary_file)
        .await
        .with_context(|| format!("Failed to create summary file: {summary_file:?}"))?;

    let mut summary = format!(
        "Command Execution Summary\n{}\n\nCommand: {}\nTimestamp: {}\nTotal Nodes: {}\n\n",
        "=".repeat(60),
        command,
        timestamp,
        results.len()
    );

    summary.push_str("Node Results:\n");
    summary.push_str("-".repeat(40).as_str());
    summary.push('\n');

    for result in results {
        match &result.result {
            Ok(cmd_result) => {
                summary.push_str(&format!(
                    "  {} - Exit Status: {} {}\n",
                    result.node,
                    cmd_result.exit_status,
                    if cmd_result.is_success() {
                        "✓"
                    } else {
                        "✗"
                    }
                ));
            }
            Err(e) => {
                summary.push_str(&format!("  {} - Error: {}\n", result.node, e));
            }
        }
    }

    let success_count = results.iter().filter(|r| r.is_success()).count();
    let failed_count = results.len() - success_count;

    summary.push_str(&format!(
        "\nSummary: {success_count} successful, {failed_count} failed\n"
    ));

    file.write_all(summary.as_bytes()).await?;
    file.flush().await?;

    println!(
        "\n  {} {} {summary_file:?}\n",
        "●".blue(),
        "Saved execution summary to".blue()
    );

    Ok(())
}

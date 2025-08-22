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
use clap::Parser;
use glob::glob;
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing_subscriber::EnvFilter;

use bssh::{
    cli::{Cli, Commands},
    config::Config,
    executor::ParallelExecutor,
    node::Node,
    ssh::{SshClient, known_hosts::StrictHostKeyChecking},
    ui::OutputFormatter,
};

struct ExecuteCommandParams<'a> {
    nodes: Vec<Node>,
    command: &'a str,
    max_parallel: usize,
    key_path: Option<&'a Path>,
    verbose: bool,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    output_dir: Option<&'a Path>,
}

struct FileTransferParams<'a> {
    nodes: Vec<Node>,
    max_parallel: usize,
    key_path: Option<&'a Path>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    recursive: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose);

    // Load configuration with priority
    let config = Config::load_with_priority(&cli.config).await?;

    // Handle list command first (doesn't need nodes)
    if matches!(cli.command, Some(Commands::List)) {
        list_clusters(&config);
        return Ok(());
    }

    // Determine nodes to execute on
    let nodes = resolve_nodes(&cli, &config).await?;

    if nodes.is_empty() {
        anyhow::bail!(
            "No hosts specified. Please use one of the following options:\n  -H <hosts>    Specify comma-separated hosts (e.g., -H user@host1,user@host2)\n  -c <cluster>  Use a cluster from your configuration file"
        );
    }

    // Parse strict host key checking mode
    let strict_mode = cli.strict_host_key_checking.parse().unwrap_or_default();

    // Get command to execute
    let command = cli.get_command();

    // Check if command is required (not for subcommands like ping, copy)
    let needs_command = matches!(cli.command, None | Some(Commands::Exec { .. }));
    if command.is_empty() && needs_command {
        anyhow::bail!(
            "No command specified. Please provide a command to execute.\nExample: bssh -H host1,host2 'ls -la'"
        );
    }

    // Handle remaining commands
    match cli.command {
        Some(Commands::Ping) => {
            ping_nodes(
                nodes,
                cli.parallel,
                cli.identity.as_deref(),
                strict_mode,
                cli.use_agent,
                cli.password,
            )
            .await?;
        }
        Some(Commands::Upload {
            source,
            destination,
            recursive,
        }) => {
            let params = FileTransferParams {
                nodes,
                max_parallel: cli.parallel,
                key_path: cli.identity.as_deref(),
                strict_mode,
                use_agent: cli.use_agent,
                use_password: cli.password,
                recursive,
            };
            upload_file(params, &source, &destination).await?;
        }
        Some(Commands::Download {
            source,
            destination,
            recursive,
        }) => {
            let params = FileTransferParams {
                nodes,
                max_parallel: cli.parallel,
                key_path: cli.identity.as_deref(),
                strict_mode,
                use_agent: cli.use_agent,
                use_password: cli.password,
                recursive,
            };
            download_file(params, &source, &destination).await?;
        }
        _ => {
            // Execute command
            let params = ExecuteCommandParams {
                nodes,
                command: &command,
                max_parallel: cli.parallel,
                key_path: cli.identity.as_deref(),
                verbose: cli.verbose > 0,
                strict_mode,
                use_agent: cli.use_agent,
                use_password: cli.password,
                output_dir: cli.output_dir.as_deref(),
            };
            execute_command(params).await?;
        }
    }

    Ok(())
}

fn init_logging(verbosity: u8) {
    let filter = match verbosity {
        0 => EnvFilter::new("bssh=warn"),
        1 => EnvFilter::new("bssh=info"),
        2 => EnvFilter::new("bssh=debug"),
        _ => EnvFilter::new("bssh=trace"),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

async fn resolve_nodes(cli: &Cli, config: &Config) -> Result<Vec<Node>> {
    let mut nodes = Vec::new();

    // Priority: command line hosts > explicit cluster > Backend.AI cluster (if no other option)
    if let Some(hosts) = &cli.hosts {
        for host_str in hosts {
            let node = Node::parse(host_str, cli.user.as_deref())
                .with_context(|| format!("Invalid host format: '{host_str}'. Expected format: [user@]hostname[:port]\nExamples:\n  - hostname\n  - user@hostname\n  - hostname:2222\n  - user@hostname:2222"))?;
            nodes.push(node);
        }
    } else if let Some(cluster_name) = &cli.cluster {
        nodes = config.resolve_nodes(cluster_name)?;
    } else if config.clusters.contains_key("backendai") {
        // Automatically use Backend.AI cluster if no hosts or cluster specified
        nodes = config.resolve_nodes("backendai")?;
    }

    Ok(nodes)
}

fn list_clusters(config: &Config) {
    if config.clusters.is_empty() {
        println!("{}", "No clusters configured".dimmed());
        return;
    }

    println!("\n{} {}\n", "▶".cyan(), "Available clusters".bold());
    for (name, cluster) in &config.clusters {
        println!(
            "  {} {} ({} {})",
            "●".blue(),
            name.bold(),
            cluster.nodes.len().to_string().yellow(),
            if cluster.nodes.len() == 1 {
                "node"
            } else {
                "nodes"
            }
        );
        for node_config in &cluster.nodes {
            let node_str = match node_config {
                bssh::config::NodeConfig::Simple(s) => s.clone(),
                bssh::config::NodeConfig::Detailed { host, .. } => host.clone(),
            };
            println!("    {} {}", "•".dimmed(), node_str.dimmed());
        }
    }
    println!();
}

async fn ping_nodes(
    nodes: Vec<Node>,
    max_parallel: usize,
    key_path: Option<&Path>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
) -> Result<()> {
    println!(
        "{}",
        OutputFormatter::format_command_header("ping", nodes.len())
    );

    let key_path = key_path.map(|p| p.to_string_lossy().to_string());
    let executor = ParallelExecutor::new_with_all_options(
        nodes.clone(),
        max_parallel,
        key_path,
        strict_mode,
        use_agent,
        use_password,
    );

    let results = executor.execute("echo 'pong'").await?;

    let mut success_count = 0;
    let mut failed_count = 0;

    println!("\n{} {}\n", "▶".cyan(), "Connection Test Results".bold());

    for result in &results {
        if result.is_success() {
            success_count += 1;
            println!(
                "  {} {} - {}",
                "●".green(),
                result.node.to_string().bold(),
                "Connected".green()
            );
        } else {
            failed_count += 1;
            println!(
                "  {} {} - {}",
                "●".red(),
                result.node.to_string().bold(),
                "Failed".red()
            );
            if let Err(e) = &result.result {
                println!("    {} {}", "└".dimmed(), e.to_string().dimmed());
            }
        }
    }

    println!(
        "{}",
        OutputFormatter::format_summary(nodes.len(), success_count, failed_count)
    );

    Ok(())
}

async fn execute_command(params: ExecuteCommandParams<'_>) -> Result<()> {
    println!(
        "{}",
        OutputFormatter::format_command_header(params.command, params.nodes.len())
    );

    let key_path = params.key_path.map(|p| p.to_string_lossy().to_string());
    let executor = ParallelExecutor::new_with_all_options(
        params.nodes,
        params.max_parallel,
        key_path,
        params.strict_mode,
        params.use_agent,
        params.use_password,
    );

    let results = executor.execute(params.command).await?;

    // Save outputs to files if output_dir is specified
    if let Some(dir) = params.output_dir {
        save_outputs_to_files(&results, dir, params.command).await?;
    }

    // Print results
    for result in &results {
        result.print_output(params.verbose);
    }

    // Print summary
    let success_count = results.iter().filter(|r| r.is_success()).count();
    let failed_count = results.len() - success_count;

    println!(
        "{}",
        OutputFormatter::format_summary(results.len(), success_count, failed_count)
    );

    if failed_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

async fn save_outputs_to_files(
    results: &[bssh::executor::ExecutionResult],
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

async fn upload_file(
    params: FileTransferParams<'_>,
    source: &Path,
    destination: &str,
) -> Result<()> {
    // Collect all files matching the pattern
    let files = resolve_source_files(source, params.recursive)?;

    if files.is_empty() {
        anyhow::bail!("No files found matching pattern: {:?}", source);
    }

    // Determine destination handling based on file count
    let is_dir_destination = destination.ends_with('/') || files.len() > 1;

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
            .map(|m| format_bytes(m.len()))
            .unwrap_or_else(|_| "unknown".to_string());
        println!("  {} {:?} ({})", "•".dimmed(), file, size.yellow());
    }
    println!("{} {}\n", "Destination:".bold(), destination.green());

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
                    if let Some(parent) = relative_path.parent()
                        && !parent.as_os_str().is_empty()
                    {
                        let remote_dir = if destination.ends_with('/') {
                            format!("{destination}{}", parent.display())
                        } else {
                            format!("{destination}/{}", parent.display())
                        };
                        // Create remote directory using SSH command
                        let mkdir_cmd = format!("mkdir -p '{remote_dir}'");
                        let _ = executor.execute(&mkdir_cmd).await;
                    }

                    if destination.ends_with('/') {
                        format!("{destination}{remote_relative}")
                    } else {
                        format!("{destination}/{remote_relative}")
                    }
                } else {
                    // No base dir, just use filename
                    let filename = file
                        .file_name()
                        .ok_or_else(|| anyhow::anyhow!("Failed to get filename from {:?}", file))?
                        .to_string_lossy();
                    if destination.ends_with('/') {
                        format!("{destination}{filename}")
                    } else {
                        format!("{destination}/{filename}")
                    }
                }
            } else {
                // Non-recursive: just append filename
                let filename = file
                    .file_name()
                    .ok_or_else(|| anyhow::anyhow!("Failed to get filename from {:?}", file))?
                    .to_string_lossy();
                if destination.ends_with('/') {
                    format!("{destination}{filename}")
                } else {
                    format!("{destination}/{filename}")
                }
            }
        } else {
            // Single file to specific destination
            destination.to_string()
        };

        println!(
            "\n{} {} {:?} {} {}",
            "▶".cyan(),
            "Uploading".cyan(),
            file,
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

// Helper function to resolve source files from glob pattern
fn resolve_source_files(source: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let source_str = source.to_string_lossy();

    // Check if it's a glob pattern (contains *, ?, [, ])
    if source_str.contains('*') || source_str.contains('?') || source_str.contains('[') {
        // Use glob to find matching files
        let mut files = Vec::new();
        for entry in
            glob(&source_str).with_context(|| format!("Invalid glob pattern: {source_str}"))?
        {
            match entry {
                Ok(path) if path.is_file() => files.push(path),
                Ok(path) if path.is_dir() && recursive => {
                    // Recursively add files from directories when using glob with --recursive
                    files.extend(walk_directory(&path)?);
                }
                Ok(_) => {} // Skip directories if not recursive
                Err(e) => tracing::warn!("Failed to read glob entry: {}", e),
            }
        }
        Ok(files)
    } else if source.is_file() {
        // Single file
        Ok(vec![source.to_path_buf()])
    } else if source.exists() && source.is_dir() {
        if recursive {
            // Recursively walk the directory
            walk_directory(source)
        } else {
            anyhow::bail!(
                "Source is a directory. Use --recursive flag or a glob pattern like '{}/*' to upload files",
                source_str
            );
        }
    } else {
        // Try as glob pattern even without special characters (might be escaped)
        let mut files = Vec::new();
        for path in glob(&source_str)
            .unwrap_or_else(|_| glob::glob("").unwrap())
            .flatten()
        {
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() && recursive {
                files.extend(walk_directory(&path)?);
            }
        }

        if files.is_empty() {
            anyhow::bail!("Source file does not exist: {:?}", source);
        }
        Ok(files)
    }
}

// Helper function to recursively walk a directory and collect all files
fn walk_directory(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;

        if metadata.is_file() {
            files.push(path);
        } else if metadata.is_dir() {
            // Recursively walk subdirectories
            files.extend(walk_directory(&path)?);
        }
        // Skip symlinks and other special files
    }

    Ok(files)
}

// Helper function to format bytes in human-readable format
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", size as u64, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

async fn download_file(
    params: FileTransferParams<'_>,
    source: &str,
    destination: &Path,
) -> Result<()> {
    // Create destination directory if it doesn't exist
    if !destination.exists() {
        fs::create_dir_all(destination)
            .await
            .with_context(|| format!("Failed to create destination directory: {destination:?}"))?;
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
            let result = bssh::executor::download_dir_from_node(
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
            )
            .await?;

        let remote_files: Vec<String> = String::from_utf8_lossy(&glob_result.output)
            .lines()
            .filter(|line| !line.is_empty())
            .map(|s| s.to_string())
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
        println!("{} {:?}\n", "Destination:".bold(), destination);

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
            "\n{} {} {} from {} nodes to {:?} {}\n",
            "▶".cyan(),
            "Downloading".cyan().bold(),
            source.green(),
            params.nodes.len().to_string().yellow(),
            destination,
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

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
use std::path::{Path, PathBuf};
use std::time::Duration;

use bssh::{
    cli::{Cli, Commands},
    commands::{
        download::download_file,
        exec::{execute_command, ExecuteCommandParams},
        interactive::InteractiveCommand,
        list::list_clusters,
        ping::ping_nodes,
        upload::{upload_file, FileTransferParams},
    },
    config::{Config, InteractiveMode},
    node::Node,
    pty::PtyConfig,
    ssh::{known_hosts::StrictHostKeyChecking, SshConfig},
    utils::init_logging,
};

/// Show concise usage message (like SSH)
fn show_usage() {
    println!("usage: bssh [-46AqtTvx] [-C cluster] [-F ssh_configfile] [-H hosts]");
    println!("           [-i identity_file] [-J destination] [-l login_name]");
    println!("           [-o option] [-p port] [--config config] [--parallel N]");
    println!("           [--output-dir dir] [--timeout seconds] [--use-agent]");
    println!("           destination [command [argument ...]]");
    println!("       bssh [-Q query_option]");
    println!("       bssh [exec|list|ping|upload|download|interactive] ...");
    println!();
    println!("SSH Config Support:");
    println!("  -F ssh_configfile    Use alternative SSH configuration file");
    println!("                       Defaults to ~/.ssh/config if available");
    println!("                       Supports: Host, HostName, User, Port, IdentityFile,");
    println!("                       StrictHostKeyChecking, ProxyJump, and more");
    println!();
    println!("For more information, try 'bssh --help'");
}

/// Format a Duration into a human-readable string
fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs_f64();

    if total_seconds < 1.0 {
        // Less than 1 second: show in milliseconds
        format!("{:.1} ms", duration.as_secs_f64() * 1000.0)
    } else if total_seconds < 60.0 {
        // Less than 1 minute: show in seconds with 2 decimal places
        format!("{total_seconds:.2} s")
    } else {
        // 1 minute or more: show in minutes and seconds
        let minutes = duration.as_secs() / 60;
        let seconds = duration.as_secs() % 60;
        let millis = duration.subsec_millis();

        if seconds == 0 {
            format!("{minutes}m")
        } else if millis > 0 {
            format!("{minutes}m {seconds}.{millis:03}s")
        } else {
            format!("{minutes}m {seconds}s")
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Check if no arguments were provided
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        // Show concise usage when no arguments provided (like SSH)
        show_usage();
        std::process::exit(0);
    }

    let cli = Cli::parse();

    // Handle SSH query option (-Q)
    if let Some(ref query) = cli.query {
        handle_query(query);
        return Ok(());
    }

    // Initialize logging
    init_logging(cli.verbose);

    // Check if user explicitly specified options
    let has_explicit_config = args.iter().any(|arg| arg == "--config");
    let has_explicit_parallel = args
        .iter()
        .any(|arg| arg == "--parallel" || arg.starts_with("--parallel="));

    // If user explicitly specified --config, ensure the file exists
    if has_explicit_config {
        let expanded_path = if cli.config.starts_with("~") {
            let path_str = cli.config.to_string_lossy();
            if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(path_str.replacen("~", &home, 1))
            } else {
                cli.config.clone()
            }
        } else {
            cli.config.clone()
        };

        if !expanded_path.exists() {
            anyhow::bail!("Config file not found: {:?}", expanded_path);
        }
    }

    // Load configuration with priority
    let config = Config::load_with_priority(&cli.config).await?;

    // Load SSH configuration with caching for improved performance
    let ssh_config = if let Some(ref ssh_config_path) = cli.ssh_config {
        SshConfig::load_from_file_cached(ssh_config_path)
            .await
            .with_context(|| format!("Failed to load SSH config from {ssh_config_path:?}"))?
    } else {
        SshConfig::load_default_cached().await.unwrap_or_else(|_| {
            tracing::debug!("No SSH config found or failed to load, using empty config");
            SshConfig::new()
        })
    };

    // Handle list command first (doesn't need nodes)
    if matches!(cli.command, Some(Commands::List)) {
        list_clusters(&config);
        return Ok(());
    }

    // Handle cache-stats command (doesn't need nodes)
    if let Some(Commands::CacheStats {
        detailed,
        clear,
        maintain,
    }) = &cli.command
    {
        handle_cache_stats(*detailed, *clear, *maintain).await;
        return Ok(());
    }

    // Determine nodes to execute on
    let (nodes, actual_cluster_name) = resolve_nodes(&cli, &config, &ssh_config).await?;

    // Determine max_parallel: CLI argument takes precedence over config
    // For SSH mode (single host), parallel is always 1
    let max_parallel = if cli.is_ssh_mode() {
        1
    } else if has_explicit_parallel {
        cli.parallel
    } else {
        config
            .get_parallel(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
            .unwrap_or(cli.parallel) // Fall back to CLI default (10)
    };

    if nodes.is_empty() {
        anyhow::bail!(
            "No hosts specified. Please use one of the following options:\n  -H <hosts>    Specify comma-separated hosts (e.g., -H user@host1,user@host2)\n  -c <cluster>  Use a cluster from your configuration file"
        );
    }

    // Parse jump hosts if specified
    let jump_hosts = if let Some(ref jump_spec) = cli.jump_hosts {
        use bssh::jump::parse_jump_hosts;
        Some(
            parse_jump_hosts(jump_spec)
                .with_context(|| format!("Invalid jump host specification: '{jump_spec}'"))?,
        )
    } else {
        None
    };

    // Display jump host information if present
    if let Some(ref jumps) = jump_hosts {
        if jumps.len() == 1 {
            tracing::info!("Using jump host: {}", jumps[0]);
        } else {
            tracing::info!(
                "Using jump host chain: {}",
                jumps
                    .iter()
                    .map(|j| j.to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
        }
    }

    // Parse strict host key checking mode with SSH config integration
    let hostname = if cli.is_ssh_mode() {
        cli.parse_destination().map(|(_, host, _)| host)
    } else {
        None
    };
    let strict_mode = determine_strict_host_key_checking(&cli, &ssh_config, hostname.as_deref());

    // Get command to execute
    let command = cli.get_command();

    // Check if command is required (not for subcommands like ping, copy)
    // In SSH mode without a command, we start an interactive session
    let needs_command =
        matches!(cli.command, None | Some(Commands::Exec { .. })) && !cli.is_ssh_mode();
    if command.is_empty() && needs_command && !cli.force_tty {
        anyhow::bail!(
            "No command specified. Please provide a command to execute.\nExample: bssh -H host1,host2 'ls -la'"
        );
    }

    // Calculate hostname for SSH config integration (used in multiple commands)
    let hostname_for_ssh_config = if cli.is_ssh_mode() {
        cli.parse_destination().map(|(_, host, _)| host)
    } else {
        None
    };

    // Handle remaining commands
    match cli.command {
        Some(Commands::Ping) => {
            // Determine SSH key path with SSH config integration
            let key_path = determine_ssh_key_path(
                &cli,
                &config,
                &ssh_config,
                hostname_for_ssh_config.as_deref(),
                actual_cluster_name.as_deref().or(cli.cluster.as_deref()),
            );

            ping_nodes(
                nodes,
                max_parallel,
                key_path.as_deref(),
                strict_mode,
                cli.use_agent,
                cli.password,
            )
            .await
        }
        Some(Commands::Upload {
            ref source,
            ref destination,
            recursive,
        }) => {
            // Determine SSH key path with SSH config integration
            let key_path = determine_ssh_key_path(
                &cli,
                &config,
                &ssh_config,
                hostname_for_ssh_config.as_deref(),
                actual_cluster_name.as_deref().or(cli.cluster.as_deref()),
            );

            let params = FileTransferParams {
                nodes,
                max_parallel,
                key_path: key_path.as_deref(),
                strict_mode,
                use_agent: cli.use_agent,
                use_password: cli.password,
                recursive,
            };
            upload_file(params, source, destination).await
        }
        Some(Commands::Download {
            ref source,
            ref destination,
            recursive,
        }) => {
            // Determine SSH key path with SSH config integration
            let key_path = determine_ssh_key_path(
                &cli,
                &config,
                &ssh_config,
                hostname_for_ssh_config.as_deref(),
                actual_cluster_name.as_deref().or(cli.cluster.as_deref()),
            );

            let params = FileTransferParams {
                nodes,
                max_parallel,
                key_path: key_path.as_deref(),
                strict_mode,
                use_agent: cli.use_agent,
                use_password: cli.password,
                recursive,
            };
            download_file(params, source, destination).await
        }
        Some(Commands::Interactive {
            single_node,
            multiplex,
            ref prompt_format,
            ref history_file,
            ref work_dir,
        }) => {
            // Get interactive config from configuration file (with cluster-specific overrides)
            let cluster_name = cli.cluster.as_deref();
            let interactive_config = config.get_interactive_config(cluster_name);

            // Merge CLI arguments with config settings (CLI takes precedence)
            let merged_mode = if single_node {
                // CLI explicitly set single_node
                (true, false)
            } else if multiplex {
                // CLI didn't set single_node, use multiplex
                (false, true)
            } else {
                // Use config defaults
                match interactive_config.default_mode {
                    InteractiveMode::SingleNode => (true, false),
                    InteractiveMode::Multiplex => (false, true),
                }
            };

            // Use CLI values if provided, otherwise use config values
            let merged_prompt = if prompt_format != "[{node}:{user}@{host}:{pwd}]$ " {
                // CLI provided a custom prompt
                prompt_format.clone()
            } else {
                // Use config prompt
                interactive_config.prompt_format.clone()
            };

            let merged_history = if history_file.to_string_lossy() != "~/.bssh_history" {
                // CLI provided a custom history file
                history_file.clone()
            } else if let Some(config_history) = interactive_config.history_file.clone() {
                // Use config history file
                PathBuf::from(config_history)
            } else {
                // Use default
                history_file.clone()
            };

            let merged_work_dir = work_dir.clone().or(interactive_config.work_dir.clone());

            // Determine SSH key path with SSH config integration
            let key_path = determine_ssh_key_path(
                &cli,
                &config,
                &ssh_config,
                hostname_for_ssh_config.as_deref(),
                actual_cluster_name.as_deref().or(cli.cluster.as_deref()),
            );

            // Create PTY configuration based on CLI flags
            let pty_config = PtyConfig {
                force_pty: cli.force_tty,
                disable_pty: cli.no_tty,
                ..Default::default()
            };

            // Determine use_pty based on CLI flags
            let use_pty = if cli.force_tty {
                Some(true)
            } else if cli.no_tty {
                Some(false)
            } else {
                None // Auto-detect
            };

            let interactive_cmd = InteractiveCommand {
                single_node: merged_mode.0,
                multiplex: merged_mode.1,
                prompt_format: merged_prompt,
                history_file: merged_history,
                work_dir: merged_work_dir,
                nodes,
                config: config.clone(),
                interactive_config,
                cluster_name: cluster_name.map(String::from),
                key_path,
                use_agent: cli.use_agent,
                use_password: cli.password,
                strict_mode,
                pty_config,
                use_pty,
            };
            let result = interactive_cmd.execute().await?;
            println!("\nInteractive session ended.");
            println!("Duration: {}", format_duration(result.duration));
            println!("Commands executed: {}", result.commands_executed);
            println!("Nodes connected: {}", result.nodes_connected);
            Ok(())
        }
        _ => {
            // Execute command (default or Exec subcommand) or interactive shell
            // In SSH mode without command, start interactive session
            if cli.is_ssh_mode() && command.is_empty() {
                // SSH mode interactive session (like ssh user@host)
                tracing::info!("Starting SSH interactive session to {}", nodes[0].host);

                // Determine SSH key path with SSH config integration
                let key_path = determine_ssh_key_path(
                    &cli,
                    &config,
                    &ssh_config,
                    hostname_for_ssh_config.as_deref(),
                    actual_cluster_name.as_deref().or(cli.cluster.as_deref()),
                );

                // Create PTY configuration based on CLI flags (SSH mode)
                let pty_config = PtyConfig {
                    force_pty: cli.force_tty,
                    disable_pty: cli.no_tty,
                    ..Default::default()
                };

                // Determine use_pty based on CLI flags
                let use_pty = if cli.force_tty {
                    Some(true)
                } else if cli.no_tty {
                    Some(false)
                } else {
                    None // Auto-detect (typically use PTY for SSH mode)
                };

                // Use interactive mode for single host SSH connections
                let interactive_cmd = InteractiveCommand {
                    single_node: true, // Always single node for SSH mode
                    multiplex: false,  // No multiplexing for SSH mode
                    prompt_format: "[{user}@{host}:{pwd}]$ ".to_string(),
                    history_file: PathBuf::from("~/.bssh_history"),
                    work_dir: None,
                    nodes,
                    config: config.clone(),
                    interactive_config: config.get_interactive_config(None),
                    cluster_name: None,
                    key_path,
                    use_agent: cli.use_agent,
                    use_password: cli.password,
                    strict_mode,
                    pty_config,
                    use_pty,
                };
                let result = interactive_cmd.execute().await?;

                // Ensure terminal is fully restored before printing
                // Use synchronized cleanup to prevent race conditions
                bssh::pty::terminal::force_terminal_cleanup();
                let _ = crossterm::cursor::Show;
                let _ = std::io::Write::flush(&mut std::io::stdout());

                println!("\nSession ended.");
                if cli.verbose > 0 {
                    println!("Duration: {}", format_duration(result.duration));
                    println!("Commands executed: {}", result.commands_executed);
                }

                // Force exit to ensure proper termination
                std::process::exit(0);
            } else {
                // Determine timeout: CLI argument takes precedence over config
                let timeout = if cli.timeout > 0 {
                    Some(cli.timeout)
                } else {
                    config.get_timeout(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
                };

                // Determine SSH key path with SSH config integration
                let hostname = if cli.is_ssh_mode() {
                    cli.parse_destination().map(|(_, host, _)| host)
                } else {
                    None
                };
                let key_path = determine_ssh_key_path(
                    &cli,
                    &config,
                    &ssh_config,
                    hostname.as_deref(),
                    actual_cluster_name.as_deref().or(cli.cluster.as_deref()),
                );

                let params = ExecuteCommandParams {
                    nodes,
                    command: &command,
                    max_parallel,
                    key_path: key_path.as_deref(),
                    verbose: cli.verbose > 0,
                    strict_mode,
                    use_agent: cli.use_agent,
                    use_password: cli.password,
                    output_dir: cli.output_dir.as_deref(),
                    timeout,
                    jump_hosts: cli.jump_hosts.as_deref(),
                    // Pass port forwarding specifications to exec command
                    port_forwards: if cli.has_port_forwards() {
                        Some(cli.parse_port_forwards()?)
                    } else {
                        None
                    },
                };
                execute_command(params).await
            }
        }
    }
}

/// Parse a node string with SSH config integration
fn parse_node_with_ssh_config(node_str: &str, ssh_config: &SshConfig) -> Result<Node> {
    // First parse the raw node string to extract user, host, port from CLI
    let (user_part, host_part) = if let Some(at_pos) = node_str.find('@') {
        let user = &node_str[..at_pos];
        let rest = &node_str[at_pos + 1..];
        (Some(user), rest)
    } else {
        (None, node_str)
    };

    let (raw_host, cli_port) = if let Some(colon_pos) = host_part.rfind(':') {
        let host = &host_part[..colon_pos];
        let port_str = &host_part[colon_pos + 1..];
        let port = port_str.parse::<u16>().context("Invalid port number")?;
        (host, Some(port))
    } else {
        (host_part, None)
    };

    // Now resolve using SSH config with CLI taking precedence
    let effective_hostname = ssh_config.get_effective_hostname(raw_host);
    let effective_user = if let Some(user) = user_part {
        user.to_string()
    } else if let Some(ssh_user) = ssh_config.get_effective_user(raw_host, None) {
        ssh_user
    } else {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| {
                // Try to get current user from system
                #[cfg(unix)]
                {
                    whoami::username()
                }
                #[cfg(not(unix))]
                {
                    "user".to_string()
                }
            })
    };
    let effective_port = ssh_config.get_effective_port(raw_host, cli_port);

    Ok(Node::new(
        effective_hostname,
        effective_port,
        effective_user,
    ))
}

/// Determine strict host key checking mode with SSH config integration
fn determine_strict_host_key_checking(
    cli: &Cli,
    ssh_config: &SshConfig,
    hostname: Option<&str>,
) -> StrictHostKeyChecking {
    // CLI argument takes precedence
    if cli.strict_host_key_checking != "accept-new" {
        return cli.strict_host_key_checking.parse().unwrap_or_default();
    }

    // SSH config value for specific hostname
    if let Some(host) = hostname {
        if let Some(ssh_config_value) = ssh_config.get_strict_host_key_checking(host) {
            return match ssh_config_value.to_lowercase().as_str() {
                "yes" => StrictHostKeyChecking::Yes,
                "no" => StrictHostKeyChecking::No,
                "ask" | "accept-new" => StrictHostKeyChecking::AcceptNew,
                _ => StrictHostKeyChecking::AcceptNew,
            };
        }
    }

    // Default from CLI (already parsed)
    cli.strict_host_key_checking.parse().unwrap_or_default()
}

/// Determine SSH key path with integration of SSH config
fn determine_ssh_key_path(
    cli: &Cli,
    config: &Config,
    ssh_config: &SshConfig,
    hostname: Option<&str>,
    cluster_name: Option<&str>,
) -> Option<PathBuf> {
    // CLI identity file takes highest precedence
    if let Some(identity) = &cli.identity {
        return Some(identity.clone());
    }

    // SSH config identity files (for specific hostname if available)
    if let Some(host) = hostname {
        let identity_files = ssh_config.get_identity_files(host);
        if !identity_files.is_empty() {
            // Return the first identity file from SSH config
            return Some(identity_files[0].clone());
        }
    }

    // Cluster configuration SSH key
    config
        .get_ssh_key(cluster_name)
        .map(|ssh_key| bssh::config::expand_tilde(Path::new(&ssh_key)))
}

async fn resolve_nodes(
    cli: &Cli,
    config: &Config,
    ssh_config: &SshConfig,
) -> Result<(Vec<Node>, Option<String>)> {
    let mut nodes = Vec::new();
    let mut cluster_name = None;

    // Handle SSH compatibility mode (single host)
    if cli.is_ssh_mode() {
        let (user, host, port) = cli
            .parse_destination()
            .ok_or_else(|| anyhow::anyhow!("Invalid destination format"))?;

        // Resolve using SSH config with CLI taking precedence
        let effective_hostname = ssh_config.get_effective_hostname(&host);
        let effective_user = if let Some(u) = user {
            u
        } else if let Some(cli_user) = cli.get_effective_user() {
            cli_user
        } else if let Some(ssh_user) = ssh_config.get_effective_user(&host, None) {
            ssh_user
        } else if let Ok(env_user) = std::env::var("USER") {
            env_user
        } else {
            "root".to_string()
        };
        let effective_port =
            ssh_config.get_effective_port(&host, port.or_else(|| cli.get_effective_port()));

        let node = Node::new(effective_hostname, effective_port, effective_user);
        nodes.push(node);
    } else if let Some(hosts) = &cli.hosts {
        // Parse hosts from CLI
        for host_str in hosts {
            // Split by comma if a single argument contains multiple hosts
            for single_host in host_str.split(',') {
                let node = parse_node_with_ssh_config(single_host.trim(), ssh_config)?;
                nodes.push(node);
            }
        }
    } else if let Some(cli_cluster_name) = &cli.cluster {
        // Get nodes from cluster configuration
        nodes = config.resolve_nodes(cli_cluster_name)?;
        cluster_name = Some(cli_cluster_name.clone());
    } else {
        // Check if Backend.AI environment is detected (automatic cluster)
        if config.clusters.contains_key("bai_auto") {
            // Automatically use Backend.AI cluster when no explicit cluster is specified
            nodes = config.resolve_nodes("bai_auto")?;
            cluster_name = Some("bai_auto".to_string());
        }
    }

    Ok((nodes, cluster_name))
}

/// Handle cache statistics command
async fn handle_cache_stats(detailed: bool, clear: bool, maintain: bool) {
    use bssh::ssh::GLOBAL_CACHE;
    use owo_colors::OwoColorize;

    if clear {
        if let Err(e) = GLOBAL_CACHE.clear() {
            eprintln!("Failed to clear cache: {e}");
            return;
        }
        println!("{}", "Cache cleared".green());
    }

    if maintain {
        match GLOBAL_CACHE.maintain().await {
            Ok(removed) => println!(
                "{}: Removed {} expired/stale entries",
                "Cache maintenance".yellow(),
                removed
            ),
            Err(e) => {
                eprintln!("Failed to maintain cache: {e}");
                return;
            }
        }
    }

    let stats = match GLOBAL_CACHE.stats() {
        Ok(stats) => stats,
        Err(e) => {
            eprintln!("Failed to get cache stats: {e}");
            return;
        }
    };
    let config = GLOBAL_CACHE.config();

    println!("\n{}", "SSH Configuration Cache Statistics".cyan().bold());
    println!("=====================================");

    // Basic statistics
    println!("\n{}", "Cache Configuration:".bright_blue());
    println!(
        "  Enabled: {}",
        if config.enabled {
            format!("{}", "Yes".green())
        } else {
            format!("{}", "No".red())
        }
    );
    println!("  Max Entries: {}", config.max_entries.to_string().cyan());
    println!("  TTL: {}", format!("{:?}", config.ttl).cyan());

    println!("\n{}", "Cache Statistics:".bright_blue());
    println!(
        "  Current Entries: {}/{}",
        stats.current_entries.to_string().cyan(),
        stats.max_entries.to_string().yellow()
    );

    let total_requests = stats.hits + stats.misses;
    if total_requests > 0 {
        println!(
            "  Hit Rate: {:.1}% ({}/{} requests)",
            (stats.hit_rate() * 100.0).to_string().green(),
            stats.hits.to_string().green(),
            total_requests.to_string().cyan()
        );
        println!(
            "  Miss Rate: {:.1}% ({} misses)",
            (stats.miss_rate() * 100.0).to_string().yellow(),
            stats.misses.to_string().yellow()
        );
    } else {
        println!("  No cache requests yet");
    }

    println!("\n{}", "Eviction Statistics:".bright_blue());
    println!(
        "  TTL Evictions: {}",
        stats.ttl_evictions.to_string().yellow()
    );
    println!(
        "  Stale Evictions: {}",
        stats.stale_evictions.to_string().yellow()
    );
    println!(
        "  LRU Evictions: {}",
        stats.lru_evictions.to_string().yellow()
    );

    if detailed && stats.current_entries > 0 {
        println!("\n{}", "Detailed Entry Information:".bright_blue());
        match GLOBAL_CACHE.debug_info() {
            Ok(debug_info) => {
                for (path, info) in debug_info {
                    println!("  {}: {}", path.display().to_string().cyan(), info);
                }
            }
            Err(e) => {
                eprintln!("Failed to get debug info: {e}");
            }
        }
    }

    if !config.enabled {
        println!("\n{}", "Note: Caching is currently disabled".red());
        println!("Set BSSH_CACHE_ENABLED=true to enable caching");
    } else if stats.current_entries == 0 && total_requests == 0 {
        println!("\n{}", "Note: No SSH configs have been loaded yet".yellow());
        println!("Try running some bssh commands to populate the cache");
    }

    println!("\n{}", "Environment Variables:".bright_blue());
    println!(
        "  BSSH_CACHE_ENABLED={}",
        std::env::var("BSSH_CACHE_ENABLED").unwrap_or_else(|_| "true (default)".to_string())
    );
    println!(
        "  BSSH_CACHE_SIZE={}",
        std::env::var("BSSH_CACHE_SIZE").unwrap_or_else(|_| "100 (default)".to_string())
    );
    println!(
        "  BSSH_CACHE_TTL={}",
        std::env::var("BSSH_CACHE_TTL").unwrap_or_else(|_| "300 (default)".to_string())
    );
}

/// Handle SSH query options (-Q)
fn handle_query(query: &str) {
    match query {
        "cipher" => {
            println!("aes128-ctr\naes192-ctr\naes256-ctr");
            println!("aes128-gcm@openssh.com\naes256-gcm@openssh.com");
            println!("chacha20-poly1305@openssh.com");
        }
        "cipher-auth" => {
            println!("aes128-gcm@openssh.com\naes256-gcm@openssh.com");
            println!("chacha20-poly1305@openssh.com");
        }
        "mac" => {
            println!("hmac-sha2-256\nhmac-sha2-512\nhmac-sha1");
        }
        "kex" => {
            println!("curve25519-sha256\ncurve25519-sha256@libssh.org");
            println!("ecdh-sha2-nistp256\necdh-sha2-nistp384\necdh-sha2-nistp521");
        }
        "key" | "key-plain" | "key-cert" | "key-sig" => {
            println!("ssh-rsa\nssh-ed25519");
            println!("ecdsa-sha2-nistp256\necdsa-sha2-nistp384\necdsa-sha2-nistp521");
        }
        "protocol-version" => {
            println!("2");
        }
        "help" => {
            println!("Available query options:");
            println!("  cipher            - Supported ciphers");
            println!("  cipher-auth       - Authenticated encryption ciphers");
            println!("  mac               - Supported MAC algorithms");
            println!("  kex               - Supported key exchange algorithms");
            println!("  key               - Supported key types");
            println!("  protocol-version  - SSH protocol version");
        }
        _ => {
            eprintln!("Unknown query option: {query}");
            eprintln!("Use 'bssh -Q help' to see available options");
            std::process::exit(1);
        }
    }
}

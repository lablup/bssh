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

use anyhow::Result;
use clap::{CommandFactory, Parser};
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
    ssh::known_hosts::StrictHostKeyChecking,
    utils::init_logging,
};

/// Show help message and exit
fn show_help() {
    let mut cmd = Cli::command();
    let _ = cmd.print_help();
    eprintln!(); // Add a newline after help
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
        // Show help when no arguments provided
        show_help();
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

    // Handle list command first (doesn't need nodes)
    if matches!(cli.command, Some(Commands::List)) {
        list_clusters(&config);
        return Ok(());
    }

    // Determine nodes to execute on
    let (nodes, actual_cluster_name) = resolve_nodes(&cli, &config).await?;

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

    // Parse strict host key checking mode
    let strict_mode: StrictHostKeyChecking =
        cli.strict_host_key_checking.parse().unwrap_or_default();

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

    // Handle remaining commands
    match cli.command {
        Some(Commands::Ping) => {
            // Determine SSH key path: CLI argument takes precedence over config
            let key_path = if let Some(identity) = &cli.identity {
                Some(identity.clone())
            } else {
                config
                    .get_ssh_key(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
                    .map(|ssh_key| bssh::config::expand_tilde(Path::new(&ssh_key)))
            };

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
            source,
            destination,
            recursive,
        }) => {
            // Determine SSH key path: CLI argument takes precedence over config
            let key_path = if let Some(identity) = &cli.identity {
                Some(identity.clone())
            } else {
                config
                    .get_ssh_key(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
                    .map(|ssh_key| bssh::config::expand_tilde(Path::new(&ssh_key)))
            };

            let params = FileTransferParams {
                nodes,
                max_parallel,
                key_path: key_path.as_deref(),
                strict_mode,
                use_agent: cli.use_agent,
                use_password: cli.password,
                recursive,
            };
            upload_file(params, &source, &destination).await
        }
        Some(Commands::Download {
            source,
            destination,
            recursive,
        }) => {
            // Determine SSH key path: CLI argument takes precedence over config
            let key_path = if let Some(identity) = &cli.identity {
                Some(identity.clone())
            } else {
                config
                    .get_ssh_key(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
                    .map(|ssh_key| bssh::config::expand_tilde(Path::new(&ssh_key)))
            };

            let params = FileTransferParams {
                nodes,
                max_parallel,
                key_path: key_path.as_deref(),
                strict_mode,
                use_agent: cli.use_agent,
                use_password: cli.password,
                recursive,
            };
            download_file(params, &source, &destination).await
        }
        Some(Commands::Interactive {
            single_node,
            multiplex,
            prompt_format,
            history_file,
            work_dir,
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
                prompt_format
            } else {
                // Use config prompt
                interactive_config.prompt_format.clone()
            };

            let merged_history = if history_file.to_string_lossy() != "~/.bssh_history" {
                // CLI provided a custom history file
                history_file
            } else if let Some(config_history) = interactive_config.history_file.clone() {
                // Use config history file
                PathBuf::from(config_history)
            } else {
                // Use default
                history_file
            };

            let merged_work_dir = work_dir.or(interactive_config.work_dir.clone());

            // Determine SSH key path: CLI argument takes precedence over config
            let key_path = if let Some(identity) = &cli.identity {
                Some(identity.clone())
            } else {
                config
                    .get_ssh_key(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
                    .map(|ssh_key| bssh::config::expand_tilde(Path::new(&ssh_key)))
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

                // Determine SSH key path
                let key_path = if let Some(identity) = &cli.identity {
                    Some(identity.clone())
                } else {
                    config
                        .get_ssh_key(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
                        .map(|ssh_key| bssh::config::expand_tilde(Path::new(&ssh_key)))
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
                };
                let result = interactive_cmd.execute().await?;
                println!("\nSession ended.");
                if cli.verbose > 0 {
                    println!("Duration: {}", format_duration(result.duration));
                    println!("Commands executed: {}", result.commands_executed);
                }
                Ok(())
            } else {
                // Determine timeout: CLI argument takes precedence over config
                let timeout = if cli.timeout > 0 {
                    Some(cli.timeout)
                } else {
                    config.get_timeout(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
                };

                // Determine SSH key path: CLI argument takes precedence over config
                let key_path = if let Some(identity) = &cli.identity {
                    Some(identity.clone())
                } else {
                    config
                        .get_ssh_key(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
                        .map(|ssh_key| bssh::config::expand_tilde(Path::new(&ssh_key)))
                };

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
                };
                execute_command(params).await
            }
        }
    }
}

async fn resolve_nodes(cli: &Cli, config: &Config) -> Result<(Vec<Node>, Option<String>)> {
    let mut nodes = Vec::new();
    let mut cluster_name = None;

    // Handle SSH compatibility mode (single host)
    if cli.is_ssh_mode() {
        let (user, host, port) = cli
            .parse_destination()
            .ok_or_else(|| anyhow::anyhow!("Invalid destination format"))?;

        // Get effective username
        let username = user
            .or_else(|| cli.get_effective_user())
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "root".to_string());

        // Get effective port
        let port = port.or_else(|| cli.get_effective_port()).unwrap_or(22);

        let node = Node::new(host, port, username);
        nodes.push(node);
    } else if let Some(hosts) = &cli.hosts {
        // Parse hosts from CLI
        for host_str in hosts {
            // Split by comma if a single argument contains multiple hosts
            for single_host in host_str.split(',') {
                let node = Node::parse(single_host.trim(), None)?;
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

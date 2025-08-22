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
use clap::Parser;

use bssh::{
    cli::{Cli, Commands},
    commands::{
        download::download_file,
        exec::{ExecuteCommandParams, execute_command},
        interactive::InteractiveCommand,
        list::list_clusters,
        ping::ping_nodes,
        upload::{FileTransferParams, upload_file},
    },
    config::Config,
    node::Node,
    ssh::known_hosts::StrictHostKeyChecking,
    utils::init_logging,
};

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
    let strict_mode: StrictHostKeyChecking =
        cli.strict_host_key_checking.parse().unwrap_or_default();

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
            .await
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
            upload_file(params, &source, &destination).await
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
            download_file(params, &source, &destination).await
        }
        Some(Commands::Interactive {
            single_node,
            multiplex,
            prompt_format,
            history_file,
            work_dir,
        }) => {
            let interactive_cmd = InteractiveCommand {
                single_node,
                multiplex,
                prompt_format,
                history_file,
                work_dir,
                nodes,
                config: config.clone(),
            };
            let result = interactive_cmd.execute().await?;
            println!("\nInteractive session ended.");
            println!("Duration: {:?}", result.duration);
            println!("Commands executed: {}", result.commands_executed);
            println!("Nodes connected: {}", result.nodes_connected);
            Ok(())
        }
        _ => {
            // Execute command (default or Exec subcommand)
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
            execute_command(params).await
        }
    }
}

async fn resolve_nodes(cli: &Cli, config: &Config) -> Result<Vec<Node>> {
    let mut nodes = Vec::new();

    if let Some(hosts) = &cli.hosts {
        // Parse hosts from CLI
        for host_str in hosts {
            // Split by comma if a single argument contains multiple hosts
            for single_host in host_str.split(',') {
                let node = Node::parse(single_host.trim(), None)?;
                nodes.push(node);
            }
        }
    } else if let Some(cluster_name) = &cli.cluster {
        // Get nodes from cluster configuration
        nodes = config.resolve_nodes(cluster_name)?;
    } else {
        // Check if Backend.AI environment is detected (automatic cluster)
        if config.clusters.contains_key("backendai") {
            // Automatically use Backend.AI cluster when no explicit cluster is specified
            nodes = config.resolve_nodes("backendai")?;
        }
    }

    Ok(nodes)
}

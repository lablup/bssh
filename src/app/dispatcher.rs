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

//! Command dispatcher for routing CLI commands to their implementations

use anyhow::Result;
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
    config::InteractiveMode,
    pty::PtyConfig,
    security::get_sudo_password,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(target_os = "macos")]
use super::initialization::determine_use_keychain;
use super::initialization::{determine_ssh_key_path, AppContext};
use super::utils::format_duration;

/// Dispatch commands to their appropriate handlers
pub async fn dispatch_command(cli: &Cli, ctx: &AppContext) -> Result<()> {
    // Get command to execute
    let command = cli.get_command();

    // Check if command is required
    // Auto-exec happens when in multi-server mode with command_args
    let is_auto_exec = cli.should_auto_exec();
    let needs_command = (cli.command.is_none() || is_auto_exec) && !cli.is_ssh_mode();

    if command.is_empty() && needs_command && !cli.force_tty {
        anyhow::bail!(
            "No command specified. Please provide a command to execute.\n\
            Example: bssh -H host1,host2 'ls -la'"
        );
    }

    // Calculate hostname for SSH config integration
    let hostname_for_ssh_config = if cli.is_ssh_mode() {
        cli.parse_destination().map(|(_, host, _)| host)
    } else {
        None
    };

    match &cli.command {
        Some(Commands::List) => {
            list_clusters(&ctx.config);
            Ok(())
        }
        Some(Commands::Ping) => {
            let key_path = determine_ssh_key_path(
                cli,
                &ctx.config,
                &ctx.ssh_config,
                hostname_for_ssh_config.as_deref(),
                ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
            );

            #[cfg(target_os = "macos")]
            let use_keychain =
                determine_use_keychain(&ctx.ssh_config, hostname_for_ssh_config.as_deref());

            // Resolve jump_hosts: CLI takes precedence, then config
            let jump_hosts = cli.jump_hosts.clone().or_else(|| {
                ctx.config
                    .get_cluster_jump_host(ctx.cluster_name.as_deref().or(cli.cluster.as_deref()))
            });

            ping_nodes(
                ctx.nodes.clone(),
                ctx.max_parallel,
                key_path.as_deref(),
                ctx.strict_mode,
                cli.use_agent,
                cli.password,
                #[cfg(target_os = "macos")]
                use_keychain,
                cli.timeout,
                Some(cli.connect_timeout),
                jump_hosts,
            )
            .await
        }
        Some(Commands::Upload {
            source,
            destination,
            recursive,
        }) => {
            let key_path = determine_ssh_key_path(
                cli,
                &ctx.config,
                &ctx.ssh_config,
                hostname_for_ssh_config.as_deref(),
                ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
            );

            // Resolve jump_hosts: CLI takes precedence, then config
            let jump_hosts = cli.jump_hosts.clone().or_else(|| {
                ctx.config
                    .get_cluster_jump_host(ctx.cluster_name.as_deref().or(cli.cluster.as_deref()))
            });

            let params = FileTransferParams {
                nodes: ctx.nodes.clone(),
                max_parallel: ctx.max_parallel,
                key_path: key_path.as_deref(),
                strict_mode: ctx.strict_mode,
                use_agent: cli.use_agent,
                use_password: cli.password,
                recursive: *recursive,
                ssh_config: Some(&ctx.ssh_config),
                jump_hosts,
            };
            upload_file(params, source, destination).await
        }
        Some(Commands::Download {
            source,
            destination,
            recursive,
        }) => {
            let key_path = determine_ssh_key_path(
                cli,
                &ctx.config,
                &ctx.ssh_config,
                hostname_for_ssh_config.as_deref(),
                ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
            );

            // Resolve jump_hosts: CLI takes precedence, then config
            let jump_hosts = cli.jump_hosts.clone().or_else(|| {
                ctx.config
                    .get_cluster_jump_host(ctx.cluster_name.as_deref().or(cli.cluster.as_deref()))
            });

            let params = FileTransferParams {
                nodes: ctx.nodes.clone(),
                max_parallel: ctx.max_parallel,
                key_path: key_path.as_deref(),
                strict_mode: ctx.strict_mode,
                use_agent: cli.use_agent,
                use_password: cli.password,
                recursive: *recursive,
                ssh_config: Some(&ctx.ssh_config),
                jump_hosts,
            };
            download_file(params, source, destination).await
        }
        Some(Commands::Interactive {
            single_node,
            multiplex,
            prompt_format,
            history_file,
            work_dir,
        }) => {
            handle_interactive_command(
                cli,
                ctx,
                *single_node,
                *multiplex,
                prompt_format,
                history_file,
                work_dir.as_deref(),
            )
            .await
        }
        Some(Commands::CacheStats { .. }) => {
            // This is handled in main.rs before node resolution
            unreachable!("CacheStats should be handled before dispatch")
        }
        None => {
            // Execute command (auto-exec or interactive shell)
            handle_exec_command(cli, ctx, &command).await
        }
    }
}

/// Handle interactive command execution
async fn handle_interactive_command(
    cli: &Cli,
    ctx: &AppContext,
    single_node: bool,
    multiplex: bool,
    prompt_format: &str,
    history_file: &Path,
    work_dir: Option<&str>,
) -> Result<()> {
    // Get interactive config from configuration file (with cluster-specific overrides)
    let cluster_name = cli.cluster.as_deref();
    let interactive_config = ctx.config.get_interactive_config(cluster_name);

    // Merge CLI arguments with config settings (CLI takes precedence)
    let merged_mode = if single_node {
        (true, false)
    } else if multiplex {
        (false, true)
    } else {
        match interactive_config.default_mode {
            InteractiveMode::SingleNode => (true, false),
            InteractiveMode::Multiplex => (false, true),
        }
    };

    // Use CLI values if provided, otherwise use config values
    let merged_prompt = if prompt_format != "[{node}:{user}@{host}:{pwd}]$ " {
        prompt_format.to_string()
    } else {
        interactive_config.prompt_format.clone()
    };

    let merged_history = if history_file.to_string_lossy() != "~/.bssh_history" {
        history_file.to_path_buf()
    } else if let Some(config_history) = interactive_config.history_file.clone() {
        PathBuf::from(config_history)
    } else {
        history_file.to_path_buf()
    };

    let merged_work_dir = work_dir
        .map(|s| s.to_string())
        .or(interactive_config.work_dir.clone());

    // Determine SSH key path
    let hostname = if cli.is_ssh_mode() {
        cli.parse_destination().map(|(_, host, _)| host)
    } else {
        None
    };
    let key_path = determine_ssh_key_path(
        cli,
        &ctx.config,
        &ctx.ssh_config,
        hostname.as_deref(),
        ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
    );

    // Create PTY configuration
    let pty_config = PtyConfig {
        force_pty: cli.force_tty,
        disable_pty: cli.no_tty,
        ..Default::default()
    };

    let use_pty = if cli.force_tty {
        Some(true)
    } else if cli.no_tty {
        Some(false)
    } else {
        None
    };

    #[cfg(target_os = "macos")]
    let use_keychain = determine_use_keychain(&ctx.ssh_config, hostname.as_deref());

    // Resolve jump_hosts: CLI takes precedence, then config
    let jump_hosts = cli.jump_hosts.clone().or_else(|| {
        ctx.config
            .get_cluster_jump_host(ctx.cluster_name.as_deref().or(cli.cluster.as_deref()))
    });

    let interactive_cmd = InteractiveCommand {
        single_node: merged_mode.0,
        multiplex: merged_mode.1,
        prompt_format: merged_prompt,
        history_file: merged_history,
        work_dir: merged_work_dir,
        nodes: ctx.nodes.clone(),
        config: ctx.config.clone(),
        interactive_config,
        cluster_name: cluster_name.map(String::from),
        key_path,
        use_agent: cli.use_agent,
        use_password: cli.password,
        #[cfg(target_os = "macos")]
        use_keychain,
        strict_mode: ctx.strict_mode,
        jump_hosts,
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

/// Handle exec command or SSH mode interactive session
async fn handle_exec_command(cli: &Cli, ctx: &AppContext, command: &str) -> Result<()> {
    // In SSH mode without command, start interactive session
    if cli.is_ssh_mode() && command.is_empty() {
        // SSH mode interactive session (like ssh user@host)
        tracing::info!("Starting SSH interactive session to {}", ctx.nodes[0].host);

        let hostname = cli.parse_destination().map(|(_, host, _)| host);
        let key_path = determine_ssh_key_path(
            cli,
            &ctx.config,
            &ctx.ssh_config,
            hostname.as_deref(),
            ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
        );

        let pty_config = PtyConfig {
            force_pty: cli.force_tty,
            disable_pty: cli.no_tty,
            ..Default::default()
        };

        let use_pty = if cli.force_tty {
            Some(true)
        } else if cli.no_tty {
            Some(false)
        } else {
            None
        };

        #[cfg(target_os = "macos")]
        let use_keychain = determine_use_keychain(&ctx.ssh_config, hostname.as_deref());

        // Resolve jump_hosts: CLI takes precedence, then config
        let jump_hosts = cli.jump_hosts.clone().or_else(|| {
            ctx.config
                .get_cluster_jump_host(ctx.cluster_name.as_deref().or(cli.cluster.as_deref()))
        });

        let interactive_cmd = InteractiveCommand {
            single_node: true,
            multiplex: false,
            prompt_format: "[{user}@{host}:{pwd}]$ ".to_string(),
            history_file: PathBuf::from("~/.bssh_history"),
            work_dir: None,
            nodes: ctx.nodes.clone(),
            config: ctx.config.clone(),
            interactive_config: ctx.config.get_interactive_config(None),
            cluster_name: None,
            key_path,
            use_agent: cli.use_agent,
            use_password: cli.password,
            #[cfg(target_os = "macos")]
            use_keychain,
            strict_mode: ctx.strict_mode,
            jump_hosts,
            pty_config,
            use_pty,
        };

        let result = interactive_cmd.execute().await?;

        // Ensure terminal is fully restored before printing
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
        // Regular command execution
        let timeout = if let Some(t) = cli.timeout {
            // User explicitly specified --timeout, use it directly (including 0 for unlimited)
            Some(t)
        } else {
            // User did not specify --timeout, fall back to config
            ctx.config
                .get_timeout(ctx.cluster_name.as_deref().or(cli.cluster.as_deref()))
        };

        let hostname = if cli.is_ssh_mode() {
            cli.parse_destination().map(|(_, host, _)| host)
        } else {
            None
        };
        let key_path = determine_ssh_key_path(
            cli,
            &ctx.config,
            &ctx.ssh_config,
            hostname.as_deref(),
            ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
        );

        // Determine if we should use macOS Keychain for passphrases
        #[cfg(target_os = "macos")]
        let use_keychain = determine_use_keychain(&ctx.ssh_config, hostname.as_deref());

        // Get sudo password if flag is set
        let sudo_password = if cli.sudo_password {
            Some(Arc::new(get_sudo_password(true)?))
        } else {
            None
        };

        // Resolve jump_hosts: CLI takes precedence, then config
        let effective_cluster_name = ctx.cluster_name.as_deref().or(cli.cluster.as_deref());
        let config_jump_host = ctx.config.get_cluster_jump_host(effective_cluster_name);
        let jump_hosts = cli.jump_hosts.clone().or(config_jump_host.clone());

        // Debug logging for jump host resolution
        tracing::debug!(
            "Jump host resolution: cli={:?}, config={:?}, effective={:?}, cluster={:?}",
            cli.jump_hosts,
            config_jump_host,
            jump_hosts,
            effective_cluster_name
        );

        if let Some(ref jh) = jump_hosts {
            tracing::info!("Using jump host: {}", jh);
        }

        let params = ExecuteCommandParams {
            nodes: ctx.nodes.clone(),
            command,
            max_parallel: ctx.max_parallel,
            key_path: key_path.as_deref(),
            verbose: cli.verbose > 0,
            strict_mode: ctx.strict_mode,
            use_agent: cli.use_agent,
            use_password: cli.password,
            #[cfg(target_os = "macos")]
            use_keychain,
            output_dir: cli.output_dir.as_deref(),
            stream: cli.stream,
            no_prefix: cli.no_prefix,
            timeout,
            connect_timeout: Some(cli.connect_timeout),
            jump_hosts: jump_hosts.as_deref(),
            port_forwards: if cli.has_port_forwards() {
                Some(cli.parse_port_forwards()?)
            } else {
                None
            },
            require_all_success: cli.require_all_success,
            check_all_nodes: cli.check_all_nodes,
            sudo_password,
            batch: cli.batch,
            fail_fast: cli.fail_fast,
            ssh_config: Some(&ctx.ssh_config),
        };
        execute_command(params).await
    }
}

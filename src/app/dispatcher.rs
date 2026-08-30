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

use anyhow::{Context, Result};
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
    config::InteractiveMode,
    diagnosticln as eprintln,
    pty::PtyConfig,
    security::{Password, get_password, get_sudo_password},
    ssh::{
        CliTtyMode, SessionPolicy, SessionRequest,
        tokio_client::{AddressFamily, ProxyMode, SshConnectionConfigResolver},
    },
};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(target_os = "macos")]
use super::initialization::determine_use_keychain;
use super::initialization::{AppContext, determine_ssh_key_path};
use super::utils::format_duration;

/// Exit code for a subcommand that completed without a per-host failure to
/// report.
const EXIT_SUCCESS: i32 = 0;

/// Build an SSH connection config resolver with keepalive, compression, and
/// address family settings.
/// Precedence: CLI > SSH config > YAML config > defaults.
/// `Compression` has no CLI or YAML override; it is read from ssh_config only.
/// `AddressFamily` has no YAML override; `-4`/`-6` beat the ssh_config keyword,
/// which beats the `any` default.
fn build_ssh_connection_config_resolver(
    cli: &Cli,
    ctx: &AppContext,
    cluster_name: Option<&str>,
) -> SshConnectionConfigResolver {
    SshConnectionConfigResolver::new()
        .with_ssh_config(Some(ctx.ssh_config.clone()))
        .with_cli_identity_files(cli.identity.clone())
        .with_cli_keepalive_interval(cli.server_alive_interval)
        .with_cli_keepalive_max(cli.server_alive_count_max)
        .with_yaml_keepalive_interval(ctx.config.get_server_alive_interval(cluster_name))
        .with_yaml_keepalive_max(ctx.config.get_server_alive_count_max(cluster_name))
        .with_cli_address_family(AddressFamily::from_flags(cli.ipv4, cli.ipv6))
        .with_cli_host_key_alias(cli.get_ssh_option("HostKeyAlias"))
        .with_cli_proxy_jump(cli.jump_hosts.clone())
        .with_yaml_proxy_jump(ctx.config.get_cluster_jump_host(cluster_name))
        .with_cli_forwarding_order(cli.forwarding_order.clone())
        .with_cli_forwardings(
            cli.local_forwards.clone(),
            cli.remote_forwards.clone(),
            cli.dynamic_forwards.clone(),
        )
}

/// Decide whether `-S` (sudo-password) is meaningful for the given dispatch path.
///
/// Only command execution can consume `SudoPassword`, because it monitors
/// command output for sudo prompts and injects the password into the remote
/// process. Interactive shells handle their own terminal input, while ping,
/// SFTP, list, and cache-stat paths never inspect remote sudo prompts.
fn sudo_password_is_applicable(command: &Option<Commands>, command_text: &str) -> bool {
    match command {
        Some(Commands::Ping)
        | Some(Commands::Upload { .. })
        | Some(Commands::Download { .. })
        | Some(Commands::List)
        | Some(Commands::Interactive { .. })
        | Some(Commands::CacheStats { .. }) => false,
        // `None` is the exec/SSH-compatibility path. A non-empty command can
        // use sudo injection; an empty command is an interactive SSH shell and
        // has no sudo-injection hook.
        None => !command_text.is_empty(),
    }
}

/// Decide whether `--password` should be collected for this dispatcher path.
///
/// Most paths create SSH connections and can use an SSH password. List and
/// cache-stat paths do not connect to a remote host, so prompting would be a
/// surprising no-op if `dispatch_command()` is called directly in tests or
/// library-like contexts (the binary entry point handles those paths earlier).
fn ssh_password_is_applicable(command: &Option<Commands>) -> bool {
    !matches!(
        command,
        Some(Commands::List) | Some(Commands::CacheStats { .. })
    )
}

fn all_targets_use_batch_mode(resolver: &SshConnectionConfigResolver, hosts: &[&str]) -> bool {
    !hosts.is_empty()
        && hosts
            .iter()
            .all(|host| resolver.resolve_for_host(host).auth_policy.batch_mode)
}

fn effective_authentication_targets(
    resolver: &SshConnectionConfigResolver,
    destinations: &[String],
) -> Result<Vec<String>> {
    let mut targets = destinations.to_vec();
    for destination in destinations {
        let Some(ProxyMode::Jump(jump_spec)) = resolver.resolve_for_host(destination).proxy_mode
        else {
            // ProxyCommand is an external carrier, not an SSH authentication
            // hop owned by bssh, and Direct adds no target.
            continue;
        };
        targets.extend(
            bssh::jump::parse_jump_hosts(&jump_spec)?
                .into_iter()
                .map(|jump_host| jump_host.host),
        );
    }
    Ok(targets)
}

fn collect_ssh_password_with<F>(collect: bool, prompt: F) -> Result<Option<Arc<Password>>>
where
    F: FnOnce() -> Result<Password>,
{
    if collect {
        prompt().map(|password| Some(Arc::new(password)))
    } else {
        Ok(None)
    }
}

/// Human-readable name of the currently-dispatched subcommand for diagnostics.
fn subcommand_name(command: &Option<Commands>) -> &'static str {
    match command {
        Some(Commands::List) => "list",
        Some(Commands::Ping) => "ping",
        Some(Commands::Upload { .. }) => "upload",
        Some(Commands::Download { .. }) => "download",
        Some(Commands::Interactive { .. }) => "interactive",
        Some(Commands::CacheStats { .. }) => "cache-stats",
        None => "exec",
    }
}

/// Dispatch commands to their appropriate handlers.
///
/// Returns the exit code the process should report. Most subcommands either
/// succeed (0) or return `Err`, but `ping` completes normally while still
/// having per-host failures to report, so the count has to survive the return.
/// The caller (`main`) is the single place that turns a nonzero value into the
/// process exit status.
pub async fn dispatch_command(cli: &Cli, ctx: &AppContext) -> Result<i32> {
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

    // Warn if -S is passed to dispatch paths where it has no effect. We choose
    // a warning (not a hard reject) to match typical CLI UX: existing scripts
    // that happen to pass -S to `ping` or `upload` keep working, but the user
    // gets visible feedback that the flag is being ignored.
    if cli.sudo_password && !sudo_password_is_applicable(&cli.command, &command) {
        eprintln!(
            "Warning: --sudo-password (-S) has no effect for the `{}` subcommand and will be ignored",
            subcommand_name(&cli.command)
        );
    }

    if cli.password && !ssh_password_is_applicable(&cli.command) {
        eprintln!(
            "Warning: --password has no effect for the `{}` subcommand and will be ignored",
            subcommand_name(&cli.command)
        );
    }

    // Calculate hostname for SSH config integration before deciding whether an
    // up-front password prompt is permitted by every actual target policy.
    let hostname_for_ssh_config = if cli.is_ssh_mode() {
        cli.parse_destination().map(|(_, host, _)| host)
    } else {
        None
    };
    let password_policy_resolver = build_ssh_connection_config_resolver(
        cli,
        ctx,
        ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
    );
    let mut password_destinations = ctx
        .nodes
        .iter()
        .map(|node| node.config_host().to_string())
        .collect::<Vec<_>>();
    if password_destinations.is_empty()
        && let Some(host) = hostname_for_ssh_config.as_ref()
    {
        password_destinations.push(host.clone());
    }
    let collect_password = if cli.password && ssh_password_is_applicable(&cli.command) {
        let password_targets =
            effective_authentication_targets(&password_policy_resolver, &password_destinations)?;
        let password_target_refs = password_targets
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        !all_targets_use_batch_mode(&password_policy_resolver, &password_target_refs)
    } else {
        false
    };
    let ssh_password = collect_ssh_password_with(collect_password, || {
        get_password(true)
            .map_err(|error| anyhow::anyhow!("Failed to collect SSH password: {error}"))
    })?;

    match &cli.command {
        Some(Commands::List) => {
            list_clusters(&ctx.config);
            Ok(EXIT_SUCCESS)
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

            let ssh_connection_config_resolver = build_ssh_connection_config_resolver(
                cli,
                ctx,
                ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
            );

            // `ping` is the one subcommand whose exit code depends on how many
            // hosts answered, so the outcome is translated here rather than
            // discarded. See `PingOutcome` for the 0/1/255 contract.
            let outcome = ping_nodes(
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
                ssh_password.clone(),
                ssh_connection_config_resolver,
            )
            .await?;

            Ok(outcome.exit_code())
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
                ssh_password: ssh_password.clone(),
                recursive: *recursive,
                ssh_config: Some(&ctx.ssh_config),
                jump_hosts,
                ssh_connection_config_resolver: build_ssh_connection_config_resolver(
                    cli,
                    ctx,
                    ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
                ),
            };
            upload_file(params, source, destination).await?;
            Ok(EXIT_SUCCESS)
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
                ssh_password: ssh_password.clone(),
                recursive: *recursive,
                ssh_config: Some(&ctx.ssh_config),
                jump_hosts,
                ssh_connection_config_resolver: build_ssh_connection_config_resolver(
                    cli,
                    ctx,
                    ctx.cluster_name.as_deref().or(cli.cluster.as_deref()),
                ),
            };
            download_file(params, source, destination).await?;
            Ok(EXIT_SUCCESS)
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
                ssh_password.clone(),
            )
            .await?;
            Ok(EXIT_SUCCESS)
        }
        Some(Commands::CacheStats { .. }) => {
            // This is handled in main.rs before node resolution
            unreachable!("CacheStats should be handled before dispatch")
        }
        None => {
            // Execute command (auto-exec or interactive shell). This path owns
            // its own exit code strategy (`ExitCodeStrategy`, selected by
            // `--require-all-success` / `--check-all-nodes`) and exits the
            // process itself when the strategy yields a nonzero code.
            handle_exec_command(cli, ctx, &command, ssh_password.clone()).await?;
            Ok(EXIT_SUCCESS)
        }
    }
}

/// Handle interactive command execution
#[allow(clippy::too_many_arguments)]
async fn handle_interactive_command(
    cli: &Cli,
    ctx: &AppContext,
    single_node: bool,
    multiplex: bool,
    prompt_format: &str,
    history_file: &Path,
    work_dir: Option<&str>,
    ssh_password: Option<Arc<Password>>,
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

    // Build SSH connection config with keepalive settings for interactive mode
    let effective_cluster_name = ctx.cluster_name.as_deref().or(cli.cluster.as_deref());
    let ssh_connection_config_resolver =
        build_ssh_connection_config_resolver(cli, ctx, effective_cluster_name);
    let config_hostname = hostname
        .as_deref()
        .or_else(|| ctx.nodes.first().map(|node| node.host.as_str()))
        .unwrap_or("*");
    let ssh_connection_config = ssh_connection_config_resolver.resolve_for_host(config_hostname);

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
        ssh_password,
        #[cfg(target_os = "macos")]
        use_keychain,
        strict_mode: ctx.strict_mode,
        jump_hosts,
        pty_config,
        use_pty,
        session_policy: None,
        ssh_connection_config,
        ssh_connection_config_resolver: Some(ssh_connection_config_resolver),
    };

    let result = interactive_cmd.execute().await?;
    println!("\nInteractive session ended.");
    println!("Duration: {}", format_duration(result.duration));
    println!("Commands executed: {}", result.commands_executed);
    println!("Nodes connected: {}", result.nodes_connected);
    Ok(())
}

fn cli_tty_mode(cli: &Cli) -> CliTtyMode {
    if cli.force_tty {
        CliTtyMode::Force
    } else if cli.no_tty {
        CliTtyMode::Disable
    } else {
        CliTtyMode::Default
    }
}

fn resolve_ssh_mode_interactive_policy(
    config: &bssh::ssh::ssh_config::SshHostConfig,
    node: &bssh::node::Node,
    tty_mode: CliTtyMode,
    stdin_is_terminal: bool,
    jump_spec: Option<&str>,
) -> Result<Option<SessionPolicy>> {
    let policy = SessionPolicy::resolve_with_jump_spec(
        config,
        node,
        None,
        tty_mode,
        stdin_is_terminal,
        jump_spec,
    )?;
    Ok(matches!(policy.request, SessionRequest::Shell).then_some(policy))
}

/// Handle exec command or SSH mode interactive session
async fn handle_exec_command(
    cli: &Cli,
    ctx: &AppContext,
    command: &str,
    ssh_password: Option<Arc<Password>>,
) -> Result<()> {
    // Resolve policy even for a plain ssh-compatible shell. Remote/subsystem/
    // none requests stay on the command executor; shell requests retain the
    // existing interactive stdin, PTY resize, and byte-stream implementation.
    let interactive_policy = if cli.is_ssh_mode() && command.is_empty() {
        let node = ctx
            .nodes
            .first()
            .context("SSH interactive mode requires a destination node")?;
        let effective = ctx.ssh_config.find_host_config(node.config_host());
        let effective_cluster_name = ctx.cluster_name.as_deref().or(cli.cluster.as_deref());
        let yaml_jump = ctx.config.get_cluster_jump_host(effective_cluster_name);
        let jump_spec = cli.jump_hosts.as_deref().or(yaml_jump.as_deref());
        resolve_ssh_mode_interactive_policy(
            &effective,
            node,
            cli_tty_mode(cli),
            std::io::stdin().is_terminal(),
            jump_spec,
        )?
    } else {
        None
    };

    if let Some(session_policy) = interactive_policy {
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
            force_pty: session_policy.request_pty,
            disable_pty: !session_policy.request_pty,
            ..Default::default()
        };
        let use_pty = Some(session_policy.request_pty);

        #[cfg(target_os = "macos")]
        let use_keychain = determine_use_keychain(&ctx.ssh_config, hostname.as_deref());

        // Resolve jump_hosts: CLI takes precedence, then config
        let jump_hosts = cli.jump_hosts.clone().or_else(|| {
            ctx.config
                .get_cluster_jump_host(ctx.cluster_name.as_deref().or(cli.cluster.as_deref()))
        });

        // Build SSH connection config with keepalive settings for SSH mode interactive session
        let effective_cluster_name = ctx.cluster_name.as_deref().or(cli.cluster.as_deref());
        let ssh_connection_config_resolver =
            build_ssh_connection_config_resolver(cli, ctx, effective_cluster_name);
        let config_hostname = hostname
            .as_deref()
            .or_else(|| ctx.nodes.first().map(|node| node.host.as_str()))
            .unwrap_or("*");
        let ssh_connection_config =
            ssh_connection_config_resolver.resolve_for_host(config_hostname);

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
            ssh_password,
            #[cfg(target_os = "macos")]
            use_keychain,
            strict_mode: ctx.strict_mode,
            jump_hosts,
            pty_config,
            use_pty,
            session_policy: Some(session_policy),
            ssh_connection_config,
            ssh_connection_config_resolver: Some(ssh_connection_config_resolver),
        };

        let result = interactive_cmd.execute().await?;

        if cli.verbose > 0 {
            eprintln!("Session ended.");
            eprintln!("Duration: {}", format_duration(result.duration));
            eprintln!("Commands executed: {}", result.commands_executed);
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

        // Build SSH connection config resolver for exec mode. Each executor
        // task resolves it against that task's node host.
        let ssh_connection_config_resolver =
            build_ssh_connection_config_resolver(cli, ctx, effective_cluster_name);

        let params = ExecuteCommandParams {
            nodes: ctx.nodes.clone(),
            command,
            max_parallel: ctx.max_parallel,
            key_path: key_path.as_deref(),
            verbose: cli.verbose > 0,
            strict_mode: ctx.strict_mode,
            use_agent: cli.use_agent,
            use_password: cli.password,
            ssh_password,
            #[cfg(target_os = "macos")]
            use_keychain,
            output_dir: cli.output_dir.as_deref(),
            stream: cli.stream,
            no_prefix: cli.no_prefix,
            byte_transparent: cli.is_ssh_mode(),
            timeout,
            connect_timeout: Some(cli.connect_timeout),
            jump_hosts: jump_hosts.as_deref(),
            require_all_success: cli.require_all_success,
            check_all_nodes: cli.check_all_nodes,
            sudo_password,
            batch: cli.batch,
            fail_fast: cli.fail_fast,
            ssh_config: Some(&ctx.ssh_config),
            tty_mode: cli_tty_mode(cli),
            ssh_connection_config_resolver,
        };
        execute_command(params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interactive_command() -> Option<Commands> {
        Some(Commands::Interactive {
            single_node: false,
            multiplex: true,
            prompt_format: "[{node}:{user}@{host}:{pwd}]$ ".to_string(),
            history_file: PathBuf::from("~/.bssh_history"),
            work_dir: None,
        })
    }

    #[test]
    fn plain_ssh_shell_always_consumes_the_resolved_session_policy() {
        let node = bssh::node::Node::new("127.0.0.1".into(), 2222, "remote".into())
            .with_original_host("alias".into());

        let plain = resolve_ssh_mode_interactive_policy(
            &bssh::ssh::ssh_config::SshHostConfig::default(),
            &node,
            CliTtyMode::Default,
            true,
            None,
        )
        .unwrap()
        .expect("plain ssh must use the interactive policy path");
        assert_eq!(plain.request, SessionRequest::Shell);
        assert!(plain.request_pty);
        assert!(plain.environment.is_empty());
        assert!(plain.local_command.is_none());

        let mut configured = bssh::ssh::ssh_config::SshHostConfig::default();
        configured.permit_local_command = Some(true);
        configured.local_command = Some("true".into());
        configured.request_tty = Some("force".into());
        configured.session_type = Some("default".into());
        configured.set_env.insert("JUMP".into(), "%j".into());
        let resolved = resolve_ssh_mode_interactive_policy(
            &configured,
            &node,
            CliTtyMode::Default,
            false,
            Some("bastion.example"),
        )
        .unwrap()
        .expect("configured default session must retain the interactive path");
        assert_eq!(resolved.request, SessionRequest::Shell);
        assert!(resolved.request_pty);
        assert_eq!(
            resolved.environment,
            [(String::from("JUMP"), String::from("bastion.example"))]
        );
        assert_eq!(resolved.local_command.as_deref(), Some("true"));

        configured.remote_command = Some("true".into());
        assert!(
            resolve_ssh_mode_interactive_policy(
                &configured,
                &node,
                CliTtyMode::Default,
                true,
                None,
            )
            .unwrap()
            .is_none(),
            "non-shell policies must stay on the command executor"
        );
    }

    #[test]
    fn sudo_password_applies_only_to_exec_commands() {
        assert!(sudo_password_is_applicable(&None, "uptime"));

        assert!(!sudo_password_is_applicable(&None, ""));
        assert!(!sudo_password_is_applicable(&Some(Commands::Ping), "true"));
        assert!(!sudo_password_is_applicable(&interactive_command(), ""));
        assert!(!sudo_password_is_applicable(
            &Some(Commands::CacheStats {
                detailed: false,
                clear: false,
                maintain: false,
            }),
            "",
        ));
    }

    #[test]
    fn ssh_password_is_not_collected_for_local_only_subcommands() {
        assert!(ssh_password_is_applicable(&None));
        assert!(ssh_password_is_applicable(&Some(Commands::Ping)));
        assert!(ssh_password_is_applicable(&interactive_command()));

        assert!(!ssh_password_is_applicable(&Some(Commands::List)));
        assert!(!ssh_password_is_applicable(&Some(Commands::CacheStats {
            detailed: false,
            clear: false,
            maintain: false,
        })));
    }

    #[test]
    fn batch_mode_target_set_controls_password_collection_exactly_once() {
        let all_batch =
            bssh::ssh::SshConfig::parse("Host one two jump\n    BatchMode yes\n").unwrap();
        let resolver = SshConnectionConfigResolver::new().with_ssh_config(Some(all_batch));
        assert!(all_targets_use_batch_mode(
            &resolver,
            &["one", "two", "jump"]
        ));
        let calls = std::cell::Cell::new(0);
        let password = collect_ssh_password_with(false, || {
            calls.set(calls.get() + 1);
            Password::new("secret".to_string())
        })
        .unwrap();
        assert!(password.is_none());
        assert_eq!(calls.get(), 0);

        let mixed = bssh::ssh::SshConfig::parse(
            "Host batch\n    BatchMode yes\nHost interactive\n    BatchMode no\n",
        )
        .unwrap();
        let resolver = SshConnectionConfigResolver::new().with_ssh_config(Some(mixed));
        assert!(!all_targets_use_batch_mode(
            &resolver,
            &["batch", "interactive"]
        ));
        let password = collect_ssh_password_with(true, || {
            calls.set(calls.get() + 1);
            Password::new("secret".to_string())
        })
        .unwrap();
        assert!(password.is_some());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn effective_proxy_jump_hops_participate_in_batch_mode_prompt_policy() {
        let mixed = bssh::ssh::SshConfig::parse(
            "Host target\n    BatchMode yes\n    ProxyJump jump\nHost jump\n    BatchMode no\n",
        )
        .unwrap();
        let resolver = SshConnectionConfigResolver::new().with_ssh_config(Some(mixed));
        let targets = effective_authentication_targets(&resolver, &["target".into()]).unwrap();
        assert_eq!(targets, ["target", "jump"]);
        let refs = targets.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(!all_targets_use_batch_mode(&resolver, &refs));

        let all_batch = bssh::ssh::SshConfig::parse(
            "Host target\n    BatchMode yes\n    ProxyJump jump\nHost jump\n    BatchMode yes\n",
        )
        .unwrap();
        let resolver = SshConnectionConfigResolver::new().with_ssh_config(Some(all_batch));
        let targets = effective_authentication_targets(&resolver, &["target".into()]).unwrap();
        let refs = targets.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(all_targets_use_batch_mode(&resolver, &refs));

        let proxy_command = bssh::ssh::SshConfig::parse(
            "Host target\n    BatchMode yes\n    ProxyCommand ssh jump nc %h %p\nHost jump\n    BatchMode no\n",
        )
        .unwrap();
        let resolver = SshConnectionConfigResolver::new().with_ssh_config(Some(proxy_command));
        let targets = effective_authentication_targets(&resolver, &["target".into()]).unwrap();
        assert_eq!(targets, ["target"]);
    }
}

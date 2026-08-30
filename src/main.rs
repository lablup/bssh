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

use std::process::ExitCode;

use anyhow::Result;
use bssh::cli::{
    Cli, Commands, PdshCli, has_pdsh_compat_flag, is_pdsh_compat_mode, remove_pdsh_compat_flag,
};
use bssh::commands::ping::PING_SSH_LEVEL_FAILURE;
use bssh::hostlist;
use clap::Parser;
use glob::Pattern;

mod app;

use app::{
    cache::handle_cache_stats,
    config_dump::handle_config_dump,
    dispatcher::dispatch_command,
    initialization::{AppContext, initialize_app},
    query::handle_query,
    utils::show_usage,
};

/// Main entry point for bssh
///
/// Supports three modes of operation:
/// 1. Standard bssh CLI mode
/// 2. pdsh compatibility mode (via symlink, env var, or --pdsh-compat flag)
/// 3. SSH compatibility mode (single host)
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            bssh::diagnosticln!("Error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Check for pdsh compatibility mode
    // Priority: env var / binary name > --pdsh-compat flag
    let pdsh_mode = is_pdsh_compat_mode() || has_pdsh_compat_flag(&args);

    if pdsh_mode {
        return run_pdsh_mode(&args).await;
    }

    // Standard bssh mode
    run_bssh_mode(&args).await
}

/// Run the dispatcher and translate its result into the process exit status.
///
/// This is the single place where a command-level exit code becomes a process
/// exit code. `dispatch_command` returns the code instead of exiting itself, so
/// the mapping stays in one place instead of being scattered across command
/// implementations.
async fn dispatch_and_exit(cli: &Cli, ctx: &AppContext) -> Result<()> {
    match dispatch_command(cli, ctx).await {
        Ok(0) => Ok(()),
        Ok(exit_code) => std::process::exit(exit_code),
        Err(e) => Err(map_hard_failure(&cli.command, cli.is_ssh_mode(), e)),
    }
}

/// Apply the `ping` exit code contract to a hard failure.
///
/// `ping` reports 255 whenever bssh itself failed rather than a remote host: a
/// configuration file that could not be loaded, a host list that resolved to
/// nothing, or any error raised before the connectivity check could produce a
/// per-host tally. That is OpenSSH's convention for "ssh encountered an error",
/// and it keeps the pre-connection case distinct from the exit code 1 that means
/// "some hosts answered and some did not".
///
/// Typed SSH client failures use OpenSSH's exit status 255. Local validation,
/// configuration, and other subcommand failures retain the generic exit status 1.
fn is_ssh_client_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<bssh::ssh::tokio_client::Error>()
            .is_some_and(bssh::ssh::tokio_client::Error::is_ssh_client_failure)
    })
}

fn map_hard_failure(
    command: &Option<Commands>,
    ssh_mode: bool,
    error: anyhow::Error,
) -> anyhow::Error {
    if matches!(command, Some(Commands::Ping)) {
        // Match the format anyhow's `Termination` impl uses, since this path
        // replaces it.
        bssh::diagnosticln!("Error: {error:?}");
        std::process::exit(PING_SSH_LEVEL_FAILURE);
    }

    if ssh_mode && is_ssh_client_failure(&error) {
        bssh::diagnosticln!("{error:#}");
        std::process::exit(255);
    }

    error
}

/// Run in pdsh compatibility mode
///
/// Parses pdsh-style arguments and converts them to bssh CLI options.
async fn run_pdsh_mode(args: &[String]) -> Result<()> {
    // Remove --pdsh-compat flag if present (pdsh parser doesn't know it)
    let filtered_args = if has_pdsh_compat_flag(args) {
        remove_pdsh_compat_flag(args)
    } else {
        args.to_vec()
    };

    // Parse pdsh-style arguments
    let pdsh_cli = PdshCli::parse_from(filtered_args.iter());

    // Handle query mode (-q): show hosts and exit
    if pdsh_cli.is_query_mode() {
        return handle_pdsh_query_mode(&pdsh_cli).await;
    }

    // Convert to bssh CLI
    let mut cli = pdsh_cli.to_bssh_cli();
    bssh::ui::configure_color(cli.color);

    // Check if we have hosts
    if cli.hosts.is_none() {
        bssh::diagnosticln!("Error: No hosts specified. Use -w to specify target hosts.");
        bssh::diagnosticln!("Usage: pdsh -w hosts command");
        std::process::exit(1);
    }

    // Check if we have a command (unless in query mode)
    if cli.command_args.is_empty() {
        bssh::diagnosticln!("Error: No command specified.");
        bssh::diagnosticln!("Usage: pdsh -w hosts command");
        std::process::exit(1);
    }

    // Initialize and run
    let ctx = initialize_app(&mut cli, args).await?;
    dispatch_and_exit(&cli, &ctx).await
}

/// Handle pdsh query mode (-q)
///
/// Shows the list of hosts that would be targeted and exits.
/// Supports hostlist expression expansion (e.g., node[1-5], rack[1-2]-node[1-3])
/// Uses the same glob pattern matching as the standard --exclude option
/// for consistency.
async fn handle_pdsh_query_mode(pdsh_cli: &PdshCli) -> Result<()> {
    if let Some(ref hosts_str) = pdsh_cli.hosts {
        // Expand hostlist expressions (e.g., node[1-5], rack[1-2]-node[1-3])
        let hosts: Vec<String> = hostlist::expand_host_specs(hosts_str)
            .map_err(|e| anyhow::anyhow!("Failed to expand host expression: {e}"))?;

        // Process exclusion patterns (supports both glob patterns and hostlist expressions)
        let (expanded_exclusions, glob_exclusions): (Vec<String>, Vec<Pattern>) = if let Some(
            ref exclude_str,
        ) =
            pdsh_cli.exclude
        {
            let mut expanded = Vec::new();
            let mut globs = Vec::new();

            for pattern in exclude_str.split(',').map(|s| s.trim()) {
                // Security: Validate pattern length
                const MAX_PATTERN_LENGTH: usize = 256;
                if pattern.len() > MAX_PATTERN_LENGTH {
                    anyhow::bail!(
                        "Exclusion pattern too long (max {MAX_PATTERN_LENGTH} characters)"
                    );
                }

                // Security: Skip empty patterns
                if pattern.is_empty() {
                    continue;
                }

                // Check if it's a hostlist expression (contains numeric range brackets)
                if hostlist::is_hostlist_expression(pattern) {
                    // Expand hostlist expression
                    let expanded_hosts = hostlist::expand_host_specs(pattern)
                        .map_err(|e| anyhow::anyhow!("Failed to expand exclusion pattern: {e}"))?;
                    expanded.extend(expanded_hosts);
                } else {
                    // Security: Prevent excessive wildcards for glob patterns
                    let wildcard_count = pattern.chars().filter(|c| *c == '*' || *c == '?').count();
                    const MAX_WILDCARDS: usize = 10;
                    if wildcard_count > MAX_WILDCARDS {
                        anyhow::bail!(
                            "Exclusion pattern contains too many wildcards (max {MAX_WILDCARDS})"
                        );
                    }

                    // Compile the glob pattern
                    match Pattern::new(pattern) {
                        Ok(p) => globs.push(p),
                        Err(_) => {
                            anyhow::bail!("Invalid exclusion pattern: {pattern}");
                        }
                    }
                }
            }
            (expanded, globs)
        } else {
            (Vec::new(), Vec::new())
        };

        // Create a set for O(1) lookup of expanded exclusions
        let exclusion_set: std::collections::HashSet<&str> =
            expanded_exclusions.iter().map(|s| s.as_str()).collect();

        // Filter and display hosts
        for host in &hosts {
            // Check if host is in the expanded exclusion set
            let is_excluded_by_hostlist = exclusion_set.contains(host.as_str());

            // Check if host matches any glob exclusion pattern
            let is_excluded_by_glob = glob_exclusions.iter().any(|pattern| {
                // For patterns without wildcards, also do exact/contains matching
                // (consistent with exclude_nodes in app/nodes.rs)
                let pattern_str = pattern.as_str();
                if !pattern_str.contains('*')
                    && !pattern_str.contains('?')
                    && !pattern_str.contains('[')
                {
                    host == pattern_str || host.contains(pattern_str)
                } else {
                    pattern.matches(host)
                }
            });

            if !is_excluded_by_hostlist && !is_excluded_by_glob {
                println!("{host}");
            }
        }
    } else {
        bssh::diagnosticln!("Error: No hosts specified for query mode.");
        bssh::diagnosticln!("Usage: pdsh -w hosts -q");
        std::process::exit(1);
    }

    Ok(())
}

/// Run in standard bssh mode
async fn run_bssh_mode(args: &[String]) -> Result<()> {
    // Check if no arguments were provided
    if args.len() == 1 {
        // Show concise usage when no arguments provided (like SSH)
        show_usage();
        std::process::exit(0);
    }

    let mut cli = Cli::parse();
    bssh::ui::configure_color(cli.color);

    if cli.version {
        eprintln!("bssh_{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if let Some(path) = &cli.log_file {
        bssh::utils::diagnostics::set_log_file(path)?;
    }

    // `-G` uses the minimal diagnostic sink above, but remains before
    // Backend.AI discovery, DNS, agents, prompts, proxies, and all networking.
    if cli.print_config {
        return handle_config_dump(&cli, args).await;
    }

    // Handle SSH query option (-Q)
    if let Some(ref query) = cli.query {
        handle_query(query);
        return Ok(());
    }

    // Handle list command first (doesn't need initialization)
    if matches!(cli.command, Some(Commands::List))
        || (cli.is_multi_server_mode() && cli.destination.as_deref() == Some("list"))
    {
        // Load minimal config just for listing
        let config = bssh::config::Config::load_with_priority(&cli.config).await?;
        bssh::commands::list::list_clusters(&config);
        return Ok(());
    }

    // Handle cache-stats command (doesn't need full initialization)
    if let Some(Commands::CacheStats {
        detailed,
        clear,
        maintain,
    }) = &cli.command
    {
        handle_cache_stats(*detailed, *clear, *maintain).await;
        return Ok(());
    }

    // Initialize the application and load all configurations. A failure here is
    // a pre-connection failure, which `ping` reports as 255.
    let init_result = initialize_app(&mut cli, args).await;
    let ctx = match init_result {
        Ok(ctx) => ctx,
        Err(e) => return Err(map_hard_failure(&cli.command, cli.is_ssh_mode(), e)),
    };

    // Dispatch to the appropriate command handler
    dispatch_and_exit(&cli, &ctx).await
}

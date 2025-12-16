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
use bssh::cli::{
    has_pdsh_compat_flag, is_pdsh_compat_mode, remove_pdsh_compat_flag, Cli, Commands, PdshCli,
};
use clap::Parser;
use glob::Pattern;

mod app;

use app::{
    cache::handle_cache_stats, dispatcher::dispatch_command, initialization::initialize_app,
    query::handle_query, utils::show_usage,
};

/// Main entry point for bssh
///
/// Supports three modes of operation:
/// 1. Standard bssh CLI mode
/// 2. pdsh compatibility mode (via symlink, env var, or --pdsh-compat flag)
/// 3. SSH compatibility mode (single host)
#[tokio::main]
async fn main() -> Result<()> {
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

    // Check if we have hosts
    if cli.hosts.is_none() {
        eprintln!("Error: No hosts specified. Use -w to specify target hosts.");
        eprintln!("Usage: pdsh -w hosts command");
        std::process::exit(1);
    }

    // Check if we have a command (unless in query mode)
    if cli.command_args.is_empty() {
        eprintln!("Error: No command specified.");
        eprintln!("Usage: pdsh -w hosts command");
        std::process::exit(1);
    }

    // Initialize and run
    let ctx = initialize_app(&mut cli, args).await?;
    dispatch_command(&cli, &ctx).await
}

/// Handle pdsh query mode (-q)
///
/// Shows the list of hosts that would be targeted and exits.
/// Uses the same glob pattern matching as the standard --exclude option
/// for consistency.
async fn handle_pdsh_query_mode(pdsh_cli: &PdshCli) -> Result<()> {
    if let Some(ref hosts_str) = pdsh_cli.hosts {
        let hosts: Vec<&str> = hosts_str.split(',').map(|s| s.trim()).collect();

        // Compile exclusion patterns (same logic as app/nodes.rs exclude_nodes)
        let exclusion_patterns: Vec<Pattern> = if let Some(ref exclude_str) = pdsh_cli.exclude {
            let patterns: Vec<&str> = exclude_str.split(',').map(|s| s.trim()).collect();
            let mut compiled = Vec::with_capacity(patterns.len());
            for pattern in patterns {
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

                // Security: Prevent excessive wildcards
                let wildcard_count = pattern.chars().filter(|c| *c == '*' || *c == '?').count();
                const MAX_WILDCARDS: usize = 10;
                if wildcard_count > MAX_WILDCARDS {
                    anyhow::bail!(
                        "Exclusion pattern contains too many wildcards (max {MAX_WILDCARDS})"
                    );
                }

                // Compile the glob pattern
                match Pattern::new(pattern) {
                    Ok(p) => compiled.push(p),
                    Err(_) => {
                        anyhow::bail!("Invalid exclusion pattern: {pattern}");
                    }
                }
            }
            compiled
        } else {
            Vec::new()
        };

        // Filter and display hosts
        for host in hosts {
            // Check if host matches any exclusion pattern
            let is_excluded = if exclusion_patterns.is_empty() {
                false
            } else {
                exclusion_patterns.iter().any(|pattern| {
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
                })
            };

            if !is_excluded {
                println!("{host}");
            }
        }
    } else {
        eprintln!("Error: No hosts specified for query mode.");
        eprintln!("Usage: pdsh -w hosts -q");
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

    // Initialize the application and load all configurations
    let ctx = initialize_app(&mut cli, args).await?;

    // Dispatch to the appropriate command handler
    dispatch_command(&cli, &ctx).await
}

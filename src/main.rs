use anyhow::{Context, Result};
use clap::Parser;
use std::path::Path;
use tracing_subscriber::EnvFilter;

use bssh::{Cli, Config, Node, ParallelExecutor};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose);

    // Load configuration
    let config = Config::load(&cli.config).await?;

    // Determine nodes to execute on
    let nodes = resolve_nodes(&cli, &config).await?;

    if nodes.is_empty() {
        anyhow::bail!("No hosts specified. Use -H or -c option.");
    }

    // Get command to execute
    let command = cli.get_command();

    if command.is_empty()
        && !matches!(
            cli.command,
            Some(bssh::cli::Commands::List | bssh::cli::Commands::Ping)
        )
    {
        anyhow::bail!("No command specified");
    }

    // Handle different commands
    match cli.command {
        Some(bssh::cli::Commands::List) => {
            list_clusters(&config);
        }
        Some(bssh::cli::Commands::Ping) => {
            ping_nodes(nodes, cli.parallel, cli.identity.as_deref()).await?;
        }
        Some(bssh::cli::Commands::Copy {
            source: _,
            destination: _,
        }) => {
            anyhow::bail!("Copy command not yet implemented");
        }
        _ => {
            // Execute command
            execute_command(
                nodes,
                &command,
                cli.parallel,
                cli.identity.as_deref(),
                cli.verbose > 0,
            )
            .await?;
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

    // Priority: command line hosts > cluster from config
    if let Some(hosts) = &cli.hosts {
        for host_str in hosts {
            let node = Node::parse(host_str, cli.user.as_deref())
                .with_context(|| format!("Failed to parse host: {host_str}"))?;
            nodes.push(node);
        }
    } else if let Some(cluster_name) = &cli.cluster {
        nodes = config.resolve_nodes(cluster_name)?;
    }

    Ok(nodes)
}

fn list_clusters(config: &Config) {
    if config.clusters.is_empty() {
        println!("No clusters configured");
        return;
    }

    println!("Available clusters:");
    for (name, cluster) in &config.clusters {
        println!("  {} ({} nodes)", name, cluster.nodes.len());
        for node_config in &cluster.nodes {
            let node_str = match node_config {
                bssh::config::NodeConfig::Simple(s) => s.clone(),
                bssh::config::NodeConfig::Detailed { host, .. } => host.clone(),
            };
            println!("    - {node_str}");
        }
    }
}

async fn ping_nodes(nodes: Vec<Node>, max_parallel: usize, key_path: Option<&Path>) -> Result<()> {
    println!("Pinging {} nodes...\n", nodes.len());

    let key_path = key_path.map(|p| p.to_string_lossy().to_string());
    let executor = ParallelExecutor::new(nodes.clone(), max_parallel, key_path);

    let results = executor.execute("echo 'pong'").await?;

    let mut success_count = 0;
    let mut failed_count = 0;

    for result in &results {
        if result.is_success() {
            success_count += 1;
            println!("✓ {} - Connected", result.node);
        } else {
            failed_count += 1;
            println!("✗ {} - Failed", result.node);
            if let Err(e) = &result.result {
                println!("  Error: {e}");
            }
        }
    }

    println!(
        "\nSummary: {success_count} successful, {failed_count} failed"
    );

    Ok(())
}

async fn execute_command(
    nodes: Vec<Node>,
    command: &str,
    max_parallel: usize,
    key_path: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    println!("Executing command on {} nodes: {}\n", nodes.len(), command);

    let key_path = key_path.map(|p| p.to_string_lossy().to_string());
    let executor = ParallelExecutor::new(nodes, max_parallel, key_path);

    let results = executor.execute(command).await?;

    // Print results
    for result in &results {
        result.print_output(verbose);
    }

    // Print summary
    let success_count = results.iter().filter(|r| r.is_success()).count();
    let failed_count = results.len() - success_count;

    println!(
        "\nExecution complete: {success_count} successful, {failed_count} failed"
    );

    if failed_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

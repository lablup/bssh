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
use bssh::cli::{Cli, Commands};
use clap::Parser;

mod app;

use app::{
    cache::handle_cache_stats, dispatcher::dispatch_command, initialization::initialize_app,
    query::handle_query, utils::show_usage,
};

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
    let ctx = initialize_app(&cli, &args).await?;

    // Dispatch to the appropriate command handler
    dispatch_command(&cli, &ctx).await
}

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
use owo_colors::OwoColorize;
use std::path::Path;

use crate::executor::ParallelExecutor;
use crate::node::Node;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ui::OutputFormatter;

#[allow(clippy::too_many_arguments)]
pub async fn ping_nodes(
    nodes: Vec<Node>,
    max_parallel: usize,
    key_path: Option<&Path>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    #[cfg(target_os = "macos")] use_keychain: bool,
    timeout: Option<u64>,
    connect_timeout: Option<u64>,
    jump_hosts: Option<String>,
) -> Result<()> {
    println!(
        "{}",
        OutputFormatter::format_command_header("ping", nodes.len())
    );

    let key_path = key_path.map(|p| p.to_string_lossy().to_string());

    // For ping command, just use the provided timeout or default
    // Don't override user's timeout setting
    let ping_timeout = timeout;

    let executor = ParallelExecutor::new_with_all_options(
        nodes.clone(),
        max_parallel,
        key_path,
        strict_mode,
        use_agent,
        use_password,
    )
    .with_timeout(ping_timeout)
    .with_connect_timeout(connect_timeout)
    .with_jump_hosts(jump_hosts);

    #[cfg(target_os = "macos")]
    let executor = executor.with_keychain(use_keychain);

    // Use normal execution (no TUI, no streaming) for ping
    let results = executor.execute("true").await?;

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
                // Display the full error chain for better debugging
                let error_chain = format!("{e:#}");
                // Split by newlines and indent each line
                for (i, line) in error_chain.lines().enumerate() {
                    if i == 0 {
                        println!("    {} {}", "└".dimmed(), line.dimmed());
                    } else {
                        println!("      {}", line.dimmed());
                    }
                }
            }
        }
    }

    println!(
        "{}",
        OutputFormatter::format_summary(nodes.len(), success_count, failed_count)
    );

    Ok(())
}

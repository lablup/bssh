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

//! Example demonstrating interactive mode usage with bssh

use bssh::commands::interactive::InteractiveCommand;
use bssh::config::Config;
use bssh::node::Node;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_env_filter("info").init();

    println!("Interactive Mode Demo");
    println!("=====================");
    println!();
    println!("This example demonstrates how to use bssh's interactive mode programmatically.");
    println!();

    // Create sample nodes
    let nodes = vec![Node::new(
        String::from("localhost"),
        22,
        String::from("user"),
    )];

    // Create interactive command configuration
    let interactive_cmd = InteractiveCommand {
        single_node: true, // Use single-node mode for this demo
        multiplex: false,
        prompt_format: String::from("[{user}@{host}:{pwd}]$ "),
        history_file: PathBuf::from("~/.bssh_demo_history"),
        work_dir: None,
        nodes,
        config: Config::default(),
    };

    println!("Starting interactive session...");
    println!("Note: This will attempt to connect to localhost:22");
    println!("Make sure you have SSH server running locally.");
    println!();

    // Execute interactive mode
    match interactive_cmd.execute().await {
        Ok(result) => {
            println!("\nSession Summary:");
            println!("  Duration: {:?}", result.duration);
            println!("  Commands executed: {}", result.commands_executed);
            println!("  Nodes connected: {}", result.nodes_connected);
        }
        Err(e) => {
            eprintln!("Interactive session failed: {e}");
            eprintln!("\nTip: To test interactive mode, try:");
            eprintln!("  1. Start a local SSH server");
            eprintln!("  2. Or use: bssh -H user@remote-host interactive");
        }
    }

    Ok(())
}

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

//! Special command handling for interactive mode

use anyhow::Result;

use super::types::{InteractiveCommand, NodeSession};

impl InteractiveCommand {
    /// Parse and handle special commands (starting with configured prefix)
    pub(super) fn handle_special_command(
        &self,
        command: &str,
        sessions: &mut [NodeSession],
        prefix: &str,
    ) -> Result<bool> {
        if !command.starts_with(prefix) {
            return Ok(false); // Not a special command
        }

        let cmd = command.trim_start_matches(prefix).to_lowercase();

        match cmd.as_str() {
            "all" => {
                // Activate all nodes
                for session in sessions.iter_mut() {
                    if session.is_connected {
                        session.is_active = true;
                    }
                }
                println!("All nodes activated");
                Ok(true)
            }
            "list" | "nodes" | "ls" => {
                // List all nodes with their status
                println!("\nNodes status:");
                for (i, session) in sessions.iter().enumerate() {
                    let status = if !session.is_connected {
                        "disconnected"
                    } else if session.is_active {
                        "active"
                    } else {
                        "inactive"
                    };
                    println!("  [{}] {} - {}", i + 1, session.node, status);
                }
                println!();
                Ok(true)
            }
            "status" => {
                // Show current active nodes
                let active_nodes: Vec<String> = sessions
                    .iter()
                    .filter(|s| s.is_active && s.is_connected)
                    .map(|s| s.node.to_string())
                    .collect();

                if active_nodes.is_empty() {
                    println!("No active nodes");
                } else {
                    println!("Active nodes: {}", active_nodes.join(", "));
                }
                Ok(true)
            }
            "help" | "?" => {
                let broadcast_prefix = self
                    .interactive_config
                    .broadcast_prefix
                    .as_deref()
                    .unwrap_or("!broadcast ");
                println!("\nSpecial commands:");
                println!("  {prefix}all          - Activate all nodes");
                println!("  {broadcast_prefix}<cmd> - Execute command on all nodes (temporarily)");
                println!("  {prefix}node<N>      - Switch to node N (e.g., {prefix}node1)");
                println!("  {prefix}n<N>         - Shorthand for {prefix}node<N>");
                println!("  {prefix}list, {prefix}nodes - List all nodes with status");
                println!("  {prefix}status       - Show active nodes");
                println!("  {prefix}help         - Show this help");
                println!("  exit          - Exit interactive mode");
                println!();
                Ok(true)
            }
            _ => {
                // Check for broadcast command
                let broadcast_prefix = self
                    .interactive_config
                    .broadcast_prefix
                    .as_deref()
                    .unwrap_or("!broadcast ");
                let broadcast_cmd = format!("{prefix}broadcast ");

                if let Some(rest) = command.strip_prefix(&broadcast_cmd) {
                    if rest.trim().is_empty() {
                        println!("Usage: {broadcast_prefix}<command>");
                        return Ok(true);
                    }
                    // Return false with the broadcast command to signal it should be executed
                    return Ok(false);
                }
                // Check for node selection commands
                if let Some(node_num) = cmd.strip_prefix("node") {
                    Self::switch_to_node(node_num, sessions)
                } else if let Some(node_num) = cmd.strip_prefix('n') {
                    Self::switch_to_node(node_num, sessions)
                } else {
                    println!(
                        "Unknown command: {prefix}{cmd}. Type {prefix}help for available commands."
                    );
                    Ok(true)
                }
            }
        }
    }

    /// Switch to a specific node by number
    fn switch_to_node(node_num: &str, sessions: &mut [NodeSession]) -> Result<bool> {
        match node_num.parse::<usize>() {
            Ok(num) if num > 0 && num <= sessions.len() => {
                // Deactivate all nodes first
                for session in sessions.iter_mut() {
                    session.is_active = false;
                }

                // Activate the selected node
                let index = num - 1;
                if sessions[index].is_connected {
                    sessions[index].is_active = true;
                    println!("Switched to node {}: {}", num, sessions[index].node);
                } else {
                    println!("Node {num} is disconnected");
                }
                Ok(true)
            }
            _ => {
                println!("Invalid node number. Use 1-{}", sessions.len());
                Ok(true)
            }
        }
    }
}

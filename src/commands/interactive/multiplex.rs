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

//! Multi-node multiplexed interactive session handling

use anyhow::Result;
use chrono;
use owo_colors::OwoColorize;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use tokio::time::Duration;

use super::super::interactive_signal::is_interrupted;
use super::types::{
    InteractiveCommand, NodeSession, NODES_TO_SHOW_IN_COMPACT, SSH_OUTPUT_POLL_INTERVAL_MS,
};

impl InteractiveCommand {
    /// Run interactive mode with multiple nodes (multiplex)
    pub(super) async fn run_multiplex_mode(&self, mut sessions: Vec<NodeSession>) -> Result<usize> {
        let mut commands_executed = 0;

        // Set up rustyline editor
        let history_path = self.expand_path(&self.history_file)?;
        let mut rl = DefaultEditor::new()?;
        rl.set_max_history_size(1000)?;

        // Load history if it exists
        if history_path.exists() {
            let _ = rl.load_history(&history_path);
        }

        println!(
            "Interactive multiplex mode started. Commands will be sent to all {} nodes.",
            sessions.len()
        );
        println!("Type 'exit' or press Ctrl+D to quit. Type '!help' for special commands.");
        println!();

        // Main interactive loop
        loop {
            // Check for interrupt signal
            if is_interrupted() {
                println!("\nInterrupted by user. Exiting...");
                break;
            }
            // Build prompt with node status
            let active_count = sessions
                .iter()
                .filter(|s| s.is_active && s.is_connected)
                .count();
            let total_connected = sessions.iter().filter(|s| s.is_connected).count();
            let total_nodes = sessions.len();

            // Use compact display for many nodes (threshold: 10)
            const MAX_INDIVIDUAL_DISPLAY: usize = 10;

            let prompt = if total_nodes > MAX_INDIVIDUAL_DISPLAY {
                // Compact display for many nodes
                if active_count == total_connected {
                    // All active
                    format!("[All {total_connected}/{total_nodes}] bssh> ")
                } else if active_count == 0 {
                    // None active
                    format!("[None 0/{total_connected}] bssh> ")
                } else {
                    // Some active - show which nodes are active (first few)
                    let active_nodes: Vec<usize> = sessions
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| s.is_active && s.is_connected)
                        .map(|(i, _)| i + 1)
                        .collect();

                    let display = if active_nodes.len() <= 5 {
                        // Show all active node numbers if 5 or fewer
                        let node_list = active_nodes
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("[Nodes {node_list}]")
                    } else {
                        // Show first 3 and count
                        let first_three = active_nodes
                            .iter()
                            .take(NODES_TO_SHOW_IN_COMPACT)
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",");
                        format!(
                            "[Nodes {first_three}... +{}]",
                            active_nodes.len() - NODES_TO_SHOW_IN_COMPACT
                        )
                    };

                    format!("{display} ({active_count}/{total_connected}) bssh> ")
                }
            } else if active_count == total_connected {
                // All nodes active - show simple status for small number of nodes
                let mut status = String::from("[");
                for (i, session) in sessions.iter().enumerate() {
                    if i > 0 {
                        status.push(' ');
                    }
                    if session.is_connected {
                        status.push_str(&"●".green().to_string());
                    } else {
                        status.push_str(&"○".red().to_string());
                    }
                }
                status.push_str("] bssh> ");
                status
            } else {
                // Some nodes inactive - show which are active for small number of nodes
                let mut status = String::from("[");
                for (i, session) in sessions.iter().enumerate() {
                    if i > 0 {
                        status.push(' ');
                    }
                    if !session.is_connected {
                        status.push_str(&"○".red().to_string());
                    } else if session.is_active {
                        status.push_str(&format!("{}", (i + 1).to_string().green()));
                    } else {
                        status.push_str(&"·".yellow().to_string());
                    }
                }
                status.push_str(&format!("] ({active_count}/{total_connected}) bssh> "));
                status
            };

            // Read input
            match rl.readline(&prompt) {
                Ok(line) => {
                    if line.trim() == "exit" {
                        break;
                    }

                    // Check for broadcast command specifically
                    let broadcast_prefix = self
                        .interactive_config
                        .broadcast_prefix
                        .as_deref()
                        .unwrap_or("!broadcast ");
                    let is_broadcast = line.trim().starts_with(broadcast_prefix);
                    let command_to_execute = if is_broadcast {
                        // Extract the actual command from the broadcast prefix
                        line.trim()
                            .strip_prefix(broadcast_prefix)
                            .unwrap_or("")
                            .to_string()
                    } else {
                        line.clone()
                    };

                    // Check for special commands first (non-broadcast)
                    let special_prefix = self
                        .interactive_config
                        .node_switch_prefix
                        .as_deref()
                        .unwrap_or("!");
                    if !is_broadcast
                        && line.trim().starts_with(special_prefix)
                        && self.handle_special_command(&line, &mut sessions, special_prefix)?
                    {
                        continue; // Command was handled, continue to next iteration
                    }

                    // Skip if broadcast command is empty
                    if is_broadcast && command_to_execute.trim().is_empty() {
                        println!("Usage: {broadcast_prefix}<command>");
                        continue;
                    }

                    rl.add_history_entry(&line)?;

                    // Save current active states if broadcasting
                    let saved_states: Vec<bool> = if is_broadcast {
                        println!("Broadcasting command to all connected nodes...");
                        sessions.iter().map(|s| s.is_active).collect()
                    } else {
                        vec![]
                    };

                    // Temporarily activate all nodes for broadcast
                    if is_broadcast {
                        for session in &mut sessions {
                            if session.is_connected {
                                session.is_active = true;
                            }
                        }
                    }

                    // Send command to active nodes
                    let mut command_sent = false;
                    for session in &mut sessions {
                        if session.is_connected && session.is_active {
                            if let Err(e) = session.send_command(&command_to_execute).await {
                                eprintln!(
                                    "Failed to send command to {}: {}",
                                    session.node.to_string().red(),
                                    e
                                );
                                session.is_connected = false;
                            } else {
                                command_sent = true;
                            }
                        }
                    }

                    // Restore previous active states after broadcast
                    if is_broadcast && !saved_states.is_empty() {
                        for (session, was_active) in sessions.iter_mut().zip(saved_states.iter()) {
                            session.is_active = *was_active;
                        }
                    }

                    if command_sent {
                        commands_executed += 1;
                    } else {
                        eprintln!(
                            "No active nodes to send command to. Use !list to see nodes or !all to activate all."
                        );
                        continue;
                    }

                    // Use select! to efficiently collect output from all active nodes
                    let output_timeout = tokio::time::sleep(Duration::from_millis(500));
                    tokio::pin!(output_timeout);

                    // Collect output with timeout using select!
                    loop {
                        let mut has_output = false;

                        tokio::select! {
                            // Timeout reached, stop collecting output
                            _ = &mut output_timeout => {
                                break;
                            }

                            // Try to read output from each active session
                            _ = async {
                                for session in &mut sessions {
                                    if session.is_connected && session.is_active {
                                        if let Ok(Some(output)) = session.read_output().await {
                                            has_output = true;
                                            // Print output with node prefix and optional timestamp
                                            for line in output.lines() {
                                                if self.interactive_config.show_timestamps {
                                                    let timestamp = chrono::Local::now().format("%H:%M:%S");
                                                    println!(
                                                        "[{} {}] {}",
                                                        timestamp.to_string().dimmed(),
                                                        format!(
                                                            "{}@{}",
                                                            session.node.username, session.node.host
                                                        )
                                                        .cyan(),
                                                        line
                                                    );
                                                } else {
                                                    println!(
                                                        "[{}] {}",
                                                        format!(
                                                            "{}@{}",
                                                            session.node.username, session.node.host
                                                        )
                                                        .cyan(),
                                                        line
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }

                                // If no output was found, sleep briefly to avoid busy waiting
                                if !has_output {
                                    // Output polling interval in multiplex mode:
                                    // - 10ms provides responsive output collection
                                    // - Prevents busy waiting when no output available
                                    // - Short enough to maintain interactive feel
                                    tokio::time::sleep(Duration::from_millis(SSH_OUTPUT_POLL_INTERVAL_MS)).await;
                                }
                            } => {
                                if !has_output {
                                    break; // No more output available
                                }
                            }
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("^C");
                }
                Err(ReadlineError::Eof) => {
                    println!("^D");
                    break;
                }
                Err(err) => {
                    eprintln!("Error: {err}");
                    break;
                }
            }

            // Check if all nodes are disconnected
            if sessions.iter().all(|s| !s.is_connected) {
                eprintln!("All nodes disconnected. Exiting.");
                break;
            }
        }

        // Clean up
        let _ = rl.save_history(&history_path);

        Ok(commands_executed)
    }
}

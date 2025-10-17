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

//! Main execution logic for interactive sessions

use anyhow::Result;
use owo_colors::OwoColorize;
use std::sync::Arc;

use crate::pty::PtyManager;

use super::super::interactive_signal::{
    reset_interrupt, setup_async_signal_handlers, setup_signal_handlers, TerminalGuard,
};
use super::types::{InteractiveCommand, InteractiveResult};

impl InteractiveCommand {
    /// Main entry point for interactive session execution
    pub async fn execute(self) -> Result<InteractiveResult> {
        let use_pty = self.should_use_pty()?;

        // Choose between PTY mode and traditional interactive mode
        if use_pty {
            // Use new PTY implementation for true terminal support
            self.execute_with_pty().await
        } else {
            // Use traditional rustyline-based interactive mode (existing implementation)
            self.execute_traditional().await
        }
    }

    /// Execute interactive session with full PTY support
    pub(super) async fn execute_with_pty(self) -> Result<InteractiveResult> {
        let start_time = std::time::Instant::now();

        println!("Starting interactive session with PTY support...");

        // Determine which nodes to connect to
        let nodes_to_connect = self.select_nodes_to_connect()?;

        // Connect to all selected nodes and get SSH channels
        let mut channels = Vec::new();
        let mut connected_nodes = Vec::new();

        for node in nodes_to_connect {
            match self.connect_to_node_pty(node.clone()).await {
                Ok(channel) => {
                    println!("✓ Connected to {} with PTY", node.to_string().green());
                    channels.push(channel);
                    connected_nodes.push(node);
                }
                Err(e) => {
                    eprintln!("✗ Failed to connect to {}: {}", node.to_string().red(), e);
                }
            }
        }

        if channels.is_empty() {
            anyhow::bail!("Failed to connect to any nodes");
        }

        let nodes_connected = channels.len();

        // Create PTY manager and sessions
        let mut pty_manager = PtyManager::new();

        if self.single_node && channels.len() == 1 {
            // Single PTY session
            let session_id = pty_manager
                .create_single_session(
                    channels.into_iter().next().unwrap(),
                    self.pty_config.clone(),
                )
                .await?;

            pty_manager.run_single_session(session_id).await?;
        } else {
            // Multiple PTY sessions with multiplexing
            let session_ids = pty_manager
                .create_multiplex_sessions(channels, self.pty_config.clone())
                .await?;

            pty_manager.run_multiplex_sessions(session_ids).await?;
        }

        // Ensure terminal is fully restored after PTY session ends
        // Use synchronized cleanup to prevent race conditions
        crate::pty::terminal::force_terminal_cleanup();
        let _ = std::io::Write::flush(&mut std::io::stdout());

        Ok(InteractiveResult {
            duration: start_time.elapsed(),
            commands_executed: 0, // PTY mode doesn't count discrete commands
            nodes_connected,
        })
    }

    /// Execute traditional interactive session (existing implementation)
    pub(super) async fn execute_traditional(self) -> Result<InteractiveResult> {
        let start_time = std::time::Instant::now();

        // Set up signal handlers and terminal guard
        let _terminal_guard = TerminalGuard::new();
        let shutdown = setup_signal_handlers()?;
        setup_async_signal_handlers(Arc::clone(&shutdown)).await;
        reset_interrupt();

        // Determine which nodes to connect to
        let nodes_to_connect = self.select_nodes_to_connect()?;

        // Connect to all selected nodes
        println!("Connecting to {} node(s)...", nodes_to_connect.len());
        let mut sessions = Vec::new();

        for node in nodes_to_connect {
            match self.connect_to_node(node.clone()).await {
                Ok(session) => {
                    println!("✓ Connected to {}", session.node.to_string().green());
                    sessions.push(session);
                }
                Err(e) => {
                    eprintln!("✗ Failed to connect to {}: {}", node.to_string().red(), e);
                }
            }
        }

        if sessions.is_empty() {
            anyhow::bail!("Failed to connect to any nodes");
        }

        let nodes_connected = sessions.len();

        // Enter interactive mode
        let commands_executed = if self.single_node {
            self.run_single_node_mode(sessions.into_iter().next().unwrap())
                .await?
        } else {
            self.run_multiplex_mode(sessions).await?
        };

        Ok(InteractiveResult {
            duration: start_time.elapsed(),
            commands_executed,
            nodes_connected,
        })
    }
}

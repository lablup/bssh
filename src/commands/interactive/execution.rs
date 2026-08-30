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

use crate::ui::Colorize;
use anyhow::Result;
use std::sync::Arc;

use crate::commands::error_format::format_connection_error;
use crate::diagnosticln as eprintln;
use crate::pty::PtyManager;

use super::super::interactive_signal::{
    TerminalGuard, reset_interrupt, setup_async_signal_handlers, setup_signal_handlers,
};
use super::types::{InteractiveCommand, InteractiveResult};

impl InteractiveCommand {
    /// Main entry point for interactive session execution
    pub async fn execute(self) -> Result<InteractiveResult> {
        let use_raw_session = self.should_use_raw_session()?;

        // SSH-compatible shells always use the raw byte-stream runner. Regular
        // bssh interactive sessions retain their traditional line UI fallback.
        if use_raw_session {
            self.execute_with_pty().await
        } else {
            // Use traditional rustyline-based interactive mode (existing implementation)
            self.execute_traditional().await
        }
    }

    /// Execute interactive session with full PTY support
    pub(super) async fn execute_with_pty(mut self) -> Result<InteractiveResult> {
        let start_time = std::time::Instant::now();
        let ssh_compatible = self.session_policy.is_some();

        if !ssh_compatible {
            println!("Starting interactive SSH byte-stream session...");
        }

        // Determine which nodes to connect to
        let nodes_to_connect = self.select_nodes_to_connect()?;

        // Connect to all selected nodes and get SSH channels
        let mut channels = Vec::new();
        let mut clients = Vec::new();
        let mut connected_nodes = Vec::new();

        for node in nodes_to_connect {
            match self.connect_to_node_pty(node.clone()).await {
                Ok((client, channel)) => {
                    if !ssh_compatible {
                        println!("✓ Connected to {}", node.to_string().green());
                    }
                    channels.push(channel);
                    clients.push(client);
                    connected_nodes.push(node);
                }
                Err(e) => {
                    eprintln!(
                        "✗ Failed to connect to {}: {}",
                        node.to_string().red_stderr(),
                        format_connection_error(&e)
                    );
                }
            }
        }

        if channels.is_empty() {
            anyhow::bail!("Failed to connect to any nodes");
        }

        let nodes_connected = channels.len();

        let mut session_config = self.pty_config.clone();
        if let Some(policy) = self.session_policy.take() {
            session_config.environment = policy.environment;
        }

        // Create raw stream manager and sessions. PtyConfig::disable_pty only
        // controls remote PTY/resize requests, not byte-transparent I/O.
        let requested_remote_pty = !session_config.disable_pty;
        let mut pty_manager = PtyManager::new();

        let session_result: Result<()> = async {
            if self.single_node && channels.len() == 1 {
                // Single PTY session
                let session_id = pty_manager
                    .create_single_session(
                        channels.into_iter().next().unwrap(),
                        session_config.clone(),
                    )
                    .await?;

                pty_manager.run_single_session(session_id).await?;
            } else {
                // Multiple PTY sessions with multiplexing
                let session_ids = pty_manager
                    .create_multiplex_sessions(channels, session_config)
                    .await?;

                pty_manager.run_multiplex_sessions(session_ids).await?;
            }
            Ok(())
        }
        .await;
        for client in &clients {
            client.flush_hostkey_updates().await;
        }
        session_result?;

        if requested_remote_pty {
            crate::pty::terminal::force_terminal_cleanup();
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }

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
                    eprintln!(
                        "✗ Failed to connect to {}: {}",
                        node.to_string().red_stderr(),
                        format_connection_error(&e)
                    );
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

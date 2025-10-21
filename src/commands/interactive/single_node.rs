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

//! Single node interactive session handling

use anyhow::Result;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::Duration;

use super::super::interactive_signal::is_interrupted;
use super::types::{InteractiveCommand, NodeSession, SSH_OUTPUT_POLL_INTERVAL_MS};

impl InteractiveCommand {
    /// Run interactive mode with a single node
    pub(super) async fn run_single_node_mode(&self, session: NodeSession) -> Result<usize> {
        let mut commands_executed = 0;

        // Set up rustyline editor
        let history_path = self.expand_path(&self.history_file)?;
        let mut rl = DefaultEditor::new()?;
        rl.set_max_history_size(1000)?;

        // Load history if it exists
        if history_path.exists() {
            let _ = rl.load_history(&history_path);
        }

        // Create shared state for the session
        let session_arc = Arc::new(Mutex::new(session));
        let session_clone = Arc::clone(&session_arc);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        // Create a bounded channel for receiving output from the SSH session
        // SSH output channel sizing:
        // - 128 capacity handles burst terminal output without blocking SSH reader
        // - Each message is variable size (terminal output lines/chunks)
        // - Bounded to prevent memory exhaustion from high-volume output
        // - Large enough to smooth out bursty shell command output
        const SSH_OUTPUT_CHANNEL_SIZE: usize = 128;
        let (output_tx, mut output_rx) = mpsc::channel::<String>(SSH_OUTPUT_CHANNEL_SIZE);

        // Spawn a task to read output from the SSH channel using select! for efficiency
        let output_reader = tokio::spawn(async move {
            let mut shutdown_watch = {
                let shutdown_clone_for_watch = Arc::clone(&shutdown_clone);
                tokio::spawn(async move {
                    loop {
                        if shutdown_clone_for_watch.load(Ordering::Relaxed) || is_interrupted() {
                            break;
                        }
                        // Shutdown polling interval:
                        // - 50ms provides responsive shutdown detection
                        // - Prevents tight spin loop during shutdown
                        // - Fast enough that users won't notice delay on Ctrl+C
                        const SHUTDOWN_POLL_INTERVAL_MS: u64 = 50;
                        tokio::time::sleep(Duration::from_millis(SHUTDOWN_POLL_INTERVAL_MS)).await;
                    }
                })
            };

            loop {
                tokio::select! {
                    // Check for output from SSH session
                    // SSH output polling interval:
                    // - 10ms provides very responsive output display
                    // - Short enough to appear instantaneous to users
                    // - Balances CPU usage with terminal responsiveness
                    _ = tokio::time::sleep(Duration::from_millis(SSH_OUTPUT_POLL_INTERVAL_MS)) => {
                        let mut session_guard = session_clone.lock().await;
                        if !session_guard.is_connected {
                            break;
                        }
                        if let Ok(Some(output)) = session_guard.read_output().await {
                            // Use try_send to avoid blocking; drop output if buffer is full
                            // This prevents memory exhaustion but may lose some output under extreme load
                            if output_tx.try_send(output).is_err() {
                                // Channel closed or full, exit gracefully
                                break;
                            }
                        }
                        drop(session_guard);
                    }

                    // Check for shutdown signal
                    _ = &mut shutdown_watch => {
                        break;
                    }
                }
            }
        });

        println!("Interactive session started. Type 'exit' or press Ctrl+D to quit.");
        println!();

        // Main interactive loop using tokio::select! for efficient event multiplexing
        loop {
            // Check for interrupt signal
            if is_interrupted() {
                println!("\nInterrupted by user. Exiting...");
                shutdown.store(true, Ordering::Relaxed);
                break;
            }

            // Print any pending output first
            while let Ok(output) = output_rx.try_recv() {
                print!("{output}");
                io::stdout().flush()?;
            }

            // Get current session state for prompt
            let session_guard = session_arc.lock().await;
            let prompt = self.format_prompt(&session_guard.node, &session_guard.working_dir);
            let is_connected = session_guard.is_connected;
            drop(session_guard);

            if !is_connected {
                eprintln!("Connection lost. Exiting.");
                break;
            }

            // Use select! to handle multiple events efficiently
            tokio::select! {
                // Handle new output from SSH session
                output = output_rx.recv() => {
                    match output {
                        Some(output) => {
                            print!("{output}");
                            io::stdout().flush()?;
                            continue; // Continue without reading input to process more output
                        }
                        None => {
                            // Output channel closed, session likely ended
                            eprintln!("Session output channel closed. Exiting.");
                            break;
                        }
                    }
                }

                // Handle user input (this runs in a separate task since readline is blocking)
                // User input processing interval:
                // - 10ms keeps UI responsive during input processing
                // - Allows other events to be processed (output, signals)
                // - Short interval since readline() might block briefly
                _ = tokio::time::sleep(Duration::from_millis(SSH_OUTPUT_POLL_INTERVAL_MS)) => {
                    // Read input using rustyline (this needs to remain synchronous)
                    match rl.readline(&prompt) {
                        Ok(line) => {
                            if line.trim() == "exit" {
                                // Send exit command to remote server before breaking
                                let mut session_guard = session_arc.lock().await;
                                session_guard.send_command("exit").await?;
                                drop(session_guard);
                                // Give the SSH session a moment to process the exit
                                // SSH exit command processing delay:
                                // - 100ms allows remote shell to process exit command
                                // - Prevents premature connection termination
                                // - Ensures clean session shutdown
                                const SSH_EXIT_DELAY_MS: u64 = 100;
                                tokio::time::sleep(Duration::from_millis(SSH_EXIT_DELAY_MS)).await;
                                break;
                            }

                            rl.add_history_entry(&line)?;

                            // Send command to remote
                            let mut session_guard = session_arc.lock().await;
                            session_guard.send_command(&line).await?;
                            commands_executed += 1;

                            // Track directory changes
                            if line.trim().starts_with("cd ") {
                                // Update working directory
                                session_guard.send_command("pwd").await?;
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
                }
            }
        }

        // Clean up
        shutdown.store(true, Ordering::Relaxed);
        output_reader.abort();

        // Properly close the SSH session
        let mut session_guard = session_arc.lock().await;
        if session_guard.is_connected {
            // Close the SSH channel properly
            let _ = session_guard.channel.close().await;
            session_guard.is_connected = false;
        }
        drop(session_guard);

        let _ = rl.save_history(&history_path);

        Ok(commands_executed)
    }
}

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

//! PTY (Pseudo-terminal) support for interactive SSH sessions.
//!
//! This module provides true PTY allocation with full terminal emulation capabilities
//! including terminal resize handling, raw mode support, and proper handling of colors
//! and special keys.

use anyhow::{Context, Result};
use russh::{client::Msg, Channel};
use signal_hook::{consts::SIGWINCH, iterator::Signals};
use smallvec::SmallVec;
use terminal_size::{terminal_size, Height, Width};
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;

pub mod session;
pub mod terminal;

pub use session::PtySession;
pub use terminal::{force_terminal_cleanup, TerminalState, TerminalStateGuard};

/// Session processing interval for multiplex mode
/// - 100ms provides reasonable time-slicing for multiplex mode
/// - Allows other async tasks to run without starving
/// - Not critical for responsiveness as actual I/O is event-driven
const SESSION_PROCESSING_INTERVAL_MS: u64 = 100;

/// PTY session configuration
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// Terminal type (e.g., "xterm-256color", "xterm", "vt100")
    pub term_type: String,
    /// Whether to force PTY allocation
    pub force_pty: bool,
    /// Whether to disable PTY allocation
    pub disable_pty: bool,
    /// Enable mouse event support
    pub enable_mouse: bool,
    /// Terminal input/output timeout
    pub timeout: Duration,
}

impl Default for PtyConfig {
    fn default() -> Self {
        // Default PTY configuration timeout design:
        // - 10ms provides rapid response to input/output events
        // - Short enough to feel instantaneous to users (<20ms threshold)
        // - Balances CPU usage with responsiveness for interactive terminals
        const DEFAULT_PTY_TIMEOUT_MS: u64 = 10;

        Self {
            term_type: "xterm-256color".to_string(),
            force_pty: false,
            disable_pty: false,
            enable_mouse: false,
            timeout: Duration::from_millis(DEFAULT_PTY_TIMEOUT_MS),
        }
    }
}

/// PTY session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyState {
    /// PTY is not active
    Inactive,
    /// PTY is initializing
    Initializing,
    /// PTY is active and ready
    Active,
    /// PTY is being shut down
    ShuttingDown,
    /// PTY has been closed
    Closed,
}

/// Terminal input/output message
/// Uses SmallVec to avoid heap allocations for small messages (typical for key presses)
#[derive(Debug)]
pub enum PtyMessage {
    /// Data from local terminal to send to remote
    /// SmallVec<[u8; 8]> keeps key sequences stack-allocated
    LocalInput(SmallVec<[u8; 8]>),
    /// Data from remote to display on local terminal
    /// SmallVec<[u8; 64]> handles most terminal output without allocation
    RemoteOutput(SmallVec<[u8; 64]>),
    /// Terminal resize event
    Resize { width: u32, height: u32 },
    /// PTY session should terminate
    Terminate,
    /// Error occurred
    Error(String),
}

/// PTY manager for handling multiple PTY sessions
pub struct PtyManager {
    active_sessions: Vec<PtySession>,
    cancel_tx: watch::Sender<bool>,
    cancel_rx: watch::Receiver<bool>,
}

impl PtyManager {
    /// Create a new PTY manager
    pub fn new() -> Self {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        Self {
            active_sessions: Vec::new(),
            cancel_tx,
            cancel_rx,
        }
    }

    /// Create a PTY session for a single node
    pub async fn create_single_session(
        &mut self,
        channel: Channel<Msg>,
        config: PtyConfig,
    ) -> Result<usize> {
        let session_id = self.active_sessions.len();
        let session = PtySession::new(session_id, channel, config).await?;
        self.active_sessions.push(session);
        Ok(session_id)
    }

    /// Create PTY sessions for multiple nodes with multiplexing
    pub async fn create_multiplex_sessions(
        &mut self,
        channels: Vec<Channel<Msg>>,
        config: PtyConfig,
    ) -> Result<Vec<usize>> {
        let mut session_ids = Vec::new();
        for channel in channels {
            let session_id = self.create_single_session(channel, config.clone()).await?;
            session_ids.push(session_id);
        }
        Ok(session_ids)
    }

    /// Run a single PTY session
    pub async fn run_single_session(&mut self, session_id: usize) -> Result<()> {
        let result = if let Some(session) = self.active_sessions.get_mut(session_id) {
            session.run().await
        } else {
            anyhow::bail!("PTY session {session_id} not found")
        };

        // Ensure terminal is properly restored after session ends
        // Use synchronized cleanup from terminal module
        crate::pty::terminal::force_terminal_cleanup();

        result
    }

    /// Run multiple PTY sessions with session switching
    pub async fn run_multiplex_sessions(&mut self, session_ids: Vec<usize>) -> Result<()> {
        if session_ids.is_empty() {
            anyhow::bail!("No PTY sessions to run");
        }

        // Start with the first session active
        let mut active_session = session_ids[0];

        // Set up bounded channels for communication between sessions
        // Session switching channel sizing:
        // - 32 capacity handles burst session switches without blocking
        // - Session switches are infrequent user actions, small buffer sufficient
        // - Prevents memory exhaustion from accumulated switch commands
        const SESSION_SWITCH_CHANNEL_SIZE: usize = 32;
        let (_switch_tx, mut _switch_rx) = mpsc::channel::<usize>(SESSION_SWITCH_CHANNEL_SIZE);

        // Run the multiplexed session loop using select! for efficient event handling
        let mut cancel_rx = self.cancel_rx.clone();

        loop {
            tokio::select! {
                // Check for cancellation signal
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        tracing::debug!("PTY multiplex received cancellation signal");
                        break;
                    }
                }

                // Check for session switch commands
                new_session = _switch_rx.recv() => {
                    match new_session {
                        Some(session_id) => {
                            if session_ids.contains(&session_id) {
                                active_session = session_id;
                                println!("Switched to PTY session {session_id}");
                            } else {
                                eprintln!("Invalid PTY session: {session_id}");
                            }
                        }
                        None => {
                            // Switch channel closed
                            break;
                        }
                    }
                }

                // Run active session processing
                // Session processing interval design:
                // - 100ms provides reasonable time-slicing for multiplex mode
                // - Allows other async tasks to run without starving
                // - Not critical for responsiveness as actual I/O is event-driven
                _ = tokio::time::sleep(Duration::from_millis(SESSION_PROCESSING_INTERVAL_MS)) => {
                    // TODO: Implement session time-slicing for multiplex mode
                    // For now, just continue the loop
                    if let Some(_session) = self.active_sessions.get_mut(active_session) {
                        // Session processing would go here
                    }
                }
            }
        }

        Ok(())
    }

    /// Shutdown all PTY sessions with proper select!-based cleanup
    pub async fn shutdown(&mut self) -> Result<()> {
        // Signal cancellation to all operations
        let _ = self.cancel_tx.send(true);

        // Use select! to handle concurrent shutdown of multiple sessions
        let shutdown_futures: Vec<_> = self
            .active_sessions
            .iter_mut()
            .map(|session| session.shutdown())
            .collect();

        // Wait for all sessions to shutdown with timeout
        // PTY manager shutdown timeout design:
        // - 5 seconds allows time for multiple sessions to cleanup gracefully
        // - Long enough for network operations to complete (channel close, etc.)
        // - Prevents indefinite hang if some sessions don't respond to shutdown
        // - After timeout, remaining sessions are abandoned (memory cleanup via Drop)
        const PTY_SHUTDOWN_TIMEOUT_SECS: u64 = 5;
        let shutdown_timeout = Duration::from_secs(PTY_SHUTDOWN_TIMEOUT_SECS);

        tokio::select! {
            results = futures::future::try_join_all(shutdown_futures) => {
                match results {
                    Ok(_) => tracing::debug!("All PTY sessions shutdown successfully"),
                    Err(e) => tracing::warn!("Some PTY sessions failed to shutdown cleanly: {e}"),
                }
            }
            _ = tokio::time::sleep(shutdown_timeout) => {
                tracing::warn!("PTY session shutdown timed out after {} seconds", shutdown_timeout.as_secs());
            }
        }

        self.active_sessions.clear();
        Ok(())
    }
}

impl Default for PtyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for PTY operations
pub mod utils {
    use super::*;

    /// Check if PTY should be allocated based on configuration and terminal state
    pub fn should_allocate_pty(config: &PtyConfig) -> Result<bool> {
        if config.disable_pty {
            return Ok(false);
        }

        if config.force_pty {
            return Ok(true);
        }

        // Auto-detect if we're in an interactive terminal
        Ok(atty::is(atty::Stream::Stdin) && atty::is(atty::Stream::Stdout))
    }

    /// Get current terminal size
    pub fn get_terminal_size() -> Result<(u32, u32)> {
        if let Some((Width(w), Height(h))) = terminal_size() {
            Ok((u32::from(w), u32::from(h)))
        } else {
            // Default size if terminal size cannot be determined
            Ok((80, 24))
        }
    }

    /// Setup terminal resize signal handler
    pub fn setup_resize_handler() -> Result<Signals> {
        let signals = Signals::new([SIGWINCH])
            .with_context(|| "Failed to register SIGWINCH signal handler")?;
        Ok(signals)
    }

    /// Check if the current process has controlling terminal
    pub fn has_controlling_terminal() -> bool {
        atty::is(atty::Stream::Stdin) && atty::is(atty::Stream::Stdout)
    }
}

// Re-export key types
pub use utils::*;

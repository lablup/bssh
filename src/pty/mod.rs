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
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use terminal_size::{terminal_size, Height, Width};
use tokio::sync::mpsc;
use tokio::time::Duration;

pub mod session;
pub mod terminal;

pub use session::PtySession;
pub use terminal::{TerminalState, TerminalStateGuard};

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
        Self {
            term_type: "xterm-256color".to_string(),
            force_pty: false,
            disable_pty: false,
            enable_mouse: false,
            timeout: Duration::from_millis(10),
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
#[derive(Debug)]
pub enum PtyMessage {
    /// Data from local terminal to send to remote
    LocalInput(Vec<u8>),
    /// Data from remote to display on local terminal
    RemoteOutput(Vec<u8>),
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
    shutdown: Arc<AtomicBool>,
}

impl PtyManager {
    /// Create a new PTY manager
    pub fn new() -> Self {
        Self {
            active_sessions: Vec::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
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
        if let Some(session) = self.active_sessions.get_mut(session_id) {
            session.run().await
        } else {
            anyhow::bail!("PTY session {session_id} not found")
        }
    }

    /// Run multiple PTY sessions with session switching
    pub async fn run_multiplex_sessions(&mut self, session_ids: Vec<usize>) -> Result<()> {
        if session_ids.is_empty() {
            anyhow::bail!("No PTY sessions to run");
        }

        // Start with the first session active
        let mut active_session = session_ids[0];

        // Set up channels for communication between sessions
        let (_switch_tx, mut _switch_rx) = mpsc::unbounded_channel::<usize>();

        // Run the multiplexed session loop
        loop {
            // Check for shutdown signal
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Check for session switch commands
            if let Ok(new_session) = _switch_rx.try_recv() {
                if session_ids.contains(&new_session) {
                    active_session = new_session;
                    println!("Switched to PTY session {new_session}");
                } else {
                    eprintln!("Invalid PTY session: {new_session}");
                }
            }

            // Run the active session for a short time
            if let Some(_session) = self.active_sessions.get_mut(active_session) {
                // TODO: Implement session time-slicing for multiplex mode
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        Ok(())
    }

    /// Shutdown all PTY sessions
    pub async fn shutdown(&mut self) -> Result<()> {
        self.shutdown.store(true, Ordering::Relaxed);

        for session in &mut self.active_sessions {
            session.shutdown().await?;
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

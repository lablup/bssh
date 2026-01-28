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

//! Core PTY session management implementation

use super::constants::*;
use super::escape_filter::EscapeSequenceFilter;
use super::local_escape::{LocalAction, LocalEscapeDetector};
use super::raw_input::RawInputReader;
use super::terminal_modes::configure_terminal_modes;
use crate::pty::{
    terminal::{TerminalOps, TerminalStateGuard},
    PtyConfig, PtyMessage, PtyState,
};
use anyhow::{Context, Result};
use russh::{client::Msg, Channel, ChannelMsg};
use std::io::{self, Write};
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;

/// A PTY session managing the bidirectional communication between
/// local terminal and remote SSH session.
pub struct PtySession {
    /// Unique session identifier
    pub session_id: usize,
    /// SSH channel for communication
    channel: Channel<Msg>,
    /// PTY configuration
    config: PtyConfig,
    /// Current session state
    state: PtyState,
    /// Terminal state guard for proper cleanup
    terminal_guard: Option<TerminalStateGuard>,
    /// Cancellation signal for graceful shutdown
    cancel_tx: watch::Sender<bool>,
    cancel_rx: watch::Receiver<bool>,
    /// Message channels for internal communication (bounded to prevent memory exhaustion)
    msg_tx: Option<mpsc::Sender<PtyMessage>>,
    msg_rx: Option<mpsc::Receiver<PtyMessage>>,
    /// Filter for terminal escape sequence responses
    escape_filter: EscapeSequenceFilter,
}

impl PtySession {
    /// Create a new PTY session
    pub async fn new(session_id: usize, channel: Channel<Msg>, config: PtyConfig) -> Result<Self> {
        // Use bounded channel with reasonable buffer size to prevent memory exhaustion
        let (msg_tx, msg_rx) = mpsc::channel(PTY_MESSAGE_CHANNEL_SIZE);

        // Create cancellation channel
        let (cancel_tx, cancel_rx) = watch::channel(false);

        Ok(Self {
            session_id,
            channel,
            config,
            state: PtyState::Inactive,
            terminal_guard: None,
            cancel_tx,
            cancel_rx,
            msg_tx: Some(msg_tx),
            msg_rx: Some(msg_rx),
            escape_filter: EscapeSequenceFilter::new(),
        })
    }

    /// Get the current session state
    pub fn state(&self) -> PtyState {
        self.state
    }

    /// Initialize the PTY session with the remote terminal
    pub async fn initialize(&mut self) -> Result<()> {
        self.state = PtyState::Initializing;

        // Get terminal size
        let (width, height) = crate::pty::utils::get_terminal_size()?;

        // Set TERM environment variable before requesting PTY
        // This ensures the remote shell knows the terminal capabilities
        // Note: The server may not accept this (AcceptEnv in sshd_config),
        // but the PTY request will also include the term type
        if let Err(e) = self
            .channel
            .set_env(false, "TERM", &self.config.term_type)
            .await
        {
            // Log but don't fail - server may reject env requests
            tracing::debug!(
                "Server did not accept TERM environment variable: {}. \
                This is expected if AcceptEnv is not configured for TERM in sshd_config. \
                The terminal type will still be set via the PTY request.",
                e
            );
        }

        // Also set COLORTERM for better color support detection
        // Many modern terminals set this to indicate truecolor support
        if let Err(e) = self.channel.set_env(false, "COLORTERM", "truecolor").await {
            tracing::trace!(
                "Server did not accept COLORTERM environment variable: {}",
                e
            );
        }

        // Request PTY on the SSH channel with properly configured terminal modes
        // Configure terminal modes for proper sudo/passwd password input support
        let terminal_modes = configure_terminal_modes();
        self.channel
            .request_pty(
                false,
                &self.config.term_type,
                width,
                height,
                0,               // pixel width (0 means undefined)
                0,               // pixel height (0 means undefined)
                &terminal_modes, // Terminal modes using russh Pty enum
            )
            .await
            .with_context(|| "Failed to request PTY on SSH channel")?;

        // Request shell
        self.channel
            .request_shell(false)
            .await
            .with_context(|| "Failed to request shell on SSH channel")?;

        self.state = PtyState::Active;
        tracing::debug!(
            "PTY session {} initialized with TERM={}",
            self.session_id,
            self.config.term_type
        );
        Ok(())
    }

    /// Run the main PTY session loop
    pub async fn run(&mut self) -> Result<()> {
        if self.state == PtyState::Inactive {
            self.initialize().await?;
        }

        if self.state != PtyState::Active {
            anyhow::bail!("PTY session is not in active state");
        }

        // Set up terminal state guard
        self.terminal_guard = Some(TerminalStateGuard::new()?);

        // Enable mouse support if requested
        if self.config.enable_mouse {
            TerminalOps::enable_mouse()?;
        }

        // Get message receiver
        let mut msg_rx = self
            .msg_rx
            .take()
            .ok_or_else(|| anyhow::anyhow!("Message receiver already taken"))?;

        // Set up resize signal handler
        let mut resize_signals = crate::pty::utils::setup_resize_handler()?;
        let cancel_for_resize = self.cancel_rx.clone();

        // Spawn resize handler task
        let resize_tx = self
            .msg_tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Message sender not available"))?
            .clone();

        let resize_task = tokio::spawn(async move {
            let mut cancel_for_resize = cancel_for_resize;

            loop {
                tokio::select! {
                    // Handle resize signals
                    signal = async {
                        for signal in resize_signals.forever() {
                            if signal == signal_hook::consts::SIGWINCH {
                                return signal;
                            }
                        }
                        signal_hook::consts::SIGWINCH // fallback, won't be reached
                    } => {
                        if signal == signal_hook::consts::SIGWINCH {
                            if let Ok((width, height)) = crate::pty::utils::get_terminal_size() {
                                // Try to send resize message, but don't block if channel is full
                                if resize_tx.try_send(PtyMessage::Resize { width, height }).is_err() {
                                    // Channel full or closed, exit gracefully
                                    break;
                                }
                            }
                        }
                    }

                    // Handle cancellation
                    _ = cancel_for_resize.changed() => {
                        if *cancel_for_resize.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn input reader task
        let input_tx = self
            .msg_tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Message sender not available"))?
            .clone();
        let cancel_for_input = self.cancel_rx.clone();

        // Spawn input reader in blocking thread pool to avoid blocking async runtime
        // NOTE: TerminalStateGuard has already called enable_raw_mode() at this point,
        // so stdin.read() will return raw bytes without line buffering
        let input_task = tokio::task::spawn_blocking(move || {
            let mut reader = RawInputReader::new();
            let mut buffer = [0u8; 1024];
            let mut escape_detector = LocalEscapeDetector::new();

            loop {
                if *cancel_for_input.borrow() {
                    break;
                }

                let poll_timeout = Duration::from_millis(INPUT_POLL_TIMEOUT_MS);

                match reader.poll(poll_timeout) {
                    Ok(true) => {
                        match reader.read(&mut buffer) {
                            Ok(0) => {
                                // EOF - user closed stdin
                                tracing::debug!("EOF received on stdin");
                                break;
                            }
                            Ok(n) => {
                                // Check for local escape sequences (e.g., ~. for disconnect)
                                if let Some(action) = escape_detector.process(&buffer[..n]) {
                                    match action {
                                        LocalAction::Disconnect => {
                                            tracing::debug!("Disconnect escape sequence detected");
                                            let _ = input_tx.try_send(PtyMessage::Terminate);
                                            break;
                                        }
                                        LocalAction::Passthrough(data) => {
                                            // Send filtered data
                                            if input_tx
                                                .try_send(PtyMessage::LocalInput(data))
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    // Pass raw bytes through as-is
                                    // This includes arrow keys, function keys, terminal responses, etc.
                                    let data = smallvec::SmallVec::from_slice(&buffer[..n]);
                                    if input_tx.try_send(PtyMessage::LocalInput(data)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = input_tx
                                    .try_send(PtyMessage::Error(format!("Input error: {e}")));
                                break;
                            }
                        }
                    }
                    Ok(false) => {
                        // Timeout - continue polling
                        continue;
                    }
                    Err(e) => {
                        let _ = input_tx.try_send(PtyMessage::Error(format!("Poll error: {e}")));
                        break;
                    }
                }
            }
        });

        // We'll integrate channel reading into the main loop since russh Channel doesn't clone

        // Main message handling loop using tokio::select! for efficient event multiplexing
        let mut should_terminate = false;
        let mut cancel_rx = self.cancel_rx.clone();

        // Track last activity time for connection health monitoring
        let mut last_activity = std::time::Instant::now();
        let health_check_interval =
            Duration::from_secs(CONNECTION_HEALTH_CHECK_INTERVAL_SECS);
        let max_idle_time = Duration::from_secs(MAX_IDLE_TIME_BEFORE_WARNING_SECS);
        let mut idle_warning_shown = false;

        while !should_terminate {
            tokio::select! {
                // Handle SSH channel messages
                msg = self.channel.wait() => {
                    // Reset activity timer on any channel activity
                    last_activity = std::time::Instant::now();
                    idle_warning_shown = false;

                    match msg {
                        Some(ChannelMsg::Data { ref data }) => {
                            // Filter terminal escape sequence responses before display
                            // This prevents raw XTGETTCAP, DA1/DA2/DA3 responses from appearing
                            // on screen when running applications like Neovim
                            let filtered_data = self.escape_filter.filter(data);
                            if !filtered_data.is_empty() {
                                if let Err(e) = io::stdout().write_all(&filtered_data) {
                                    tracing::error!("Failed to write to stdout: {e}");
                                    should_terminate = true;
                                } else {
                                    let _ = io::stdout().flush();
                                }
                            }
                        }
                        Some(ChannelMsg::ExtendedData { ref data, ext }) => {
                            if ext == 1 {
                                // stderr - also filter escape sequences
                                let filtered_data = self.escape_filter.filter(data);
                                if !filtered_data.is_empty() {
                                    if let Err(e) = io::stdout().write_all(&filtered_data) {
                                        tracing::error!("Failed to write stderr to stdout: {e}");
                                        should_terminate = true;
                                    } else {
                                        let _ = io::stdout().flush();
                                    }
                                }
                            }
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => {
                            tracing::debug!("SSH channel closed");
                            // Signal cancellation to all child tasks before terminating
                            let _ = self.cancel_tx.send(true);
                            should_terminate = true;
                        }
                        Some(_) => {
                            // Handle other channel messages if needed
                        }
                        None => {
                            // Channel ended - connection is dead
                            tracing::warn!(
                                "SSH channel returned None - connection may have dropped"
                            );
                            should_terminate = true;
                        }
                    }
                }

                // Handle local messages (input, resize, etc.)
                message = msg_rx.recv() => {
                    // Reset activity timer for local input (user is active)
                    if matches!(message, Some(PtyMessage::LocalInput(_))) {
                        last_activity = std::time::Instant::now();
                        idle_warning_shown = false;
                    }

                    match message {
                        Some(PtyMessage::LocalInput(data)) => {
                            if let Err(e) = self.channel.data(data.as_slice()).await {
                                tracing::error!("Failed to send data to SSH channel: {e}");
                                // Connection likely dead - terminate gracefully
                                eprintln!("\r\n[bssh] Connection lost: failed to send data to remote host\r");
                                should_terminate = true;
                            }
                        }
                        Some(PtyMessage::RemoteOutput(data)) => {
                            // Apply escape filter for consistency with SSH channel data
                            // This path may receive data from other sources that could
                            // contain terminal responses that shouldn't be displayed
                            let filtered_data = self.escape_filter.filter(&data);
                            if !filtered_data.is_empty() {
                                if let Err(e) = io::stdout().write_all(&filtered_data) {
                                    tracing::error!("Failed to write to stdout: {e}");
                                    should_terminate = true;
                                } else {
                                    let _ = io::stdout().flush();
                                }
                            }
                        }
                        Some(PtyMessage::Resize { width, height }) => {
                            if let Err(e) = self.channel.window_change(width, height, 0, 0).await {
                                tracing::warn!("Failed to send window resize to remote: {e}");
                            } else {
                                tracing::debug!("Terminal resized to {width}x{height}");
                            }
                        }
                        Some(PtyMessage::Terminate) => {
                            tracing::debug!("PTY session {} terminating", self.session_id);
                            should_terminate = true;
                        }
                        Some(PtyMessage::Error(error)) => {
                            tracing::error!("PTY error: {error}");
                            should_terminate = true;
                        }
                        None => {
                            // Message channel closed
                            should_terminate = true;
                        }
                    }
                }

                // Handle cancellation signal
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        tracing::debug!("PTY session {} received cancellation signal", self.session_id);
                        should_terminate = true;
                    }
                }

                // Periodic health check to detect dead connections
                _ = tokio::time::sleep(health_check_interval) => {
                    let idle_duration = last_activity.elapsed();

                    // Check if the session has been idle for too long
                    if idle_duration > max_idle_time && !idle_warning_shown {
                        tracing::debug!(
                            "PTY session {} idle for {:?}, connection may be stale",
                            self.session_id,
                            idle_duration
                        );
                        // Don't terminate, but log for debugging
                        // SSH keepalive should handle actual connection detection
                        idle_warning_shown = true;
                    }

                    // Periodic trace logging for debugging long sessions
                    tracing::trace!(
                        "PTY session {} health check: idle for {:?}",
                        self.session_id,
                        idle_duration
                    );
                }
            }
        }

        // Signal cancellation to all tasks
        let _ = self.cancel_tx.send(true);

        // Tasks will exit gracefully on cancellation
        // No need to abort since they check cancellation signal

        // Wait for tasks to complete gracefully with select!
        let _ = tokio::time::timeout(Duration::from_millis(TASK_CLEANUP_TIMEOUT_MS), async {
            tokio::select! {
                _ = resize_task => {},
                _ = input_task => {},
                _ = tokio::time::sleep(Duration::from_millis(TASK_CLEANUP_TIMEOUT_MS)) => {
                    // Timeout reached, tasks should have finished by now
                }
            }
        })
        .await;

        // Disable mouse support if we enabled it
        if self.config.enable_mouse {
            let _ = TerminalOps::disable_mouse();
        }

        // IMPORTANT: Explicitly restore terminal state by dropping the guard
        // The guard's drop implementation handles synchronized cleanup
        self.terminal_guard = None;

        // Flush stdout to ensure all output is written
        let _ = io::stdout().flush();

        self.state = PtyState::Closed;
        Ok(())
    }

    /// Shutdown the PTY session
    pub async fn shutdown(&mut self) -> Result<()> {
        self.state = PtyState::ShuttingDown;

        // Signal cancellation to all tasks
        let _ = self.cancel_tx.send(true);

        // Send EOF to close the channel gracefully
        if let Err(e) = self.channel.eof().await {
            tracing::warn!("Failed to send EOF to SSH channel: {e}");
        }

        // Drop terminal guard to restore terminal state
        self.terminal_guard = None;

        self.state = PtyState::Closed;
        Ok(())
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // Signal cancellation to all tasks when session is dropped
        let _ = self.cancel_tx.send(true);
        // Terminal guard will be dropped automatically, restoring terminal state
    }
}

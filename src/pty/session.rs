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

//! PTY session management for interactive SSH connections.

use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent};
use russh::{client::Msg, Channel, ChannelMsg};
// use signal_hook::iterator::Signals; // Unused in current implementation
use std::io::{self, Write};
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;

use super::{
    terminal::{TerminalOps, TerminalStateGuard},
    PtyConfig, PtyMessage, PtyState,
};

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
}

impl PtySession {
    /// Create a new PTY session
    pub async fn new(session_id: usize, channel: Channel<Msg>, config: PtyConfig) -> Result<Self> {
        // Use bounded channel with reasonable buffer size to prevent memory exhaustion
        // 256 messages should be enough for terminal I/O without causing delays
        let (msg_tx, msg_rx) = mpsc::channel(256);

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
        let (width, height) = super::utils::get_terminal_size()?;

        // Request PTY on the SSH channel
        self.channel
            .request_pty(
                false,
                &self.config.term_type,
                width,
                height,
                0,   // pixel width (0 means undefined)
                0,   // pixel height (0 means undefined)
                &[], // terminal modes (empty means use defaults)
            )
            .await
            .with_context(|| "Failed to request PTY on SSH channel")?;

        // Request shell
        self.channel
            .request_shell(false)
            .await
            .with_context(|| "Failed to request shell on SSH channel")?;

        self.state = PtyState::Active;
        tracing::debug!("PTY session {} initialized", self.session_id);
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
        let mut resize_signals = super::utils::setup_resize_handler()?;
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
                            if let Ok((width, height)) = super::utils::get_terminal_size() {
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
        let input_task = tokio::task::spawn_blocking(move || {
            // This runs in a dedicated thread pool for blocking operations
            loop {
                if *cancel_for_input.borrow() {
                    break;
                }

                // Poll with a longer timeout since we're in blocking thread
                // This reduces CPU usage while maintaining responsiveness
                let poll_timeout = Duration::from_millis(500);

                // Check for input events with timeout (blocking is OK here)
                if crossterm::event::poll(poll_timeout).unwrap_or(false) {
                    match crossterm::event::read() {
                        Ok(event) => {
                            if let Some(data) = Self::handle_input_event(event) {
                                // Use try_send to avoid blocking on bounded channel
                                if input_tx.try_send(PtyMessage::LocalInput(data)).is_err() {
                                    // Channel is either full or closed
                                    // For input, we should break on error as it means session is ending
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            let _ =
                                input_tx.try_send(PtyMessage::Error(format!("Input error: {e}")));
                            break;
                        }
                    }
                }
            }
        });

        // We'll integrate channel reading into the main loop since russh Channel doesn't clone

        // Main message handling loop using tokio::select! for efficient event multiplexing
        let mut should_terminate = false;
        let mut cancel_rx = self.cancel_rx.clone();

        while !should_terminate {
            tokio::select! {
                // Handle SSH channel messages
                msg = self.channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { ref data }) => {
                            // Write directly to stdout
                            if let Err(e) = io::stdout().write_all(data) {
                                tracing::error!("Failed to write to stdout: {e}");
                                should_terminate = true;
                            } else {
                                let _ = io::stdout().flush();
                            }
                        }
                        Some(ChannelMsg::ExtendedData { ref data, ext }) => {
                            if ext == 1 {
                                // stderr - write to stdout as well for PTY mode
                                if let Err(e) = io::stdout().write_all(data) {
                                    tracing::error!("Failed to write stderr to stdout: {e}");
                                    should_terminate = true;
                                } else {
                                    let _ = io::stdout().flush();
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
                            // Channel ended
                            should_terminate = true;
                        }
                    }
                }

                // Handle local messages (input, resize, etc.)
                message = msg_rx.recv() => {
                    match message {
                        Some(PtyMessage::LocalInput(data)) => {
                            if let Err(e) = self.channel.data(data.as_slice()).await {
                                tracing::error!("Failed to send data to SSH channel: {e}");
                                should_terminate = true;
                            }
                        }
                        Some(PtyMessage::RemoteOutput(data)) => {
                            // Write directly to stdout for better performance
                            if let Err(e) = io::stdout().write_all(&data) {
                                tracing::error!("Failed to write to stdout: {e}");
                                should_terminate = true;
                            } else {
                                let _ = io::stdout().flush();
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
            }
        }

        // Signal cancellation to all tasks
        let _ = self.cancel_tx.send(true);

        // Tasks will exit gracefully on cancellation
        // No need to abort since they check cancellation signal

        // Wait for tasks to complete gracefully with select!
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            tokio::select! {
                _ = resize_task => {},
                _ = input_task => {},
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
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

    /// Handle input events and convert them to raw bytes
    fn handle_input_event(event: Event) -> Option<Vec<u8>> {
        match event {
            Event::Key(key_event) => {
                // Only process key press events (not release)
                if key_event.kind != KeyEventKind::Press {
                    return None;
                }

                Self::key_event_to_bytes(key_event)
            }
            Event::Mouse(mouse_event) => {
                // TODO: Implement mouse event handling
                Self::mouse_event_to_bytes(mouse_event)
            }
            Event::Resize(_width, _height) => {
                // Resize events are handled separately
                // This shouldn't happen as we handle resize via signals
                None
            }
            _ => None,
        }
    }

    /// Convert key events to raw byte sequences
    fn key_event_to_bytes(key_event: KeyEvent) -> Option<Vec<u8>> {
        match key_event {
            // Handle special key combinations
            KeyEvent {
                code: KeyCode::Char(c),
                modifiers: KeyModifiers::CONTROL,
                ..
            } => {
                match c {
                    'c' | 'C' => Some(vec![0x03]), // Ctrl+C (SIGINT)
                    'd' | 'D' => Some(vec![0x04]), // Ctrl+D (EOF)
                    'z' | 'Z' => Some(vec![0x1a]), // Ctrl+Z (SIGTSTP)
                    'a' | 'A' => Some(vec![0x01]), // Ctrl+A
                    'e' | 'E' => Some(vec![0x05]), // Ctrl+E
                    'u' | 'U' => Some(vec![0x15]), // Ctrl+U
                    'k' | 'K' => Some(vec![0x0b]), // Ctrl+K
                    'w' | 'W' => Some(vec![0x17]), // Ctrl+W
                    'l' | 'L' => Some(vec![0x0c]), // Ctrl+L
                    'r' | 'R' => Some(vec![0x12]), // Ctrl+R
                    _ => {
                        // General Ctrl+ handling: Ctrl+A is 0x01, Ctrl+B is 0x02, etc.
                        let byte = (c.to_ascii_lowercase() as u8).saturating_sub(b'a' - 1);
                        if byte <= 26 {
                            Some(vec![byte])
                        } else {
                            None
                        }
                    }
                }
            }

            // Handle regular characters
            KeyEvent {
                code: KeyCode::Char(c),
                modifiers: KeyModifiers::NONE,
                ..
            } => Some(c.to_string().into_bytes()),

            // Handle special keys
            KeyEvent {
                code: KeyCode::Enter,
                ..
            } => Some(vec![0x0d]), // Carriage return

            KeyEvent {
                code: KeyCode::Tab, ..
            } => Some(vec![0x09]), // Tab

            KeyEvent {
                code: KeyCode::Backspace,
                ..
            } => Some(vec![0x7f]), // DEL (some terminals use 0x08 for backspace)

            KeyEvent {
                code: KeyCode::Esc, ..
            } => Some(vec![0x1b]), // ESC

            // Arrow keys (ANSI escape sequences)
            KeyEvent {
                code: KeyCode::Up, ..
            } => Some(vec![0x1b, 0x5b, 0x41]), // ESC[A

            KeyEvent {
                code: KeyCode::Down,
                ..
            } => Some(vec![0x1b, 0x5b, 0x42]), // ESC[B

            KeyEvent {
                code: KeyCode::Right,
                ..
            } => Some(vec![0x1b, 0x5b, 0x43]), // ESC[C

            KeyEvent {
                code: KeyCode::Left,
                ..
            } => Some(vec![0x1b, 0x5b, 0x44]), // ESC[D

            // Function keys
            KeyEvent {
                code: KeyCode::F(n),
                ..
            } => {
                match n {
                    1 => Some(vec![0x1b, 0x4f, 0x50]),              // F1: ESC OP
                    2 => Some(vec![0x1b, 0x4f, 0x51]),              // F2: ESC OQ
                    3 => Some(vec![0x1b, 0x4f, 0x52]),              // F3: ESC OR
                    4 => Some(vec![0x1b, 0x4f, 0x53]),              // F4: ESC OS
                    5 => Some(vec![0x1b, 0x5b, 0x31, 0x35, 0x7e]),  // F5: ESC[15~
                    6 => Some(vec![0x1b, 0x5b, 0x31, 0x37, 0x7e]),  // F6: ESC[17~
                    7 => Some(vec![0x1b, 0x5b, 0x31, 0x38, 0x7e]),  // F7: ESC[18~
                    8 => Some(vec![0x1b, 0x5b, 0x31, 0x39, 0x7e]),  // F8: ESC[19~
                    9 => Some(vec![0x1b, 0x5b, 0x32, 0x30, 0x7e]),  // F9: ESC[20~
                    10 => Some(vec![0x1b, 0x5b, 0x32, 0x31, 0x7e]), // F10: ESC[21~
                    11 => Some(vec![0x1b, 0x5b, 0x32, 0x33, 0x7e]), // F11: ESC[23~
                    12 => Some(vec![0x1b, 0x5b, 0x32, 0x34, 0x7e]), // F12: ESC[24~
                    _ => None,                                      // F13+ not commonly supported
                }
            }

            // Other special keys
            KeyEvent {
                code: KeyCode::Home,
                ..
            } => Some(vec![0x1b, 0x5b, 0x48]), // ESC[H

            KeyEvent {
                code: KeyCode::End, ..
            } => Some(vec![0x1b, 0x5b, 0x46]), // ESC[F

            KeyEvent {
                code: KeyCode::PageUp,
                ..
            } => Some(vec![0x1b, 0x5b, 0x35, 0x7e]), // ESC[5~

            KeyEvent {
                code: KeyCode::PageDown,
                ..
            } => Some(vec![0x1b, 0x5b, 0x36, 0x7e]), // ESC[6~

            KeyEvent {
                code: KeyCode::Insert,
                ..
            } => Some(vec![0x1b, 0x5b, 0x32, 0x7e]), // ESC[2~

            KeyEvent {
                code: KeyCode::Delete,
                ..
            } => Some(vec![0x1b, 0x5b, 0x33, 0x7e]), // ESC[3~

            _ => None,
        }
    }

    /// Convert mouse events to raw byte sequences
    fn mouse_event_to_bytes(_mouse_event: MouseEvent) -> Option<Vec<u8>> {
        // TODO: Implement mouse event to bytes conversion
        // This requires implementing the terminal mouse reporting protocol
        None
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

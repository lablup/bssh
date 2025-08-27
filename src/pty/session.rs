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
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

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
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Message channels for internal communication
    msg_tx: Option<mpsc::UnboundedSender<PtyMessage>>,
    msg_rx: Option<mpsc::UnboundedReceiver<PtyMessage>>,
}

impl PtySession {
    /// Create a new PTY session
    pub async fn new(session_id: usize, channel: Channel<Msg>, config: PtyConfig) -> Result<Self> {
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();

        Ok(Self {
            session_id,
            channel,
            config,
            state: PtyState::Inactive,
            terminal_guard: None,
            shutdown: Arc::new(AtomicBool::new(false)),
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
        let shutdown_for_resize = Arc::clone(&self.shutdown);

        // Spawn resize handler task
        let resize_tx = self
            .msg_tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Message sender not available"))?
            .clone();

        let resize_task = tokio::spawn(async move {
            for signal in resize_signals.forever() {
                if shutdown_for_resize.load(Ordering::Relaxed) {
                    break;
                }

                if signal == signal_hook::consts::SIGWINCH {
                    if let Ok((width, height)) = super::utils::get_terminal_size() {
                        let _ = resize_tx.send(PtyMessage::Resize { width, height });
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
        let shutdown_for_input = Arc::clone(&self.shutdown);

        let input_task = tokio::spawn(async move {
            loop {
                if shutdown_for_input.load(Ordering::Relaxed) {
                    break;
                }

                // Use a shorter polling timeout for better responsiveness
                // This allows the task to check the shutdown flag more frequently
                let poll_timeout = Duration::from_millis(100);

                // Check for input events with timeout
                if crossterm::event::poll(poll_timeout).unwrap_or(false) {
                    match crossterm::event::read() {
                        Ok(event) => {
                            if let Some(data) = Self::handle_input_event(event) {
                                if input_tx.send(PtyMessage::LocalInput(data)).is_err() {
                                    break; // Channel closed
                                }
                            }
                        }
                        Err(e) => {
                            let _ = input_tx.send(PtyMessage::Error(format!("Input error: {e}")));
                            break;
                        }
                    }
                }
            }
        });

        // We'll integrate channel reading into the main loop since russh Channel doesn't clone

        // Main message handling loop
        let mut should_terminate = false;

        while !should_terminate && !self.shutdown.load(Ordering::Relaxed) {
            // First check for SSH channel messages
            if let Ok(Some(msg)) = timeout(Duration::from_millis(10), self.channel.wait()).await {
                match msg {
                    ChannelMsg::Data { ref data } => {
                        // Write directly to stdout
                        if let Err(e) = io::stdout().write_all(data) {
                            tracing::error!("Failed to write to stdout: {e}");
                            should_terminate = true;
                        } else {
                            let _ = io::stdout().flush();
                        }
                    }
                    ChannelMsg::ExtendedData { ref data, ext } => {
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
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        tracing::debug!("SSH channel closed");
                        // Set shutdown signal before terminating to ensure input task stops
                        self.shutdown.store(true, Ordering::Relaxed);
                        should_terminate = true;
                    }
                    _ => {}
                }
            }

            // Then check for local messages (input, resize, etc.)
            match timeout(Duration::from_millis(10), msg_rx.recv()).await {
                Ok(Some(message)) => {
                    match message {
                        PtyMessage::LocalInput(data) => {
                            if let Err(e) = self.channel.data(data.as_slice()).await {
                                tracing::error!("Failed to send data to SSH channel: {e}");
                                should_terminate = true;
                            }
                        }
                        PtyMessage::RemoteOutput(data) => {
                            // Write directly to stdout for better performance
                            if let Err(e) = io::stdout().write_all(&data) {
                                tracing::error!("Failed to write to stdout: {e}");
                                should_terminate = true;
                            } else {
                                let _ = io::stdout().flush();
                            }
                        }
                        PtyMessage::Resize { width, height } => {
                            if let Err(e) = self.channel.window_change(width, height, 0, 0).await {
                                tracing::warn!("Failed to send window resize to remote: {e}");
                            } else {
                                tracing::debug!("Terminal resized to {width}x{height}");
                            }
                        }
                        PtyMessage::Terminate => {
                            tracing::debug!("PTY session {} terminating", self.session_id);
                            should_terminate = true;
                        }
                        PtyMessage::Error(error) => {
                            tracing::error!("PTY error: {error}");
                            should_terminate = true;
                        }
                    }
                }
                Ok(None) => {
                    // Channel closed
                    should_terminate = true;
                }
                Err(_) => {
                    // Timeout - continue loop
                }
            }
        }

        // Signal shutdown first
        self.shutdown.store(true, Ordering::Relaxed);

        // Abort tasks immediately
        resize_task.abort();
        input_task.abort();

        // Wait for tasks to complete their abort
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            while !resize_task.is_finished() || !input_task.is_finished() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        // Disable mouse support if we enabled it
        if self.config.enable_mouse {
            let _ = TerminalOps::disable_mouse();
        }

        // IMPORTANT: Explicitly restore terminal state by dropping the guard
        // This ensures raw mode is disabled before we return
        self.terminal_guard = None;

        // Ensure terminal is fully restored
        let _ = crossterm::terminal::disable_raw_mode();

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
        self.shutdown.store(true, Ordering::Relaxed);

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
        self.shutdown.store(true, Ordering::Relaxed);
        // Terminal guard will be dropped automatically, restoring terminal state
    }
}

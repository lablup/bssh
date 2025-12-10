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

//! SSH channel operations including command execution and PTY management.
//!
//! This module provides methods for:
//! - Opening SSH channels
//! - Executing commands
//! - Managing interactive shells and PTY sessions
//! - Port forwarding channels

use russh::client::Msg;
use russh::Channel;
use russh::CryptoVec;
use std::io;
use std::net::SocketAddr;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

use super::connection::Client;
use super::ToSocketAddrsWithHostname;
use crate::security::{contains_sudo_failure, contains_sudo_prompt, SudoPassword};

// Buffer size constants for SSH operations
/// SSH I/O buffer size constants - optimized for different operation types
///
/// Buffer sizing rationale:
/// - Initial allocations start small and grow dynamically based on actual output
/// - This avoids wasting memory for commands with minimal output
/// - Growth factor of 1.5x amortizes reallocation costs
///
/// Output events channel capacity for streaming
///
/// - 100 events provides good buffering without excessive memory
/// - Balances between latency and throughput
/// - With typical SSH packet sizes (32KB), this can buffer ~3.2MB of data
/// - If the channel fills, backpressure is applied to prevent memory exhaustion
/// - Commands producing more than 3.2MB/sec may experience throttling
const OUTPUT_EVENTS_CHANNEL_SIZE: usize = 100;

/// Maximum buffer size for sudo prompt detection (64KB)
///
/// This prevents unbounded memory growth when detecting sudo prompts in command output.
/// Sudo prompts are typically very short (<1KB), so 64KB is more than sufficient.
/// If output exceeds this size without a sudo prompt, we truncate to prevent memory issues.
const MAX_SUDO_PROMPT_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum number of times to send sudo password in a single session.
/// This allows handling multiple sudo commands (e.g., `sudo cmd1 && sudo cmd2`)
/// while preventing infinite loops if authentication fails.
/// Set to 10 to support reasonable multi-sudo command chains.
const MAX_SUDO_PASSWORD_SENDS: u32 = 10;

/// Command output variants for streaming
#[derive(Debug, Clone)]
pub enum CommandOutput {
    /// Standard output data
    StdOut(CryptoVec),
    /// Standard error data
    StdErr(CryptoVec),
}

/// Buffer for collecting streaming command output
pub(crate) struct CommandOutputBuffer {
    pub(crate) sender: Sender<CommandOutput>,
    pub(crate) receiver_task: JoinHandle<(Vec<u8>, Vec<u8>)>,
}

impl CommandOutputBuffer {
    /// Create a new command output buffer with a background task to collect output
    ///
    /// The background task collects output in a memory-efficient manner with proper
    /// capacity management to avoid excessive allocations.
    pub(crate) fn new() -> Self {
        let (sender, mut receiver): (Sender<CommandOutput>, Receiver<CommandOutput>) =
            channel(OUTPUT_EVENTS_CHANNEL_SIZE);

        let receiver_task = tokio::task::spawn(async move {
            // Start with smaller initial capacity and grow as needed
            // This avoids wasting memory for commands with minimal output
            let mut stdout = Vec::with_capacity(1024); // Start with 1KB
            let mut stderr = Vec::with_capacity(256); // Start with 256B for stderr

            while let Some(output) = receiver.recv().await {
                match output {
                    CommandOutput::StdOut(buffer) => {
                        // Reserve additional capacity if needed to avoid frequent reallocations
                        let required = stdout.len() + buffer.len();
                        if stdout.capacity() < required {
                            // Grow by at least 50% to amortize allocation cost
                            let new_capacity =
                                required.max(stdout.capacity() + stdout.capacity() / 2);
                            stdout.reserve(new_capacity - stdout.capacity());
                        }
                        stdout.extend_from_slice(&buffer);
                    }
                    CommandOutput::StdErr(buffer) => {
                        // Reserve additional capacity if needed
                        let required = stderr.len() + buffer.len();
                        if stderr.capacity() < required {
                            // Grow by at least 50% to amortize allocation cost
                            let new_capacity =
                                required.max(stderr.capacity() + stderr.capacity() / 2);
                            stderr.reserve(new_capacity - stderr.capacity());
                        }
                        stderr.extend_from_slice(&buffer);
                    }
                }
            }

            (stdout, stderr)
        });

        Self {
            sender,
            receiver_task,
        }
    }
}

/// Result of a command execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandExecutedResult {
    /// The stdout output of the command.
    pub stdout: String,
    /// The stderr output of the command.
    pub stderr: String,
    /// The unix exit status (`$?` in bash).
    pub exit_status: u32,
}

impl Client {
    /// Get a new SSH channel for communication.
    pub async fn get_channel(&self) -> Result<Channel<Msg>, super::Error> {
        self.connection_handle
            .channel_open_session()
            .await
            .map_err(super::Error::SshError)
    }

    /// Open a TCP/IP forwarding channel.
    ///
    /// This opens a `direct-tcpip` channel to the given target.
    pub async fn open_direct_tcpip_channel<
        T: ToSocketAddrsWithHostname,
        S: Into<Option<SocketAddr>>,
    >(
        &self,
        target: T,
        src: S,
    ) -> Result<Channel<Msg>, super::Error> {
        let targets = target
            .to_socket_addrs()
            .map_err(super::Error::AddressInvalid)?;
        let src = src
            .into()
            .map(|src| (src.ip().to_string(), src.port().into()))
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 22));

        let mut connect_err = super::Error::AddressInvalid(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        ));
        for target in targets {
            match self
                .connection_handle
                .channel_open_direct_tcpip(
                    target.ip().to_string(),
                    target.port().into(),
                    src.0.clone(),
                    src.1,
                )
                .await
            {
                Ok(channel) => return Ok(channel),
                Err(err) => connect_err = super::Error::SshError(err),
            }
        }

        Err(connect_err)
    }

    /// Execute a remote command via the ssh connection with streaming output.
    ///
    /// This method sends command output in real-time to the provided sender channel.
    /// Output is sent as `CommandOutput::StdOut` or `CommandOutput::StdErr` variants.
    ///
    /// Returns only the exit status of the command. Stdout and stderr are streamed
    /// through the sender channel.
    ///
    /// Make sure your commands don't read from stdin and exit after bounded time.
    ///
    /// Can be called multiple times, but every invocation is a new shell context.
    /// Thus `cd`, setting variables and alike have no effect on future invocations.
    ///
    /// # Backpressure Handling
    /// If the channel fills up (receiver is slower than output production), this method
    /// will apply backpressure by blocking until space is available. This prevents
    /// unbounded memory growth but may slow down command execution for high-throughput
    /// commands.
    ///
    /// # Error Handling
    /// - If the receiver drops the channel, this method will stop processing output
    ///   and return the last known exit status.
    /// - Command sanitization errors are propagated as `CommandValidationFailed`.
    ///
    /// # Arguments
    /// * `command` - The command to execute
    /// * `sender` - Channel sender for streaming output
    ///
    /// # Returns
    /// The exit status of the command
    pub async fn execute_streaming(
        &self,
        command: &str,
        sender: Sender<CommandOutput>,
    ) -> Result<u32, super::Error> {
        // Sanitize command to prevent injection attacks
        let sanitized_command = crate::utils::sanitize_command(command)
            .map_err(|e| super::Error::CommandValidationFailed(e.to_string()))?;

        let mut channel = self.connection_handle.channel_open_session().await?;
        channel.exec(true, sanitized_command.as_str()).await?;

        let mut result: Option<u32> = None;

        // While the channel has messages...
        while let Some(msg) = channel.wait().await {
            match msg {
                // If we get data, send it to the streaming channel
                // Note: We must clone the data here because russh owns it and will reuse the buffer
                russh::ChannelMsg::Data { ref data } => {
                    // Try non-blocking send first for better performance
                    match sender.try_send(CommandOutput::StdOut(data.clone())) {
                        Ok(_) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(output)) => {
                            // Channel is full - apply backpressure by waiting
                            // This prevents memory exhaustion on high-throughput commands
                            tracing::trace!("Channel full, applying backpressure for stdout");
                            if sender.send(output).await.is_err() {
                                // Receiver dropped - stop processing
                                tracing::debug!("Receiver dropped, stopping stdout processing");
                                break;
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            // Receiver dropped - stop processing
                            tracing::debug!("Channel closed, stopping stdout processing");
                            break;
                        }
                    }
                }
                russh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        // Handle backpressure for stderr as well
                        match sender.try_send(CommandOutput::StdErr(data.clone())) {
                            Ok(_) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(output)) => {
                                // Channel is full - apply backpressure by waiting
                                tracing::trace!("Channel full, applying backpressure for stderr");
                                if sender.send(output).await.is_err() {
                                    // Receiver dropped - stop processing
                                    tracing::debug!("Receiver dropped, stopping stderr processing");
                                    break;
                                }
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                // Receiver dropped - stop processing
                                tracing::debug!("Channel closed, stopping stderr processing");
                                break;
                            }
                        }
                    }
                }

                // If we get an exit code report, store it, but crucially don't
                // assume this message means end of communications. The data might
                // not be finished yet!
                russh::ChannelMsg::ExitStatus { exit_status } => result = Some(exit_status),

                // We SHOULD get this EOF message, but 4254 sec 5.3 also permits
                // the channel to close without it being sent. And sometimes this
                // message can even precede the Data message, so don't handle it
                // russh::ChannelMsg::Eof => break,
                _ => {}
            }
        }

        // Drop sender to signal completion to receiver
        // This is critical: dropping the sender causes receiver.recv() to return None,
        // allowing the background task to finish collecting any remaining buffered data
        drop(sender);

        // If we received an exit code, report it back
        if let Some(result) = result {
            Ok(result)
        // Otherwise, report an error
        } else {
            Err(super::Error::CommandDidntExit)
        }
    }

    /// Execute a remote command with sudo password support.
    ///
    /// This method handles automatic sudo password injection when sudo prompts are detected
    /// in the command output. It monitors both stdout and stderr for sudo password prompts
    /// and automatically sends the password when detected.
    ///
    /// # Arguments
    /// * `command` - The command to execute (typically starts with `sudo`)
    /// * `sender` - Channel sender for streaming output
    /// * `sudo_password` - The sudo password to inject when prompted
    ///
    /// # Returns
    /// The exit status of the command
    ///
    /// # Security
    /// - Password is only sent when a sudo prompt is detected
    /// - Password is never logged or included in error messages
    /// - Detects sudo authentication failures and reports them appropriately
    pub async fn execute_with_sudo(
        &self,
        command: &str,
        sender: Sender<CommandOutput>,
        sudo_password: &SudoPassword,
    ) -> Result<u32, super::Error> {
        // Sanitize command to prevent injection attacks
        let sanitized_command = crate::utils::sanitize_command(command)
            .map_err(|e| super::Error::CommandValidationFailed(e.to_string()))?;

        // Request a PTY for sudo to properly interact with
        // Sudo requires a PTY to prompt for password
        let mut channel = self.connection_handle.channel_open_session().await?;

        // Request PTY with reasonable defaults for sudo
        channel
            .request_pty(
                true,    // want reply
                "xterm", // term type
                80,      // columns
                24,      // rows
                0,       // pixel width
                0,       // pixel height
                &[],     // terminal modes (empty for defaults)
            )
            .await?;

        channel.exec(true, sanitized_command.as_str()).await?;

        let mut result: Option<u32> = None;
        let mut password_send_count: u32 = 0;
        let mut sudo_auth_failed = false;
        let mut accumulated_output = String::new();

        // While the channel has messages...
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    // Check for sudo prompt before sending to output
                    let text = String::from_utf8_lossy(data);
                    accumulated_output.push_str(&text);

                    // Enforce buffer size limit to prevent unbounded memory growth
                    if accumulated_output.len() > MAX_SUDO_PROMPT_BUFFER_SIZE {
                        // Keep only the last MAX_SUDO_PROMPT_BUFFER_SIZE bytes
                        // This ensures we can still detect sudo prompts at the end
                        let truncate_at = accumulated_output.len() - MAX_SUDO_PROMPT_BUFFER_SIZE;
                        accumulated_output = accumulated_output[truncate_at..].to_string();
                        tracing::debug!(
                            "Sudo prompt buffer exceeded limit, truncated to {} bytes",
                            MAX_SUDO_PROMPT_BUFFER_SIZE
                        );
                    }

                    // Send output to streaming channel
                    match sender.try_send(CommandOutput::StdOut(data.clone())) {
                        Ok(_) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(output)) => {
                            tracing::trace!("Channel full, applying backpressure for stdout");
                            if sender.send(output).await.is_err() {
                                tracing::debug!("Receiver dropped, stopping stdout processing");
                                break;
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            tracing::debug!("Channel closed, stopping stdout processing");
                            break;
                        }
                    }

                    // Check if we need to send the password (supports multiple sudo prompts)
                    if !sudo_auth_failed
                        && password_send_count < MAX_SUDO_PASSWORD_SENDS
                        && contains_sudo_prompt(&accumulated_output)
                    {
                        password_send_count += 1;
                        tracing::debug!(
                            "Sudo prompt detected, sending password (attempt {}/{})",
                            password_send_count,
                            MAX_SUDO_PASSWORD_SENDS
                        );
                        // Send the password with newline
                        let password_data = sudo_password.with_newline();
                        if let Err(e) = channel.data(&password_data[..]).await {
                            tracing::error!("Failed to send sudo password: {}", e);
                            return Err(super::Error::SshError(e));
                        }
                        // Clear accumulated output after sending password to detect next prompt
                        accumulated_output.clear();
                    }

                    // Check for sudo failure after password was sent
                    if password_send_count > 0 && contains_sudo_failure(&accumulated_output) {
                        tracing::warn!(
                            "Sudo authentication failed after {} attempt(s)",
                            password_send_count
                        );
                        // Stop trying to send more passwords
                        sudo_auth_failed = true;
                    }
                }
                russh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        // Stderr - also check for sudo prompts
                        let text = String::from_utf8_lossy(data);
                        accumulated_output.push_str(&text);

                        // Enforce buffer size limit to prevent unbounded memory growth
                        if accumulated_output.len() > MAX_SUDO_PROMPT_BUFFER_SIZE {
                            // Keep only the last MAX_SUDO_PROMPT_BUFFER_SIZE bytes
                            let truncate_at =
                                accumulated_output.len() - MAX_SUDO_PROMPT_BUFFER_SIZE;
                            accumulated_output = accumulated_output[truncate_at..].to_string();
                            tracing::debug!(
                                "Sudo prompt buffer exceeded limit (stderr), truncated to {} bytes",
                                MAX_SUDO_PROMPT_BUFFER_SIZE
                            );
                        }

                        match sender.try_send(CommandOutput::StdErr(data.clone())) {
                            Ok(_) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(output)) => {
                                tracing::trace!("Channel full, applying backpressure for stderr");
                                if sender.send(output).await.is_err() {
                                    tracing::debug!("Receiver dropped, stopping stderr processing");
                                    break;
                                }
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                tracing::debug!("Channel closed, stopping stderr processing");
                                break;
                            }
                        }

                        // Check if we need to send the password (sudo can prompt on stderr)
                        if !sudo_auth_failed
                            && password_send_count < MAX_SUDO_PASSWORD_SENDS
                            && contains_sudo_prompt(&accumulated_output)
                        {
                            password_send_count += 1;
                            tracing::debug!(
                                "Sudo prompt detected on stderr, sending password (attempt {}/{})",
                                password_send_count,
                                MAX_SUDO_PASSWORD_SENDS
                            );
                            let password_data = sudo_password.with_newline();
                            if let Err(e) = channel.data(&password_data[..]).await {
                                tracing::error!("Failed to send sudo password: {}", e);
                                return Err(super::Error::SshError(e));
                            }
                            accumulated_output.clear();
                        }

                        // Check for sudo failure
                        if password_send_count > 0 && contains_sudo_failure(&accumulated_output) {
                            tracing::warn!(
                                "Sudo authentication failed on stderr after {} attempt(s)",
                                password_send_count
                            );
                            sudo_auth_failed = true;
                        }
                    }
                }
                russh::ChannelMsg::ExitStatus { exit_status } => result = Some(exit_status),
                _ => {}
            }
        }

        drop(sender);

        if let Some(result) = result {
            Ok(result)
        } else {
            Err(super::Error::CommandDidntExit)
        }
    }

    /// Execute a remote command via the ssh connection.
    ///
    /// Returns stdout, stderr and the exit code of the command,
    /// packaged in a [`CommandExecutedResult`] struct.
    /// If you need the stderr output interleaved within stdout, you should postfix the command with a redirection,
    /// e.g. `echo foo 2>&1`.
    /// If you dont want any output at all, use something like `echo foo >/dev/null 2>&1`.
    ///
    /// Make sure your commands don't read from stdin and exit after bounded time.
    ///
    /// Can be called multiple times, but every invocation is a new shell context.
    /// Thus `cd`, setting variables and alike have no effect on future invocations.
    pub async fn execute(&self, command: &str) -> Result<CommandExecutedResult, super::Error> {
        // Use streaming internally but collect all output
        let output_buffer = CommandOutputBuffer::new();
        let sender = output_buffer.sender.clone();

        // Execute with streaming
        let exit_status = self.execute_streaming(command, sender).await?;

        // CRITICAL: Drop the original sender to signal completion to the receiver task
        // execute_streaming() only drops the clone, but the receiver task waits for
        // ALL senders to be dropped before finishing. Without this, receiver.recv()
        // will hang forever waiting for more data.
        drop(output_buffer.sender);

        // Wait for all output to be collected
        // Handle both JoinError (task panic) and potential collection errors
        let (stdout_bytes, stderr_bytes) = output_buffer.receiver_task.await.map_err(|e| {
            // JoinError occurs if the task panicked or was cancelled
            // Convert to a more informative error
            super::Error::JoinError(e)
        })?;

        Ok(CommandExecutedResult {
            stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
            stderr: String::from_utf8_lossy(&stderr_bytes).to_string(),
            exit_status,
        })
    }

    /// Request an interactive shell channel.
    ///
    /// This method opens a new SSH channel suitable for interactive shell sessions.
    /// Note: This method no longer requests PTY directly. The PTY should be requested
    /// by the caller (e.g., PtySession) with appropriate terminal modes.
    ///
    /// # Arguments
    /// * `_term_type` - Terminal type (unused, kept for API compatibility)
    /// * `_width` - Terminal width (unused, kept for API compatibility)
    /// * `_height` - Terminal height (unused, kept for API compatibility)
    ///
    /// # Returns
    /// A `Channel` that can be used for bidirectional communication with the remote shell.
    ///
    /// # Note
    /// The caller is responsible for:
    /// 1. Requesting PTY with proper terminal modes via `channel.request_pty()`
    /// 2. Requesting shell via `channel.request_shell()`
    ///
    /// This change fixes issue #40: PTY should be requested once with proper terminal
    /// modes by PtySession::initialize() rather than twice with empty modes.
    pub async fn request_interactive_shell(
        &self,
        _term_type: &str,
        _width: u32,
        _height: u32,
    ) -> Result<Channel<Msg>, super::Error> {
        // Open a session channel - PTY and shell will be requested by the caller
        // (e.g., PtySession::initialize() with proper terminal modes)
        let channel = self.connection_handle.channel_open_session().await?;
        Ok(channel)
    }

    /// Request window size change for an existing PTY channel.
    ///
    /// This should be called when the local terminal is resized to update
    /// the remote PTY dimensions.
    pub async fn resize_pty(
        &self,
        channel: &mut Channel<Msg>,
        width: u32,
        height: u32,
    ) -> Result<(), super::Error> {
        channel
            .window_change(width, height, 0, 0)
            .await
            .map_err(super::Error::SshError)
    }
}

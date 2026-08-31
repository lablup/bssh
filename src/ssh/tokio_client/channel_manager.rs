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

use bytes::Bytes;
use russh::Channel;
use russh::client::Msg;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;

use super::ToSocketAddrsWithHostname;
use super::address_family::AddressFamily;
use super::connection::Client;
use crate::security::{SudoPassword, contains_sudo_failure, contains_sudo_prompt};

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

/// Forward one command event without making receiver lifetime part of the SSH result.
///
/// A pager or pipeline such as `head` may close its read end before the remote
/// command reports an exit status. Continue draining the SSH channel in that
/// case so a local consumer decision is not misreported as a command failure.
async fn forward_command_output(sender: &Sender<CommandOutput>, output: CommandOutput) -> bool {
    match sender.try_send(output) {
        Ok(()) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Full(output)) => {
            tracing::trace!("Output channel full, applying backpressure");
            if sender.send(output).await.is_ok() {
                true
            } else {
                tracing::debug!("Output receiver dropped; continuing to drain SSH channel");
                false
            }
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("Output receiver dropped; continuing to drain SSH channel");
            false
        }
    }
}

async fn handle_command_message(
    sender: &Sender<CommandOutput>,
    message: russh::ChannelMsg,
    output_receiver_open: &mut bool,
    result: &mut Option<u32>,
) {
    match message {
        russh::ChannelMsg::Data { data } if *output_receiver_open => {
            *output_receiver_open =
                forward_command_output(sender, CommandOutput::StdOut(data)).await;
        }
        russh::ChannelMsg::ExtendedData { data, ext: 1 } if *output_receiver_open => {
            *output_receiver_open =
                forward_command_output(sender, CommandOutput::StdErr(data)).await;
        }
        // An exit status does not imply that all channel data has arrived.
        russh::ChannelMsg::ExitStatus { exit_status } => *result = Some(exit_status),
        _ => {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectTcpipRequestTarget {
    host: String,
    port: u32,
}

/// Command output variants for streaming
#[derive(Debug, Clone)]
pub enum CommandOutput {
    /// Standard output data
    StdOut(Bytes),
    /// Standard error data
    StdErr(Bytes),
    /// Exit code (sent when command completes)
    ExitCode(u32),
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
                    CommandOutput::ExitCode(_) => {
                        // Exit code is handled by the stream manager, not collected here
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
    fn direct_tcpip_targets<T: ToSocketAddrsWithHostname>(
        target: &T,
        address_family: AddressFamily,
    ) -> Result<Vec<SocketAddr>, super::Error> {
        let resolved = target
            .to_socket_addrs()
            .map_err(|source| super::Error::DnsResolution {
                host: target.hostname(),
                source,
            })?;
        let targets = address_family.filter(resolved);

        if address_family.is_forced() && targets.is_empty() {
            return Err(super::Error::NoAddressForFamily {
                host: target.hostname(),
                family: address_family,
            });
        }

        Ok(targets)
    }

    fn direct_tcpip_request_targets<T: ToSocketAddrsWithHostname>(
        target: &T,
        address_family: AddressFamily,
    ) -> Result<Vec<DirectTcpipRequestTarget>, super::Error> {
        if !address_family.is_forced() {
            let (host, port) = target.host_port().map_err(super::Error::AddressInvalid)?;
            return Ok(vec![DirectTcpipRequestTarget {
                host,
                port: port.into(),
            }]);
        }

        Self::direct_tcpip_targets(target, address_family).map(|targets| {
            targets
                .into_iter()
                .map(|target| DirectTcpipRequestTarget {
                    host: target.ip().to_string(),
                    port: target.port().into(),
                })
                .collect()
        })
    }

    /// Get a new SSH channel for communication.
    pub async fn get_channel(&self) -> Result<Channel<Msg>, super::Error> {
        self.connection_handle
            .channel_open_session()
            .await
            .map_err(|source| self.session_error_or(super::Error::ChannelOpen { source }))
    }

    /// Open a TCP/IP forwarding channel.
    ///
    /// This opens a `direct-tcpip` channel to the given target, with no
    /// address family constraint. Use
    /// [`open_direct_tcpip_channel_with_family`](Self::open_direct_tcpip_channel_with_family)
    /// to honor `-4` / `-6`.
    pub async fn open_direct_tcpip_channel<
        T: ToSocketAddrsWithHostname,
        S: Into<Option<SocketAddr>>,
    >(
        &self,
        target: T,
        src: S,
    ) -> Result<Channel<Msg>, super::Error> {
        self.open_direct_tcpip_channel_with_family(target, src, AddressFamily::Any)
            .await
    }

    /// Open a `direct-tcpip` channel, optionally restricting the candidate
    /// target addresses to `address_family`.
    ///
    /// With [`AddressFamily::Any`] bssh sends the hostname exactly as supplied,
    /// and the remote sshd resolves and connects it. With a forced family
    /// (`-4`, `-6`, or ssh_config `AddressFamily inet|inet6`), bssh resolves
    /// locally, filters to the requested family, and sends the matching numeric
    /// address so the family request has a concrete effect on the server-side
    /// connection.
    pub async fn open_direct_tcpip_channel_with_family<
        T: ToSocketAddrsWithHostname,
        S: Into<Option<SocketAddr>>,
    >(
        &self,
        target: T,
        src: S,
        address_family: AddressFamily,
    ) -> Result<Channel<Msg>, super::Error> {
        let targets = Self::direct_tcpip_request_targets(&target, address_family)?;

        let src = src
            .into()
            .map(|src| (src.ip().to_string(), src.port().into()))
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 22));

        let mut connect_err = super::Error::AddressInvalid(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        ));
        for DirectTcpipRequestTarget { host, port } in targets {
            match self
                .connection_handle
                .channel_open_direct_tcpip(host, port, src.0.clone(), src.1)
                .await
            {
                Ok(channel) => return Ok(channel),
                Err(source) => {
                    connect_err = self.session_error_or(super::Error::ChannelOpen { source });
                }
            }
        }

        Err(connect_err)
    }

    /// Forward process stdin/stdout over a `direct-tcpip` channel.
    ///
    /// Local EOF half-closes only the sending side. The remote side is still
    /// drained to stdout until the SSH channel closes, which is required for
    /// protocols that send their final response after consuming request EOF.
    pub async fn forward_stdio(
        &self,
        target: (String, u16),
        address_family: AddressFamily,
    ) -> Result<(), super::Error> {
        self.forward_stdio_with_io(
            target,
            address_family,
            tokio::io::stdin(),
            tokio::io::stdout(),
        )
        .await
    }

    /// Forward arbitrary asynchronous input/output over a `direct-tcpip`
    /// channel. The two directions are pumped independently so SSH flow
    /// control in one direction cannot block progress in the other.
    pub async fn forward_stdio_with_io<R, W>(
        &self,
        target: (String, u16),
        address_family: AddressFamily,
        mut input: R,
        mut output: W,
    ) -> Result<(), super::Error>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let channel = self
            .open_direct_tcpip_channel_with_family(target, None, address_family)
            .await?;
        let (mut channel_read, channel_write) = channel.split();

        let upload = async {
            let mut writer = channel_write.make_writer();
            tokio::io::copy(&mut input, &mut writer)
                .await
                .map_err(super::Error::IoError)?;
            writer.flush().await.map_err(super::Error::IoError)?;
            drop(writer);
            channel_write.eof().await?;
            Ok::<(), super::Error>(())
        };
        let download = async {
            while let Some(message) = channel_read.wait().await {
                match message {
                    russh::ChannelMsg::Data { data } => {
                        output
                            .write_all(&data)
                            .await
                            .map_err(super::Error::IoError)?;
                        output.flush().await.map_err(super::Error::IoError)?;
                    }
                    // Remote EOF only half-closes remote-to-local traffic.
                    // Keep pumping stdin until local EOF or a full Close.
                    russh::ChannelMsg::Eof => {}
                    russh::ChannelMsg::Close => break,
                    // direct-tcpip is a single byte stream. Extended data is
                    // not part of that transport and must never contaminate
                    // stdout.
                    _ => {}
                }
            }
            output.flush().await.map_err(super::Error::IoError)
        };
        tokio::pin!(upload, download);
        tokio::select! {
            biased;
            result = &mut download => result,
            result = &mut upload => {
                result?;
                download.await
            }
        }
    }

    /// Execute a remote command via the ssh connection with streaming output.
    ///
    /// This method sends command output in real-time to the provided sender channel.
    /// Output is sent as `CommandOutput::StdOut` or `CommandOutput::StdErr` variants.
    ///
    /// Returns only the exit status of the command. Stdout and stderr are streamed
    /// through the sender channel.
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
        self.execute_streaming_with_input(command, sender, tokio::io::empty())
            .await
    }

    /// Execute a remote command while forwarding the process stdin with
    /// bounded reads and SSH channel backpressure.
    pub async fn execute_streaming_with_stdin(
        &self,
        command: &str,
        sender: Sender<CommandOutput>,
    ) -> Result<u32, super::Error> {
        self.execute_streaming_with_input(command, sender, tokio::io::stdin())
            .await
    }

    async fn execute_streaming_with_input<R>(
        &self,
        command: &str,
        sender: Sender<CommandOutput>,
        mut input: R,
    ) -> Result<u32, super::Error>
    where
        R: AsyncRead + Unpin,
    {
        let execution = async {
            // Sanitize command to prevent injection attacks
            let sanitized_command = crate::utils::sanitize_command(command)
                .map_err(|e| super::Error::CommandValidationFailed(e.to_string()))?;

            let mut channel = self
                .connection_handle
                .channel_open_session()
                .await
                .map_err(|source| self.session_error_or(super::Error::ChannelOpen { source }))?;
            channel
                .exec(true, sanitized_command.as_str())
                .await
                .map_err(|source| {
                    self.session_error_or(super::Error::CommandExecution {
                        action: "exec request",
                        source,
                    })
                })?;

            let mut result: Option<u32> = None;
            let mut output_receiver_open = true;
            let mut input_open = true;
            let mut input_buffer = [0_u8; 32 * 1024];

            loop {
                if input_open {
                    tokio::select! {
                        read = input.read(&mut input_buffer) => {
                            match read.map_err(super::Error::IoError)? {
                                0 => {
                                    channel.eof().await?;
                                    input_open = false;
                                }
                                count => channel.data(&input_buffer[..count]).await?,
                            }
                        }
                        message = channel.wait() => {
                            let Some(message) = message else {
                                break;
                            };
                            handle_command_message(
                                &sender,
                                message,
                                &mut output_receiver_open,
                                &mut result,
                            ).await;
                        }
                    }
                } else {
                    let Some(message) = channel.wait().await else {
                        break;
                    };
                    handle_command_message(
                        &sender,
                        message,
                        &mut output_receiver_open,
                        &mut result,
                    )
                    .await;
                }
            }

            // Dropping the sender signals the output collector after the SSH channel is drained.
            drop(sender);

            result.ok_or_else(|| self.session_error_or(super::Error::CommandDidntExit))
        }
        .await;
        self.flush_hostkey_updates().await;
        execution
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
        self.execute_with_sudo_policy(command, sender, sudo_password, None)
            .await
    }

    pub(crate) async fn execute_with_sudo_policy(
        &self,
        command: &str,
        sender: Sender<CommandOutput>,
        sudo_password: &SudoPassword,
        session_policy: Option<&crate::ssh::SessionPolicy>,
    ) -> Result<u32, super::Error> {
        let execution = async {
        // Sanitize command to prevent injection attacks
        let sanitized_command = crate::utils::sanitize_command(command)
            .map_err(|e| super::Error::CommandValidationFailed(e.to_string()))?;

        // Request a PTY for sudo to properly interact with
        // Sudo requires a PTY to prompt for password
        let mut channel = self
            .connection_handle
            .channel_open_session()
            .await
            .map_err(|source| self.session_error_or(super::Error::ChannelOpen { source }))?;

        // Preserve the legacy sudo PTY default unless a resolved session policy
        // carries explicit RequestTTY/CLI precedence.
        if session_policy.is_none_or(|policy| policy.request_pty) {
            channel
                .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .map_err(|source| {
                    self.session_error_or(super::Error::CommandExecution {
                        action: "PTY request",
                        source,
                    })
                })?;
        }
        if let Some(policy) = session_policy {
            for (name, value) in &policy.environment {
                channel
                    .set_env(false, name, value)
                    .await
                    .map_err(|source| {
                        self.session_error_or(super::Error::CommandExecution {
                            action: "environment request",
                            source,
                        })
                    })?;
            }
        }

        channel
            .exec(true, sanitized_command.as_str())
            .await
            .map_err(|source| {
                self.session_error_or(super::Error::CommandExecution {
                    action: "exec request",
                    source,
                })
            })?;

        let mut result: Option<u32> = None;
        let mut password_send_count: u32 = 0;
        let mut accumulated_output = String::new();
        let mut output_receiver_open = true;

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
                    if output_receiver_open {
                        output_receiver_open =
                            forward_command_output(&sender, CommandOutput::StdOut(data.clone()))
                                .await;
                    }

                    // Check if we need to send the password (supports multiple sudo prompts)
                    if password_send_count < MAX_SUDO_PASSWORD_SENDS
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
                            return Err(self.session_error_or(super::Error::CommandExecution {
                                action: "sudo password write",
                                source: e,
                            }));
                        }
                        // Clear accumulated output after sending password to detect next prompt
                        accumulated_output.clear();
                    }

                    // Check for sudo failure after password was sent
                    if password_send_count > 0 && contains_sudo_failure(&accumulated_output) {
                        tracing::debug!(
                            "Sudo authentication failed after {} attempt(s), closing channel",
                            password_send_count
                        );
                        // Send error message to stderr so user can see why it failed
                        let error_msg = format!(
                            "\n[bssh] Sudo authentication failed after {} attempt(s). \
                             Please verify your sudo password is correct.\n",
                            password_send_count
                        );
                        let _ = sender
                            .send(CommandOutput::StdErr(Bytes::from(error_msg.into_bytes())))
                            .await;
                        // Send exit code 1 to indicate failure to the stream
                        let _ = sender.send(CommandOutput::ExitCode(1)).await;
                        // Close the channel and return failure exit code
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                        drop(sender);
                        // Return exit code 1 to indicate sudo authentication failure
                        return Ok(1);
                    }
                }
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    // Stderr - also check for sudo prompts
                    let text = String::from_utf8_lossy(data);
                    accumulated_output.push_str(&text);

                    // Enforce buffer size limit to prevent unbounded memory growth
                    if accumulated_output.len() > MAX_SUDO_PROMPT_BUFFER_SIZE {
                        // Keep only the last MAX_SUDO_PROMPT_BUFFER_SIZE bytes
                        let truncate_at = accumulated_output.len() - MAX_SUDO_PROMPT_BUFFER_SIZE;
                        accumulated_output = accumulated_output[truncate_at..].to_string();
                        tracing::debug!(
                            "Sudo prompt buffer exceeded limit (stderr), truncated to {} bytes",
                            MAX_SUDO_PROMPT_BUFFER_SIZE
                        );
                    }

                    if output_receiver_open {
                        output_receiver_open =
                            forward_command_output(&sender, CommandOutput::StdErr(data.clone()))
                                .await;
                    }

                    // Check if we need to send the password (sudo can prompt on stderr)
                    if password_send_count < MAX_SUDO_PASSWORD_SENDS
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
                            return Err(self.session_error_or(super::Error::CommandExecution {
                                action: "sudo password write",
                                source: e,
                            }));
                        }
                        accumulated_output.clear();
                    }

                    // Check for sudo failure
                    if password_send_count > 0 && contains_sudo_failure(&accumulated_output) {
                        tracing::debug!(
                            "Sudo authentication failed on stderr after {} attempt(s), closing channel",
                            password_send_count
                        );
                        // Send error message to stderr so user can see why it failed
                        let error_msg = format!(
                            "\n[bssh] Sudo authentication failed after {} attempt(s). \
                                 Please verify your sudo password is correct.\n",
                            password_send_count
                        );
                        let _ = sender
                            .send(CommandOutput::StdErr(Bytes::from(error_msg.into_bytes())))
                            .await;
                        // Send exit code 1 to indicate failure to the stream
                        let _ = sender.send(CommandOutput::ExitCode(1)).await;
                        // Close the channel and return failure exit code
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                        drop(sender);
                        return Ok(1);
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
            Err(self.session_error_or(super::Error::CommandDidntExit))
        }
        }
        .await;
        self.flush_hostkey_updates().await;
        execution
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
        let channel = self
            .connection_handle
            .channel_open_session()
            .await
            .map_err(|source| self.session_error_or(super::Error::ChannelOpen { source }))?;
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
            .map_err(|source| {
                self.session_error_or(super::Error::CommandExecution {
                    action: "window-change request",
                    source,
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_output_receiver_is_not_a_command_error() {
        let (sender, receiver) = channel(1);
        drop(receiver);

        let receiver_open = forward_command_output(
            &sender,
            CommandOutput::StdOut(Bytes::from_static(b"ignored")),
        )
        .await;

        assert!(!receiver_open);
    }

    fn v4(s: &str) -> SocketAddr {
        s.parse().expect("valid IPv4 socket address")
    }

    fn v6(s: &str) -> SocketAddr {
        s.parse().expect("valid IPv6 socket address")
    }

    fn multi_hop_candidates() -> Vec<SocketAddr> {
        vec![
            v6("[2001:db8::10]:22"),
            v4("192.0.2.10:22"),
            v6("[2001:db8::11]:22"),
            v4("192.0.2.11:22"),
        ]
    }

    #[test]
    fn direct_tcpip_targets_preserve_any_family_candidates_for_tunneled_hops() {
        let candidates = multi_hop_candidates();
        let targets = Client::direct_tcpip_targets(&candidates.as_slice(), AddressFamily::Any)
            .expect("unconstrained direct-tcpip target selection must succeed");

        assert_eq!(targets, candidates);
    }

    #[test]
    fn direct_tcpip_targets_filter_ipv4_candidates_for_tunneled_hops() {
        let candidates = multi_hop_candidates();
        let targets = Client::direct_tcpip_targets(&candidates.as_slice(), AddressFamily::V4)
            .expect("IPv4 direct-tcpip target selection must succeed");

        assert_eq!(targets, vec![v4("192.0.2.10:22"), v4("192.0.2.11:22")]);
    }

    #[test]
    fn direct_tcpip_targets_filter_ipv6_candidates_for_tunneled_hops() {
        let candidates = multi_hop_candidates();
        let targets = Client::direct_tcpip_targets(&candidates.as_slice(), AddressFamily::V6)
            .expect("IPv6 direct-tcpip target selection must succeed");

        assert_eq!(
            targets,
            vec![v6("[2001:db8::10]:22"), v6("[2001:db8::11]:22")]
        );
    }

    #[test]
    fn direct_tcpip_request_targets_send_unforced_hostname_without_resolution() {
        let targets =
            Client::direct_tcpip_request_targets(&"server-only.internal:5432", AddressFamily::Any)
                .expect("unforced direct-tcpip targets must not require local DNS");

        assert_eq!(
            targets,
            vec![DirectTcpipRequestTarget {
                host: "server-only.internal".to_string(),
                port: 5432,
            }]
        );
    }

    #[test]
    fn direct_tcpip_request_targets_send_unforced_tuple_hostname_for_jump_hops() {
        let targets = Client::direct_tcpip_request_targets(
            &("jump-private.internal", 2222),
            AddressFamily::Any,
        )
        .expect("unforced jump-hop targets must not require local DNS");

        assert_eq!(
            targets,
            vec![DirectTcpipRequestTarget {
                host: "jump-private.internal".to_string(),
                port: 2222,
            }]
        );
    }

    #[test]
    fn direct_tcpip_request_targets_send_forced_ipv4_address() {
        let candidates = multi_hop_candidates();
        let targets =
            Client::direct_tcpip_request_targets(&candidates.as_slice(), AddressFamily::V4)
                .expect("forced IPv4 direct-tcpip targets must resolve to numeric addresses");

        assert_eq!(
            targets,
            vec![
                DirectTcpipRequestTarget {
                    host: "192.0.2.10".to_string(),
                    port: 22,
                },
                DirectTcpipRequestTarget {
                    host: "192.0.2.11".to_string(),
                    port: 22,
                },
            ]
        );
    }

    #[test]
    fn direct_tcpip_request_targets_send_forced_ipv6_address() {
        let candidates = multi_hop_candidates();
        let targets =
            Client::direct_tcpip_request_targets(&candidates.as_slice(), AddressFamily::V6)
                .expect("forced IPv6 direct-tcpip targets must resolve to numeric addresses");

        assert_eq!(
            targets,
            vec![
                DirectTcpipRequestTarget {
                    host: "2001:db8::10".to_string(),
                    port: 22,
                },
                DirectTcpipRequestTarget {
                    host: "2001:db8::11".to_string(),
                    port: 22,
                },
            ]
        );
    }
}

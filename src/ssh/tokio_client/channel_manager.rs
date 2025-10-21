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
use std::io;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;

use super::connection::Client;
use super::ToSocketAddrsWithHostname;

// Buffer size constants for SSH operations
/// SSH I/O buffer size constants - optimized for different operation types
///
/// Buffer sizing rationale:
/// - Sizes chosen based on SSH protocol characteristics and network efficiency
/// - Balance between memory usage and I/O performance
/// - Aligned with common SSH implementation patterns
///
/// Buffer size for SSH command I/O operations
/// - 8KB (8192 bytes) optimal for most SSH command operations
/// - Matches typical SSH channel window sizes
/// - Reduces syscall overhead while keeping memory usage reasonable
/// - Handles multi-line command output efficiently
const SSH_CMD_BUFFER_SIZE: usize = 8192;

/// Small buffer size for SSH response parsing
/// - 1KB (1024 bytes) for typical command responses and headers
/// - Optimal for status messages and short responses
/// - Minimizes memory allocation for frequent small reads
/// - Matches typical terminal line lengths
const SSH_RESPONSE_BUFFER_SIZE: usize = 1024;

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
        // Sanitize command to prevent injection attacks
        let sanitized_command = crate::utils::sanitize_command(command)
            .map_err(|e| super::Error::CommandValidationFailed(e.to_string()))?;

        // Pre-allocate buffers with capacity to avoid frequent reallocations
        let mut stdout_buffer = Vec::with_capacity(SSH_CMD_BUFFER_SIZE);
        let mut stderr_buffer = Vec::with_capacity(SSH_RESPONSE_BUFFER_SIZE);
        let mut channel = self.connection_handle.channel_open_session().await?;
        channel.exec(true, sanitized_command.as_str()).await?;

        let mut result: Option<u32> = None;

        // While the channel has messages...
        while let Some(msg) = channel.wait().await {
            //dbg!(&msg);
            match msg {
                // If we get data, add it to the buffer
                russh::ChannelMsg::Data { ref data } => {
                    stdout_buffer.write_all(data).await.unwrap()
                }
                russh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr_buffer.write_all(data).await.unwrap()
                    }
                }

                // If we get an exit code report, store it, but crucially don't
                // assume this message means end of communications. The data might
                // not be finished yet!
                russh::ChannelMsg::ExitStatus { exit_status } => result = Some(exit_status),

                // We SHOULD get this EOF messagge, but 4254 sec 5.3 also permits
                // the channel to close without it being sent. And sometimes this
                // message can even precede the Data message, so don't handle it
                // russh::ChannelMsg::Eof => break,
                _ => {}
            }
        }

        // If we received an exit code, report it back
        if let Some(result) = result {
            Ok(CommandExecutedResult {
                stdout: String::from_utf8_lossy(&stdout_buffer).to_string(),
                stderr: String::from_utf8_lossy(&stderr_buffer).to_string(),
                exit_status: result,
            })

        // Otherwise, report an error
        } else {
            Err(super::Error::CommandDidntExit)
        }
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

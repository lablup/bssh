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

use async_trait::async_trait;
use russh::client::{Handler, Msg};
use russh::{Channel, ChannelId, Disconnect};
use russh_keys::key::PublicKey;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::error::{SftpError, SftpResult};
use super::host_verification::HostKeyVerification;

/// SSH client session handler for bssh
#[derive(Clone)]
pub struct BsshClientHandler {
    host_key_verification: HostKeyVerification,
    host: String,
    port: u16,
}

impl BsshClientHandler {
    pub fn new(
        host: String,
        port: u16,
        host_key_verification: HostKeyVerification,
    ) -> Self {
        Self {
            host_key_verification,
            host,
            port,
        }
    }
}

#[async_trait]
impl Handler for BsshClientHandler {
    type Error = SftpError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        self.host_key_verification
            .verify_host_key(&self.host, self.port, server_public_key)
            .await
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        Err(SftpError::channel("Forwarded TCP/IP not supported"))
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        Err(SftpError::channel("X11 forwarding not supported"))
    }

    async fn server_channel_handle_unknown(
        &mut self,
        _channel: Channel<Msg>,
        _channel_type: &str,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        Err(SftpError::channel("Unknown channel type not supported"))
    }
}

/// Manages SSH connection and SFTP session
#[derive(Debug)]
pub struct SshSession {
    handle: russh::client::Handle<BsshClientHandler>,
    sftp_channel: Option<russh_sftp::client::SftpSession>,
    host: String,
    port: u16,
    username: String,
}

impl SshSession {
    /// Create a new SSH session
    pub async fn new(
        host: String,
        port: u16,
        username: String,
        host_key_verification: HostKeyVerification,
    ) -> SftpResult<Self> {
        let config = russh::client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(300)),
            ..Default::default()
        };

        let handler = BsshClientHandler::new(host.clone(), port, host_key_verification);

        tracing::debug!("Connecting to {}:{}", host, port);

        let mut handle = russh::client::connect(Arc::new(config), (host.as_str(), port), handler)
            .await
            .map_err(|e| {
                SftpError::Connection(e).into()
            })?;

        Ok(Self {
            handle,
            sftp_channel: None,
            host,
            port,
            username,
        })
    }

    /// Get mutable reference to the session handle for authentication
    pub fn handle_mut(&mut self) -> &mut russh::client::Handle<BsshClientHandler> {
        &mut self.handle
    }

    /// Initialize SFTP channel after authentication
    pub async fn init_sftp(&mut self) -> SftpResult<()> {
        if self.sftp_channel.is_some() {
            return Ok(()); // Already initialized
        }

        tracing::debug!("Initializing SFTP channel");

        let channel = self.handle
            .channel_open_session()
            .await
            .map_err(|e| SftpError::channel(format!("Failed to open SSH channel: {}", e)))?;

        let sftp = channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| SftpError::channel(format!("Failed to request SFTP subsystem: {}", e)))?;

        let sftp_session = russh_sftp::client::SftpSession::new(sftp.into_stream())
            .await
            .map_err(|e| SftpError::Sftp(e))?;

        self.sftp_channel = Some(sftp_session);
        tracing::debug!("SFTP channel initialized successfully");

        Ok(())
    }

    /// Get reference to the SFTP session
    pub fn sftp(&mut self) -> SftpResult<&mut russh_sftp::client::SftpSession> {
        self.sftp_channel
            .as_mut()
            .ok_or_else(|| SftpError::generic("SFTP channel not initialized. Call init_sftp() first."))
    }

    /// Execute a command via SSH
    pub async fn execute(&mut self, command: &str) -> SftpResult<super::client::CommandResult> {
        tracing::debug!("Executing command: {}", command);

        let channel = self.handle
            .channel_open_session()
            .await
            .map_err(|e| SftpError::channel(format!("Failed to open SSH channel: {}", e)))?;

        let mut channel = channel
            .exec(true, command)
            .await
            .map_err(|e| SftpError::channel(format!("Failed to execute command: {}", e)))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = 0u32;

        // Read output
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    stdout.extend_from_slice(data);
                }
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    stderr.extend_from_slice(data);
                }
                russh::ChannelMsg::ExitStatus { exit_status: status } => {
                    exit_status = status;
                }
                russh::ChannelMsg::Eof => {
                    break;
                }
                _ => {}
            }
        }

        tracing::debug!(
            "Command execution completed with status: {}",
            exit_status
        );

        Ok(super::client::CommandResult {
            host: self.host.clone(),
            output: stdout,
            stderr,
            exit_status,
        })
    }

    /// Get connection info
    pub fn connection_info(&self) -> (&str, u16, &str) {
        (&self.host, self.port, &self.username)
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        // The session will be automatically closed when the handle is dropped
        tracing::debug!("SSH session to {}:{} being dropped", self.host, self.port);
    }
}
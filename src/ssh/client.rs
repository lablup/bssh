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

use super::tokio_client::{AuthMethod, Client};
use crate::jump::{parse_jump_hosts, JumpHostChain};
use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

/// Configuration for SSH connection and command execution
#[derive(Clone)]
pub struct ConnectionConfig<'a> {
    pub key_path: Option<&'a Path>,
    pub strict_mode: Option<StrictHostKeyChecking>,
    pub use_agent: bool,
    pub use_password: bool,
    pub timeout_seconds: Option<u64>,
    pub jump_hosts_spec: Option<&'a str>,
}

use super::known_hosts::StrictHostKeyChecking;

pub struct SshClient {
    host: String,
    port: u16,
    username: String,
}

impl SshClient {
    pub fn new(host: String, port: u16, username: String) -> Self {
        Self {
            host,
            port,
            username,
        }
    }

    pub async fn connect_and_execute(
        &mut self,
        command: &str,
        key_path: Option<&Path>,
        use_agent: bool,
    ) -> Result<CommandResult> {
        self.connect_and_execute_with_host_check(command, key_path, None, use_agent, false, None)
            .await
    }

    pub async fn connect_and_execute_with_host_check(
        &mut self,
        command: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        timeout_seconds: Option<u64>,
    ) -> Result<CommandResult> {
        let config = ConnectionConfig {
            key_path,
            strict_mode,
            use_agent,
            use_password,
            timeout_seconds,
            jump_hosts_spec: None, // No jump hosts
        };

        self.connect_and_execute_with_jump_hosts(command, &config)
            .await
    }

    pub async fn connect_and_execute_with_jump_hosts(
        &mut self,
        command: &str,
        config: &ConnectionConfig<'_>,
    ) -> Result<CommandResult> {
        tracing::debug!("Connecting to {}:{}", self.host, self.port);

        // Determine authentication method based on parameters
        let auth_method =
            self.determine_auth_method(config.key_path, config.use_agent, config.use_password)?;

        let strict_mode = config
            .strict_mode
            .unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts
        let client = if let Some(jump_spec) = config.jump_hosts_spec {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection");
                self.connect_direct(&auth_method, strict_mode).await?
            } else {
                tracing::info!(
                    "Connecting to {}:{} via {} jump host(s): {}",
                    self.host,
                    self.port,
                    jump_hosts.len(),
                    jump_hosts
                        .iter()
                        .map(|j| j.to_string())
                        .collect::<Vec<_>>()
                        .join(" -> ")
                );

                self.connect_via_jump_hosts(
                    &jump_hosts,
                    &auth_method,
                    strict_mode,
                    config.key_path,
                    config.use_agent,
                    config.use_password,
                )
                .await?
            }
        } else {
            // Direct connection
            tracing::debug!("Using direct connection (no jump hosts)");
            self.connect_direct(&auth_method, strict_mode).await?
        };

        tracing::debug!("Connected and authenticated successfully");
        tracing::debug!("Executing command: {}", command);

        // Execute command with timeout
        let result = if let Some(timeout_secs) = config.timeout_seconds {
            if timeout_secs == 0 {
                // No timeout (unlimited)
                tracing::debug!("Executing command with no timeout (unlimited)");
                client.execute(command)
                    .await
                    .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))?
            } else {
                // With timeout
                let command_timeout = Duration::from_secs(timeout_secs);
                tracing::debug!("Executing command with timeout of {} seconds", timeout_secs);
                tokio::time::timeout(
                    command_timeout,
                    client.execute(command)
                )
                .await
                .with_context(|| format!("Command execution timeout: The command '{}' did not complete within {} seconds on {}:{}", command, timeout_secs, self.host, self.port))?
                .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))?
            }
        } else {
            // Default timeout if not specified
            // SSH command execution timeout design:
            // - 5 minutes (300s) handles long-running commands
            // - Prevents indefinite hang on unresponsive commands
            // - Long enough for system updates, compilations, etc.
            // - Short enough to detect truly hung processes
            const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 300;
            let command_timeout = Duration::from_secs(DEFAULT_COMMAND_TIMEOUT_SECS);
            tracing::debug!("Executing command with default timeout of 300 seconds");
            tokio::time::timeout(
                command_timeout,
                client.execute(command)
            )
            .await
            .with_context(|| format!("Command execution timeout: The command '{}' did not complete within 5 minutes on {}:{}", command, self.host, self.port))?
            .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))?
        };

        tracing::debug!(
            "Command execution completed with status: {}",
            result.exit_status
        );

        // Convert result to our format
        Ok(CommandResult {
            host: self.host.clone(),
            output: result.stdout.into_bytes(),
            stderr: result.stderr.into_bytes(),
            exit_status: result.exit_status,
        })
    }

    /// Create a direct SSH connection (no jump hosts)
    async fn connect_direct(
        &self,
        auth_method: &AuthMethod,
        strict_mode: StrictHostKeyChecking,
    ) -> Result<Client> {
        let addr = (self.host.as_str(), self.port);
        let check_method = super::known_hosts::get_check_method(strict_mode);

        // SSH connection timeout design:
        // - 30 seconds accommodates slow networks and SSH negotiation
        // - Industry standard for SSH client connections
        // - Balances user patience with reliability on poor networks
        const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;
        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);

        match tokio::time::timeout(
            connect_timeout,
            Client::connect(addr, &self.username, auth_method.clone(), check_method),
        )
        .await
        {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(e)) => {
                // Specific error from the SSH connection attempt
                let error_msg = match &e {
                    super::tokio_client::Error::KeyAuthFailed => {
                        "Authentication failed. The private key was rejected by the server.".to_string()
                    }
                    super::tokio_client::Error::PasswordWrong => {
                        "Password authentication failed.".to_string()
                    }
                    super::tokio_client::Error::ServerCheckFailed => {
                        "Host key verification failed. The server's host key was not recognized or has changed.".to_string()
                    }
                    super::tokio_client::Error::KeyInvalid(key_err) => {
                        format!("Failed to load SSH key: {}. Please check the key file format and passphrase.", key_err)
                    }
                    super::tokio_client::Error::AgentConnectionFailed => {
                        "Failed to connect to SSH agent. Please ensure SSH_AUTH_SOCK is set and the agent is running.".to_string()
                    }
                    super::tokio_client::Error::AgentNoIdentities => {
                        "SSH agent has no identities. Please add your key to the agent using 'ssh-add'.".to_string()
                    }
                    super::tokio_client::Error::AgentAuthenticationFailed => {
                        "SSH agent authentication failed.".to_string()
                    }
                    super::tokio_client::Error::SshError(ssh_err) => {
                        format!("SSH connection error: {}", ssh_err)
                    }
                    _ => {
                        format!("Failed to connect: {}", e)
                    }
                };
                Err(anyhow::anyhow!(error_msg).context(e))
            }
            Err(_) => Err(anyhow::anyhow!(
                "Connection timeout after {} seconds. \
                     Please check if the host is reachable and SSH service is running.",
                SSH_CONNECT_TIMEOUT_SECS
            )),
        }
    }

    /// Create an SSH connection through jump hosts
    async fn connect_via_jump_hosts(
        &self,
        jump_hosts: &[crate::jump::parser::JumpHost],
        auth_method: &AuthMethod,
        strict_mode: StrictHostKeyChecking,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<Client> {
        // Create jump host chain
        let chain = JumpHostChain::new(jump_hosts.to_vec())
            .with_connect_timeout(Duration::from_secs(30))
            .with_command_timeout(Duration::from_secs(300));

        // Connect through the chain
        let connection = chain
            .connect(
                &self.host,
                self.port,
                &self.username,
                auth_method.clone(),
                key_path,
                Some(strict_mode),
                use_agent,
                use_password,
            )
            .await
            .with_context(|| {
                format!(
                    "Failed to establish jump host connection to {}:{}",
                    self.host, self.port
                )
            })?;

        tracing::info!(
            "Jump host connection established: {}",
            connection.jump_info.path_description()
        );

        Ok(connection.client)
    }

    pub async fn upload_file(
        &mut self,
        local_path: &Path,
        remote_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<()> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!("Connecting to {}:{} for file copy", self.host, self.port);

        // Determine authentication method based on parameters
        let auth_method = self.determine_auth_method(key_path, use_agent, use_password)?;

        // Set up host key checking
        let check_method = if let Some(mode) = strict_mode {
            super::known_hosts::get_check_method(mode)
        } else {
            super::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew)
        };

        // Connect and authenticate with timeout
        // SSH connection timeout design:
        // - 30 seconds accommodates slow networks and SSH negotiation
        // - Industry standard for SSH client connections
        // - Balances user patience with reliability on poor networks
        const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;
        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);
        let client = match tokio::time::timeout(
            connect_timeout,
            Client::connect(addr, &self.username, auth_method, check_method),
        )
        .await
        {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                let context = format!("SSH connection to {}:{}", self.host, self.port);
                let detailed = match &e {
                    super::tokio_client::Error::KeyAuthFailed => {
                        format!(
                            "{} failed: Authentication rejected with provided SSH key",
                            context
                        )
                    }
                    super::tokio_client::Error::KeyInvalid(err) => {
                        format!("{} failed: Invalid SSH key - {}", context, err)
                    }
                    super::tokio_client::Error::ServerCheckFailed => {
                        format!("{} failed: Host key verification failed. The server's host key is not trusted.", context)
                    }
                    super::tokio_client::Error::PasswordWrong => {
                        format!("{} failed: Password authentication rejected", context)
                    }
                    super::tokio_client::Error::AgentConnectionFailed => {
                        format!(
                            "{} failed: Cannot connect to SSH agent. Ensure SSH_AUTH_SOCK is set.",
                            context
                        )
                    }
                    super::tokio_client::Error::AgentNoIdentities => {
                        format!(
                            "{} failed: SSH agent has no keys. Use 'ssh-add' to add your key.",
                            context
                        )
                    }
                    super::tokio_client::Error::AgentAuthenticationFailed => {
                        format!("{} failed: SSH agent authentication rejected", context)
                    }
                    _ => format!("{} failed: {}", context, e),
                };
                return Err(anyhow::anyhow!(detailed).context(e));
            }
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Connection timeout after {} seconds. Host may be unreachable or SSH service not running.",
                    SSH_CONNECT_TIMEOUT_SECS
                ));
            }
        };

        tracing::debug!("Connected and authenticated successfully");

        // Check if local file exists
        if !local_path.exists() {
            anyhow::bail!("Local file does not exist: {:?}", local_path);
        }

        let metadata = std::fs::metadata(local_path)
            .with_context(|| format!("Failed to get metadata for {local_path:?}"))?;

        let file_size = metadata.len();

        tracing::debug!(
            "Uploading file {:?} ({} bytes) to {}:{} using SFTP",
            local_path,
            file_size,
            self.host,
            remote_path
        );

        // Use the built-in upload_file method with timeout (SFTP-based)
        // File upload timeout design:
        // - 5 minutes handles typical file sizes over slow networks
        // - Sufficient for multi-MB files on broadband connections
        // - Prevents hang on network failures or very large files
        const FILE_UPLOAD_TIMEOUT_SECS: u64 = 300;
        let upload_timeout = Duration::from_secs(FILE_UPLOAD_TIMEOUT_SECS);
        tokio::time::timeout(
            upload_timeout,
            client.upload_file(local_path, remote_path.to_string()),
        )
        .await
        .with_context(|| {
            format!(
                "File upload timeout: Transfer of {:?} to {}:{} did not complete within 5 minutes",
                local_path, self.host, remote_path
            )
        })?
        .with_context(|| {
            format!(
                "Failed to upload file {:?} to {}:{}",
                local_path, self.host, remote_path
            )
        })?;

        tracing::debug!("File upload completed successfully");

        Ok(())
    }

    pub async fn download_file(
        &mut self,
        remote_path: &str,
        local_path: &Path,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<()> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!(
            "Connecting to {}:{} for file download",
            self.host,
            self.port
        );

        // Determine authentication method based on parameters
        let auth_method = self.determine_auth_method(key_path, use_agent, use_password)?;

        // Set up host key checking
        let check_method = if let Some(mode) = strict_mode {
            super::known_hosts::get_check_method(mode)
        } else {
            super::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew)
        };

        // Connect and authenticate with timeout
        // SSH connection timeout design:
        // - 30 seconds accommodates slow networks and SSH negotiation
        // - Industry standard for SSH client connections
        // - Balances user patience with reliability on poor networks
        const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;
        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);
        let client = match tokio::time::timeout(
            connect_timeout,
            Client::connect(addr, &self.username, auth_method, check_method),
        )
        .await
        {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                let context = format!("SSH connection to {}:{}", self.host, self.port);
                let detailed = match &e {
                    super::tokio_client::Error::KeyAuthFailed => {
                        format!(
                            "{} failed: Authentication rejected with provided SSH key",
                            context
                        )
                    }
                    super::tokio_client::Error::KeyInvalid(err) => {
                        format!("{} failed: Invalid SSH key - {}", context, err)
                    }
                    super::tokio_client::Error::ServerCheckFailed => {
                        format!("{} failed: Host key verification failed. The server's host key is not trusted.", context)
                    }
                    super::tokio_client::Error::PasswordWrong => {
                        format!("{} failed: Password authentication rejected", context)
                    }
                    super::tokio_client::Error::AgentConnectionFailed => {
                        format!(
                            "{} failed: Cannot connect to SSH agent. Ensure SSH_AUTH_SOCK is set.",
                            context
                        )
                    }
                    super::tokio_client::Error::AgentNoIdentities => {
                        format!(
                            "{} failed: SSH agent has no keys. Use 'ssh-add' to add your key.",
                            context
                        )
                    }
                    super::tokio_client::Error::AgentAuthenticationFailed => {
                        format!("{} failed: SSH agent authentication rejected", context)
                    }
                    _ => format!("{} failed: {}", context, e),
                };
                return Err(anyhow::anyhow!(detailed).context(e));
            }
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Connection timeout after {} seconds. Host may be unreachable or SSH service not running.",
                    SSH_CONNECT_TIMEOUT_SECS
                ));
            }
        };

        tracing::debug!("Connected and authenticated successfully");

        // Create parent directory if it doesn't exist
        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create parent directory for {local_path:?}"))?;
        }

        tracing::debug!(
            "Downloading file from {}:{} to {:?} using SFTP",
            self.host,
            remote_path,
            local_path
        );

        // Use the built-in download_file method with timeout (SFTP-based)
        // File download timeout design:
        // - 5 minutes handles typical file sizes over slow networks
        // - Sufficient for multi-MB files on broadband connections
        // - Prevents hang on network failures or very large files
        const FILE_DOWNLOAD_TIMEOUT_SECS: u64 = 300;
        let download_timeout = Duration::from_secs(FILE_DOWNLOAD_TIMEOUT_SECS);
        tokio::time::timeout(
            download_timeout,
            client.download_file(remote_path.to_string(), local_path),
        )
        .await
        .with_context(|| {
            format!(
                "File download timeout: Transfer from {}:{} to {:?} did not complete within 5 minutes",
                self.host, remote_path, local_path
            )
        })?
        .with_context(|| {
            format!(
                "Failed to download file from {}:{} to {:?}",
                self.host, remote_path, local_path
            )
        })?;

        tracing::debug!("File download completed successfully");

        Ok(())
    }

    pub async fn upload_dir(
        &mut self,
        local_dir_path: &Path,
        remote_dir_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<()> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!(
            "Connecting to {}:{} for directory upload",
            self.host,
            self.port
        );

        // Determine authentication method based on parameters
        let auth_method = self.determine_auth_method(key_path, use_agent, use_password)?;

        // Set up host key checking
        let check_method = if let Some(mode) = strict_mode {
            super::known_hosts::get_check_method(mode)
        } else {
            super::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew)
        };

        // Connect and authenticate with timeout
        // SSH connection timeout design:
        // - 30 seconds accommodates slow networks and SSH negotiation
        // - Industry standard for SSH client connections
        // - Balances user patience with reliability on poor networks
        const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;
        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);
        let client = match tokio::time::timeout(
            connect_timeout,
            Client::connect(addr, &self.username, auth_method, check_method),
        )
        .await
        {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                let context = format!("SSH connection to {}:{}", self.host, self.port);
                let detailed = match &e {
                    super::tokio_client::Error::KeyAuthFailed => {
                        format!(
                            "{} failed: Authentication rejected with provided SSH key",
                            context
                        )
                    }
                    super::tokio_client::Error::KeyInvalid(err) => {
                        format!("{} failed: Invalid SSH key - {}", context, err)
                    }
                    super::tokio_client::Error::ServerCheckFailed => {
                        format!("{} failed: Host key verification failed. The server's host key is not trusted.", context)
                    }
                    super::tokio_client::Error::PasswordWrong => {
                        format!("{} failed: Password authentication rejected", context)
                    }
                    _ => format!("{} failed: {}", context, e),
                };
                return Err(anyhow::anyhow!(detailed).context(e));
            }
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Connection timeout after {} seconds. Host may be unreachable or SSH service not running.",
                    SSH_CONNECT_TIMEOUT_SECS
                ));
            }
        };

        tracing::debug!("Connected and authenticated successfully");

        // Check if local directory exists
        if !local_dir_path.exists() {
            anyhow::bail!("Local directory does not exist: {:?}", local_dir_path);
        }

        if !local_dir_path.is_dir() {
            anyhow::bail!("Local path is not a directory: {:?}", local_dir_path);
        }

        tracing::debug!(
            "Uploading directory {:?} to {}:{} using SFTP",
            local_dir_path,
            self.host,
            remote_dir_path
        );

        // Use the built-in upload_dir method with timeout
        // Directory upload timeout design:
        // - 10 minutes handles directories with many files
        // - Accounts for SFTP overhead per file (connection setup, etc.)
        // - Longer than single file to accommodate batch operations
        // - Prevents indefinite hang on large directory trees
        const DIR_UPLOAD_TIMEOUT_SECS: u64 = 600;
        let upload_timeout = Duration::from_secs(DIR_UPLOAD_TIMEOUT_SECS);
        tokio::time::timeout(
            upload_timeout,
            client.upload_dir(local_dir_path, remote_dir_path.to_string()),
        )
        .await
        .with_context(|| {
            format!(
                "Directory upload timeout: Transfer of {:?} to {}:{} did not complete within 10 minutes",
                local_dir_path, self.host, remote_dir_path
            )
        })?
        .with_context(|| {
            format!(
                "Failed to upload directory {:?} to {}:{}",
                local_dir_path, self.host, remote_dir_path
            )
        })?;

        tracing::debug!("Directory upload completed successfully");

        Ok(())
    }

    pub async fn download_dir(
        &mut self,
        remote_dir_path: &str,
        local_dir_path: &Path,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<()> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!(
            "Connecting to {}:{} for directory download",
            self.host,
            self.port
        );

        // Determine authentication method based on parameters
        let auth_method = self.determine_auth_method(key_path, use_agent, use_password)?;

        // Set up host key checking
        let check_method = if let Some(mode) = strict_mode {
            super::known_hosts::get_check_method(mode)
        } else {
            super::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew)
        };

        // Connect and authenticate with timeout
        // SSH connection timeout design:
        // - 30 seconds accommodates slow networks and SSH negotiation
        // - Industry standard for SSH client connections
        // - Balances user patience with reliability on poor networks
        const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;
        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);
        let client = match tokio::time::timeout(
            connect_timeout,
            Client::connect(addr, &self.username, auth_method, check_method),
        )
        .await
        {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                let context = format!("SSH connection to {}:{}", self.host, self.port);
                let detailed = match &e {
                    super::tokio_client::Error::KeyAuthFailed => {
                        format!(
                            "{} failed: Authentication rejected with provided SSH key",
                            context
                        )
                    }
                    super::tokio_client::Error::KeyInvalid(err) => {
                        format!("{} failed: Invalid SSH key - {}", context, err)
                    }
                    super::tokio_client::Error::ServerCheckFailed => {
                        format!("{} failed: Host key verification failed. The server's host key is not trusted.", context)
                    }
                    super::tokio_client::Error::PasswordWrong => {
                        format!("{} failed: Password authentication rejected", context)
                    }
                    _ => format!("{} failed: {}", context, e),
                };
                return Err(anyhow::anyhow!(detailed).context(e));
            }
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Connection timeout after {} seconds. Host may be unreachable or SSH service not running.",
                    SSH_CONNECT_TIMEOUT_SECS
                ));
            }
        };

        tracing::debug!("Connected and authenticated successfully");

        // Create parent directory if it doesn't exist
        if let Some(parent) = local_dir_path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create parent directory for {local_dir_path:?}")
            })?;
        }

        tracing::debug!(
            "Downloading directory from {}:{} to {:?} using SFTP",
            self.host,
            remote_dir_path,
            local_dir_path
        );

        // Use the built-in download_dir method with timeout
        // Directory download timeout design:
        // - 10 minutes handles directories with many files
        // - Accounts for SFTP overhead per file (connection setup, etc.)
        // - Longer than single file to accommodate batch operations
        // - Prevents indefinite hang on large directory trees
        const DIR_DOWNLOAD_TIMEOUT_SECS: u64 = 600;
        let download_timeout = Duration::from_secs(DIR_DOWNLOAD_TIMEOUT_SECS);
        tokio::time::timeout(
            download_timeout,
            client.download_dir(remote_dir_path.to_string(), local_dir_path),
        )
        .await
        .with_context(|| {
            format!(
                "Directory download timeout: Transfer from {}:{} to {:?} did not complete within 10 minutes",
                self.host, remote_dir_path, local_dir_path
            )
        })?
        .with_context(|| {
            format!(
                "Failed to download directory from {}:{} to {:?}",
                self.host, remote_dir_path, local_dir_path
            )
        })?;

        tracing::debug!("Directory download completed successfully");

        Ok(())
    }

    /// Upload file with jump host support
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_file_with_jump_hosts(
        &mut self,
        local_path: &Path,
        remote_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        jump_hosts_spec: Option<&str>,
    ) -> Result<()> {
        tracing::debug!(
            "Uploading file to {}:{} (jump hosts: {:?})",
            self.host,
            self.port,
            jump_hosts_spec
        );

        // Determine authentication method
        let auth_method = self.determine_auth_method(key_path, use_agent, use_password)?;

        let strict_mode = strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts
        let client = if let Some(jump_spec) = jump_hosts_spec {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection");
                self.connect_direct(&auth_method, strict_mode).await?
            } else {
                tracing::info!(
                    "Uploading to {}:{} via {} jump host(s)",
                    self.host,
                    self.port,
                    jump_hosts.len()
                );

                self.connect_via_jump_hosts(
                    &jump_hosts,
                    &auth_method,
                    strict_mode,
                    key_path,
                    use_agent,
                    use_password,
                )
                .await?
            }
        } else {
            // Direct connection
            tracing::debug!("Using direct connection (no jump hosts)");
            self.connect_direct(&auth_method, strict_mode).await?
        };

        tracing::debug!("Connected and authenticated successfully");

        // Check if local file exists
        if !local_path.exists() {
            anyhow::bail!("Local file does not exist: {:?}", local_path);
        }

        let metadata = std::fs::metadata(local_path)
            .with_context(|| format!("Failed to get metadata for {local_path:?}"))?;

        let file_size = metadata.len();

        tracing::debug!(
            "Uploading file {:?} ({} bytes) to {}:{} using SFTP",
            local_path,
            file_size,
            self.host,
            remote_path
        );

        // Use the built-in upload_file method with timeout (SFTP-based)
        const FILE_UPLOAD_TIMEOUT_SECS: u64 = 300;
        let upload_timeout = Duration::from_secs(FILE_UPLOAD_TIMEOUT_SECS);
        tokio::time::timeout(
            upload_timeout,
            client.upload_file(local_path, remote_path.to_string()),
        )
        .await
        .with_context(|| {
            format!(
                "File upload timeout: Transfer of {:?} to {}:{} did not complete within 5 minutes",
                local_path, self.host, remote_path
            )
        })?
        .with_context(|| {
            format!(
                "Failed to upload file {:?} to {}:{}",
                local_path, self.host, remote_path
            )
        })?;

        tracing::debug!("File upload completed successfully");

        Ok(())
    }

    /// Download file with jump host support
    #[allow(clippy::too_many_arguments)]
    pub async fn download_file_with_jump_hosts(
        &mut self,
        remote_path: &str,
        local_path: &Path,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        jump_hosts_spec: Option<&str>,
    ) -> Result<()> {
        tracing::debug!(
            "Downloading file from {}:{} (jump hosts: {:?})",
            self.host,
            self.port,
            jump_hosts_spec
        );

        // Determine authentication method
        let auth_method = self.determine_auth_method(key_path, use_agent, use_password)?;

        let strict_mode = strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts
        let client = if let Some(jump_spec) = jump_hosts_spec {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection");
                self.connect_direct(&auth_method, strict_mode).await?
            } else {
                tracing::info!(
                    "Downloading from {}:{} via {} jump host(s)",
                    self.host,
                    self.port,
                    jump_hosts.len()
                );

                self.connect_via_jump_hosts(
                    &jump_hosts,
                    &auth_method,
                    strict_mode,
                    key_path,
                    use_agent,
                    use_password,
                )
                .await?
            }
        } else {
            // Direct connection
            tracing::debug!("Using direct connection (no jump hosts)");
            self.connect_direct(&auth_method, strict_mode).await?
        };

        tracing::debug!("Connected and authenticated successfully");

        // Create parent directory if it doesn't exist
        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create parent directory for {local_path:?}"))?;
        }

        tracing::debug!(
            "Downloading file from {}:{} to {:?} using SFTP",
            self.host,
            remote_path,
            local_path
        );

        // Use the built-in download_file method with timeout (SFTP-based)
        const FILE_DOWNLOAD_TIMEOUT_SECS: u64 = 300;
        let download_timeout = Duration::from_secs(FILE_DOWNLOAD_TIMEOUT_SECS);
        tokio::time::timeout(
            download_timeout,
            client.download_file(remote_path.to_string(), local_path),
        )
        .await
        .with_context(|| {
            format!(
                "File download timeout: Transfer from {}:{} to {:?} did not complete within 5 minutes",
                self.host, remote_path, local_path
            )
        })?
        .with_context(|| {
            format!(
                "Failed to download file from {}:{} to {:?}",
                self.host, remote_path, local_path
            )
        })?;

        tracing::debug!("File download completed successfully");

        Ok(())
    }

    /// Upload directory with jump host support
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_dir_with_jump_hosts(
        &mut self,
        local_dir_path: &Path,
        remote_dir_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        jump_hosts_spec: Option<&str>,
    ) -> Result<()> {
        tracing::debug!(
            "Uploading directory to {}:{} (jump hosts: {:?})",
            self.host,
            self.port,
            jump_hosts_spec
        );

        // Determine authentication method
        let auth_method = self.determine_auth_method(key_path, use_agent, use_password)?;

        let strict_mode = strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts
        let client = if let Some(jump_spec) = jump_hosts_spec {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection");
                self.connect_direct(&auth_method, strict_mode).await?
            } else {
                tracing::info!(
                    "Uploading directory to {}:{} via {} jump host(s)",
                    self.host,
                    self.port,
                    jump_hosts.len()
                );

                self.connect_via_jump_hosts(
                    &jump_hosts,
                    &auth_method,
                    strict_mode,
                    key_path,
                    use_agent,
                    use_password,
                )
                .await?
            }
        } else {
            // Direct connection
            tracing::debug!("Using direct connection (no jump hosts)");
            self.connect_direct(&auth_method, strict_mode).await?
        };

        tracing::debug!("Connected and authenticated successfully");

        // Check if local directory exists
        if !local_dir_path.exists() {
            anyhow::bail!("Local directory does not exist: {:?}", local_dir_path);
        }

        if !local_dir_path.is_dir() {
            anyhow::bail!("Local path is not a directory: {:?}", local_dir_path);
        }

        tracing::debug!(
            "Uploading directory {:?} to {}:{} using SFTP",
            local_dir_path,
            self.host,
            remote_dir_path
        );

        // Use the built-in upload_dir method with timeout
        const DIR_UPLOAD_TIMEOUT_SECS: u64 = 600;
        let upload_timeout = Duration::from_secs(DIR_UPLOAD_TIMEOUT_SECS);
        tokio::time::timeout(
            upload_timeout,
            client.upload_dir(local_dir_path, remote_dir_path.to_string()),
        )
        .await
        .with_context(|| {
            format!(
                "Directory upload timeout: Transfer of {:?} to {}:{} did not complete within 10 minutes",
                local_dir_path, self.host, remote_dir_path
            )
        })?
        .with_context(|| {
            format!(
                "Failed to upload directory {:?} to {}:{}",
                local_dir_path, self.host, remote_dir_path
            )
        })?;

        tracing::debug!("Directory upload completed successfully");

        Ok(())
    }

    /// Download directory with jump host support
    #[allow(clippy::too_many_arguments)]
    pub async fn download_dir_with_jump_hosts(
        &mut self,
        remote_dir_path: &str,
        local_dir_path: &Path,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        jump_hosts_spec: Option<&str>,
    ) -> Result<()> {
        tracing::debug!(
            "Downloading directory from {}:{} (jump hosts: {:?})",
            self.host,
            self.port,
            jump_hosts_spec
        );

        // Determine authentication method
        let auth_method = self.determine_auth_method(key_path, use_agent, use_password)?;

        let strict_mode = strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts
        let client = if let Some(jump_spec) = jump_hosts_spec {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection");
                self.connect_direct(&auth_method, strict_mode).await?
            } else {
                tracing::info!(
                    "Downloading directory from {}:{} via {} jump host(s)",
                    self.host,
                    self.port,
                    jump_hosts.len()
                );

                self.connect_via_jump_hosts(
                    &jump_hosts,
                    &auth_method,
                    strict_mode,
                    key_path,
                    use_agent,
                    use_password,
                )
                .await?
            }
        } else {
            // Direct connection
            tracing::debug!("Using direct connection (no jump hosts)");
            self.connect_direct(&auth_method, strict_mode).await?
        };

        tracing::debug!("Connected and authenticated successfully");

        // Create parent directory if it doesn't exist
        if let Some(parent) = local_dir_path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create parent directory for {local_dir_path:?}")
            })?;
        }

        tracing::debug!(
            "Downloading directory from {}:{} to {:?} using SFTP",
            self.host,
            remote_dir_path,
            local_dir_path
        );

        // Use the built-in download_dir method with timeout
        const DIR_DOWNLOAD_TIMEOUT_SECS: u64 = 600;
        let download_timeout = Duration::from_secs(DIR_DOWNLOAD_TIMEOUT_SECS);
        tokio::time::timeout(
            download_timeout,
            client.download_dir(remote_dir_path.to_string(), local_dir_path),
        )
        .await
        .with_context(|| {
            format!(
                "Directory download timeout: Transfer from {}:{} to {:?} did not complete within 10 minutes",
                self.host, remote_dir_path, local_dir_path
            )
        })?
        .with_context(|| {
            format!(
                "Failed to download directory from {}:{} to {:?}",
                self.host, remote_dir_path, local_dir_path
            )
        })?;

        tracing::debug!("Directory download completed successfully");

        Ok(())
    }

    fn determine_auth_method(
        &self,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<AuthMethod> {
        // If password authentication is explicitly requested
        if use_password {
            tracing::debug!("Using password authentication");
            // Use Zeroizing to ensure password is cleared from memory
            let password = Zeroizing::new(
                rpassword::prompt_password(format!(
                    "Enter password for {}@{}: ",
                    self.username, self.host
                ))
                .with_context(|| "Failed to read password")?,
            );
            return Ok(AuthMethod::with_password(&password));
        }

        // If SSH agent is explicitly requested, try that first
        if use_agent {
            #[cfg(not(target_os = "windows"))]
            {
                // Check if SSH_AUTH_SOCK is available
                if std::env::var("SSH_AUTH_SOCK").is_ok() {
                    tracing::debug!("Using SSH agent for authentication");
                    return Ok(AuthMethod::Agent);
                }
                tracing::warn!(
                    "SSH agent requested but SSH_AUTH_SOCK environment variable not set"
                );
                // Fall through to key file authentication
            }
            #[cfg(target_os = "windows")]
            {
                anyhow::bail!("SSH agent authentication is not supported on Windows");
            }
        }

        // Try key file authentication
        if let Some(key_path) = key_path {
            tracing::debug!("Authenticating with key: {:?}", key_path);

            // Check if the key is encrypted by attempting to read it
            let key_contents = std::fs::read_to_string(key_path)
                .with_context(|| format!("Failed to read SSH key file: {key_path:?}"))?;

            let passphrase = if key_contents.contains("ENCRYPTED")
                || key_contents.contains("Proc-Type: 4,ENCRYPTED")
            {
                tracing::debug!("Detected encrypted SSH key, prompting for passphrase");
                // Use Zeroizing for passphrase security
                let pass = Zeroizing::new(
                    rpassword::prompt_password(format!("Enter passphrase for key {key_path:?}: "))
                        .with_context(|| "Failed to read passphrase")?,
                );
                Some(pass)
            } else {
                None
            };

            return Ok(AuthMethod::with_key_file(
                key_path,
                passphrase.as_ref().map(|p| p.as_str()),
            ));
        }

        // Skip SSH agent auto-detection to avoid failures with empty agents
        // Only use agent if explicitly requested
        #[cfg(not(target_os = "windows"))]
        if use_agent && std::env::var("SSH_AUTH_SOCK").is_ok() {
            tracing::debug!("SSH agent explicitly requested and available");
            return Ok(AuthMethod::Agent);
        }

        // Fallback to default key locations
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let home_path = Path::new(&home).join(".ssh");

        // Try common key files in order of preference
        let default_keys = [
            home_path.join("id_ed25519"),
            home_path.join("id_rsa"),
            home_path.join("id_ecdsa"),
            home_path.join("id_dsa"),
        ];

        for default_key in &default_keys {
            if default_key.exists() {
                tracing::debug!("Using default key: {:?}", default_key);

                // Check if the key is encrypted
                let key_contents = std::fs::read_to_string(default_key)
                    .with_context(|| format!("Failed to read SSH key file: {default_key:?}"))?;

                let passphrase = if key_contents.contains("ENCRYPTED")
                    || key_contents.contains("Proc-Type: 4,ENCRYPTED")
                {
                    tracing::debug!("Detected encrypted SSH key, prompting for passphrase");
                    // Use Zeroizing for passphrase security
                    let pass = Zeroizing::new(
                        rpassword::prompt_password(format!(
                            "Enter passphrase for key {default_key:?}: "
                        ))
                        .with_context(|| "Failed to read passphrase")?,
                    );
                    Some(pass)
                } else {
                    None
                };

                return Ok(AuthMethod::with_key_file(
                    default_key,
                    passphrase.as_ref().map(|p| p.as_str()),
                ));
            }
        }

        anyhow::bail!(
            "SSH authentication failed: No authentication method available.\n\
             Tried:\n\
             - SSH agent (SSH_AUTH_SOCK not set or agent not available)\n\
             - Default key files (~/.ssh/id_ed25519, ~/.ssh/id_rsa, etc. not found)\n\
             \n\
             Solutions:\n\
             - Use --password for password authentication\n\
             - Start SSH agent and add keys with 'ssh-add'\n\
             - Specify a key file with -i/--identity\n\
             - Create a default key at ~/.ssh/id_ed25519 or ~/.ssh/id_rsa"
        );
    }
}

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub host: String,
    pub output: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: u32,
}

impl CommandResult {
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.output).to_string()
    }

    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }

    pub fn is_success(&self) -> bool {
        self.exit_status == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_ssh_client_creation() {
        let client = SshClient::new("example.com".to_string(), 22, "user".to_string());
        assert_eq!(client.host, "example.com");
        assert_eq!(client.port, 22);
        assert_eq!(client.username, "user");
    }

    #[test]
    fn test_command_result_success() {
        let result = CommandResult {
            host: "test.com".to_string(),
            output: b"Hello World\n".to_vec(),
            stderr: Vec::new(),
            exit_status: 0,
        };

        assert!(result.is_success());
        assert_eq!(result.stdout_string(), "Hello World\n");
        assert_eq!(result.stderr_string(), "");
    }

    #[test]
    fn test_command_result_failure() {
        let result = CommandResult {
            host: "test.com".to_string(),
            output: Vec::new(),
            stderr: b"Command not found\n".to_vec(),
            exit_status: 127,
        };

        assert!(!result.is_success());
        assert_eq!(result.stdout_string(), "");
        assert_eq!(result.stderr_string(), "Command not found\n");
    }

    #[test]
    fn test_command_result_with_utf8() {
        let result = CommandResult {
            host: "test.com".to_string(),
            output: "한글 테스트\n".as_bytes().to_vec(),
            stderr: "エラー\n".as_bytes().to_vec(),
            exit_status: 1,
        };

        assert!(!result.is_success());
        assert_eq!(result.stdout_string(), "한글 테스트\n");
        assert_eq!(result.stderr_string(), "エラー\n");
    }

    #[test]
    fn test_determine_auth_method_with_key() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key");
        std::fs::write(&key_path, "fake key content").unwrap();

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client
            .determine_auth_method(Some(&key_path), false, false)
            .unwrap();

        match auth {
            AuthMethod::PrivateKeyFile { key_file_path, .. } => {
                assert_eq!(key_file_path, key_path);
            }
            _ => panic!("Expected PrivateKeyFile auth method"),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_determine_auth_method_with_agent() {
        unsafe {
            std::env::set_var("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock");
        }

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client.determine_auth_method(None, true, false).unwrap();

        match auth {
            AuthMethod::Agent => {}
            _ => panic!("Expected Agent auth method"),
        }

        unsafe {
            std::env::remove_var("SSH_AUTH_SOCK");
        }
    }

    #[test]
    fn test_determine_auth_method_with_password() {
        let _client = SshClient::new("test.com".to_string(), 22, "user".to_string());

        // Note: We can't actually test password prompt in unit tests
        // as it requires terminal input. This would need integration testing.
        // For now, we just verify the function compiles with the new parameter.
    }

    #[test]
    fn test_determine_auth_method_fallback_to_default() {
        // Save original environment variables
        let original_home = std::env::var("HOME").ok();
        let original_ssh_auth_sock = std::env::var("SSH_AUTH_SOCK").ok();

        // Create a fake home directory with default key
        let temp_dir = TempDir::new().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let default_key = ssh_dir.join("id_rsa");
        std::fs::write(&default_key, "fake key").unwrap();

        // Set test environment
        std::env::set_var("HOME", temp_dir.path().to_str().unwrap());
        std::env::remove_var("SSH_AUTH_SOCK");

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client.determine_auth_method(None, false, false).unwrap();

        // Restore original environment variables
        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        } else {
            std::env::remove_var("HOME");
        }
        if let Some(sock) = original_ssh_auth_sock {
            std::env::set_var("SSH_AUTH_SOCK", sock);
        }

        match auth {
            AuthMethod::PrivateKeyFile { key_file_path, .. } => {
                assert_eq!(key_file_path, default_key);
            }
            _ => panic!("Expected PrivateKeyFile auth method"),
        }
    }
}

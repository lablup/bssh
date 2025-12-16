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

use super::config::ConnectionConfig;
use super::core::SshClient;
use super::result::CommandResult;
use crate::security::SudoPassword;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::CommandOutput;
use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

// SSH command execution timeout design:
// - 5 minutes (300s) handles long-running commands
// - Prevents indefinite hang on unresponsive commands
// - Long enough for system updates, compilations, etc.
// - Short enough to detect truly hung processes
const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 300;

impl SshClient {
    /// Execute a command on the remote host with basic configuration
    pub async fn connect_and_execute(
        &mut self,
        command: &str,
        key_path: Option<&Path>,
        use_agent: bool,
    ) -> Result<CommandResult> {
        self.connect_and_execute_with_host_check(command, key_path, None, use_agent, false, None)
            .await
    }

    /// Execute a command with host key checking configuration
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
            #[cfg(target_os = "macos")]
            use_keychain: false, // Not supported in this legacy API
            timeout_seconds,
            connect_timeout_seconds: None, // Use default
            jump_hosts_spec: None,         // No jump hosts
        };

        self.connect_and_execute_with_jump_hosts(command, &config)
            .await
    }

    /// Execute a command with full configuration including jump hosts
    pub async fn connect_and_execute_with_jump_hosts(
        &mut self,
        command: &str,
        config: &ConnectionConfig<'_>,
    ) -> Result<CommandResult> {
        tracing::debug!("Connecting to {}:{}", self.host, self.port);

        // Determine authentication method based on parameters
        let auth_method = self
            .determine_auth_method(
                config.key_path,
                config.use_agent,
                config.use_password,
                #[cfg(target_os = "macos")]
                config.use_keychain,
            )
            .await?;

        let strict_mode = config
            .strict_mode
            .unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts
        let client = self
            .establish_connection(
                &auth_method,
                strict_mode,
                config.jump_hosts_spec,
                config.key_path,
                config.use_agent,
                config.use_password,
                config.connect_timeout_seconds,
            )
            .await?;

        tracing::debug!("Connected and authenticated successfully");
        tracing::debug!("Executing command: {}", command);

        // Execute command with timeout
        let result = self
            .execute_with_timeout(&client, command, config.timeout_seconds)
            .await?;

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

    /// Execute a command with the specified timeout
    async fn execute_with_timeout(
        &self,
        client: &crate::ssh::tokio_client::Client,
        command: &str,
        timeout_seconds: Option<u64>,
    ) -> Result<crate::ssh::tokio_client::CommandExecutedResult> {
        if let Some(timeout_secs) = timeout_seconds {
            if timeout_secs == 0 {
                // No timeout (unlimited)
                tracing::debug!("Executing command with no timeout (unlimited)");
                client.execute(command)
                    .await
                    .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))
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
                .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))
            }
        } else {
            // Default timeout if not specified
            let command_timeout = Duration::from_secs(DEFAULT_COMMAND_TIMEOUT_SECS);
            tracing::debug!("Executing command with default timeout of 300 seconds");
            tokio::time::timeout(
                command_timeout,
                client.execute(command)
            )
            .await
            .with_context(|| format!("Command execution timeout: The command '{}' did not complete within 5 minutes on {}:{}", command, self.host, self.port))?
            .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))
        }
    }

    /// Execute a command with streaming output support
    ///
    /// This method provides real-time command output streaming through the provided sender channel.
    /// Output is sent as `CommandOutput::StdOut` or `CommandOutput::StdErr` variants.
    ///
    /// # Arguments
    /// * `command` - The command to execute
    /// * `config` - Connection configuration
    /// * `output_sender` - Channel sender for streaming output
    ///
    /// # Returns
    /// The exit status of the command
    pub async fn connect_and_execute_with_output_streaming(
        &mut self,
        command: &str,
        config: &ConnectionConfig<'_>,
        output_sender: Sender<CommandOutput>,
    ) -> Result<u32> {
        tracing::debug!("Connecting to {}:{}", self.host, self.port);

        // Determine authentication method based on parameters
        let auth_method = self
            .determine_auth_method(
                config.key_path,
                config.use_agent,
                config.use_password,
                #[cfg(target_os = "macos")]
                config.use_keychain,
            )
            .await?;

        let strict_mode = config
            .strict_mode
            .unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts
        let client = self
            .establish_connection(
                &auth_method,
                strict_mode,
                config.jump_hosts_spec,
                config.key_path,
                config.use_agent,
                config.use_password,
                config.connect_timeout_seconds,
            )
            .await?;

        tracing::debug!("Connected and authenticated successfully");
        tracing::debug!("Executing command with streaming: {}", command);

        // Execute command with streaming and timeout
        let exit_status = self
            .execute_streaming_with_timeout(&client, command, config.timeout_seconds, output_sender)
            .await?;

        tracing::debug!("Command execution completed with status: {}", exit_status);

        Ok(exit_status)
    }

    /// Execute a command with streaming output and the specified timeout
    async fn execute_streaming_with_timeout(
        &self,
        client: &crate::ssh::tokio_client::Client,
        command: &str,
        timeout_seconds: Option<u64>,
        output_sender: Sender<CommandOutput>,
    ) -> Result<u32> {
        if let Some(timeout_secs) = timeout_seconds {
            if timeout_secs == 0 {
                // No timeout (unlimited)
                tracing::debug!("Executing command with streaming, no timeout (unlimited)");
                client.execute_streaming(command, output_sender)
                    .await
                    .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))
            } else {
                // With timeout
                let command_timeout = Duration::from_secs(timeout_secs);
                tracing::debug!(
                    "Executing command with streaming, timeout of {} seconds",
                    timeout_secs
                );
                tokio::time::timeout(
                    command_timeout,
                    client.execute_streaming(command, output_sender)
                )
                .await
                .with_context(|| format!("Command execution timeout: The command '{}' did not complete within {} seconds on {}:{}", command, timeout_secs, self.host, self.port))?
                .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))
            }
        } else {
            // Default timeout if not specified
            let command_timeout = Duration::from_secs(DEFAULT_COMMAND_TIMEOUT_SECS);
            tracing::debug!("Executing command with streaming, default timeout of 300 seconds");
            tokio::time::timeout(
                command_timeout,
                client.execute_streaming(command, output_sender)
            )
            .await
            .with_context(|| format!("Command execution timeout: The command '{}' did not complete within 5 minutes on {}:{}", command, self.host, self.port))?
            .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))
        }
    }

    /// Execute a command with sudo password support and streaming output.
    ///
    /// This method handles automatic sudo password injection when sudo prompts are detected
    /// in the command output.
    ///
    /// # Arguments
    /// * `command` - The command to execute (typically uses sudo)
    /// * `config` - Connection configuration
    /// * `output_sender` - Channel sender for streaming output
    /// * `sudo_password` - The sudo password to inject when prompted
    ///
    /// # Returns
    /// The exit status of the command
    pub async fn connect_and_execute_with_sudo(
        &mut self,
        command: &str,
        config: &ConnectionConfig<'_>,
        output_sender: Sender<CommandOutput>,
        sudo_password: &SudoPassword,
    ) -> Result<u32> {
        tracing::debug!(
            "Connecting to {}:{} for sudo execution",
            self.host,
            self.port
        );

        // Determine authentication method based on parameters
        let auth_method = self
            .determine_auth_method(
                config.key_path,
                config.use_agent,
                config.use_password,
                #[cfg(target_os = "macos")]
                config.use_keychain,
            )
            .await?;

        let strict_mode = config
            .strict_mode
            .unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts
        let client = self
            .establish_connection(
                &auth_method,
                strict_mode,
                config.jump_hosts_spec,
                config.key_path,
                config.use_agent,
                config.use_password,
                config.connect_timeout_seconds,
            )
            .await?;

        tracing::debug!("Connected and authenticated successfully");
        tracing::debug!("Executing command with sudo support: {}", command);

        // Execute command with sudo support and timeout
        let exit_status = self
            .execute_sudo_with_timeout(
                &client,
                command,
                config.timeout_seconds,
                output_sender,
                sudo_password,
            )
            .await?;

        tracing::debug!("Command execution completed with status: {}", exit_status);

        Ok(exit_status)
    }

    /// Execute a command with sudo support and the specified timeout
    async fn execute_sudo_with_timeout(
        &self,
        client: &crate::ssh::tokio_client::Client,
        command: &str,
        timeout_seconds: Option<u64>,
        output_sender: Sender<CommandOutput>,
        sudo_password: &SudoPassword,
    ) -> Result<u32> {
        if let Some(timeout_secs) = timeout_seconds {
            if timeout_secs == 0 {
                // No timeout (unlimited)
                tracing::debug!("Executing sudo command with no timeout (unlimited)");
                client
                    .execute_with_sudo(command, output_sender, sudo_password)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to execute sudo command '{}' on {}:{}",
                            command, self.host, self.port
                        )
                    })
            } else {
                // With timeout
                let command_timeout = Duration::from_secs(timeout_secs);
                tracing::debug!(
                    "Executing sudo command with timeout of {} seconds",
                    timeout_secs
                );
                tokio::time::timeout(
                    command_timeout,
                    client.execute_with_sudo(command, output_sender, sudo_password)
                )
                .await
                .with_context(|| format!("Command execution timeout: The sudo command '{}' did not complete within {} seconds on {}:{}", command, timeout_secs, self.host, self.port))?
                .with_context(|| format!("Failed to execute sudo command '{}' on {}:{}", command, self.host, self.port))
            }
        } else {
            // Default timeout if not specified
            let command_timeout = Duration::from_secs(DEFAULT_COMMAND_TIMEOUT_SECS);
            tracing::debug!("Executing sudo command with default timeout of 300 seconds");
            tokio::time::timeout(
                command_timeout,
                client.execute_with_sudo(command, output_sender, sudo_password)
            )
            .await
            .with_context(|| format!("Command execution timeout: The sudo command '{}' did not complete within 5 minutes on {}:{}", command, self.host, self.port))?
            .with_context(|| format!("Failed to execute sudo command '{}' on {}:{}", command, self.host, self.port))
        }
    }
}

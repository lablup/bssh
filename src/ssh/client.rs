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

use anyhow::{Context, Result};
use async_ssh2_tokio::{AuthMethod, Client};
use std::path::Path;
use std::time::Duration;

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
    ) -> Result<CommandResult> {
        self.connect_and_execute_with_host_check(command, key_path, None)
            .await
    }

    pub async fn connect_and_execute_with_host_check(
        &mut self,
        command: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
    ) -> Result<CommandResult> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!("Connecting to {}:{}", self.host, self.port);

        // Determine authentication method
        let auth_method = if let Some(key_path) = key_path {
            tracing::debug!("Authenticating with key: {:?}", key_path);
            AuthMethod::with_key_file(key_path, None)
        } else {
            // Try default key location
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let default_key = Path::new(&home).join(".ssh").join("id_rsa");

            if default_key.exists() {
                tracing::debug!("Using default key: {:?}", default_key);
                AuthMethod::with_key_file(default_key, None)
            } else {
                anyhow::bail!("SSH authentication failed: No SSH key specified and no default key found at ~/.ssh/id_rsa. Please specify a key with -i or ensure a default key exists.");
            }
        };

        // Set up host key checking
        let check_method = if let Some(mode) = strict_mode {
            super::known_hosts::get_check_method(mode)
        } else {
            super::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew)
        };

        // Connect and authenticate with timeout
        let connect_timeout = Duration::from_secs(30);
        let client = tokio::time::timeout(
            connect_timeout,
            Client::connect(addr, &self.username, auth_method, check_method)
        )
        .await
        .with_context(|| format!("Connection timeout: Failed to connect to {}:{} after 30 seconds. Please check if the host is reachable and SSH service is running.", self.host, self.port))?
        .with_context(|| format!("SSH connection failed to {}:{}. Please verify the hostname, port, and authentication credentials.", self.host, self.port))?;

        tracing::debug!("Connected and authenticated successfully");
        tracing::debug!("Executing command: {}", command);

        // Execute command with timeout
        let command_timeout = Duration::from_secs(300); // 5 minutes default
        let result = tokio::time::timeout(
            command_timeout,
            client.execute(command)
        )
        .await
        .with_context(|| format!("Command execution timeout: The command '{}' did not complete within 5 minutes on {}:{}", command, self.host, self.port))?
        .with_context(|| format!("Failed to execute command '{}' on {}:{}. The SSH connection was successful but the command could not be executed.", command, self.host, self.port))?;

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

    pub async fn copy_file(
        &mut self,
        local_path: &Path,
        remote_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
    ) -> Result<()> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!("Connecting to {}:{} for file copy", self.host, self.port);

        // Determine authentication method
        let auth_method = if let Some(key_path) = key_path {
            tracing::debug!("Authenticating with key: {:?}", key_path);
            AuthMethod::with_key_file(key_path, None)
        } else {
            // Try default key location
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let default_key = Path::new(&home).join(".ssh").join("id_rsa");

            if default_key.exists() {
                tracing::debug!("Using default key: {:?}", default_key);
                AuthMethod::with_key_file(default_key, None)
            } else {
                anyhow::bail!("SSH authentication failed: No SSH key specified and no default key found at ~/.ssh/id_rsa. Please specify a key with -i or ensure a default key exists.");
            }
        };

        // Set up host key checking
        let check_method = if let Some(mode) = strict_mode {
            super::known_hosts::get_check_method(mode)
        } else {
            super::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew)
        };

        // Connect and authenticate with timeout
        let connect_timeout = Duration::from_secs(30);
        let client = tokio::time::timeout(
            connect_timeout,
            Client::connect(addr, &self.username, auth_method, check_method)
        )
        .await
        .with_context(|| format!("Connection timeout: Failed to connect to {}:{} after 30 seconds. Please check if the host is reachable and SSH service is running.", self.host, self.port))?
        .with_context(|| format!("SSH connection failed to {}:{}. Please verify the hostname, port, and authentication credentials.", self.host, self.port))?;

        tracing::debug!("Connected and authenticated successfully");

        // Check if local file exists
        if !local_path.exists() {
            anyhow::bail!("Local file does not exist: {:?}", local_path);
        }

        let metadata = std::fs::metadata(local_path)
            .with_context(|| format!("Failed to get metadata for {local_path:?}"))?;

        let file_size = metadata.len();

        tracing::debug!(
            "Copying file {:?} ({} bytes) to {}:{}",
            local_path,
            file_size,
            self.host,
            remote_path
        );

        // Use the built-in upload_file method with timeout
        let upload_timeout = Duration::from_secs(300); // 5 minutes for file upload
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

        tracing::debug!("File copy completed successfully");

        Ok(())
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

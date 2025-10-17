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

use super::core::SshClient;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::Client;
use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;

// File upload timeout design:
// - 5 minutes handles typical file sizes over slow networks
// - Sufficient for multi-MB files on broadband connections
// - Prevents hang on network failures or very large files
const FILE_UPLOAD_TIMEOUT_SECS: u64 = 300;

// File download timeout design:
// - 5 minutes handles typical file sizes over slow networks
// - Sufficient for multi-MB files on broadband connections
// - Prevents hang on network failures or very large files
const FILE_DOWNLOAD_TIMEOUT_SECS: u64 = 300;

// Directory upload timeout design:
// - 10 minutes handles directories with many files
// - Accounts for SFTP overhead per file (connection setup, etc.)
// - Longer than single file to accommodate batch operations
// - Prevents indefinite hang on large directory trees
const DIR_UPLOAD_TIMEOUT_SECS: u64 = 600;

// Directory download timeout design:
// - 10 minutes handles directories with many files
// - Accounts for SFTP overhead per file (connection setup, etc.)
// - Longer than single file to accommodate batch operations
// - Prevents indefinite hang on large directory trees
const DIR_DOWNLOAD_TIMEOUT_SECS: u64 = 600;

// SSH connection timeout design:
// - 30 seconds accommodates slow networks and SSH negotiation
// - Industry standard for SSH client connections
// - Balances user patience with reliability on poor networks
const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;

impl SshClient {
    /// Upload a single file to the remote host
    pub async fn upload_file(
        &mut self,
        local_path: &Path,
        remote_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<()> {
        let client = self
            .connect_for_file_transfer(key_path, strict_mode, use_agent, use_password, "file copy")
            .await?;

        tracing::debug!("Connected and authenticated successfully");

        // Check if local file exists
        if !local_path.exists() {
            anyhow::bail!("Local file does not exist: {local_path:?}");
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

    /// Download a single file from the remote host
    pub async fn download_file(
        &mut self,
        remote_path: &str,
        local_path: &Path,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<()> {
        let client = self
            .connect_for_file_transfer(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                "file download",
            )
            .await?;

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

    /// Upload a directory to the remote host
    pub async fn upload_dir(
        &mut self,
        local_dir_path: &Path,
        remote_dir_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<()> {
        let client = self
            .connect_for_file_transfer(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                "directory upload",
            )
            .await?;

        tracing::debug!("Connected and authenticated successfully");

        // Check if local directory exists
        if !local_dir_path.exists() {
            anyhow::bail!("Local directory does not exist: {local_dir_path:?}");
        }

        if !local_dir_path.is_dir() {
            anyhow::bail!("Local path is not a directory: {local_dir_path:?}");
        }

        tracing::debug!(
            "Uploading directory {:?} to {}:{} using SFTP",
            local_dir_path,
            self.host,
            remote_dir_path
        );

        // Use the built-in upload_dir method with timeout
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

    /// Download a directory from the remote host
    pub async fn download_dir(
        &mut self,
        remote_dir_path: &str,
        local_dir_path: &Path,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<()> {
        let client = self
            .connect_for_file_transfer(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                "directory download",
            )
            .await?;

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

        let client = self
            .connect_for_transfer_with_jump_hosts(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                jump_hosts_spec,
            )
            .await?;

        tracing::debug!("Connected and authenticated successfully");

        // Check if local file exists
        if !local_path.exists() {
            anyhow::bail!("Local file does not exist: {local_path:?}");
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

        let client = self
            .connect_for_transfer_with_jump_hosts(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                jump_hosts_spec,
            )
            .await?;

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

        let client = self
            .connect_for_transfer_with_jump_hosts(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                jump_hosts_spec,
            )
            .await?;

        tracing::debug!("Connected and authenticated successfully");

        // Check if local directory exists
        if !local_dir_path.exists() {
            anyhow::bail!("Local directory does not exist: {local_dir_path:?}");
        }

        if !local_dir_path.is_dir() {
            anyhow::bail!("Local path is not a directory: {local_dir_path:?}");
        }

        tracing::debug!(
            "Uploading directory {:?} to {}:{} using SFTP",
            local_dir_path,
            self.host,
            remote_dir_path
        );

        // Use the built-in upload_dir method with timeout
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

        let client = self
            .connect_for_transfer_with_jump_hosts(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                jump_hosts_spec,
            )
            .await?;

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

    /// Helper function to connect for file transfer operations (without jump hosts)
    async fn connect_for_file_transfer(
        &self,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        operation_desc: &str,
    ) -> Result<Client> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!(
            "Connecting to {}:{} for {}",
            self.host,
            self.port,
            operation_desc
        );

        // Determine authentication method based on parameters
        let auth_method = self
            .determine_auth_method(key_path, use_agent, use_password)
            .await?;

        // Set up host key checking
        let check_method = if let Some(mode) = strict_mode {
            crate::ssh::known_hosts::get_check_method(mode)
        } else {
            crate::ssh::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew)
        };

        // Connect and authenticate with timeout
        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);
        match tokio::time::timeout(
            connect_timeout,
            Client::connect(addr, &self.username, auth_method, check_method),
        )
        .await
        {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(e)) => {
                let context = format!("SSH connection to {}:{}", self.host, self.port);
                let detailed = format_ssh_error(&context, &e);
                Err(anyhow::anyhow!(detailed).context(e))
            }
            Err(_) => Err(anyhow::anyhow!(
                "Connection timeout after {SSH_CONNECT_TIMEOUT_SECS} seconds. Host may be unreachable or SSH service not running."
            )),
        }
    }

    /// Helper function to connect for file transfer with jump hosts
    async fn connect_for_transfer_with_jump_hosts(
        &self,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        jump_hosts_spec: Option<&str>,
    ) -> Result<Client> {
        // Determine authentication method
        let auth_method = self
            .determine_auth_method(key_path, use_agent, use_password)
            .await?;

        let strict_mode = strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts
        self.establish_connection(
            &auth_method,
            strict_mode,
            jump_hosts_spec,
            key_path,
            use_agent,
            use_password,
        )
        .await
    }
}

/// Format detailed SSH error messages
fn format_ssh_error(context: &str, e: &crate::ssh::tokio_client::Error) -> String {
    match e {
        crate::ssh::tokio_client::Error::KeyAuthFailed => {
            format!("{context} failed: Authentication rejected with provided SSH key")
        }
        crate::ssh::tokio_client::Error::KeyInvalid(err) => {
            format!("{context} failed: Invalid SSH key - {err}")
        }
        crate::ssh::tokio_client::Error::ServerCheckFailed => {
            format!(
                "{context} failed: Host key verification failed. The server's host key is not trusted."
            )
        }
        crate::ssh::tokio_client::Error::PasswordWrong => {
            format!("{context} failed: Password authentication rejected")
        }
        crate::ssh::tokio_client::Error::AgentConnectionFailed => {
            format!("{context} failed: Cannot connect to SSH agent. Ensure SSH_AUTH_SOCK is set.")
        }
        crate::ssh::tokio_client::Error::AgentNoIdentities => {
            format!("{context} failed: SSH agent has no keys. Use 'ssh-add' to add your key.")
        }
        crate::ssh::tokio_client::Error::AgentAuthenticationFailed => {
            format!("{context} failed: SSH agent authentication rejected")
        }
        _ => format!("{context} failed: {e}"),
    }
}

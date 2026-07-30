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
use crate::security::Password;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::Client;
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
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
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_file(
        &mut self,
        local_path: &Path,
        remote_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        connect_timeout_seconds: Option<u64>,
    ) -> Result<()> {
        let client = self
            .connect_for_file_transfer(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                "file copy",
                connect_timeout_seconds,
                None,
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

    /// Download a single file from the remote host
    #[allow(clippy::too_many_arguments)]
    pub async fn download_file(
        &mut self,
        remote_path: &str,
        local_path: &Path,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        connect_timeout_seconds: Option<u64>,
    ) -> Result<()> {
        let client = self
            .connect_for_file_transfer(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                "file download",
                connect_timeout_seconds,
                None,
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
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_dir(
        &mut self,
        local_dir_path: &Path,
        remote_dir_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        connect_timeout_seconds: Option<u64>,
    ) -> Result<()> {
        let client = self
            .connect_for_file_transfer(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                "directory upload",
                connect_timeout_seconds,
                None,
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
    #[allow(clippy::too_many_arguments)]
    pub async fn download_dir(
        &mut self,
        remote_dir_path: &str,
        local_dir_path: &Path,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        connect_timeout_seconds: Option<u64>,
    ) -> Result<()> {
        let client = self
            .connect_for_file_transfer(
                key_path,
                strict_mode,
                use_agent,
                use_password,
                "directory download",
                connect_timeout_seconds,
                None,
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
        connect_timeout_seconds: Option<u64>,
        pre_collected_password: Option<Arc<Password>>,
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
                connect_timeout_seconds,
                pre_collected_password,
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
        connect_timeout_seconds: Option<u64>,
        pre_collected_password: Option<Arc<Password>>,
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
                connect_timeout_seconds,
                pre_collected_password,
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
        connect_timeout_seconds: Option<u64>,
        pre_collected_password: Option<Arc<Password>>,
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
                connect_timeout_seconds,
                pre_collected_password,
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
        connect_timeout_seconds: Option<u64>,
        pre_collected_password: Option<Arc<Password>>,
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
                connect_timeout_seconds,
                pre_collected_password,
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
    #[allow(clippy::too_many_arguments)]
    async fn connect_for_file_transfer(
        &self,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        operation_desc: &str,
        connect_timeout_seconds: Option<u64>,
        pre_collected_password: Option<Arc<Password>>,
    ) -> Result<Client> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!(
            "Connecting to {}:{} for {}",
            self.host,
            self.port,
            operation_desc
        );

        // Determine authentication method based on parameters
        // Note: use_keychain is set to false for file transfers to avoid prompts
        let auth_method = self
            .determine_auth_method(
                key_path,
                use_agent,
                use_password,
                #[cfg(target_os = "macos")]
                false,
                pre_collected_password,
            )
            .await?;

        // Set up host key checking
        let check_method = if let Some(mode) = strict_mode {
            crate::ssh::known_hosts::get_check_method(mode)
        } else {
            crate::ssh::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew)
        };

        // Connect and authenticate with timeout
        let timeout_secs = connect_timeout_seconds.unwrap_or(SSH_CONNECT_TIMEOUT_SECS);
        let connect_timeout = Duration::from_secs(timeout_secs);
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
                Err(anyhow::Error::new(e).context(detailed))
            }
            Err(_) => Err(anyhow::anyhow!(
                "Connection timeout after {timeout_secs} seconds. Host may be unreachable or SSH service not running."
            )),
        }
    }

    /// Helper function to connect for file transfer with jump hosts
    #[allow(clippy::too_many_arguments)]
    async fn connect_for_transfer_with_jump_hosts(
        &self,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
        use_password: bool,
        jump_hosts_spec: Option<&str>,
        connect_timeout_seconds: Option<u64>,
        pre_collected_password: Option<Arc<Password>>,
    ) -> Result<Client> {
        // Determine authentication method
        // Note: use_keychain is set to false for file transfers to avoid prompts
        let auth_method = self
            .determine_auth_method(
                key_path,
                use_agent,
                use_password,
                #[cfg(target_os = "macos")]
                false,
                pre_collected_password.clone(),
            )
            .await?;

        let strict_mode = strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew);

        // Create client connection - either direct or through jump hosts.
        // Threading `pre_collected_password` here ensures jump-host auth
        // (when `--password` is combined with `-J`) consumes the dispatcher's
        // single up-front prompt instead of re-prompting per jump. See #200.
        self.establish_connection(
            &auth_method,
            strict_mode,
            jump_hosts_spec,
            key_path,
            use_agent,
            use_password,
            connect_timeout_seconds,
            None,
            pre_collected_password,
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
        // The inner key error is not interpolated here: the `KeyInvalid`
        // variant's own `Display` already includes it, and this message is the
        // outer context layer, so echoing it would print it twice.
        crate::ssh::tokio_client::Error::KeyInvalid(_) => {
            format!("{context} failed: Invalid SSH key")
        }
        crate::ssh::tokio_client::Error::ServerCheckFailed => {
            format!(
                "{context} failed: Host key verification failed, the server's host key is not trusted"
            )
        }
        crate::ssh::tokio_client::Error::HostKeyChanged { host, port, .. } => {
            // Name the entry as known_hosts records it, so the command also
            // works for non-standard ports, and double quote it so zsh does not
            // reject the unmatched `[...]` glob. No `-f` here: this path has no
            // known_hosts path to hand, and production always uses the default
            // file, which `ssh-keygen` picks itself.
            let entry =
                crate::ssh::tokio_client::host_verification::known_hosts_entry_name(host, *port);
            format!(
                "{context} failed: Possible man-in-the-middle attack, remove the old known_hosts entry with 'ssh-keygen -R \"{entry}\"' only if the key change is expected"
            )
        }
        crate::ssh::tokio_client::Error::PasswordWrong => {
            format!("{context} failed: Password authentication rejected")
        }
        crate::ssh::tokio_client::Error::AgentConnectionFailed => {
            format!("{context} failed: Cannot connect to SSH agent, ensure SSH_AUTH_SOCK is set")
        }
        crate::ssh::tokio_client::Error::AgentNoIdentities => {
            format!("{context} failed: SSH agent has no keys, use 'ssh-add' to add your key")
        }
        crate::ssh::tokio_client::Error::AgentAuthenticationFailed => {
            format!("{context} failed: SSH agent authentication rejected")
        }
        _ => format!("{context} failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_for_file_transfer_error_ordering_puts_friendly_message_first() {
        // Regression test for issue #238's readability defect: `detailed`
        // must be the OUTER context so `{:#}` renders it first, followed by
        // the underlying cause, instead of the reverse.
        let e = crate::ssh::tokio_client::Error::PasswordWrong;
        let context = "SSH connection to host:22".to_string();
        let detailed = format_ssh_error(&context, &e);
        let err = anyhow::Error::new(e).context(detailed.clone());

        let rendered = format!("{err:#}");
        assert!(
            rendered.starts_with(&detailed),
            "expected friendly message first, got: {rendered}"
        );
        assert!(
            rendered[detailed.len()..].contains("Password authentication failed"),
            "expected the cause to appear after the friendly message, got: {rendered}"
        );
    }

    #[test]
    fn test_format_ssh_error_does_not_duplicate_inner_key_error() {
        // `KeyInvalid`'s own `Display` already interpolates the underlying key
        // error, so this outer context layer must not interpolate it again.
        let key_err = russh::keys::Error::KeyIsCorrupt;
        let inner_text = key_err.to_string();
        let e = crate::ssh::tokio_client::Error::KeyInvalid(key_err);
        let context = "SSH connection to host:22".to_string();

        let detailed = format_ssh_error(&context, &e);
        assert!(
            !detailed.contains(&inner_text),
            "context must not echo the inner key error, got: {detailed}"
        );

        let rendered = format!("{:#}", anyhow::Error::new(e).context(detailed));
        assert_eq!(
            rendered.matches(inner_text.as_str()).count(),
            1,
            "inner key error should appear exactly once, got: {rendered}"
        );
    }

    #[test]
    fn test_format_ssh_error_messages_have_no_trailing_period() {
        // `{:#}` joins layers with ": ", so a trailing period would render as
        // the awkward sequence ".: " in the middle of a line.
        let context = "SSH connection to host:22".to_string();
        for e in [
            crate::ssh::tokio_client::Error::KeyAuthFailed,
            crate::ssh::tokio_client::Error::ServerCheckFailed,
            crate::ssh::tokio_client::Error::PasswordWrong,
            crate::ssh::tokio_client::Error::AgentConnectionFailed,
            crate::ssh::tokio_client::Error::AgentNoIdentities,
            crate::ssh::tokio_client::Error::AgentAuthenticationFailed,
            crate::ssh::tokio_client::Error::HostKeyChanged {
                host: "node1.example.com".to_string(),
                port: 22,
                line: 3,
            },
            crate::ssh::tokio_client::Error::HostKeyChanged {
                host: "node1.example.com".to_string(),
                port: 2222,
                line: 3,
            },
        ] {
            let detailed = format_ssh_error(&context, &e);
            assert!(
                !detailed.ends_with('.'),
                "context message must not end with a period, got: {detailed}"
            );
        }
    }

    #[test]
    fn test_format_ssh_error_host_key_changed_adds_guidance_without_echo() {
        // The changed-key context layer must point at the offending entry's
        // removal command without restating the cause's own wording, which
        // would render twice through anyhow's `{:#}` form (#239, #238).
        let e = crate::ssh::tokio_client::Error::HostKeyChanged {
            host: "node1.example.com".to_string(),
            port: 22,
            line: 7,
        };
        let cause_text = e.to_string();
        let context = "SFTP upload to host:22".to_string();

        let detailed = format_ssh_error(&context, &e);
        assert!(
            detailed.contains("ssh-keygen -R \"node1.example.com\""),
            "guidance must include the removal command, got: {detailed}"
        );
        assert!(
            !detailed.contains("has changed and no longer matches"),
            "context must not restate the cause, got: {detailed}"
        );

        let rendered = format!("{:#}", anyhow::Error::new(e).context(detailed));
        assert_eq!(
            rendered.matches(cause_text.as_str()).count(),
            1,
            "cause text should appear exactly once, got: {rendered}"
        );
    }

    #[test]
    fn test_format_ssh_error_host_key_changed_names_port_qualified_entry() {
        // known_hosts records a non-standard port as `[host]:port`, so
        // `ssh-keygen -R host` would remove nothing and leave the user stuck.
        // The guidance must name the entry that actually exists, quoted so the
        // unmatched `[...]` glob does not make zsh reject the command.
        let e = crate::ssh::tokio_client::Error::HostKeyChanged {
            host: "node1.example.com".to_string(),
            port: 2222,
            line: 7,
        };
        let context = "SFTP upload to host:2222".to_string();

        let detailed = format_ssh_error(&context, &e);
        assert!(
            detailed.contains("ssh-keygen -R \"[node1.example.com]:2222\""),
            "guidance must name the port-qualified entry, got: {detailed}"
        );
        assert!(
            !detailed.contains("has changed and no longer matches"),
            "context must not restate the cause, got: {detailed}"
        );
    }

    #[test]
    fn test_format_ssh_error_catch_all_does_not_duplicate_cause() {
        // The catch-all arm used to interpolate `{e}` directly into the
        // detailed message; once nesting is corrected that would print the
        // cause's text twice. It must not repeat the variant's own text.
        let e = crate::ssh::tokio_client::Error::CommandDidntExit;
        let context = "SSH connection to host:22".to_string();
        let detailed = format_ssh_error(&context, &e);
        assert_eq!(detailed, "SSH connection to host:22 failed");

        let cause_text = e.to_string();
        let err = anyhow::Error::new(e).context(detailed);
        let rendered = format!("{err:#}");
        assert_eq!(
            rendered.matches(cause_text.as_str()).count(),
            1,
            "cause text should appear exactly once, got: {rendered}"
        );
    }
}

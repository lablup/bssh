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
use anyhow::{Context, Result};
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
        use_agent: bool,
    ) -> Result<CommandResult> {
        self.connect_and_execute_with_host_check(command, key_path, None, use_agent)
            .await
    }

    pub async fn connect_and_execute_with_host_check(
        &mut self,
        command: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
    ) -> Result<CommandResult> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!("Connecting to {}:{}", self.host, self.port);

        // Determine authentication method based on parameters
        let auth_method = self.determine_auth_method(key_path, use_agent)?;

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

    pub async fn upload_file(
        &mut self,
        local_path: &Path,
        remote_path: &str,
        key_path: Option<&Path>,
        strict_mode: Option<StrictHostKeyChecking>,
        use_agent: bool,
    ) -> Result<()> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!("Connecting to {}:{} for file copy", self.host, self.port);

        // Determine authentication method based on parameters
        let auth_method = self.determine_auth_method(key_path, use_agent)?;

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
            "Uploading file {:?} ({} bytes) to {}:{} using SFTP",
            local_path,
            file_size,
            self.host,
            remote_path
        );

        // Use the built-in upload_file method with timeout (SFTP-based)
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
    ) -> Result<()> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!(
            "Connecting to {}:{} for file download",
            self.host,
            self.port
        );

        // Determine authentication method based on parameters
        let auth_method = self.determine_auth_method(key_path, use_agent)?;

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
        let download_timeout = Duration::from_secs(300); // 5 minutes for file download
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
    ) -> Result<()> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!(
            "Connecting to {}:{} for directory upload",
            self.host,
            self.port
        );

        // Determine authentication method based on parameters
        let auth_method = self.determine_auth_method(key_path, use_agent)?;

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
            Client::connect(addr, &self.username, auth_method, check_method),
        )
        .await
        .with_context(|| format!("Connection timeout: Failed to connect to {}:{} after 30 seconds. Please check if the host is reachable and SSH service is running.", self.host, self.port))?
        .with_context(|| format!("SSH connection failed to {}:{}. Please verify the hostname, port, and authentication credentials.", self.host, self.port))?;

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
        let upload_timeout = Duration::from_secs(600); // 10 minutes for directory upload
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
    ) -> Result<()> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!(
            "Connecting to {}:{} for directory download",
            self.host,
            self.port
        );

        // Determine authentication method based on parameters
        let auth_method = self.determine_auth_method(key_path, use_agent)?;

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
            Client::connect(addr, &self.username, auth_method, check_method),
        )
        .await
        .with_context(|| format!("Connection timeout: Failed to connect to {}:{} after 30 seconds. Please check if the host is reachable and SSH service is running.", self.host, self.port))?
        .with_context(|| format!("SSH connection failed to {}:{}. Please verify the hostname, port, and authentication credentials.", self.host, self.port))?;

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
        let download_timeout = Duration::from_secs(600); // 10 minutes for directory download
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
    ) -> Result<AuthMethod> {
        // If SSH agent is explicitly requested, try that first
        if use_agent {
            #[cfg(not(target_os = "windows"))]
            {
                // Check if SSH_AUTH_SOCK is available
                if std::env::var("SSH_AUTH_SOCK").is_ok() {
                    tracing::debug!("Using SSH agent for authentication");
                    return Ok(AuthMethod::Agent);
                } else {
                    tracing::warn!(
                        "SSH agent requested but SSH_AUTH_SOCK environment variable not set"
                    );
                    // Fall through to key file authentication
                }
            }
            #[cfg(target_os = "windows")]
            {
                anyhow::bail!("SSH agent authentication is not supported on Windows");
            }
        }

        // Try key file authentication
        if let Some(key_path) = key_path {
            tracing::debug!("Authenticating with key: {:?}", key_path);
            return Ok(AuthMethod::with_key_file(key_path, None));
        }

        // If no explicit key path, try SSH agent if available (auto-detect)
        #[cfg(not(target_os = "windows"))]
        if !use_agent && std::env::var("SSH_AUTH_SOCK").is_ok() {
            tracing::debug!("SSH agent detected, attempting agent authentication");
            return Ok(AuthMethod::Agent);
        }

        // Fallback to default key location
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let default_key = Path::new(&home).join(".ssh").join("id_rsa");

        if default_key.exists() {
            tracing::debug!("Using default key: {:?}", default_key);
            Ok(AuthMethod::with_key_file(default_key, None))
        } else {
            anyhow::bail!(
                "SSH authentication failed: No authentication method available.\n\
                 Tried:\n\
                 - SSH agent (SSH_AUTH_SOCK not set or agent not available)\n\
                 - Default key file (~/.ssh/id_rsa not found)\n\
                 \n\
                 Solutions:\n\
                 - Start SSH agent and add keys with 'ssh-add'\n\
                 - Specify a key file with -i/--identity\n\
                 - Create a default key at ~/.ssh/id_rsa"
            );
        }
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
            .determine_auth_method(Some(&key_path), false)
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
        let auth = client.determine_auth_method(None, true).unwrap();

        match auth {
            AuthMethod::Agent => {}
            _ => panic!("Expected Agent auth method"),
        }

        unsafe {
            std::env::remove_var("SSH_AUTH_SOCK");
        }
    }

    #[test]
    fn test_determine_auth_method_fallback_to_default() {
        // Create a fake home directory with default key
        let temp_dir = TempDir::new().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let default_key = ssh_dir.join("id_rsa");
        std::fs::write(&default_key, "fake key").unwrap();

        unsafe {
            std::env::set_var("HOME", temp_dir.path().to_str().unwrap());
            std::env::remove_var("SSH_AUTH_SOCK");
        }

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client.determine_auth_method(None, false).unwrap();

        match auth {
            AuthMethod::PrivateKeyFile { key_file_path, .. } => {
                assert_eq!(key_file_path, default_key);
            }
            _ => panic!("Expected PrivateKeyFile auth method"),
        }
    }
}

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

use futures::TryStreamExt;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::error::{SftpError, SftpResult};
use super::session::SshSession;

/// File and directory operations using SFTP
impl SshSession {
    /// Upload a single file to the remote server
    pub async fn upload_file<P: AsRef<Path>>(
        &mut self,
        local_path: P,
        remote_path: &str,
    ) -> SftpResult<()> {
        let local_path = local_path.as_ref();
        
        tracing::debug!(
            "Uploading file {:?} to {}:{}",
            local_path,
            self.host,
            remote_path
        );

        // Check if local file exists
        if !local_path.exists() {
            return Err(SftpError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Local file does not exist: {:?}", local_path),
            )));
        }

        let metadata = tokio::fs::metadata(local_path).await
            .map_err(|e| SftpError::Io(e))?;

        if !metadata.is_file() {
            return Err(SftpError::generic(format!(
                "Path is not a file: {:?}",
                local_path
            )));
        }

        let file_size = metadata.len();
        tracing::debug!("File size: {} bytes", file_size);

        // Read local file
        let mut local_file = tokio::fs::File::open(local_path).await
            .map_err(|e| SftpError::Io(e))?;

        let mut buffer = Vec::new();
        local_file.read_to_end(&mut buffer).await
            .map_err(|e| SftpError::Io(e))?;

        // Get SFTP session
        let sftp = self.sftp()?;

        // Create remote file
        let mut remote_file = sftp
            .create(remote_path)
            .await
            .map_err(|e| SftpError::Sftp(e))?;

        // Write data to remote file
        remote_file.write_all(&buffer).await
            .map_err(|e| SftpError::Sftp(e))?;

        remote_file.shutdown().await
            .map_err(|e| SftpError::Sftp(e))?;

        tracing::debug!("File upload completed successfully");
        Ok(())
    }

    /// Download a single file from the remote server
    pub async fn download_file<P: AsRef<Path>>(
        &mut self,
        remote_path: &str,
        local_path: P,
    ) -> SftpResult<()> {
        let local_path = local_path.as_ref();
        
        tracing::debug!(
            "Downloading file from {}:{} to {:?}",
            self.host,
            remote_path,
            local_path
        );

        // Create parent directory if it doesn't exist
        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| SftpError::Io(e))?;
        }

        // Get SFTP session
        let sftp = self.sftp()?;

        // Open remote file
        let mut remote_file = sftp
            .open(remote_path)
            .await
            .map_err(|e| SftpError::Sftp(e))?;

        // Read remote file content
        let mut buffer = Vec::new();
        remote_file.read_to_end(&mut buffer).await
            .map_err(|e| SftpError::Sftp(e))?;

        // Write to local file
        tokio::fs::write(local_path, buffer).await
            .map_err(|e| SftpError::Io(e))?;

        tracing::debug!("File download completed successfully");
        Ok(())
    }

    /// Upload a directory recursively
    pub async fn upload_dir<P: AsRef<Path>>(
        &mut self,
        local_dir: P,
        remote_dir: &str,
    ) -> SftpResult<()> {
        let local_dir = local_dir.as_ref();
        
        tracing::debug!(
            "Uploading directory {:?} to {}:{}",
            local_dir,
            self.host,
            remote_dir
        );

        if !local_dir.exists() {
            return Err(SftpError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Local directory does not exist: {:?}", local_dir),
            )));
        }

        if !local_dir.is_dir() {
            return Err(SftpError::generic(format!(
                "Path is not a directory: {:?}",
                local_dir
            )));
        }

        // Create remote directory
        self.create_dir_recursive(remote_dir).await?;

        // Upload directory contents recursively
        self.upload_dir_contents(local_dir, remote_dir).await?;

        tracing::debug!("Directory upload completed successfully");
        Ok(())
    }

    /// Download a directory recursively
    pub async fn download_dir<P: AsRef<Path>>(
        &mut self,
        remote_dir: &str,
        local_dir: P,
    ) -> SftpResult<()> {
        let local_dir = local_dir.as_ref();
        
        tracing::debug!(
            "Downloading directory from {}:{} to {:?}",
            self.host,
            remote_dir,
            local_dir
        );

        // Create local directory
        tokio::fs::create_dir_all(local_dir).await
            .map_err(|e| SftpError::Io(e))?;

        // Download directory contents recursively
        self.download_dir_contents(remote_dir, local_dir).await?;

        tracing::debug!("Directory download completed successfully");
        Ok(())
    }

    /// Create a directory recursively on the remote server
    async fn create_dir_recursive(&mut self, remote_path: &str) -> SftpResult<()> {
        let sftp = self.sftp()?;

        // Try to create the directory
        match sftp.create_dir(remote_path).await {
            Ok(_) => {
                tracing::debug!("Created remote directory: {}", remote_path);
                Ok(())
            }
            Err(russh_sftp::client::error::Error::Sftp(russh_sftp::protocol::StatusCode::Failure)) => {
                // Directory might already exist, which is fine
                tracing::debug!("Remote directory already exists or creation failed: {}", remote_path);
                Ok(())
            }
            Err(e) => {
                // Try creating parent directories
                if let Some(parent) = Path::new(remote_path).parent() {
                    if let Some(parent_str) = parent.to_str() {
                        if !parent_str.is_empty() && parent_str != "/" {
                            self.create_dir_recursive(parent_str).await?;
                            // Try creating the directory again
                            return match sftp.create_dir(remote_path).await {
                                Ok(_) => Ok(()),
                                Err(russh_sftp::client::error::Error::Sftp(russh_sftp::protocol::StatusCode::Failure)) => Ok(()),
                                Err(e) => Err(SftpError::Sftp(e)),
                            };
                        }
                    }
                }
                Err(SftpError::Sftp(e))
            }
        }
    }

    /// Upload directory contents recursively
    async fn upload_dir_contents<P: AsRef<Path>>(
        &mut self,
        local_dir: P,
        remote_dir: &str,
    ) -> SftpResult<()> {
        let local_dir = local_dir.as_ref();
        
        let mut entries = tokio::fs::read_dir(local_dir).await
            .map_err(|e| SftpError::Io(e))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| SftpError::Io(e))? {
            
            let local_path = entry.path();
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            
            let remote_path = if remote_dir.ends_with('/') {
                format!("{}{}", remote_dir, file_name_str)
            } else {
                format!("{}/{}", remote_dir, file_name_str)
            };

            let metadata = entry.metadata().await
                .map_err(|e| SftpError::Io(e))?;

            if metadata.is_file() {
                tracing::debug!("Uploading file: {:?} -> {}", local_path, remote_path);
                self.upload_file(&local_path, &remote_path).await?;
            } else if metadata.is_dir() {
                tracing::debug!("Uploading directory: {:?} -> {}", local_path, remote_path);
                self.create_dir_recursive(&remote_path).await?;
                self.upload_dir_contents(&local_path, &remote_path).await?;
            }
        }

        Ok(())
    }

    /// Download directory contents recursively
    async fn download_dir_contents<P: AsRef<Path>>(
        &mut self,
        remote_dir: &str,
        local_dir: P,
    ) -> SftpResult<()> {
        let local_dir = local_dir.as_ref();
        let sftp = self.sftp()?;

        // Read remote directory contents
        let mut entries = sftp.read_dir(remote_dir).await
            .map_err(|e| SftpError::Sftp(e))?;

        while let Some(entry) = entries.try_next().await
            .map_err(|e| SftpError::Sftp(e))? {
            
            let file_name = entry.filename();
            let remote_path = if remote_dir.ends_with('/') {
                format!("{}{}", remote_dir, file_name)
            } else {
                format!("{}/{}", remote_dir, file_name)
            };
            
            let local_path = local_dir.join(file_name);

            let attrs = entry.attrs();
            
            if attrs.is_dir() {
                tracing::debug!("Downloading directory: {} -> {:?}", remote_path, local_path);
                tokio::fs::create_dir_all(&local_path).await
                    .map_err(|e| SftpError::Io(e))?;
                self.download_dir_contents(&remote_path, &local_path).await?;
            } else if attrs.is_file() {
                tracing::debug!("Downloading file: {} -> {:?}", remote_path, local_path);
                self.download_file(&remote_path, &local_path).await?;
            }
        }

        Ok(())
    }
}
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

//! SFTP file transfer operations.
//!
//! This module provides file transfer capabilities including:
//! - Single file upload/download
//! - Recursive directory upload/download
//! - Support for glob patterns

use russh_sftp::{client::SftpSession, protocol::OpenFlags};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Chunk size used for streaming SFTP uploads/downloads.
///
/// Sized to match SFTP's standard MAX_WRITE_LENGTH (255 KiB) so each chunk maps
/// to a single SFTP WRITE/READ packet without further fragmentation.
const STREAM_CHUNK_SIZE: usize = 256 * 1024;

/// Stream `reader` to `writer` in fixed-size chunks so a single transfer never
/// holds more than `STREAM_CHUNK_SIZE` of file payload in memory at once.
async fn stream_copy<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    Ok(total)
}

use super::connection::Client;

impl Client {
    /// Upload a file with sftp to the remote server.
    ///
    /// `src_file_path` is the path to the file on the local machine.
    /// `dest_file_path` is the path to the file on the remote machine.
    /// Some sshd_config does not enable sftp by default, so make sure it is enabled.
    /// A config line like a `Subsystem sftp internal-sftp` or
    /// `Subsystem sftp /usr/lib/openssh/sftp-server` is needed in the sshd_config in remote machine.
    pub async fn upload_file<T: AsRef<Path>, U: Into<String>>(
        &self,
        src_file_path: T,
        //fa993: This cannot be AsRef<Path> because of underlying lib constraints as described here
        //https://github.com/AspectUnk/russh-sftp/issues/7#issuecomment-1738355245
        dest_file_path: U,
    ) -> Result<(), super::Error> {
        // start sftp session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // Open local file for streaming reads (avoids loading whole file in memory).
        let mut local_file = tokio::fs::File::open(src_file_path)
            .await
            .map_err(super::Error::IoError)?;

        let mut file = sftp
            .open_with_flags(
                dest_file_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
            )
            .await?;
        stream_copy(&mut local_file, &mut file)
            .await
            .map_err(super::Error::IoError)?;
        file.flush().await.map_err(super::Error::IoError)?;
        file.shutdown().await.map_err(super::Error::IoError)?;

        Ok(())
    }

    /// Download a file from the remote server using sftp.
    ///
    /// `remote_file_path` is the path to the file on the remote machine.
    /// `local_file_path` is the path to the file on the local machine.
    /// Some sshd_config does not enable sftp by default, so make sure it is enabled.
    /// A config line like a `Subsystem sftp internal-sftp` or
    /// `Subsystem sftp /usr/lib/openssh/sftp-server` is needed in the sshd_config in remote machine.
    pub async fn download_file<T: AsRef<Path>, U: Into<String>>(
        &self,
        remote_file_path: U,
        local_file_path: T,
    ) -> Result<(), super::Error> {
        // start sftp session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // open remote file for reading
        let mut remote_file = sftp
            .open_with_flags(remote_file_path, OpenFlags::READ)
            .await?;

        // Stream remote file directly to local disk to avoid buffering the
        // whole file in memory.
        let mut local_file = tokio::fs::File::create(local_file_path.as_ref())
            .await
            .map_err(super::Error::IoError)?;
        stream_copy(&mut remote_file, &mut local_file)
            .await
            .map_err(super::Error::IoError)?;
        local_file.flush().await.map_err(super::Error::IoError)?;

        Ok(())
    }

    /// Upload a directory to the remote server using sftp recursively.
    ///
    /// `local_dir_path` is the path to the directory on the local machine.
    /// `remote_dir_path` is the path to the directory on the remote machine.
    /// All files and subdirectories will be uploaded recursively.
    pub async fn upload_dir<T: AsRef<Path>, U: Into<String>>(
        &self,
        local_dir_path: T,
        remote_dir_path: U,
    ) -> Result<(), super::Error> {
        let local_dir = local_dir_path.as_ref();
        let remote_dir = remote_dir_path.into();

        // Verify local directory exists
        if !local_dir.is_dir() {
            return Err(super::Error::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Local directory does not exist: {local_dir:?}"),
            )));
        }

        // Start SFTP session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // Create remote directory if it doesn't exist
        let _ = sftp.create_dir(&remote_dir).await; // Ignore error if already exists

        // Process directory recursively
        self.upload_dir_recursive(&sftp, local_dir, &remote_dir)
            .await?;

        Ok(())
    }

    /// Helper function to recursively upload directory contents
    #[allow(clippy::only_used_in_recursion)]
    fn upload_dir_recursive<'a>(
        &'a self,
        sftp: &'a SftpSession,
        local_dir: &'a Path,
        remote_dir: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), super::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            // Read local directory contents
            let entries = tokio::fs::read_dir(local_dir)
                .await
                .map_err(super::Error::IoError)?;

            let mut entries = entries;
            while let Some(entry) = entries.next_entry().await.map_err(super::Error::IoError)? {
                let path = entry.path();
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();
                let remote_path = format!("{remote_dir}/{file_name_str}");

                let metadata = entry.metadata().await.map_err(super::Error::IoError)?;

                if metadata.is_dir() {
                    // Create remote directory and recurse
                    let _ = sftp.create_dir(&remote_path).await; // Ignore error if already exists
                    self.upload_dir_recursive(sftp, &path, &remote_path).await?;
                } else if metadata.is_file() {
                    // Stream local file to remote in chunks instead of loading
                    // the entire file in memory before send.
                    let mut local_file = tokio::fs::File::open(&path)
                        .await
                        .map_err(super::Error::IoError)?;

                    let mut remote_file = sftp
                        .open_with_flags(
                            &remote_path,
                            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                        )
                        .await?;

                    stream_copy(&mut local_file, &mut remote_file)
                        .await
                        .map_err(super::Error::IoError)?;
                    remote_file.flush().await.map_err(super::Error::IoError)?;
                    remote_file
                        .shutdown()
                        .await
                        .map_err(super::Error::IoError)?;
                }
            }

            Ok(())
        })
    }

    /// Download a directory from the remote server using sftp recursively.
    ///
    /// `remote_dir_path` is the path to the directory on the remote machine.
    /// `local_dir_path` is the path to the directory on the local machine.
    /// All files and subdirectories will be downloaded recursively.
    pub async fn download_dir<T: AsRef<Path>, U: Into<String>>(
        &self,
        remote_dir_path: U,
        local_dir_path: T,
    ) -> Result<(), super::Error> {
        let local_dir = local_dir_path.as_ref();
        let remote_dir = remote_dir_path.into();

        // Start SFTP session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // Create local directory if it doesn't exist
        tokio::fs::create_dir_all(local_dir)
            .await
            .map_err(super::Error::IoError)?;

        // Process directory recursively
        self.download_dir_recursive(&sftp, &remote_dir, local_dir)
            .await?;

        Ok(())
    }

    /// Helper function to recursively download directory contents
    #[allow(clippy::only_used_in_recursion)]
    fn download_dir_recursive<'a>(
        &'a self,
        sftp: &'a SftpSession,
        remote_dir: &'a str,
        local_dir: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), super::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            // Read remote directory contents
            let entries = sftp.read_dir(remote_dir).await?;

            for entry in entries {
                let name = entry.file_name();
                let metadata = entry.metadata();

                // Skip . and .. (already handled by iterator)
                if name == "." || name == ".." {
                    continue;
                }

                let remote_path = format!("{remote_dir}/{name}");
                let local_path = local_dir.join(&name);

                if metadata.file_type().is_dir() {
                    // Create local directory and recurse
                    tokio::fs::create_dir_all(&local_path)
                        .await
                        .map_err(super::Error::IoError)?;

                    self.download_dir_recursive(sftp, &remote_path, &local_path)
                        .await?;
                } else if metadata.file_type().is_file() {
                    // Stream remote file directly to local disk in chunks.
                    let mut remote_file =
                        sftp.open_with_flags(&remote_path, OpenFlags::READ).await?;

                    let mut local_file = tokio::fs::File::create(&local_path)
                        .await
                        .map_err(super::Error::IoError)?;
                    stream_copy(&mut remote_file, &mut local_file)
                        .await
                        .map_err(super::Error::IoError)?;
                    local_file.flush().await.map_err(super::Error::IoError)?;
                }
            }

            Ok(())
        })
    }
}

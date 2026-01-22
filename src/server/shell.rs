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

//! Shell session handler for interactive SSH sessions.
//!
//! This module implements the shell session functionality for bssh-server,
//! providing users with interactive login shells through SSH.
//!
//! # Architecture
//!
//! A shell session consists of:
//! - A PTY (pseudo-terminal) pair for terminal emulation
//! - A shell process running on the slave side of the PTY
//! - Bidirectional I/O forwarding between SSH channel and PTY master
//!
//! # Example
//!
//! ```ignore
//! use bssh::server::shell::ShellSession;
//! use bssh::server::pty::PtyConfig;
//!
//! let config = PtyConfig::default();
//! let mut session = ShellSession::new(channel_id, config)?;
//! session.start(&user_info, handle).await?;
//! ```

use std::os::fd::{AsRawFd, FromRawFd};
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use russh::server::Handle;
use russh::{ChannelId, CryptoVec};
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot, Mutex};

use super::pty::{PtyConfig, PtyMaster};
use crate::shared::auth_types::UserInfo;

/// Buffer size for I/O operations.
const IO_BUFFER_SIZE: usize = 8192;

/// Shell session managing PTY and shell process.
///
/// Handles the lifecycle of an interactive shell session including:
/// - PTY creation and configuration
/// - Shell process spawning
/// - Bidirectional I/O forwarding
/// - Window resize events
/// - Graceful shutdown
pub struct ShellSession {
    /// The SSH channel ID for this session.
    channel_id: ChannelId,

    /// PTY master handle.
    pty: Arc<Mutex<PtyMaster>>,

    /// Shell child process.
    child: Option<Child>,

    /// Channel to signal shutdown to I/O tasks.
    shutdown_tx: Option<oneshot::Sender<()>>,

    /// Channel to receive data from SSH for writing to PTY.
    data_tx: Option<mpsc::Sender<Vec<u8>>>,
}

impl ShellSession {
    /// Create a new shell session.
    ///
    /// # Arguments
    ///
    /// * `channel_id` - The SSH channel ID for this session
    /// * `config` - PTY configuration from the pty_request
    ///
    /// # Returns
    ///
    /// Returns a new `ShellSession` or an error if PTY creation fails.
    pub fn new(channel_id: ChannelId, config: PtyConfig) -> Result<Self> {
        let pty = PtyMaster::open(config).context("Failed to create PTY")?;

        Ok(Self {
            channel_id,
            pty: Arc::new(Mutex::new(pty)),
            child: None,
            shutdown_tx: None,
            data_tx: None,
        })
    }

    /// Start the shell session.
    ///
    /// Spawns the shell process and starts I/O forwarding tasks.
    ///
    /// # Arguments
    ///
    /// * `user_info` - Information about the authenticated user
    /// * `handle` - The russh session handle for sending data
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the shell was started successfully.
    pub async fn start(&mut self, user_info: &UserInfo, handle: Handle) -> Result<()> {
        // Spawn shell process
        let child = self.spawn_shell(user_info).await?;
        self.child = Some(child);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        // Create data channel for SSH -> PTY forwarding
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(256);
        self.data_tx = Some(data_tx);

        // Start I/O forwarding tasks
        self.start_io_forwarding(handle, shutdown_rx, data_rx)
            .await?;

        Ok(())
    }

    /// Spawn the shell process.
    async fn spawn_shell(&self, user_info: &UserInfo) -> Result<Child> {
        let pty = self.pty.lock().await;
        let slave_path = pty.slave_path().clone();
        let term = pty.config().term.clone();
        drop(pty);

        let shell = user_info.shell.clone();
        let home_dir = user_info.home_dir.clone();
        let username = user_info.username.clone();

        // Open slave PTY
        let slave_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&slave_path)
            .context("Failed to open slave PTY")?;

        // Get raw fd for stdio setup
        let slave_fd = slave_file.as_raw_fd();

        let mut cmd = tokio::process::Command::new(&shell);

        // Login shell flag
        cmd.arg("-l");

        // Set up environment
        cmd.env_clear();
        cmd.env("HOME", &home_dir);
        cmd.env("USER", &username);
        cmd.env("LOGNAME", &username);
        cmd.env("SHELL", &shell);
        cmd.env("TERM", &term);
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");

        // Set working directory
        cmd.current_dir(&home_dir);

        // Set up stdio to use PTY slave
        // SAFETY: The file descriptor is valid and we own it via slave_file
        unsafe {
            cmd.stdin(Stdio::from_raw_fd(slave_fd));
            cmd.stdout(Stdio::from_raw_fd(slave_fd));
            cmd.stderr(Stdio::from_raw_fd(slave_fd));
        }

        // Enable process group management
        cmd.kill_on_drop(true);

        // Create new session and set controlling terminal
        // SAFETY: These are standard POSIX operations for setting up a PTY session
        unsafe {
            cmd.pre_exec(|| {
                // Create new session (become session leader)
                nix::unistd::setsid().map_err(|e| std::io::Error::other(e.to_string()))?;

                // Set controlling terminal
                // TIOCSCTTY with arg 0 means don't steal from another session
                if nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }

        // Spawn the process
        let child = cmd.spawn().context("Failed to spawn shell process")?;

        // Keep slave_file alive until here to prevent fd from being closed too early
        // The fd is now owned by the child process, so we can safely forget the file
        std::mem::forget(slave_file);

        tracing::info!(
            shell = %shell.display(),
            home = %home_dir.display(),
            user = %username,
            "Shell process spawned"
        );

        Ok(child)
    }

    /// Start I/O forwarding between PTY and SSH channel.
    async fn start_io_forwarding(
        &self,
        handle: Handle,
        shutdown_rx: oneshot::Receiver<()>,
        mut data_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        let channel_id = self.channel_id;
        let pty = Arc::clone(&self.pty);

        // Spawn PTY -> SSH forwarding task
        let pty_read = Arc::clone(&pty);
        let handle_read = handle.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; IO_BUFFER_SIZE];

            loop {
                let pty_guard = pty_read.lock().await;
                let read_result = pty_guard.read(&mut buf).await;
                drop(pty_guard);

                match read_result {
                    Ok(0) => {
                        tracing::debug!(channel = ?channel_id, "PTY EOF");
                        break;
                    }
                    Ok(n) => {
                        let data = CryptoVec::from_slice(&buf[..n]);
                        if handle_read.data(channel_id, data).await.is_err() {
                            tracing::debug!(channel = ?channel_id, "Failed to send data to channel");
                            break;
                        }
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            tracing::debug!(
                                channel = ?channel_id,
                                error = %e,
                                "PTY read error"
                            );
                        }
                        break;
                    }
                }
            }

            // Send EOF and close channel
            let _ = handle_read.eof(channel_id).await;
            let _ = handle_read.close(channel_id).await;
        });

        // Spawn SSH -> PTY forwarding task
        let pty_write = Arc::clone(&pty);
        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;

            loop {
                tokio::select! {
                    biased;

                    _ = &mut shutdown_rx => {
                        tracing::debug!(channel = ?channel_id, "Shell session shutdown requested");
                        break;
                    }

                    data = data_rx.recv() => {
                        match data {
                            Some(data) => {
                                let pty_guard = pty_write.lock().await;
                                if let Err(e) = pty_guard.write_all(&data).await {
                                    tracing::debug!(
                                        channel = ?channel_id,
                                        error = %e,
                                        "PTY write error"
                                    );
                                    break;
                                }
                                drop(pty_guard);
                            }
                            None => {
                                tracing::debug!(channel = ?channel_id, "Data channel closed");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle data from SSH channel (forward to PTY).
    ///
    /// # Arguments
    ///
    /// * `data` - Data received from SSH client
    pub async fn handle_data(&self, data: &[u8]) -> Result<()> {
        if let Some(ref tx) = self.data_tx {
            tx.send(data.to_vec())
                .await
                .context("Failed to send data to PTY")?;
        }
        Ok(())
    }

    /// Get a clone of the data sender for forwarding SSH data to PTY.
    ///
    /// Returns None if the session hasn't been started yet.
    pub fn data_sender(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        self.data_tx.clone()
    }

    /// Get a reference to the PTY mutex for resize operations.
    pub fn pty(&self) -> &Arc<Mutex<PtyMaster>> {
        &self.pty
    }

    /// Handle window size change.
    ///
    /// # Arguments
    ///
    /// * `cols` - New window width in columns
    /// * `rows` - New window height in rows
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        let mut pty = self.pty.lock().await;
        pty.resize(cols, rows)
    }

    /// Check if the shell process is still running.
    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }

    /// Wait for the shell process to exit and return the exit code.
    pub async fn wait(&mut self) -> Option<i32> {
        if let Some(ref mut child) = self.child {
            match child.wait().await {
                Ok(status) => status.code(),
                Err(e) => {
                    tracing::warn!(error = %e, "Error waiting for shell process");
                    Some(1)
                }
            }
        } else {
            None
        }
    }

    /// Shutdown the shell session.
    ///
    /// Signals the I/O tasks to stop and waits for the shell process to exit.
    pub async fn shutdown(&mut self) -> Option<i32> {
        // Signal shutdown to I/O tasks
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Drop data channel sender
        self.data_tx.take();

        // Kill the shell process if still running
        if let Some(ref mut child) = self.child {
            let _ = child.kill().await;
            return self.wait().await;
        }

        None
    }
}

impl Drop for ShellSession {
    fn drop(&mut self) {
        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Kill child process if still running
        if let Some(ref mut child) = self.child {
            let _ = child.start_kill();
        }

        tracing::debug!(channel = ?self.channel_id, "Shell session dropped");
    }
}

impl std::fmt::Debug for ShellSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShellSession")
            .field("channel_id", &self.channel_id)
            .field("has_child", &self.child.is_some())
            .field("has_data_tx", &self.data_tx.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full shell session tests require integration testing with
    // actual russh channels. These unit tests cover the basic structures.

    #[test]
    fn test_io_buffer_size() {
        // Verify buffer size is reasonable
        assert!(IO_BUFFER_SIZE >= 4096);
        assert!(IO_BUFFER_SIZE <= 65536);
    }
}

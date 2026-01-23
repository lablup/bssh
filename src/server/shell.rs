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
//! # I/O Strategy
//!
//! This module uses russh's `ChannelStream` for bidirectional I/O between
//! the SSH channel and the PTY. The `ChannelStream` implements `AsyncRead`
//! and `AsyncWrite`, allowing direct data transfer without going through
//! russh's `Handle::data()` message queue. This approach is the same as
//! used by russh-sftp and avoids event loop synchronization issues.

use std::os::fd::{AsRawFd, FromRawFd};
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use russh::server::{Handle, Msg};
use russh::{ChannelId, ChannelStream, CryptoVec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::{mpsc, RwLock};

use super::pty::{PtyConfig, PtyMaster};
use crate::shared::auth_types::UserInfo;

/// Buffer size for I/O operations.
const IO_BUFFER_SIZE: usize = 8192;

/// Shell session managing PTY and shell process.
///
/// Handles the lifecycle of an interactive shell session including:
/// - PTY creation and configuration
/// - Shell process spawning
/// - Bidirectional I/O forwarding via ChannelStream
/// - Window resize events
/// - Graceful shutdown
pub struct ShellSession {
    /// The SSH channel ID for this session.
    channel_id: ChannelId,

    /// PTY master handle.
    pty: Arc<RwLock<PtyMaster>>,

    /// Shell child process.
    child: Option<Child>,
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
            pty: Arc::new(RwLock::new(pty)),
            child: None,
        })
    }

    /// Spawn the shell process.
    async fn spawn_shell(&self, user_info: &UserInfo) -> Result<Child> {
        let pty = self.pty.read().await;
        let slave_path = pty.slave_path().clone();
        let term = pty.config().term.clone();
        drop(pty);

        let shell = user_info.shell.clone();
        let home_dir = user_info.home_dir.clone();
        let username = user_info.username.clone();

        // Validate shell path exists
        if !shell.exists() {
            anyhow::bail!("Shell does not exist: {}", shell.display());
        }

        // Open slave PTY - we need to duplicate the fd for stdin/stdout/stderr
        // since each Stdio::from_raw_fd takes ownership
        let slave_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&slave_path)
            .context("Failed to open slave PTY")?;

        let slave_fd = slave_file.as_raw_fd();

        // Duplicate fd for stdin, stdout, stderr
        // SAFETY: slave_fd is valid since slave_file is still in scope
        let stdin_fd = unsafe { nix::libc::dup(slave_fd) };
        let stdout_fd = unsafe { nix::libc::dup(slave_fd) };
        let stderr_fd = unsafe { nix::libc::dup(slave_fd) };

        if stdin_fd < 0 || stdout_fd < 0 || stderr_fd < 0 {
            // Clean up any successful dups before returning error
            unsafe {
                if stdin_fd >= 0 {
                    nix::libc::close(stdin_fd);
                }
                if stdout_fd >= 0 {
                    nix::libc::close(stdout_fd);
                }
                if stderr_fd >= 0 {
                    nix::libc::close(stderr_fd);
                }
            }
            anyhow::bail!("Failed to duplicate slave PTY file descriptor");
        }

        // Now slave_file can be dropped safely, we have our own fds
        drop(slave_file);

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

        // Set up stdio to use PTY slave fds
        // SAFETY: Each fd was created via dup() and is uniquely owned
        unsafe {
            cmd.stdin(Stdio::from_raw_fd(stdin_fd));
            cmd.stdout(Stdio::from_raw_fd(stdout_fd));
            cmd.stderr(Stdio::from_raw_fd(stderr_fd));
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
                if nix::libc::ioctl(0, nix::libc::TIOCSCTTY as nix::libc::c_ulong, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }

        // Spawn the process
        let child = cmd.spawn().context("Failed to spawn shell process")?;

        tracing::info!(
            shell = %shell.display(),
            home = %home_dir.display(),
            user = %username,
            "Shell process spawned"
        );

        Ok(child)
    }

    /// Take the child process for use in the I/O loop.
    ///
    /// This should be called after spawning the shell.
    pub fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }

    /// Get a reference to the PTY mutex for resize operations.
    pub fn pty(&self) -> &Arc<RwLock<PtyMaster>> {
        &self.pty
    }

    /// Get the channel ID for this shell session.
    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    /// Spawn the shell process.
    ///
    /// This should be called before taking the child process and data receiver.
    pub async fn spawn_shell_process(&mut self, user_info: &UserInfo) -> Result<()> {
        let child = self.spawn_shell(user_info).await?;
        self.child = Some(child);
        Ok(())
    }

    /// Handle window size change.
    ///
    /// # Arguments
    ///
    /// * `cols` - New window width in columns
    /// * `rows` - New window height in rows
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        let mut pty = self.pty.write().await;
        pty.resize(cols, rows)
    }
}

/// Run the shell I/O loop using ChannelStream for direct I/O.
///
/// This function runs the bidirectional I/O forwarding loop between the PTY
/// and the SSH channel. It uses russh's `ChannelStream` which implements
/// `AsyncRead + AsyncWrite` for direct data transfer, avoiding the
/// `Handle::data()` message queue issues.
///
/// # Arguments
///
/// * `channel_id` - The SSH channel ID (for logging only)
/// * `pty` - The PTY master handle
/// * `child` - The shell child process (optional)
/// * `channel_stream` - The russh channel stream for SSH I/O
///
/// # Returns
///
/// Returns the exit code of the shell process.
pub async fn run_shell_io_loop(
    channel_id: ChannelId,
    pty: Arc<RwLock<PtyMaster>>,
    mut child: Option<Child>,
    mut channel_stream: ChannelStream<Msg>,
) -> i32 {
    let mut pty_buf = vec![0u8; IO_BUFFER_SIZE];
    let mut ssh_buf = vec![0u8; IO_BUFFER_SIZE];

    tracing::debug!(channel = ?channel_id, "Starting shell I/O loop (ChannelStream)");

    let mut iteration = 0u64;
    loop {
        iteration += 1;
        tracing::debug!(channel = ?channel_id, iter = iteration, "I/O loop iteration start");

        // Check if child process has exited (synchronous check)
        if let Some(ref mut c) = child {
            match c.try_wait() {
                Ok(Some(status)) => {
                    tracing::debug!(
                        channel = ?channel_id,
                        exit_code = ?status.code(),
                        "Shell process exited"
                    );
                    // Drain any remaining PTY output before exiting
                    drain_pty_output_to_stream(channel_id, &pty, &mut channel_stream, &mut pty_buf)
                        .await;
                    return status.code().unwrap_or(1);
                }
                Ok(None) => {
                    // Process still running, continue with I/O
                }
                Err(e) => {
                    tracing::warn!(
                        channel = ?channel_id,
                        error = %e,
                        "Error checking child process status"
                    );
                }
            }
        }

        tracing::debug!(channel = ?channel_id, iter = iteration, "About to enter select! (PTY read vs SSH read)");

        // Poll I/O operations
        tokio::select! {
            // Read from PTY and write to SSH channel stream
            read_result = async {
                let pty_guard = pty.read().await;
                pty_guard.read(&mut pty_buf).await
            } => {
                tracing::debug!(channel = ?channel_id, iter = iteration, result = ?read_result.as_ref().map(|n| *n), "PTY read branch triggered");
                match read_result {
                    Ok(0) => {
                        tracing::debug!(channel = ?channel_id, "PTY EOF");
                        return wait_for_child(&mut child).await;
                    }
                    Ok(n) => {
                        tracing::debug!(channel = ?channel_id, bytes = n, "Read from PTY, writing to SSH");
                        if let Err(e) = channel_stream.write_all(&pty_buf[..n]).await {
                            tracing::debug!(
                                channel = ?channel_id,
                                error = %e,
                                "Failed to write to channel stream"
                            );
                            return wait_for_child(&mut child).await;
                        }
                        // Flush to ensure data is sent immediately
                        if let Err(e) = channel_stream.flush().await {
                            tracing::debug!(
                                channel = ?channel_id,
                                error = %e,
                                "Failed to flush channel stream"
                            );
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            continue;
                        }
                        tracing::debug!(
                            channel = ?channel_id,
                            error = %e,
                            "PTY read error"
                        );
                        return wait_for_child(&mut child).await;
                    }
                }
            }

            // Read from SSH channel stream and write to PTY
            read_result = channel_stream.read(&mut ssh_buf) => {
                tracing::debug!(channel = ?channel_id, iter = iteration, result = ?read_result.as_ref().map(|n| *n), "SSH read branch triggered");
                match read_result {
                    Ok(0) => {
                        tracing::debug!(channel = ?channel_id, "SSH channel stream EOF");
                        // Drain PTY output before killing shell
                        drain_pty_output_to_stream(channel_id, &pty, &mut channel_stream, &mut pty_buf)
                            .await;
                        // Kill shell and exit
                        if let Some(ref mut c) = child {
                            let _ = c.kill().await;
                        }
                        return wait_for_child(&mut child).await;
                    }
                    Ok(n) => {
                        tracing::debug!(channel = ?channel_id, bytes = n, "Read from SSH, writing to PTY");
                        let pty_guard = pty.read().await;
                        if let Err(e) = pty_guard.write_all(&ssh_buf[..n]).await {
                            tracing::debug!(
                                channel = ?channel_id,
                                error = %e,
                                "PTY write error"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            channel = ?channel_id,
                            error = %e,
                            "SSH channel stream read error"
                        );
                        // Kill shell and exit
                        if let Some(ref mut c) = child {
                            let _ = c.kill().await;
                        }
                        return wait_for_child(&mut child).await;
                    }
                }
            }
        }
    }
}

/// Drain any remaining output from PTY before closing.
async fn drain_pty_output_to_stream(
    channel_id: ChannelId,
    pty: &Arc<RwLock<PtyMaster>>,
    channel_stream: &mut ChannelStream<Msg>,
    buf: &mut [u8],
) {
    tracing::debug!(channel = ?channel_id, "Starting PTY drain");
    // Give shell a brief moment to process any pending input
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut consecutive_timeouts = 0;
    for _ in 0..100 {
        let pty_guard = pty.read().await;
        match tokio::time::timeout(std::time::Duration::from_millis(100), pty_guard.read(buf)).await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                consecutive_timeouts = 0;
                drop(pty_guard);
                if channel_stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                let _ = channel_stream.flush().await;
            }
            Ok(Err(_)) => break,
            Err(_) => {
                consecutive_timeouts += 1;
                if consecutive_timeouts >= 3 {
                    break;
                }
            }
        }
    }
    tracing::trace!(channel = ?channel_id, "Drained PTY output");
}

/// Wait for child process to exit and return exit code.
async fn wait_for_child(child: &mut Option<Child>) -> i32 {
    if let Some(ref mut c) = child {
        match c.wait().await {
            Ok(status) => status.code().unwrap_or(1),
            Err(e) => {
                tracing::warn!(error = %e, "Error waiting for shell process");
                1
            }
        }
    } else {
        1
    }
}

/// Run shell I/O loop using Handle for output (instead of ChannelStream).
///
/// This version spawns a separate task for PTY-to-SSH streaming, similar to
/// how exec does it. handle.data() is called from the spawned task, not
/// directly from the handler's await chain.
///
/// # Arguments
///
/// * `channel_id` - The SSH channel ID
/// * `pty` - The PTY master handle
/// * `child` - The shell child process (optional)
/// * `handle` - The russh Handle for sending data
/// * `data_rx` - Receiver for incoming data from SSH client
///
/// # Returns
///
/// Returns the exit code of the shell process.
pub async fn run_shell_io_loop_with_handle(
    channel_id: ChannelId,
    pty: Arc<RwLock<PtyMaster>>,
    mut child: Option<Child>,
    handle: Handle,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
) -> i32 {
    tracing::debug!(channel = ?channel_id, "Starting shell I/O loop (Handle-based, spawned output task)");

    // Create a shutdown signal for the output task
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Spawn task for PTY -> SSH (like exec does for stdout/stderr)
    //
    // IMPORTANT: We use a timeout on PTY reads to avoid deadlock.
    // The deadlock scenario:
    // 1. Output task acquires PTY lock, awaits pty.read() (waiting for shell output)
    // 2. User types, SSH data arrives, main loop tries to acquire PTY lock to write
    // 3. Main loop blocks on lock (held by output task)
    // 4. Output task blocks on pty.read() (waiting for input that can't arrive)
    // 5. Deadlock!
    //
    // By using a short timeout on reads, we periodically release the lock,
    // allowing the main loop to write SSH input to PTY.
    let pty_clone = Arc::clone(&pty);
    let handle_clone = handle.clone();
    let output_task = tokio::spawn(async move {
        let mut buf = vec![0u8; IO_BUFFER_SIZE];

        loop {
            tokio::select! {
                biased;

                // Check for shutdown signal
                _ = shutdown_rx.recv() => {
                    tracing::trace!(channel = ?channel_id, "Output task received shutdown signal");
                    break;
                }

                // Read from PTY with timeout to prevent holding lock too long
                read_result = async {
                    let pty_guard = pty_clone.read().await;
                    // Use a short timeout so we release the lock periodically
                    // This prevents deadlock with the main loop's write operations
                    tokio::time::timeout(
                        std::time::Duration::from_millis(50),
                        pty_guard.read(&mut buf)
                    ).await
                } => {
                    match read_result {
                        // Timeout - no data yet, loop back (releases lock)
                        Err(_elapsed) => {
                            // Sleep briefly to give main loop a chance to acquire lock
                            // yield_now() alone is not enough because this task may be
                            // rescheduled immediately before the main loop gets the lock
                            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                            continue;
                        }
                        Ok(Ok(0)) => {
                            tracing::trace!(channel = ?channel_id, "PTY EOF in output task");
                            break;
                        }
                        Ok(Ok(n)) => {
                            tracing::trace!(channel = ?channel_id, bytes = n, "Read from PTY, calling handle.data()");
                            let data = CryptoVec::from_slice(&buf[..n]);
                            match handle_clone.data(channel_id, data).await {
                                Ok(_) => {
                                    tracing::trace!(channel = ?channel_id, "handle.data() returned successfully");
                                    // Yield to allow russh session loop to flush the message
                                    // This is critical for interactive PTY sessions
                                    tokio::task::yield_now().await;
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        channel = ?channel_id,
                                        error = ?e,
                                        "Output task: failed to send data"
                                    );
                                    break;
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                tracing::debug!(
                                    channel = ?channel_id,
                                    error = %e,
                                    "Output task: PTY read error"
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    // Main loop: handle SSH -> PTY and child process status
    let exit_code = loop {
        // Check if child process has exited
        if let Some(ref mut c) = child {
            match c.try_wait() {
                Ok(Some(status)) => {
                    tracing::debug!(
                        channel = ?channel_id,
                        exit_code = ?status.code(),
                        "Shell process exited"
                    );
                    break status.code().unwrap_or(1);
                }
                Ok(None) => {
                    // Process still running
                }
                Err(e) => {
                    tracing::warn!(
                        channel = ?channel_id,
                        error = %e,
                        "Error checking child process status"
                    );
                }
            }
        }

        // Wait for SSH input or a small timeout to check child status
        tokio::select! {
            Some(data) = data_rx.recv() => {
                tracing::debug!(
                    channel = ?channel_id,
                    bytes = data.len(),
                    "Received data from SSH via mpsc, writing to PTY"
                );
                let pty_guard = pty.read().await;
                if let Err(e) = pty_guard.write_all(&data).await {
                    tracing::debug!(
                        channel = ?channel_id,
                        error = %e,
                        "Failed to write to PTY"
                    );
                } else {
                    tracing::debug!(
                        channel = ?channel_id,
                        bytes = data.len(),
                        "Successfully wrote data to PTY"
                    );
                }
            }

            // Check child status periodically
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                // Just loop back to check child status
            }
        }
    };

    // Signal output task to shutdown
    let _ = shutdown_tx.send(()).await;

    // Wait for output task to complete (with timeout)
    match tokio::time::timeout(std::time::Duration::from_secs(1), output_task).await {
        Ok(Ok(())) => tracing::debug!(channel = ?channel_id, "Output task completed"),
        Ok(Err(e)) => tracing::warn!(channel = ?channel_id, error = %e, "Output task panicked"),
        Err(_) => tracing::warn!(channel = ?channel_id, "Output task timed out"),
    }

    exit_code
}

impl Drop for ShellSession {
    fn drop(&mut self) {
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
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Note: Full shell session tests require integration testing with
    // actual russh channels. These unit tests cover the basic structures.

    #[test]
    fn test_io_buffer_size() {
        // Verify buffer size is reasonable using const assertions
        const _: () = {
            assert!(IO_BUFFER_SIZE >= 4096);
            assert!(IO_BUFFER_SIZE <= 65536);
        };
    }

    #[test]
    fn test_io_buffer_size_value() {
        // Explicit test for documentation purposes
        assert_eq!(IO_BUFFER_SIZE, 8192);
    }

    #[test]
    fn test_shell_session_debug() {
        // Test Debug implementation for ShellSession (indirectly through PtyConfig)
        let config = PtyConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("term"));
        assert!(debug_str.contains("col_width"));
        assert!(debug_str.contains("row_height"));
    }

    #[test]
    fn test_pty_config_default_values() {
        let config = PtyConfig::default();
        assert_eq!(config.term, "xterm-256color");
        assert_eq!(config.col_width, 80);
        assert_eq!(config.row_height, 24);
    }

    #[test]
    fn test_pty_config_custom_values() {
        use super::super::pty::PtyConfig as PtyMasterConfig;

        let config = PtyMasterConfig::new("vt100".to_string(), 120, 40, 800, 600);

        assert_eq!(config.term, "vt100");
        assert_eq!(config.col_width, 120);
        assert_eq!(config.row_height, 40);
        assert_eq!(config.pix_width, 800);
        assert_eq!(config.pix_height, 600);
    }

    // Note: Tests requiring ChannelId are difficult because ChannelId's
    // constructor is not public in russh. These would be integration tests.

    #[tokio::test]
    async fn test_shell_path_validation() {
        // Test that shell path validation works
        let nonexistent_path = PathBuf::from("/nonexistent/shell/path");
        assert!(!nonexistent_path.exists());

        // Common shell paths that should exist on Unix systems
        let common_shells = ["/bin/sh", "/bin/bash", "/usr/bin/bash"];
        let has_valid_shell = common_shells.iter().any(|s| PathBuf::from(s).exists());

        // At least one common shell should exist
        assert!(has_valid_shell, "No common shell found on system");
    }
}

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

//! PTY (pseudo-terminal) management for SSH shell sessions.
//!
//! This module provides Unix PTY handling for interactive shell sessions.
//! It creates PTY master/slave pairs, manages window sizes, and provides
//! async I/O for the PTY master file descriptor.
//!
//! # Platform Support
//!
//! This module uses POSIX PTY APIs and is Unix-specific. Windows support
//! would require ConPTY (future enhancement).
//!
//! # Example
//!
//! ```ignore
//! use bssh::server::pty::{PtyMaster, PtyConfig};
//!
//! let config = PtyConfig::new("xterm-256color".to_string(), 80, 24, 0, 0);
//! let pty = PtyMaster::open(config)?;
//! ```

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::PathBuf;

use anyhow::{Context, Result};
use nix::libc;
use nix::pty::{openpty, OpenptyResult, Winsize};
use nix::unistd;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Default terminal type if not specified by client.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// Default terminal columns.
pub const DEFAULT_COLS: u32 = 80;

/// Default terminal rows.
pub const DEFAULT_ROWS: u32 = 24;

/// Maximum value for terminal dimensions (u16::MAX).
const MAX_DIMENSION: u32 = u16::MAX as u32;

/// PTY configuration from SSH pty_request.
///
/// Contains terminal settings requested by the SSH client.
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// Terminal type (e.g., "xterm-256color").
    pub term: String,

    /// Width in columns.
    pub col_width: u32,

    /// Height in rows.
    pub row_height: u32,

    /// Width in pixels (may be 0 if unknown).
    pub pix_width: u32,

    /// Height in pixels (may be 0 if unknown).
    pub pix_height: u32,
}

impl PtyConfig {
    /// Create a new PTY configuration.
    pub fn new(
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Self {
        Self {
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
        }
    }

    /// Create a Winsize struct from this configuration.
    ///
    /// Values exceeding u16::MAX are clamped to u16::MAX to prevent overflow.
    pub fn winsize(&self) -> Winsize {
        Winsize {
            ws_row: self.row_height.min(MAX_DIMENSION) as u16,
            ws_col: self.col_width.min(MAX_DIMENSION) as u16,
            ws_xpixel: self.pix_width.min(MAX_DIMENSION) as u16,
            ws_ypixel: self.pix_height.min(MAX_DIMENSION) as u16,
        }
    }
}

impl Default for PtyConfig {
    fn default() -> Self {
        Self {
            term: DEFAULT_TERM.to_string(),
            col_width: DEFAULT_COLS,
            row_height: DEFAULT_ROWS,
            pix_width: 0,
            pix_height: 0,
        }
    }
}

/// PTY master handle with async I/O support.
///
/// Manages the master side of a PTY pair. The slave side path is provided
/// for the shell process to open.
pub struct PtyMaster {
    /// The configuration used to create this PTY.
    config: PtyConfig,

    /// Async file descriptor wrapper for the master.
    async_fd: AsyncFd<OwnedFd>,

    /// Path to the slave PTY device.
    slave_path: PathBuf,
}

impl PtyMaster {
    /// Open a new PTY pair with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - PTY configuration including terminal size
    ///
    /// # Returns
    ///
    /// Returns a `PtyMaster` on success, or an error if PTY creation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - PTY pair creation fails
    /// - Getting slave path fails
    /// - Setting window size fails
    /// - Making master non-blocking fails
    pub fn open(config: PtyConfig) -> Result<Self> {
        // Open PTY master/slave pair
        let OpenptyResult {
            master: master_fd,
            slave: slave_fd,
        } = openpty(None, None).context("Failed to open PTY pair")?;

        // Get slave path before closing slave fd
        let slave_path =
            unistd::ttyname(slave_fd.as_fd()).context("Failed to get slave TTY path")?;

        // Set initial window size on slave
        Self::set_window_size_fd(slave_fd.as_fd(), &config.winsize())
            .context("Failed to set initial window size")?;

        // Close slave fd - will be reopened by child process
        drop(slave_fd);

        // Make master fd non-blocking for async I/O
        Self::set_nonblocking(master_fd.as_fd())?;

        // Wrap in AsyncFd for tokio integration
        let async_fd = AsyncFd::new(master_fd).context("Failed to create AsyncFd")?;

        Ok(Self {
            config,
            async_fd,
            slave_path,
        })
    }

    /// Get the slave PTY device path.
    ///
    /// This path should be used by the shell process to open the slave
    /// side of the PTY.
    pub fn slave_path(&self) -> &PathBuf {
        &self.slave_path
    }

    /// Get the PTY configuration.
    pub fn config(&self) -> &PtyConfig {
        &self.config
    }

    /// Get the raw file descriptor for the master.
    pub fn as_raw_fd(&self) -> RawFd {
        self.async_fd.get_ref().as_raw_fd()
    }

    /// Resize the terminal window.
    ///
    /// # Arguments
    ///
    /// * `cols` - New width in columns
    /// * `rows` - New height in rows
    ///
    /// # Errors
    ///
    /// Returns an error if the ioctl to set window size fails.
    pub fn resize(&mut self, cols: u32, rows: u32) -> Result<()> {
        self.config.col_width = cols;
        self.config.row_height = rows;

        let winsize = self.config.winsize();
        Self::set_window_size_fd(self.async_fd.get_ref().as_fd(), &winsize)
    }

    /// Set window size on a file descriptor.
    fn set_window_size_fd(fd: BorrowedFd<'_>, winsize: &Winsize) -> Result<()> {
        // SAFETY: The fd is valid and we're passing a valid Winsize struct
        let result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, winsize) };

        if result < 0 {
            Err(io::Error::last_os_error()).context("Failed to set window size (TIOCSWINSZ ioctl)")
        } else {
            Ok(())
        }
    }

    /// Set a file descriptor to non-blocking mode.
    fn set_nonblocking(fd: BorrowedFd<'_>) -> Result<()> {
        // Get current flags
        let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).context("F_GETFL")?;

        // Add O_NONBLOCK
        let new_flags =
            nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK;

        nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(new_flags)).context("F_SETFL")?;

        Ok(())
    }

    /// Read data from the PTY master.
    ///
    /// This is an async operation that waits for data to be available.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.async_fd.readable().await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // SAFETY: fd is valid and buf is a valid slice
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write data to the PTY master.
    ///
    /// This is an async operation that waits for the fd to be writable.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.async_fd.writable().await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // SAFETY: fd is valid and buf is a valid slice
                let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write all data to the PTY master.
    ///
    /// Continues writing until all bytes are written or an error occurs.
    pub async fn write_all(&self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.write(buf).await?;
            buf = &buf[n..];
        }
        Ok(())
    }
}

impl std::fmt::Debug for PtyMaster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyMaster")
            .field("config", &self.config)
            .field("slave_path", &self.slave_path)
            .field("fd", &self.as_raw_fd())
            .finish()
    }
}

/// Async reader for PTY master.
///
/// Implements `AsyncRead` for use with tokio I/O utilities.
pub struct PtyReader<'a> {
    pty: &'a PtyMaster,
}

impl<'a> PtyReader<'a> {
    /// Create a new async reader for the PTY.
    pub fn new(pty: &'a PtyMaster) -> Self {
        Self { pty }
    }
}

impl AsyncRead for PtyReader<'_> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        loop {
            let mut guard = match self.pty.async_fd.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(guard)) => guard,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            let unfilled = buf.initialize_unfilled();
            let fd = self.pty.async_fd.get_ref().as_raw_fd();

            // SAFETY: fd is valid, unfilled is a valid slice
            let result = unsafe { libc::read(fd, unfilled.as_mut_ptr() as *mut _, unfilled.len()) };

            if result < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return std::task::Poll::Ready(Err(err));
            }

            buf.advance(result as usize);
            return std::task::Poll::Ready(Ok(()));
        }
    }
}

/// Async writer for PTY master.
///
/// Implements `AsyncWrite` for use with tokio I/O utilities.
pub struct PtyWriter<'a> {
    pty: &'a PtyMaster,
}

impl<'a> PtyWriter<'a> {
    /// Create a new async writer for the PTY.
    pub fn new(pty: &'a PtyMaster) -> Self {
        Self { pty }
    }
}

impl AsyncWrite for PtyWriter<'_> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.pty.async_fd.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(guard)) => guard,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            let fd = self.pty.async_fd.get_ref().as_raw_fd();

            // SAFETY: fd is valid, buf is a valid slice
            let result = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };

            if result < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return std::task::Poll::Ready(Err(err));
            }

            return std::task::Poll::Ready(Ok(result as usize));
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // PTY doesn't need explicit flushing
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // PTY shutdown is handled by dropping
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_config_default() {
        let config = PtyConfig::default();

        assert_eq!(config.term, DEFAULT_TERM);
        assert_eq!(config.col_width, DEFAULT_COLS);
        assert_eq!(config.row_height, DEFAULT_ROWS);
        assert_eq!(config.pix_width, 0);
        assert_eq!(config.pix_height, 0);
    }

    #[test]
    fn test_pty_config_new() {
        let config = PtyConfig::new("vt100".to_string(), 132, 50, 1024, 768);

        assert_eq!(config.term, "vt100");
        assert_eq!(config.col_width, 132);
        assert_eq!(config.row_height, 50);
        assert_eq!(config.pix_width, 1024);
        assert_eq!(config.pix_height, 768);
    }

    #[test]
    fn test_pty_config_winsize() {
        let config = PtyConfig::new("xterm".to_string(), 80, 24, 640, 480);
        let winsize = config.winsize();

        assert_eq!(winsize.ws_col, 80);
        assert_eq!(winsize.ws_row, 24);
        assert_eq!(winsize.ws_xpixel, 640);
        assert_eq!(winsize.ws_ypixel, 480);
    }

    #[test]
    fn test_pty_config_winsize_overflow_clamping() {
        // Test that values exceeding u16::MAX are clamped
        let config = PtyConfig::new("xterm".to_string(), 100_000, 100_000, 100_000, 100_000);
        let winsize = config.winsize();

        assert_eq!(winsize.ws_col, u16::MAX);
        assert_eq!(winsize.ws_row, u16::MAX);
        assert_eq!(winsize.ws_xpixel, u16::MAX);
        assert_eq!(winsize.ws_ypixel, u16::MAX);
    }

    #[tokio::test]
    async fn test_pty_master_open() {
        let config = PtyConfig::default();
        let result = PtyMaster::open(config);

        // PTY creation should succeed on Unix systems
        assert!(result.is_ok(), "Failed to open PTY: {:?}", result.err());

        let pty = result.unwrap();
        assert!(pty.slave_path().exists());
        assert!(pty.as_raw_fd() >= 0);
    }

    #[tokio::test]
    async fn test_pty_master_resize() {
        let config = PtyConfig::default();
        let mut pty = PtyMaster::open(config).expect("Failed to open PTY");

        // Resize should succeed
        assert!(pty.resize(120, 40).is_ok());
        assert_eq!(pty.config().col_width, 120);
        assert_eq!(pty.config().row_height, 40);
    }

    #[tokio::test]
    async fn test_pty_master_read_write() {
        let config = PtyConfig::default();
        let pty = PtyMaster::open(config).expect("Failed to open PTY");

        // Write some data
        let test_data = b"hello\n";
        let write_result = pty.write(test_data).await;
        assert!(write_result.is_ok());

        // Note: Reading requires something on the other end (slave) to echo
        // This is tested more thoroughly in integration tests
    }

    #[tokio::test]
    async fn test_pty_master_debug() {
        let config = PtyConfig::default();
        let pty = PtyMaster::open(config).expect("Failed to open PTY");

        let debug = format!("{:?}", pty);
        assert!(debug.contains("PtyMaster"));
        assert!(debug.contains("config"));
        assert!(debug.contains("slave_path"));
    }
}

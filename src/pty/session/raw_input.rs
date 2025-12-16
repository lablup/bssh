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

//! Raw byte input reader for PTY sessions.
//!
//! Reads stdin as raw bytes without escape sequence parsing,
//! providing transparent passthrough like OpenSSH.
//!
//! # Prerequisites
//! This module requires `crossterm::terminal::enable_raw_mode()` to be called
//! before reading. The raw mode ensures:
//! - No line buffering (bytes available immediately)
//! - No echo (typed characters not displayed by terminal)
//! - No signal generation (Ctrl+C doesn't generate SIGINT)
//!
//! # Why Raw Bytes?
//! Using crossterm's `event::read()` parses escape sequences, which consumes
//! the ESC byte (0x1b) and corrupts terminal responses. Reading raw bytes with
//! `stdin.read()` provides transparent passthrough of all bytes, including:
//! - Terminal query responses (DA1, DA2, DA3, XTGETTCAP, etc.)
//! - Arrow keys (`\x1b[A`, `\x1b[B`, `\x1b[C`, `\x1b[D`)
//! - Function keys (`\x1bOP`, `\x1bOQ`, etc.)
//! - Mouse events
//!
//! This approach matches OpenSSH's behavior.

use std::io::{self, Read};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

/// Raw input reader that provides transparent byte passthrough.
///
/// # Usage
/// ```ignore
/// // Example is for documentation only - module is internal
/// use std::time::Duration;
///
/// // Ensure raw mode is enabled first
/// crossterm::terminal::enable_raw_mode().unwrap();
///
/// let mut reader = RawInputReader::new();
/// let mut buffer = [0u8; 1024];
///
/// if reader.poll(Duration::from_millis(100)).unwrap() {
///     let n = reader.read(&mut buffer).unwrap();
///     // Process raw bytes...
/// }
///
/// crossterm::terminal::disable_raw_mode().unwrap();
/// ```
pub struct RawInputReader {
    stdin: io::Stdin,
}

impl RawInputReader {
    /// Create a new raw input reader.
    ///
    /// # Prerequisites
    /// The terminal must be in raw mode (via `enable_raw_mode()`) before
    /// calling `read()` to ensure immediate byte availability.
    pub fn new() -> Self {
        Self {
            stdin: io::stdin(),
        }
    }

    /// Poll for available input with timeout.
    ///
    /// Returns `Ok(true)` if data is available to read, `Ok(false)` if timeout
    /// occurred, or an error if the poll failed.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for input
    ///
    /// # Example
    /// ```ignore
    /// // Example is for documentation only - module is internal
    /// use std::time::Duration;
    /// let reader = RawInputReader::new();
    /// if reader.poll(Duration::from_millis(100))? {
    ///     // Data is available
    /// }
    /// ```
    pub fn poll(&self, timeout: Duration) -> io::Result<bool> {
        use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
        use std::os::unix::io::BorrowedFd;

        let fd = self.stdin.as_raw_fd();
        // SAFETY: We're borrowing the fd within this function scope only,
        // and stdin remains valid for the lifetime of this borrow
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let mut poll_fds = [PollFd::new(borrowed_fd, PollFlags::POLLIN)];

        // Convert Duration to PollTimeout
        // PollTimeout accepts u16 in milliseconds (or Option for -1)
        let timeout_ms = timeout.as_millis().min(u16::MAX as u128) as u16;
        let poll_timeout = PollTimeout::from(timeout_ms);

        match poll(&mut poll_fds, poll_timeout) {
            Ok(n) => Ok(n > 0),
            Err(nix::errno::Errno::EINTR) => Ok(false), // Interrupted, treat as timeout
            Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }

    /// Read available bytes from stdin.
    ///
    /// Returns the number of bytes read. A return value of 0 indicates EOF.
    ///
    /// # Raw Mode Behavior
    /// When terminal is in raw mode (via `enable_raw_mode()`), this returns
    /// raw bytes including escape sequences like:
    /// - Arrow keys: `\x1b[A`, `\x1b[B`, `\x1b[C`, `\x1b[D`
    /// - Function keys: `\x1bOP`, `\x1bOQ`, etc.
    /// - Terminal responses: `\x1b[>64;2500;0c`, etc.
    /// - Mouse events: `\x1b[<...M`
    ///
    /// All bytes are passed through as-is without interpretation.
    ///
    /// # Example
    /// ```ignore
    /// // Example is for documentation only - module is internal
    /// let mut reader = RawInputReader::new();
    /// let mut buffer = [0u8; 1024];
    ///
    /// match reader.read(&mut buffer)? {
    ///     0 => println!("EOF"),
    ///     n => println!("Read {} bytes", n),
    /// }
    /// ```
    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stdin.read(buffer)
    }
}

impl Default for RawInputReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_input_reader_creation() {
        let _reader = RawInputReader::new();
        // If we can create it, the test passes
    }

    #[test]
    fn test_default() {
        let _reader = RawInputReader::default();
    }

    #[test]
    fn test_poll_timeout() {
        let reader = RawInputReader::new();
        // Short timeout should return false when no input
        let result = reader.poll(Duration::from_millis(10));
        assert!(result.is_ok());
        // We can't guarantee false since input might be available
    }
}

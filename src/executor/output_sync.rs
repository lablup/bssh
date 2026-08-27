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

//! Thread-safe output synchronization for preventing race conditions
//! when multiple nodes write to stdout/stderr simultaneously.

use std::io::{self, Write};
use std::sync::{LazyLock, Mutex};

/// Global stdout mutex to prevent interleaved output
static STDOUT_MUTEX: LazyLock<Mutex<io::Stdout>> = LazyLock::new(|| Mutex::new(io::stdout()));

/// Global stderr mutex to prevent interleaved output
static STDERR_MUTEX: LazyLock<Mutex<io::Stderr>> = LazyLock::new(|| Mutex::new(io::stderr()));

/// Thread-safe println! that prevents output interleaving
///
/// This function acquires a mutex lock before writing to ensure
/// that the entire line is written atomically without interruption
/// from other threads.
pub fn synchronized_println(text: &str) -> io::Result<()> {
    let mut stdout = STDOUT_MUTEX.lock().unwrap();
    writeln!(stdout, "{text}")?;
    stdout.flush()?;
    Ok(())
}

/// Thread-safe eprintln! that prevents output interleaving
///
/// This function acquires a mutex lock before writing to ensure
/// that the entire line is written atomically without interruption
/// from other threads.
#[allow(dead_code)]
pub fn synchronized_eprintln(text: &str) -> io::Result<()> {
    let mut stderr = STDERR_MUTEX.lock().unwrap();
    writeln!(stderr, "{text}")?;
    stderr.flush()?;
    Ok(())
}

/// Batch write multiple lines to stdout atomically
///
/// This function writes multiple lines while holding the lock,
/// ensuring that all lines from the same node appear together.
#[allow(dead_code)]
pub fn synchronized_print_lines<'a, I>(lines: I) -> io::Result<()>
where
    I: Iterator<Item = &'a str>,
{
    let mut stdout = STDOUT_MUTEX.lock().unwrap();
    for line in lines {
        writeln!(stdout, "{line}")?;
    }
    stdout.flush()?;
    Ok(())
}

/// Batch write multiple lines to stderr atomically
///
/// This function writes multiple lines while holding the lock,
/// ensuring that all lines from the same node appear together.
#[allow(dead_code)]
pub fn synchronized_eprint_lines<'a, I>(lines: I) -> io::Result<()>
where
    I: Iterator<Item = &'a str>,
{
    let mut stderr = STDERR_MUTEX.lock().unwrap();
    for line in lines {
        writeln!(stderr, "{line}")?;
    }
    stderr.flush()?;
    Ok(())
}

/// Synchronized output writer for node prefixed output
pub struct NodeOutputWriter {
    node_prefix: String,
    no_prefix: bool,
}

impl NodeOutputWriter {
    /// Create a new writer with a node prefix (prefix enabled by default)
    #[allow(dead_code)]
    pub fn new(node_host: &str) -> Self {
        Self::new_with_no_prefix(node_host, false)
    }

    /// Create a new writer with optional prefix disabled
    pub fn new_with_no_prefix(node_host: &str, no_prefix: bool) -> Self {
        Self {
            node_prefix: format!("[{node_host}]"),
            no_prefix,
        }
    }

    /// Format a line with or without prefix based on configuration
    fn format_line(&self, line: &str) -> String {
        if self.no_prefix {
            line.to_string()
        } else {
            format!("{} {}", self.node_prefix, line)
        }
    }

    /// Write stdout lines with optional node prefix atomically
    pub fn write_stdout_lines(&self, text: &str) -> io::Result<()> {
        let lines: Vec<String> = text.lines().map(|line| self.format_line(line)).collect();

        if !lines.is_empty() {
            let mut stdout = STDOUT_MUTEX.lock().unwrap();
            for line in lines {
                writeln!(stdout, "{line}")?;
            }
            stdout.flush()?;
        }
        Ok(())
    }

    /// Write stderr lines with optional node prefix atomically
    pub fn write_stderr_lines(&self, text: &str) -> io::Result<()> {
        let lines: Vec<String> = text.lines().map(|line| self.format_line(line)).collect();

        if !lines.is_empty() {
            let mut stderr = STDERR_MUTEX.lock().unwrap();
            for line in lines {
                writeln!(stderr, "{line}")?;
            }
            stderr.flush()?;
        }
        Ok(())
    }

    /// Write a stdout chunk without decoding, prefixing, or adding a newline.
    pub fn write_stdout_bytes(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut stdout = STDOUT_MUTEX
            .lock()
            .map_err(|_| io::Error::other("stdout lock is poisoned"))?;
        stdout.write_all(bytes)?;
        stdout.flush()
    }

    /// Write a stderr chunk without decoding, prefixing, or adding a newline.
    pub fn write_stderr_bytes(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut stderr = STDERR_MUTEX
            .lock()
            .map_err(|_| io::Error::other("stderr lock is poisoned"))?;
        stderr.write_all(bytes)?;
        stderr.flush()
    }

    /// Write a single stdout line with optional node prefix
    pub fn write_stdout(&self, line: &str) -> io::Result<()> {
        synchronized_println(&self.format_line(line))
    }

    /// Write a single stderr line with optional node prefix
    #[allow(dead_code)]
    pub fn write_stderr(&self, line: &str) -> io::Result<()> {
        synchronized_eprintln(&self.format_line(line))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_node_output_writer() {
        let writer = NodeOutputWriter::new("test-host");
        assert_eq!(writer.node_prefix, "[test-host]");
        assert!(!writer.no_prefix);
    }

    #[test]
    fn test_node_output_writer_with_no_prefix() {
        let writer = NodeOutputWriter::new_with_no_prefix("test-host", true);
        assert_eq!(writer.node_prefix, "[test-host]");
        assert!(writer.no_prefix);

        // Test format_line with no_prefix enabled
        assert_eq!(writer.format_line("test output"), "test output");

        // Test with no_prefix disabled
        let writer_with_prefix = NodeOutputWriter::new_with_no_prefix("test-host", false);
        assert_eq!(
            writer_with_prefix.format_line("test output"),
            "[test-host] test output"
        );
    }

    #[test]
    fn test_synchronized_output() {
        // These tests just verify the functions compile and don't panic
        // Actual thread safety is tested through integration tests

        let _ = synchronized_println("test");
        let _ = synchronized_eprintln("test error");

        let lines = ["line1", "line2"];
        let _ = synchronized_print_lines(lines.iter().copied());
        let _ = synchronized_eprint_lines(lines.iter().copied());
    }

    #[test]
    fn remote_stderr_helper() {
        if std::env::var_os("BSSH_LOG_FILE_TEST_HELPER").is_none() {
            return;
        }

        let log = PathBuf::from(
            std::env::var_os("BSSH_LOG_FILE_TEST_PATH").expect("helper log path should be set"),
        );
        crate::utils::diagnostics::set_log_file(&log).expect("helper should open diagnostic log");
        crate::diagnosticln!("bssh-owned diagnostic");
        NodeOutputWriter::new_with_no_prefix("example", true)
            .write_stderr_lines("remote command stderr")
            .expect("helper should write remote stderr");
    }

    #[test]
    fn remote_command_stderr_stays_on_fd_2() {
        let directory = tempdir().expect("failed to create temporary directory");
        let log = directory.path().join("bssh.log");
        let output = Command::new(std::env::current_exe().expect("test executable should exist"))
            .args([
                "--exact",
                "executor::output_sync::tests::remote_stderr_helper",
                "--nocapture",
            ])
            .env("BSSH_LOG_FILE_TEST_HELPER", "1")
            .env("BSSH_LOG_FILE_TEST_PATH", &log)
            .output()
            .expect("failed to run remote stderr helper");

        assert!(output.status.success(), "remote stderr helper should pass");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("remote command stderr"),
            "stderr was: {stderr}"
        );
        assert!(!stderr.contains("bssh-owned diagnostic"));

        let contents = std::fs::read_to_string(&log).expect("failed to read diagnostic log");
        assert!(contents.contains("bssh-owned diagnostic"));
        assert!(!contents.contains("remote command stderr"));
    }
    #[test]
    fn raw_output_helper() {
        if std::env::var_os("BSSH_RAW_OUTPUT_TEST_HELPER").is_none() {
            return;
        }

        let writer = NodeOutputWriter::new_with_no_prefix("example", true);
        writer
            .write_stdout_bytes(b"stdout\0\xff-no-newline")
            .expect("helper should write raw stdout");
        writer
            .write_stderr_bytes(b"stderr\0\xfe-no-newline")
            .expect("helper should write raw stderr");
    }

    #[test]
    fn raw_output_preserves_bytes_and_streams() {
        let output = Command::new(std::env::current_exe().expect("test executable should exist"))
            .args([
                "--exact",
                "executor::output_sync::tests::raw_output_helper",
                "--nocapture",
            ])
            .env("BSSH_RAW_OUTPUT_TEST_HELPER", "1")
            .output()
            .expect("failed to run raw output helper");

        assert!(output.status.success(), "raw output helper should pass");
        let expected_stdout = b"stdout\0\xff-no-newline";
        let expected_stderr = b"stderr\0\xfe-no-newline";
        let stdout_start = output
            .stdout
            .windows(expected_stdout.len())
            .position(|window| window == expected_stdout)
            .expect("exact raw stdout payload should be present");
        let stderr_start = output
            .stderr
            .windows(expected_stderr.len())
            .position(|window| window == expected_stderr)
            .expect("exact raw stderr payload should be present");
        assert_eq!(
            &output.stdout[stdout_start..stdout_start + expected_stdout.len()],
            expected_stdout
        );
        assert_eq!(
            &output.stderr[stderr_start..stderr_start + expected_stderr.len()],
            expected_stderr
        );
        assert_eq!(
            output
                .stdout
                .windows(expected_stdout.len())
                .filter(|window| *window == expected_stdout)
                .count(),
            1
        );
        assert_eq!(
            output
                .stderr
                .windows(expected_stderr.len())
                .filter(|window| *window == expected_stderr)
                .count(),
            1
        );
    }
}

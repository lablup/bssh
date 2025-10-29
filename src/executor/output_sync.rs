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

use once_cell::sync::Lazy;
use std::io::{self, Write};
use std::sync::Mutex;

/// Global stdout mutex to prevent interleaved output
static STDOUT_MUTEX: Lazy<Mutex<io::Stdout>> = Lazy::new(|| Mutex::new(io::stdout()));

/// Global stderr mutex to prevent interleaved output
static STDERR_MUTEX: Lazy<Mutex<io::Stderr>> = Lazy::new(|| Mutex::new(io::stderr()));

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
}

impl NodeOutputWriter {
    /// Create a new writer with a node prefix
    pub fn new(node_host: &str) -> Self {
        Self {
            node_prefix: format!("[{node_host}]"),
        }
    }

    /// Write stdout lines with node prefix atomically
    pub fn write_stdout_lines(&self, text: &str) -> io::Result<()> {
        let lines: Vec<String> = text
            .lines()
            .map(|line| format!("{} {}", self.node_prefix, line))
            .collect();

        if !lines.is_empty() {
            let mut stdout = STDOUT_MUTEX.lock().unwrap();
            for line in lines {
                writeln!(stdout, "{line}")?;
            }
            stdout.flush()?;
        }
        Ok(())
    }

    /// Write stderr lines with node prefix atomically
    pub fn write_stderr_lines(&self, text: &str) -> io::Result<()> {
        let lines: Vec<String> = text
            .lines()
            .map(|line| format!("{} {}", self.node_prefix, line))
            .collect();

        if !lines.is_empty() {
            let mut stderr = STDERR_MUTEX.lock().unwrap();
            for line in lines {
                writeln!(stderr, "{line}")?;
            }
            stderr.flush()?;
        }
        Ok(())
    }

    /// Write a single stdout line with node prefix
    pub fn write_stdout(&self, line: &str) -> io::Result<()> {
        synchronized_println(&format!("{} {}", self.node_prefix, line))
    }

    /// Write a single stderr line with node prefix
    #[allow(dead_code)]
    pub fn write_stderr(&self, line: &str) -> io::Result<()> {
        synchronized_eprintln(&format!("{} {}", self.node_prefix, line))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_output_writer() {
        let writer = NodeOutputWriter::new("test-host");
        assert_eq!(writer.node_prefix, "[test-host]");
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
}

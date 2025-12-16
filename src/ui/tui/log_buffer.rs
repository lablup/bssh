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

//! In-memory log buffer for TUI mode
//!
//! This module provides a thread-safe buffer for capturing log entries
//! during TUI mode, preventing logs from breaking the ratatui alternate screen.

use chrono::{DateTime, Local};
use std::collections::VecDeque;
use tracing::Level;

/// Default maximum number of log entries to keep in buffer
const DEFAULT_MAX_ENTRIES: usize = 1000;

/// Environment variable to configure max log entries
const MAX_ENTRIES_ENV_VAR: &str = "BSSH_TUI_LOG_MAX_ENTRIES";

/// A single log entry captured from tracing events
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Log level (ERROR, WARN, INFO, DEBUG, TRACE)
    pub level: Level,
    /// Module/target that generated the log
    pub target: String,
    /// Log message content
    pub message: String,
    /// Timestamp when the log was captured
    pub timestamp: DateTime<Local>,
}

impl LogEntry {
    /// Create a new log entry with the current timestamp
    pub fn new(level: Level, target: String, message: String) -> Self {
        Self {
            level,
            target,
            message,
            timestamp: Local::now(),
        }
    }

    /// Format the log entry for display
    pub fn format_short(&self) -> String {
        let level_str = match self.level {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };
        format!(
            "[{}] {}: {}",
            level_str,
            self.target.rsplit("::").next().unwrap_or(&self.target),
            self.message
        )
    }

    /// Format the log entry with timestamp for display
    pub fn format_with_time(&self) -> String {
        let level_str = match self.level {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };
        format!(
            "{} [{}] {}: {}",
            self.timestamp.format("%H:%M:%S"),
            level_str,
            self.target.rsplit("::").next().unwrap_or(&self.target),
            self.message
        )
    }
}

/// Thread-safe buffer for storing log entries
///
/// Uses a `VecDeque` with FIFO deletion when the maximum capacity is reached.
/// The buffer is designed to be shared between the tracing layer and TUI
/// rendering thread via `Arc<Mutex<LogBuffer>>`.
#[derive(Debug)]
pub struct LogBuffer {
    /// Ring buffer storing log entries
    entries: VecDeque<LogEntry>,
    /// Maximum number of entries to keep
    max_entries: usize,
    /// Flag indicating new entries have been added since last read
    has_new_entries: bool,
}

impl LogBuffer {
    /// Create a new log buffer with the specified maximum capacity
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries.min(DEFAULT_MAX_ENTRIES)),
            max_entries,
            has_new_entries: false,
        }
    }

    /// Create a new log buffer with configuration from environment variables
    pub fn from_env() -> Self {
        let max_entries = std::env::var(MAX_ENTRIES_ENV_VAR)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_ENTRIES);
        Self::new(max_entries)
    }

    /// Push a new log entry to the buffer
    ///
    /// If the buffer is at capacity, the oldest entry is removed (FIFO).
    pub fn push(&mut self, entry: LogEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
        self.has_new_entries = true;
    }

    /// Get an iterator over all log entries
    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter()
    }

    /// Get the number of entries in the buffer
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries from the buffer
    pub fn clear(&mut self) {
        self.entries.clear();
        self.has_new_entries = false;
    }

    /// Check if there are new entries since last check and reset the flag
    pub fn take_has_new_entries(&mut self) -> bool {
        let result = self.has_new_entries;
        self.has_new_entries = false;
        result
    }

    /// Get the last N entries (most recent)
    pub fn last_n(&self, n: usize) -> impl Iterator<Item = &LogEntry> {
        let skip = self.entries.len().saturating_sub(n);
        self.entries.iter().skip(skip)
    }

    /// Get entries within a scroll window
    ///
    /// `offset` is the number of entries to skip from the end (for scrolling up)
    /// `count` is the number of entries to return
    pub fn get_window(&self, offset: usize, count: usize) -> Vec<&LogEntry> {
        let total = self.entries.len();
        if total == 0 || count == 0 {
            return Vec::new();
        }

        // Calculate the starting position
        // offset=0 means show the most recent entries
        let end = total.saturating_sub(offset);
        let start = end.saturating_sub(count);

        self.entries.iter().skip(start).take(end - start).collect()
    }

    /// Get entries filtered by log level
    pub fn filter_by_level(&self, min_level: Level) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.level <= min_level)
            .collect()
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::from_env()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_buffer_basic() {
        let mut buffer = LogBuffer::new(5);
        assert!(buffer.is_empty());

        buffer.push(LogEntry::new(
            Level::INFO,
            "test".to_string(),
            "message 1".to_string(),
        ));
        assert_eq!(buffer.len(), 1);
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_log_buffer_fifo() {
        let mut buffer = LogBuffer::new(3);

        for i in 1..=5 {
            buffer.push(LogEntry::new(
                Level::INFO,
                "test".to_string(),
                format!("message {i}"),
            ));
        }

        assert_eq!(buffer.len(), 3);

        let messages: Vec<_> = buffer.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(messages, vec!["message 3", "message 4", "message 5"]);
    }

    #[test]
    fn test_log_buffer_last_n() {
        let mut buffer = LogBuffer::new(10);

        for i in 1..=5 {
            buffer.push(LogEntry::new(
                Level::INFO,
                "test".to_string(),
                format!("message {i}"),
            ));
        }

        let last_two: Vec<_> = buffer.last_n(2).map(|e| e.message.as_str()).collect();
        assert_eq!(last_two, vec!["message 4", "message 5"]);
    }

    #[test]
    fn test_log_buffer_get_window() {
        let mut buffer = LogBuffer::new(10);

        for i in 1..=10 {
            buffer.push(LogEntry::new(
                Level::INFO,
                "test".to_string(),
                format!("message {i}"),
            ));
        }

        // Get last 3 entries (offset=0)
        let window: Vec<_> = buffer
            .get_window(0, 3)
            .iter()
            .map(|e| e.message.as_str())
            .collect();
        assert_eq!(window, vec!["message 8", "message 9", "message 10"]);

        // Get 3 entries scrolled up by 2 (offset=2)
        let window: Vec<_> = buffer
            .get_window(2, 3)
            .iter()
            .map(|e| e.message.as_str())
            .collect();
        assert_eq!(window, vec!["message 6", "message 7", "message 8"]);
    }

    #[test]
    fn test_log_entry_format() {
        let entry = LogEntry::new(
            Level::ERROR,
            "bssh::ssh::client".to_string(),
            "Connection failed".to_string(),
        );

        let short = entry.format_short();
        assert!(short.contains("[ERROR]"));
        assert!(short.contains("client:"));
        assert!(short.contains("Connection failed"));
    }

    #[test]
    fn test_has_new_entries() {
        let mut buffer = LogBuffer::new(10);
        assert!(!buffer.take_has_new_entries());

        buffer.push(LogEntry::new(
            Level::INFO,
            "test".to_string(),
            "message".to_string(),
        ));
        assert!(buffer.take_has_new_entries());
        assert!(!buffer.take_has_new_entries()); // Should be reset
    }

    #[test]
    fn test_clear() {
        let mut buffer = LogBuffer::new(10);
        buffer.push(LogEntry::new(
            Level::INFO,
            "test".to_string(),
            "message".to_string(),
        ));
        assert!(!buffer.is_empty());

        buffer.clear();
        assert!(buffer.is_empty());
    }
}

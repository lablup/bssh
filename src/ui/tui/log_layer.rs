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

//! Custom tracing layer for TUI mode
//!
//! This module implements a tracing subscriber layer that captures log events
//! and stores them in a shared buffer for display in the TUI log panel,
//! instead of writing to stdout which would break the ratatui alternate screen.

use super::log_buffer::{LogBuffer, LogEntry};
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// A tracing layer that captures log events for TUI display
///
/// This layer intercepts all tracing events and stores them in a shared
/// `LogBuffer` instead of writing to stdout. The buffer can then be
/// rendered in the TUI log panel.
pub struct TuiLogLayer {
    /// Shared buffer for storing captured log entries
    buffer: Arc<Mutex<LogBuffer>>,
    /// Minimum log level to capture
    min_level: Level,
}

impl TuiLogLayer {
    /// Create a new TUI log layer with the given buffer
    pub fn new(buffer: Arc<Mutex<LogBuffer>>) -> Self {
        Self {
            buffer,
            min_level: Level::TRACE, // Capture all levels by default
        }
    }

    /// Create a new TUI log layer with a minimum log level
    pub fn with_min_level(buffer: Arc<Mutex<LogBuffer>>, min_level: Level) -> Self {
        Self { buffer, min_level }
    }

    /// Get a reference to the shared log buffer
    pub fn buffer(&self) -> Arc<Mutex<LogBuffer>> {
        Arc::clone(&self.buffer)
    }
}

/// Visitor for extracting message field from tracing events
struct MessageVisitor {
    message: String,
}

impl MessageVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
        }
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // Prefer "message" field, but fall back to first field if no message yet
        if field.name() == "message" || self.message.is_empty() {
            self.message = format!("{value:?}");
            // Remove surrounding quotes if present
            if self.message.starts_with('"') && self.message.ends_with('"') {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        // Prefer "message" field, but fall back to first field if no message yet
        if field.name() == "message" || self.message.is_empty() {
            self.message = value.to_string();
        }
    }
}

impl<S> Layer<S> for TuiLogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = *metadata.level();

        // Skip events below minimum level
        if level > self.min_level {
            return;
        }

        // Extract the message from the event
        let mut visitor = MessageVisitor::new();
        event.record(&mut visitor);

        // Skip empty messages
        if visitor.message.is_empty() {
            return;
        }

        // Create log entry
        let entry = LogEntry::new(level, metadata.target().to_string(), visitor.message);

        // Add to buffer (with minimal lock time)
        if let Ok(mut buffer) = self.buffer.lock() {
            buffer.push(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    #[test]
    fn test_tui_log_layer_captures_events() {
        let buffer = Arc::new(Mutex::new(LogBuffer::new(100)));
        let layer = TuiLogLayer::new(Arc::clone(&buffer));

        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("Test message");
            tracing::warn!("Warning message");
            tracing::error!("Error message");
        });

        let buffer = buffer.lock().unwrap();
        assert_eq!(buffer.len(), 3);

        let entries: Vec<_> = buffer.iter().collect();
        assert_eq!(entries[0].level, Level::INFO);
        assert!(entries[0].message.contains("Test message"));
        assert_eq!(entries[1].level, Level::WARN);
        assert_eq!(entries[2].level, Level::ERROR);
    }

    #[test]
    fn test_tui_log_layer_min_level() {
        let buffer = Arc::new(Mutex::new(LogBuffer::new(100)));
        let layer = TuiLogLayer::with_min_level(Arc::clone(&buffer), Level::WARN);

        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("Debug message");
            tracing::info!("Info message");
            tracing::warn!("Warning message");
            tracing::error!("Error message");
        });

        let buffer = buffer.lock().unwrap();
        // Only WARN and ERROR should be captured (DEBUG and INFO are below WARN)
        assert_eq!(buffer.len(), 2);

        let entries: Vec<_> = buffer.iter().collect();
        assert_eq!(entries[0].level, Level::WARN);
        assert_eq!(entries[1].level, Level::ERROR);
    }
}

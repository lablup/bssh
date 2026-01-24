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

//! Audit event exporters for sending events to various destinations.
//!
//! This module defines the trait that all audit exporters must implement,
//! as well as built-in exporters like the null exporter.

use super::event::AuditEvent;
use anyhow::Result;
use async_trait::async_trait;

/// Trait for audit log exporters.
///
/// Exporters are responsible for taking audit events and sending them
/// to their destination (file, network, etc.). Exporters must be thread-safe
/// and should handle errors gracefully.
#[async_trait]
pub trait AuditExporter: Send + Sync {
    /// Export a single audit event.
    ///
    /// # Arguments
    ///
    /// * `event` - The audit event to export
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be exported.
    async fn export(&self, event: AuditEvent) -> Result<()>;

    /// Export multiple events in a batch.
    ///
    /// The default implementation calls `export()` for each event,
    /// but exporters can override this for more efficient batch processing.
    ///
    /// # Arguments
    ///
    /// * `events` - Slice of audit events to export
    ///
    /// # Errors
    ///
    /// Returns an error if any event fails to export.
    async fn export_batch(&self, events: &[AuditEvent]) -> Result<()> {
        for event in events {
            self.export(event.clone()).await?;
        }
        Ok(())
    }

    /// Flush any buffered events.
    ///
    /// This should ensure all pending events are written to their destination.
    ///
    /// # Errors
    ///
    /// Returns an error if the flush operation fails.
    async fn flush(&self) -> Result<()>;

    /// Close the exporter and release resources.
    ///
    /// After calling close, no more events should be exported.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    async fn close(&self) -> Result<()>;
}

/// Null exporter that discards all events.
///
/// This is useful for testing or when audit logging is disabled.
/// All operations succeed immediately without doing any work.
#[derive(Debug, Clone, Default)]
pub struct NullExporter;

impl NullExporter {
    /// Create a new null exporter.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AuditExporter for NullExporter {
    async fn export(&self, _event: AuditEvent) -> Result<()> {
        // Discard the event
        Ok(())
    }

    async fn export_batch(&self, _events: &[AuditEvent]) -> Result<()> {
        // Discard all events
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // Nothing to flush
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        // Nothing to close
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::audit::event::{EventResult, EventType};

    #[tokio::test]
    async fn test_null_exporter_export() {
        let exporter = NullExporter::new();
        let event = AuditEvent::new(
            EventType::AuthSuccess,
            "test".to_string(),
            "session-1".to_string(),
        );

        let result = exporter.export(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_null_exporter_batch() {
        let exporter = NullExporter::new();
        let events = vec![
            AuditEvent::new(
                EventType::AuthSuccess,
                "user1".to_string(),
                "session-1".to_string(),
            ),
            AuditEvent::new(
                EventType::AuthFailure,
                "user2".to_string(),
                "session-2".to_string(),
            )
            .with_result(EventResult::Failure),
        ];

        let result = exporter.export_batch(&events).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_null_exporter_flush() {
        let exporter = NullExporter::new();
        let result = exporter.flush().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_null_exporter_close() {
        let exporter = NullExporter::new();
        let result = exporter.close().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_null_exporter_multiple_operations() {
        let exporter = NullExporter::new();

        // Export single event
        let event1 = AuditEvent::new(
            EventType::SessionStart,
            "alice".to_string(),
            "session-123".to_string(),
        );
        exporter.export(event1).await.unwrap();

        // Export batch
        let events = vec![AuditEvent::new(
            EventType::FileUploaded,
            "bob".to_string(),
            "session-456".to_string(),
        )];
        exporter.export_batch(&events).await.unwrap();

        // Flush and close
        exporter.flush().await.unwrap();
        exporter.close().await.unwrap();
    }
}

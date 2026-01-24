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

//! Audit logging infrastructure for the SSH server.
//!
//! This module provides comprehensive audit logging capabilities for tracking
//! security-relevant events, file transfers, and user activities.
//!
//! # Overview
//!
//! The audit system consists of:
//!
//! - [`AuditEvent`]: Event types representing various auditable actions
//! - [`AuditExporter`]: Trait for implementing audit event destinations
//! - [`AuditManager`]: Central manager for collecting and distributing events
//! - [`NullExporter`]: No-op exporter for testing and disabled audit logging
//!
//! # Example
//!
//! ```no_run
//! use bssh::server::audit::{AuditManager, AuditConfig, event::{AuditEvent, EventType}};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = AuditConfig::default();
//! let manager = AuditManager::new(&config)?;
//!
//! let event = AuditEvent::new(
//!     EventType::AuthSuccess,
//!     "alice".to_string(),
//!     "session-123".to_string(),
//! );
//!
//! manager.log(event).await;
//! # Ok(())
//! # }
//! ```

pub mod event;
pub mod exporter;

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub use event::{AuditEvent, EventResult, EventType};
pub use exporter::{AuditExporter, NullExporter};

/// Configuration for the audit system.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Whether audit logging is enabled
    pub enabled: bool,

    /// Buffer size for the event channel
    pub buffer_size: usize,

    /// Maximum events to buffer before flushing
    pub batch_size: usize,

    /// Interval for automatic flush of buffered events
    pub flush_interval_secs: u64,

    /// Exporters to use
    pub exporters: Vec<AuditExporterConfig>,
}

/// Configuration for an audit exporter.
#[derive(Debug, Clone)]
pub enum AuditExporterConfig {
    /// Null exporter (discards events)
    Null,
    /// File exporter (future implementation)
    #[allow(dead_code)]
    File {
        /// Path to the audit log file
        path: String,
    },
    /// OpenTelemetry exporter (future implementation)
    #[allow(dead_code)]
    Otel {
        /// OTLP endpoint URL
        endpoint: String,
    },
    /// Logstash exporter (future implementation)
    #[allow(dead_code)]
    Logstash {
        /// Logstash host
        host: String,
        /// Logstash port
        port: u16,
    },
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            buffer_size: 1000,
            batch_size: 100,
            flush_interval_secs: 5,
            exporters: vec![AuditExporterConfig::Null],
        }
    }
}

impl AuditConfig {
    /// Create a new audit configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable audit logging.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set the buffer size.
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Set the batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Set the flush interval.
    pub fn with_flush_interval(mut self, secs: u64) -> Self {
        self.flush_interval_secs = secs;
        self
    }

    /// Set the exporters.
    pub fn with_exporters(mut self, exporters: Vec<AuditExporterConfig>) -> Self {
        self.exporters = exporters;
        self
    }
}

/// Manages audit logging with multiple exporters.
///
/// The audit manager collects events from the application and distributes
/// them to configured exporters. It uses a background worker for async
/// processing and buffering to improve performance.
pub struct AuditManager {
    /// Configured exporters
    exporters: Vec<Arc<dyn AuditExporter>>,

    /// Channel sender for audit events
    sender: mpsc::Sender<AuditEvent>,

    /// Whether audit logging is enabled
    enabled: bool,
}

impl AuditManager {
    /// Create a new audit manager with the given configuration.
    ///
    /// This starts a background worker task that processes events
    /// asynchronously.
    ///
    /// # Arguments
    ///
    /// * `config` - Audit configuration
    ///
    /// # Errors
    ///
    /// Returns an error if any exporter fails to initialize.
    pub fn new(config: &AuditConfig) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(config.buffer_size);

        let mut exporters: Vec<Arc<dyn AuditExporter>> = Vec::new();

        for exporter_config in &config.exporters {
            let exporter: Arc<dyn AuditExporter> = match exporter_config {
                AuditExporterConfig::Null => Arc::new(NullExporter::new()),
                AuditExporterConfig::File { .. } => {
                    // Future implementation
                    tracing::warn!("File exporter not yet implemented, using null exporter");
                    Arc::new(NullExporter::new())
                }
                AuditExporterConfig::Otel { .. } => {
                    // Future implementation
                    tracing::warn!("OTEL exporter not yet implemented, using null exporter");
                    Arc::new(NullExporter::new())
                }
                AuditExporterConfig::Logstash { .. } => {
                    // Future implementation
                    tracing::warn!("Logstash exporter not yet implemented, using null exporter");
                    Arc::new(NullExporter::new())
                }
            };
            exporters.push(exporter);
        }

        let manager = Self {
            exporters: exporters.clone(),
            sender,
            enabled: config.enabled,
        };

        // Start background worker
        if config.enabled {
            let batch_size = config.batch_size;
            let flush_interval = Duration::from_secs(config.flush_interval_secs);
            tokio::spawn(Self::worker(
                receiver,
                exporters,
                batch_size,
                flush_interval,
            ));
        }

        Ok(manager)
    }

    /// Log an audit event.
    ///
    /// If auditing is disabled, this is a no-op. Events are sent to the
    /// background worker for processing.
    ///
    /// # Arguments
    ///
    /// * `event` - The audit event to log
    pub async fn log(&self, event: AuditEvent) {
        if !self.enabled {
            return;
        }

        if let Err(e) = self.sender.send(event).await {
            tracing::warn!("Failed to send audit event: {}", e);
        }
    }

    /// Background worker for async event processing.
    ///
    /// This task receives events from the channel, buffers them, and
    /// periodically flushes them to all configured exporters.
    async fn worker(
        mut receiver: mpsc::Receiver<AuditEvent>,
        exporters: Vec<Arc<dyn AuditExporter>>,
        batch_size: usize,
        flush_interval: Duration,
    ) {
        let mut buffer = Vec::with_capacity(batch_size);
        let mut flush_timer = tokio::time::interval(flush_interval);
        flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                Some(event) = receiver.recv() => {
                    buffer.push(event);

                    // Flush if buffer is full
                    if buffer.len() >= batch_size {
                        Self::flush_buffer(&exporters, &mut buffer).await;
                    }
                }
                _ = flush_timer.tick() => {
                    if !buffer.is_empty() {
                        Self::flush_buffer(&exporters, &mut buffer).await;
                    }
                }
                else => {
                    // Channel closed, flush remaining events and exit
                    if !buffer.is_empty() {
                        Self::flush_buffer(&exporters, &mut buffer).await;
                    }
                    break;
                }
            }
        }

        // Close all exporters
        for exporter in &exporters {
            if let Err(e) = exporter.close().await {
                tracing::error!("Failed to close exporter: {}", e);
            }
        }
    }

    /// Flush the event buffer to all exporters.
    async fn flush_buffer(exporters: &[Arc<dyn AuditExporter>], buffer: &mut Vec<AuditEvent>) {
        for exporter in exporters {
            if let Err(e) = exporter.export_batch(buffer.clone()).await {
                tracing::error!("Audit export failed: {}", e);
            }
        }
        buffer.clear();
    }

    /// Flush all pending events immediately.
    ///
    /// This waits for all exporters to complete their flush operations.
    pub async fn flush(&self) {
        for exporter in &self.exporters {
            if let Err(e) = exporter.flush().await {
                tracing::error!("Audit flush failed: {}", e);
            }
        }
    }

    /// Check if audit logging is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_manager_creation() {
        let config = AuditConfig::default();
        let manager = AuditManager::new(&config);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_audit_manager_disabled() {
        let config = AuditConfig::new().with_enabled(false);
        let manager = AuditManager::new(&config).unwrap();

        let event = AuditEvent::new(
            EventType::AuthSuccess,
            "test".to_string(),
            "session-1".to_string(),
        );

        // Should not panic when disabled
        manager.log(event).await;
        assert!(!manager.is_enabled());
    }

    #[tokio::test]
    async fn test_audit_manager_enabled() {
        let config = AuditConfig::new()
            .with_enabled(true)
            .with_buffer_size(10)
            .with_batch_size(5);

        let manager = AuditManager::new(&config).unwrap();
        assert!(manager.is_enabled());

        let event = AuditEvent::new(
            EventType::SessionStart,
            "alice".to_string(),
            "session-123".to_string(),
        );

        manager.log(event).await;
        // Give the worker time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_audit_manager_batch() {
        let config = AuditConfig::new()
            .with_enabled(true)
            .with_batch_size(3)
            .with_buffer_size(100);

        let manager = AuditManager::new(&config).unwrap();

        // Send multiple events
        for i in 0..5 {
            let event = AuditEvent::new(
                EventType::FileUploaded,
                format!("user{}", i),
                format!("session-{}", i),
            );
            manager.log(event).await;
        }

        // Give the worker time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
        manager.flush().await;
    }

    #[tokio::test]
    async fn test_audit_config_builder() {
        let config = AuditConfig::new()
            .with_enabled(true)
            .with_buffer_size(500)
            .with_batch_size(50)
            .with_flush_interval(10);

        assert!(config.enabled);
        assert_eq!(config.buffer_size, 500);
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.flush_interval_secs, 10);
    }

    #[tokio::test]
    async fn test_audit_manager_with_null_exporter() {
        let config = AuditConfig::new()
            .with_enabled(true)
            .with_exporters(vec![AuditExporterConfig::Null]);

        let manager = AuditManager::new(&config).unwrap();

        let event = AuditEvent::new(
            EventType::CommandExecuted,
            "bob".to_string(),
            "session-456".to_string(),
        );

        manager.log(event).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager.flush().await;
    }

    #[tokio::test]
    async fn test_audit_manager_flush_on_interval() {
        let config = AuditConfig::new()
            .with_enabled(true)
            .with_batch_size(100) // Large batch to avoid early flush
            .with_flush_interval(1); // 1 second interval

        let manager = AuditManager::new(&config).unwrap();

        // Send a few events
        for i in 0..3 {
            let event = AuditEvent::new(
                EventType::DirectoryListed,
                format!("user{}", i),
                format!("session-{}", i),
            );
            manager.log(event).await;
        }

        // Wait for flush interval
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }
}

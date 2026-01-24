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

//! OpenTelemetry audit event exporter.
//!
//! This module provides an exporter that sends audit events to an OpenTelemetry
//! Collector using the OTLP protocol over gRPC. This enables integration with
//! observability platforms like Jaeger, Grafana Tempo, and cloud monitoring services.

use super::event::{AuditEvent, EventResult, EventType};
use super::exporter::AuditExporter;
use anyhow::{Context, Result};
use async_trait::async_trait;
use opentelemetry::{
    logs::{AnyValue, LogRecord, Logger, LoggerProvider as _, Severity},
    KeyValue,
};
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use opentelemetry_sdk::{
    logs::{Config, LoggerProvider},
    Resource,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// OpenTelemetry audit exporter.
///
/// Exports audit events as OpenTelemetry log records to an OTLP collector
/// using gRPC protocol.
///
/// # Example
///
/// ```no_run
/// use bssh::server::audit::otel::OtelExporter;
/// use bssh::server::audit::exporter::AuditExporter;
/// use bssh::server::audit::event::{AuditEvent, EventType};
///
/// # async fn example() -> anyhow::Result<()> {
/// let exporter = OtelExporter::new("http://localhost:4317")?;
///
/// let event = AuditEvent::new(
///     EventType::AuthSuccess,
///     "alice".to_string(),
///     "session-123".to_string(),
/// );
///
/// exporter.export(event).await?;
/// exporter.close().await?;
/// # Ok(())
/// # }
/// ```
pub struct OtelExporter {
    logger_provider: Arc<RwLock<LoggerProvider>>,
    endpoint: String,
}

impl OtelExporter {
    /// Create a new OpenTelemetry exporter.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - OTLP endpoint URL (e.g., "http://localhost:4317" for local development,
    ///   "https://otel-collector.example.com:4317" for production)
    ///
    /// # TLS Requirements
    ///
    /// For production deployments, it is strongly recommended to use HTTPS endpoints to ensure
    /// audit data is transmitted securely. HTTP endpoints should only be used for local testing
    /// or when the OTLP collector is on the same trusted network.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The endpoint URL is invalid
    /// - The exporter cannot be initialized
    pub fn new(endpoint: &str) -> Result<Self> {
        // Validate endpoint URL
        url::Url::parse(endpoint).context("invalid endpoint URL")?;

        // Warn if not using HTTPS
        if !endpoint.starts_with("https://") {
            tracing::warn!(
                endpoint = %endpoint,
                "OpenTelemetry audit exporter is not using HTTPS. \
                 Audit data will be transmitted unencrypted. \
                 Use HTTPS for production deployments."
            );
        }
        let export_config = ExportConfig {
            endpoint: endpoint.to_string(),
            protocol: Protocol::Grpc,
            ..Default::default()
        };

        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_export_config(export_config)
            .build_log_exporter()
            .context("failed to build OTLP log exporter")?;

        let resource = Resource::new(vec![
            KeyValue::new("service.name", "bssh-server"),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        ]);

        let logger_provider = LoggerProvider::builder()
            .with_config(Config::default().with_resource(resource))
            .with_simple_exporter(exporter)
            .build();

        Ok(Self {
            logger_provider: Arc::new(RwLock::new(logger_provider)),
            endpoint: endpoint.to_string(),
        })
    }

    /// Convert an audit event to an OpenTelemetry log record.
    fn event_to_log_record(&self, event: &AuditEvent) -> LogRecord {
        let mut attributes = vec![
            KeyValue::new("event.id", event.id.clone()),
            KeyValue::new("event.type", format!("{:?}", event.event_type)),
            KeyValue::new("session.id", event.session_id.clone()),
            KeyValue::new("user.name", event.user.clone()),
            KeyValue::new("result", format!("{:?}", event.result)),
        ];

        if let Some(ref ip) = event.client_ip {
            attributes.push(KeyValue::new("client.ip", ip.to_string()));
        }
        if let Some(ref path) = event.path {
            attributes.push(KeyValue::new("file.path", path.display().to_string()));
        }
        if let Some(ref dest_path) = event.dest_path {
            attributes.push(KeyValue::new(
                "file.dest_path",
                dest_path.display().to_string(),
            ));
        }
        if let Some(bytes) = event.bytes {
            attributes.push(KeyValue::new("file.bytes", bytes as i64));
        }
        if let Some(ref protocol) = event.protocol {
            attributes.push(KeyValue::new("protocol", protocol.clone()));
        }
        if let Some(ref details) = event.details {
            attributes.push(KeyValue::new("details", details.clone()));
        }

        let severity = self.event_to_severity(&event.event_type, &event.result);
        let body = format!(
            "{:?} - {} - {:?}",
            event.event_type, event.user, event.result
        );

        LogRecord::builder()
            .with_timestamp(event.timestamp.into())
            .with_observed_timestamp(event.timestamp.into())
            .with_severity_number(severity)
            .with_severity_text(format!("{:?}", severity))
            .with_body(body.into())
            .with_attributes(
                attributes
                    .into_iter()
                    .map(|kv| (kv.key, AnyValue::from(kv.value)))
                    .collect(),
            )
            .build()
    }

    /// Map event type and result to OpenTelemetry severity level.
    fn event_to_severity(&self, event_type: &EventType, result: &EventResult) -> Severity {
        // High severity for failures and denied operations
        if matches!(result, EventResult::Failure | EventResult::Denied) {
            return match event_type {
                EventType::AuthFailure | EventType::AuthRateLimited => Severity::Warn,
                EventType::TransferDenied | EventType::CommandBlocked => Severity::Warn,
                _ => Severity::Error,
            };
        }

        // Map event types to severity
        match event_type {
            // Security events
            EventType::SuspiciousActivity | EventType::IpBlocked => Severity::Error,
            EventType::AuthFailure | EventType::AuthRateLimited => Severity::Warn,
            EventType::TransferDenied | EventType::CommandBlocked => Severity::Warn,
            EventType::IpUnblocked => Severity::Info,

            // Authentication and session events
            EventType::AuthSuccess | EventType::SessionStart | EventType::SessionEnd => {
                Severity::Info
            }

            // File and directory operations
            EventType::FileOpenRead
            | EventType::FileOpenWrite
            | EventType::FileRead
            | EventType::FileWrite
            | EventType::FileClose
            | EventType::FileUploaded
            | EventType::FileDownloaded
            | EventType::FileDeleted
            | EventType::FileRenamed
            | EventType::DirectoryCreated
            | EventType::DirectoryDeleted
            | EventType::DirectoryListed => Severity::Info,

            // Command execution
            EventType::CommandExecuted => Severity::Info,

            // Transfer allowed
            EventType::TransferAllowed => Severity::Debug,
        }
    }
}

#[async_trait]
impl AuditExporter for OtelExporter {
    async fn export(&self, event: AuditEvent) -> Result<()> {
        let log_record = self.event_to_log_record(&event);
        let provider = self.logger_provider.read().await;
        let logger = provider.logger("bssh-audit");

        logger.emit(log_record);

        Ok(())
    }

    async fn export_batch(&self, events: &[AuditEvent]) -> Result<()> {
        let provider = self.logger_provider.read().await;
        let logger = provider.logger("bssh-audit");

        for event in events {
            let log_record = self.event_to_log_record(event);
            logger.emit(log_record);
        }

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let provider = self.logger_provider.read().await;
        let results = provider.force_flush();

        // Check if any flush operation failed
        for result in results {
            result.context("failed to flush OTLP log exporter")?;
        }

        Ok(())
    }

    async fn close(&self) -> Result<()> {
        let mut provider = self.logger_provider.write().await;
        let results = provider.shutdown();

        // Check if any shutdown operation failed
        for result in results {
            result.context("failed to shutdown OTLP log exporter")?;
        }

        Ok(())
    }
}

impl std::fmt::Debug for OtelExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtelExporter")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_event_to_severity_security_events() {
        let exporter = OtelExporter::new("http://localhost:4317").unwrap();

        assert_eq!(
            exporter.event_to_severity(&EventType::SuspiciousActivity, &EventResult::Success),
            Severity::Error
        );
        assert_eq!(
            exporter.event_to_severity(&EventType::IpBlocked, &EventResult::Success),
            Severity::Error
        );
        assert_eq!(
            exporter.event_to_severity(&EventType::AuthFailure, &EventResult::Failure),
            Severity::Warn
        );
        assert_eq!(
            exporter.event_to_severity(&EventType::AuthRateLimited, &EventResult::Denied),
            Severity::Warn
        );
    }

    #[tokio::test]
    async fn test_event_to_severity_normal_operations() {
        let exporter = OtelExporter::new("http://localhost:4317").unwrap();

        assert_eq!(
            exporter.event_to_severity(&EventType::AuthSuccess, &EventResult::Success),
            Severity::Info
        );
        assert_eq!(
            exporter.event_to_severity(&EventType::FileUploaded, &EventResult::Success),
            Severity::Info
        );
        assert_eq!(
            exporter.event_to_severity(&EventType::CommandExecuted, &EventResult::Success),
            Severity::Info
        );
    }

    #[tokio::test]
    async fn test_event_to_log_record_basic() {
        let exporter = OtelExporter::new("http://localhost:4317").unwrap();
        let event = AuditEvent::new(
            EventType::AuthSuccess,
            "alice".to_string(),
            "session-123".to_string(),
        );

        let log_record = exporter.event_to_log_record(&event);

        assert!(log_record.timestamp.is_some());
        assert_eq!(log_record.severity_number, Some(Severity::Info));
        assert!(log_record.body.is_some());
        assert!(log_record.attributes.is_some());

        let attributes = log_record.attributes.unwrap();
        assert!(attributes.iter().any(|kv| kv.0.as_str() == "event.id"));
        assert!(attributes.iter().any(|kv| {
            if kv.0.as_str() == "user.name" {
                matches!(&kv.1, AnyValue::String(s) if s.as_ref() == "alice")
            } else {
                false
            }
        }));
    }

    #[tokio::test]
    async fn test_event_to_log_record_with_all_fields() {
        let exporter = OtelExporter::new("http://localhost:4317").unwrap();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let event = AuditEvent::new(
            EventType::FileUploaded,
            "bob".to_string(),
            "session-456".to_string(),
        )
        .with_client_ip(ip)
        .with_path(PathBuf::from("/home/bob/file.txt"))
        .with_bytes(1024)
        .with_protocol("sftp")
        .with_details("Upload completed".to_string());

        let log_record = exporter.event_to_log_record(&event);
        let attributes = log_record.attributes.unwrap();

        assert!(attributes.iter().any(|kv| kv.0.as_str() == "client.ip"));
        assert!(attributes.iter().any(|kv| kv.0.as_str() == "file.path"));
        assert!(attributes.iter().any(|kv| {
            if kv.0.as_str() == "file.bytes" {
                matches!(&kv.1, AnyValue::Int(1024))
            } else {
                false
            }
        }));
        assert!(attributes.iter().any(|kv| {
            if kv.0.as_str() == "protocol" {
                matches!(&kv.1, AnyValue::String(s) if s.as_ref() == "sftp")
            } else {
                false
            }
        }));
        assert!(attributes.iter().any(|kv| {
            if kv.0.as_str() == "details" {
                matches!(&kv.1, AnyValue::String(s) if s.as_ref() == "Upload completed")
            } else {
                false
            }
        }));
    }

    #[tokio::test]
    async fn test_export_single_event() {
        let exporter = OtelExporter::new("http://localhost:4317").unwrap();
        let event = AuditEvent::new(
            EventType::SessionStart,
            "charlie".to_string(),
            "session-789".to_string(),
        );

        // Should not fail even if no collector is running
        let result = exporter.export(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_batch() {
        let exporter = OtelExporter::new("http://localhost:4317").unwrap();
        let events = vec![
            AuditEvent::new(
                EventType::AuthSuccess,
                "user1".to_string(),
                "session-1".to_string(),
            ),
            AuditEvent::new(
                EventType::FileUploaded,
                "user2".to_string(),
                "session-2".to_string(),
            ),
        ];

        let result = exporter.export_batch(&events).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_flush() {
        let exporter = OtelExporter::new("http://localhost:4317").unwrap();
        let result = exporter.flush().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_close() {
        let exporter = OtelExporter::new("http://localhost:4317").unwrap();
        let result = exporter.close().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_debug_impl() {
        let exporter = OtelExporter::new("http://localhost:4317").unwrap();
        let debug_str = format!("{:?}", exporter);
        assert!(debug_str.contains("OtelExporter"));
        assert!(debug_str.contains("endpoint"));
    }
}

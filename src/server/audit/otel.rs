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
    KeyValue,
    logs::{AnyValue, LogRecord as _, Logger, LoggerProvider as _, Severity},
};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::{Resource, logs::SdkLoggerProvider};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::RwLockReadGuard;

/// Convert severity to a static string.
fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Trace | Severity::Trace2 | Severity::Trace3 | Severity::Trace4 => "TRACE",
        Severity::Debug | Severity::Debug2 | Severity::Debug3 | Severity::Debug4 => "DEBUG",
        Severity::Info | Severity::Info2 | Severity::Info3 | Severity::Info4 => "INFO",
        Severity::Warn | Severity::Warn2 | Severity::Warn3 | Severity::Warn4 => "WARN",
        Severity::Error | Severity::Error2 | Severity::Error3 | Severity::Error4 => "ERROR",
        Severity::Fatal | Severity::Fatal2 | Severity::Fatal3 | Severity::Fatal4 => "FATAL",
    }
}

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
    logger_provider: Arc<RwLock<SdkLoggerProvider>>,
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

        let exporter = LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .context("failed to build OTLP log exporter")?;

        let resource = Resource::builder()
            .with_service_name("bssh-server")
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build();

        let logger_provider = SdkLoggerProvider::builder()
            .with_resource(resource)
            .with_simple_exporter(exporter)
            .build();

        Ok(Self {
            logger_provider: Arc::new(RwLock::new(logger_provider)),
            endpoint: endpoint.to_string(),
        })
    }

    /// Emit an audit event as an OpenTelemetry log record.
    fn emit_event(&self, provider: &SdkLoggerProvider, event: &AuditEvent) {
        let logger = provider.logger("bssh-audit");
        let mut record = logger.create_log_record();

        let severity = self.event_to_severity(&event.event_type, &event.result);
        let body = format!(
            "{:?} - {} - {:?}",
            event.event_type, event.user, event.result
        );

        record.set_timestamp(event.timestamp.into());
        record.set_observed_timestamp(std::time::SystemTime::now());
        record.set_severity_number(severity);
        record.set_severity_text(severity_to_str(severity));
        record.set_body(AnyValue::String(body.into()));

        // Add core attributes
        record.add_attribute("event.id", AnyValue::String(event.id.clone().into()));
        record.add_attribute(
            "event.type",
            AnyValue::String(format!("{:?}", event.event_type).into()),
        );
        record.add_attribute(
            "session.id",
            AnyValue::String(event.session_id.clone().into()),
        );
        record.add_attribute("user.name", AnyValue::String(event.user.clone().into()));
        record.add_attribute(
            "result",
            AnyValue::String(format!("{:?}", event.result).into()),
        );

        // Add optional attributes
        if let Some(ref ip) = event.client_ip {
            record.add_attribute("client.ip", AnyValue::String(ip.to_string().into()));
        }
        if let Some(ref path) = event.path {
            record.add_attribute(
                "file.path",
                AnyValue::String(path.display().to_string().into()),
            );
        }
        if let Some(ref dest_path) = event.dest_path {
            record.add_attribute(
                "file.dest_path",
                AnyValue::String(dest_path.display().to_string().into()),
            );
        }
        if let Some(bytes) = event.bytes {
            record.add_attribute("file.bytes", AnyValue::Int(bytes as i64));
        }
        if let Some(ref protocol) = event.protocol {
            record.add_attribute("protocol", AnyValue::String(protocol.clone().into()));
        }
        if let Some(ref details) = event.details {
            record.add_attribute("details", AnyValue::String(details.clone().into()));
        }

        logger.emit(record);
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
        let provider = self.logger_provider.read().await;
        self.emit_event(&provider, &event);
        Ok(())
    }

    async fn export_batch(&self, events: &[AuditEvent]) -> Result<()> {
        let provider = self.logger_provider.read().await;
        for event in events {
            self.emit_event(&provider, event);
        }
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let provider: RwLockReadGuard<'_, SdkLoggerProvider> = self.logger_provider.read().await;
        provider
            .force_flush()
            .context("failed to flush OTLP log exporter")?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        let provider: tokio::sync::RwLockWriteGuard<'_, SdkLoggerProvider> =
            self.logger_provider.write().await;
        provider
            .shutdown()
            .context("failed to shutdown OTLP log exporter")?;
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
    #[ignore = "Requires running OTLP collector; SimpleLogProcessor blocks on gRPC send"]
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
    #[ignore = "Requires running OTLP collector; SimpleLogProcessor blocks on gRPC send"]
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

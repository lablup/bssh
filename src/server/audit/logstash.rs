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

//! Logstash audit exporter for sending events to Logstash via TCP.
//!
//! This module provides a Logstash exporter that sends audit events to a
//! Logstash server using TCP with JSON Lines protocol. Each event is
//! serialized as JSON and sent with a newline delimiter.
//!
//! # Features
//!
//! - TCP connection with automatic reconnection on failure
//! - Optional TLS encryption for secure transmission
//! - JSON Lines protocol (newline-delimited JSON)
//! - Batch support for efficient event transmission
//! - Connection timeout handling
//!
//! # Security
//!
//! **WARNING**: By default, connections are unencrypted. For production use,
//! it is strongly recommended to enable TLS encryption using `with_tls(true)`
//! to protect sensitive audit data in transit.
//!
//! # Example
//!
//! ```no_run
//! use bssh::server::audit::logstash::LogstashExporter;
//! use bssh::server::audit::exporter::AuditExporter;
//! use bssh::server::audit::event::{AuditEvent, EventType};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let exporter = LogstashExporter::new("logstash.example.com", 5044)?
//!     .with_tls(true);  // Enable TLS for secure transmission
//!
//! let event = AuditEvent::new(
//!     EventType::AuthSuccess,
//!     "alice".to_string(),
//!     "session-123".to_string(),
//! );
//!
//! exporter.export(event).await?;
//! # Ok(())
//! # }
//! ```

use super::event::AuditEvent;
use super::exporter::AuditExporter;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Represents a connection to the Logstash server, either plain TCP or TLS-encrypted.
enum Connection {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl Connection {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Connection::Plain(stream) => stream.write_all(data).await,
            Connection::Tls(stream) => stream.write_all(data).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Connection::Plain(stream) => stream.flush().await,
            Connection::Tls(stream) => stream.flush().await,
        }
    }
}

/// Logstash audit exporter.
///
/// Sends audit events to a Logstash server via TCP using JSON Lines protocol.
/// The exporter automatically handles connection failures and reconnects
/// as needed.
///
/// # Security
///
/// By default, connections are unencrypted. Use `with_tls(true)` to enable
/// TLS encryption for production environments.
///
/// # Batch Size Considerations
///
/// When using `export_batch()`, be aware that the entire batch is buffered
/// in memory before transmission. Large batches can consume significant memory.
/// Consider the following guidelines:
///
/// - For typical audit events (~1KB each), batches of 100-1000 events are reasonable
/// - Monitor memory usage if processing larger events or higher batch sizes
/// - Adjust batch sizes based on your memory constraints and network latency requirements
pub struct LogstashExporter {
    /// Logstash server hostname or IP address
    host: String,

    /// Logstash server port
    port: u16,

    /// TCP connection (wrapped in Mutex for interior mutability)
    connection: Mutex<Option<Connection>>,

    /// Delay before attempting to reconnect after failure
    reconnect_delay: Duration,

    /// Connection timeout
    connect_timeout: Duration,

    /// Whether to use TLS encryption
    use_tls: bool,

    /// TLS connector (only initialized if use_tls is true)
    tls_connector: Option<TlsConnector>,
}

impl LogstashExporter {
    /// Create a new Logstash exporter.
    ///
    /// **WARNING**: By default, connections are unencrypted. For production use,
    /// call `with_tls(true)` to enable TLS encryption.
    ///
    /// # Arguments
    ///
    /// * `host` - Logstash server hostname or IP address
    /// * `port` - Logstash server port
    ///
    /// # Errors
    ///
    /// Returns an error if the host is invalid (empty, or not a valid hostname/IP).
    pub fn new(host: &str, port: u16) -> Result<Self> {
        if host.is_empty() {
            anyhow::bail!("Logstash host cannot be empty");
        }

        // Validate host format (must be a valid hostname or IP address)
        if !Self::is_valid_host(host) {
            anyhow::bail!("Invalid host format: must be a valid hostname or IP address");
        }

        tracing::warn!(
            "Logstash exporter created without TLS encryption. \
             For production use, enable TLS with with_tls(true) to protect audit data in transit."
        );

        Ok(Self {
            host: host.to_string(),
            port,
            connection: Mutex::new(None),
            reconnect_delay: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            use_tls: false,
            tls_connector: None,
        })
    }

    /// Enable or disable TLS encryption for the connection.
    ///
    /// When TLS is enabled, the exporter will use the system's root certificates
    /// to validate the server's certificate.
    ///
    /// # Arguments
    ///
    /// * `enable` - Whether to enable TLS encryption
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use bssh::server::audit::logstash::LogstashExporter;
    /// # fn example() -> anyhow::Result<()> {
    /// let exporter = LogstashExporter::new("logstash.example.com", 5044)?
    ///     .with_tls(true);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_tls(mut self, enable: bool) -> Self {
        self.use_tls = enable;
        if enable {
            // Initialize TLS connector with system root certificates
            let mut root_store = RootCertStore::empty();
            let cert_result = rustls_native_certs::load_native_certs();

            for cert in cert_result.certs {
                root_store.add(cert).ok();
            }

            if !cert_result.errors.is_empty() {
                tracing::warn!(
                    "Some errors occurred while loading native certificates: {:?}",
                    cert_result.errors
                );
            }

            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            self.tls_connector = Some(TlsConnector::from(Arc::new(config)));
            tracing::info!("TLS encryption enabled for Logstash exporter");
        } else {
            self.tls_connector = None;
            tracing::warn!(
                "TLS encryption disabled for Logstash exporter. \
                 Audit data will be transmitted unencrypted."
            );
        }
        self
    }

    /// Validate that the host string is a valid hostname or IP address.
    ///
    /// # Arguments
    ///
    /// * `host` - The host string to validate
    ///
    /// # Returns
    ///
    /// `true` if the host is a valid hostname or IP address, `false` otherwise.
    fn is_valid_host(host: &str) -> bool {
        // Try to parse as IP address first
        if host.parse::<IpAddr>().is_ok() {
            return true;
        }

        // Validate as hostname (RFC 1123)
        // - Must be 1-253 characters
        // - Each label must be 1-63 characters
        // - Labels can contain alphanumeric characters and hyphens
        // - Labels cannot start or end with a hyphen
        // - Labels are separated by dots
        if host.len() > 253 {
            return false;
        }

        let labels: Vec<&str> = host.split('.').collect();
        if labels.is_empty() {
            return false;
        }

        for label in labels {
            if label.is_empty() || label.len() > 63 {
                return false;
            }

            // Check first and last characters
            let chars: Vec<char> = label.chars().collect();
            if chars[0] == '-' || chars[chars.len() - 1] == '-' {
                return false;
            }

            // Check that all characters are alphanumeric or hyphen
            if !chars.iter().all(|c| c.is_ascii_alphanumeric() || *c == '-') {
                return false;
            }
        }

        true
    }

    /// Ensure a connection to the Logstash server exists.
    ///
    /// If no connection exists, attempts to establish one.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    async fn ensure_connected(&self) -> Result<()> {
        let mut conn = self.connection.lock().await;

        if conn.is_none() {
            match self.connect().await {
                Ok(stream) => {
                    *conn = Some(stream);
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to Logstash: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Establish a connection to the Logstash server (TCP or TLS).
    ///
    /// # Errors
    ///
    /// Returns an error if the connection times out or fails.
    async fn connect(&self) -> Result<Connection> {
        let addr = format!("{}:{}", self.host, self.port);

        let tcp_stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect(&addr))
            .await
            .context("Connection timeout")?
            .context("Failed to connect")?;

        let connection = if self.use_tls {
            let connector = self
                .tls_connector
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("TLS enabled but connector not initialized"))?
                .clone();

            let server_name =
                ServerName::try_from(self.host.clone()).context("Invalid server name for TLS")?;

            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .context("TLS handshake failed")?;

            tracing::info!("Connected to Logstash at {} with TLS", addr);
            Connection::Tls(Box::new(tls_stream))
        } else {
            tracing::info!("Connected to Logstash at {} (unencrypted)", addr);
            Connection::Plain(tcp_stream)
        };

        Ok(connection)
    }

    /// Send data to the Logstash server.
    ///
    /// If the connection is lost, attempts to reconnect once before failing.
    /// The mutex is released during the reconnection delay to avoid blocking
    /// other operations.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte data to send
    ///
    /// # Errors
    ///
    /// Returns an error if the send fails or reconnection fails.
    async fn send(&self, data: &[u8]) -> Result<()> {
        let mut conn = self.connection.lock().await;

        // Try to send with existing connection
        if let Some(ref mut stream) = *conn {
            match stream.write_all(data).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    tracing::warn!("Logstash write failed, reconnecting: {}", e);
                    *conn = None;
                }
            }
        }

        // Connection lost or didn't exist, drop the lock before sleeping
        drop(conn);

        // Wait before reconnecting (without holding the lock)
        tokio::time::sleep(self.reconnect_delay).await;

        // Reconnect and retry
        let mut stream = self.connect().await?;
        stream
            .write_all(data)
            .await
            .context("Failed to write after reconnection")?;

        // Reacquire lock and store the connection
        let mut conn = self.connection.lock().await;
        *conn = Some(stream);

        Ok(())
    }

    /// Format an audit event as JSON with newline delimiter.
    ///
    /// # Arguments
    ///
    /// * `event` - The audit event to format
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be serialized to JSON.
    fn format_event(&self, event: &AuditEvent) -> Result<String> {
        let mut json = serde_json::to_string(event).context("Failed to serialize event")?;
        json.push('\n');
        Ok(json)
    }
}

#[async_trait]
impl AuditExporter for LogstashExporter {
    async fn export(&self, event: AuditEvent) -> Result<()> {
        self.ensure_connected().await?;
        let data = self.format_event(&event)?;
        self.send(data.as_bytes()).await
    }

    async fn export_batch(&self, events: &[AuditEvent]) -> Result<()> {
        self.ensure_connected().await?;

        // Format all events into a single buffer
        let mut batch = String::new();
        for event in events {
            batch.push_str(&self.format_event(event)?);
        }

        self.send(batch.as_bytes()).await
    }

    async fn flush(&self) -> Result<()> {
        let mut conn = self.connection.lock().await;
        if let Some(ref mut stream) = *conn {
            stream
                .flush()
                .await
                .context("Failed to flush Logstash connection")?;
        }
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        let mut conn = self.connection.lock().await;
        if let Some(stream) = conn.take() {
            drop(stream);
            tracing::info!("Closed Logstash connection");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::audit::event::{EventResult, EventType};
    use std::net::{IpAddr, SocketAddr};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// Helper to create a mock Logstash server for testing
    async fn mock_logstash_server() -> (SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut received_lines = Vec::new();
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut buffer = String::new();
            loop {
                let mut chunk = [0u8; 1024];
                match socket.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buffer.push_str(&String::from_utf8_lossy(&chunk[..n]));
                        // Process complete lines
                        while let Some(pos) = buffer.find('\n') {
                            let line = buffer[..pos].to_string();
                            buffer.drain(..=pos);
                            received_lines.push(line);
                        }
                    }
                    Err(_) => break,
                }
            }
            received_lines
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn test_logstash_exporter_creation() {
        let exporter = LogstashExporter::new("localhost", 5044);
        assert!(exporter.is_ok());
    }

    #[tokio::test]
    async fn test_logstash_exporter_invalid_host() {
        let exporter = LogstashExporter::new("", 5044);
        assert!(exporter.is_err());
    }

    #[tokio::test]
    async fn test_host_validation() {
        // Valid hostnames
        assert!(LogstashExporter::new("localhost", 5044).is_ok());
        assert!(LogstashExporter::new("logstash.example.com", 5044).is_ok());
        assert!(LogstashExporter::new("my-server-01.internal.example.com", 5044).is_ok());

        // Valid IP addresses
        assert!(LogstashExporter::new("127.0.0.1", 5044).is_ok());
        assert!(LogstashExporter::new("192.168.1.100", 5044).is_ok());
        assert!(LogstashExporter::new("::1", 5044).is_ok());
        assert!(LogstashExporter::new("2001:db8::1", 5044).is_ok());

        // Invalid hostnames
        assert!(LogstashExporter::new("", 5044).is_err());
        assert!(LogstashExporter::new("-invalid", 5044).is_err());
        assert!(LogstashExporter::new("invalid-", 5044).is_err());
        assert!(LogstashExporter::new("invalid..host", 5044).is_err());
        assert!(LogstashExporter::new("invalid host with spaces", 5044).is_err());
        assert!(LogstashExporter::new("invalid@host", 5044).is_err());
    }

    #[tokio::test]
    async fn test_with_tls() {
        let exporter = LogstashExporter::new("localhost", 5044)
            .unwrap()
            .with_tls(true);
        assert!(exporter.use_tls);
        assert!(exporter.tls_connector.is_some());

        let exporter = LogstashExporter::new("localhost", 5044)
            .unwrap()
            .with_tls(false);
        assert!(!exporter.use_tls);
        assert!(exporter.tls_connector.is_none());
    }

    #[tokio::test]
    async fn test_format_event() {
        let exporter = LogstashExporter::new("localhost", 5044).unwrap();

        let event = AuditEvent::new(
            EventType::AuthSuccess,
            "alice".to_string(),
            "session-123".to_string(),
        );

        let formatted = exporter.format_event(&event).unwrap();

        // Should be valid JSON ending with newline
        assert!(formatted.ends_with('\n'));
        let json_part = formatted.trim_end();
        assert!(serde_json::from_str::<serde_json::Value>(json_part).is_ok());
    }

    #[tokio::test]
    async fn test_export_single_event() {
        let (addr, server_handle) = mock_logstash_server().await;

        let exporter = LogstashExporter::new(&addr.ip().to_string(), addr.port()).unwrap();

        let event = AuditEvent::new(
            EventType::SessionStart,
            "bob".to_string(),
            "session-456".to_string(),
        );

        let result = exporter.export(event).await;
        assert!(result.is_ok());

        // Close connection to trigger server to finish
        exporter.close().await.unwrap();

        let received = server_handle.await.unwrap();
        assert_eq!(received.len(), 1);
        assert!(received[0].contains("session-456"));
        assert!(received[0].contains("bob"));
    }

    #[tokio::test]
    async fn test_export_batch() {
        let (addr, server_handle) = mock_logstash_server().await;

        let exporter = LogstashExporter::new(&addr.ip().to_string(), addr.port()).unwrap();

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
            )
            .with_result(EventResult::Success),
            AuditEvent::new(
                EventType::SessionEnd,
                "user3".to_string(),
                "session-3".to_string(),
            ),
        ];

        let result = exporter.export_batch(&events).await;
        assert!(result.is_ok());

        exporter.close().await.unwrap();

        let received = server_handle.await.unwrap();
        assert_eq!(received.len(), 3);
        assert!(received[0].contains("session-1"));
        assert!(received[1].contains("session-2"));
        assert!(received[2].contains("session-3"));
    }

    #[tokio::test]
    async fn test_connection_timeout() {
        // Use a non-routable IP to trigger timeout
        let exporter = LogstashExporter::new("192.0.2.1", 5044).unwrap();

        let event = AuditEvent::new(
            EventType::AuthSuccess,
            "test".to_string(),
            "session-test".to_string(),
        );

        let result = exporter.export(event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_flush() {
        let (addr, server_handle) = mock_logstash_server().await;

        let exporter = LogstashExporter::new(&addr.ip().to_string(), addr.port()).unwrap();

        let event = AuditEvent::new(
            EventType::CommandExecuted,
            "charlie".to_string(),
            "session-789".to_string(),
        );

        exporter.export(event).await.unwrap();
        let result = exporter.flush().await;
        assert!(result.is_ok());

        exporter.close().await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_close() {
        let (addr, _server_handle) = mock_logstash_server().await;

        let exporter = LogstashExporter::new(&addr.ip().to_string(), addr.port()).unwrap();

        // Connect by sending an event
        let event = AuditEvent::new(
            EventType::SessionStart,
            "dave".to_string(),
            "session-101".to_string(),
        );
        exporter.export(event).await.unwrap();

        // Close should succeed
        let result = exporter.close().await;
        assert!(result.is_ok());

        // Close again should also succeed (idempotent)
        let result = exporter.close().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_json_lines_format() {
        let exporter = LogstashExporter::new("localhost", 5044).unwrap();

        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let event = AuditEvent::new(
            EventType::FileDownloaded,
            "eve".to_string(),
            "session-202".to_string(),
        )
        .with_client_ip(ip)
        .with_bytes(2048);

        let formatted = exporter.format_event(&event).unwrap();

        // Verify JSON Lines format
        assert!(formatted.ends_with('\n'));
        let lines: Vec<&str> = formatted.lines().collect();
        assert_eq!(lines.len(), 1);

        // Parse and verify content
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["user"], "eve");
        assert_eq!(parsed["session_id"], "session-202");
        assert_eq!(parsed["bytes"], 2048);
    }
}

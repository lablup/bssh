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
//! - JSON Lines protocol (newline-delimited JSON)
//! - Batch support for efficient event transmission
//! - Connection timeout handling
//!
//! # Example
//!
//! ```no_run
//! use bssh::server::audit::logstash::LogstashExporter;
//! use bssh::server::audit::exporter::AuditExporter;
//! use bssh::server::audit::event::{AuditEvent, EventType};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let exporter = LogstashExporter::new("logstash.example.com", 5044)?;
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
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Logstash audit exporter.
///
/// Sends audit events to a Logstash server via TCP using JSON Lines protocol.
/// The exporter automatically handles connection failures and reconnects
/// as needed.
pub struct LogstashExporter {
    /// Logstash server hostname or IP address
    host: String,

    /// Logstash server port
    port: u16,

    /// TCP connection (wrapped in Mutex for interior mutability)
    connection: Mutex<Option<TcpStream>>,

    /// Delay before attempting to reconnect after failure
    reconnect_delay: Duration,

    /// Connection timeout
    connect_timeout: Duration,
}

impl LogstashExporter {
    /// Create a new Logstash exporter.
    ///
    /// # Arguments
    ///
    /// * `host` - Logstash server hostname or IP address
    /// * `port` - Logstash server port
    ///
    /// # Errors
    ///
    /// Returns an error if the host or port are invalid.
    pub fn new(host: &str, port: u16) -> Result<Self> {
        if host.is_empty() {
            anyhow::bail!("Logstash host cannot be empty");
        }

        Ok(Self {
            host: host.to_string(),
            port,
            connection: Mutex::new(None),
            reconnect_delay: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
        })
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

    /// Establish a TCP connection to the Logstash server.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection times out or fails.
    async fn connect(&self) -> Result<TcpStream> {
        let addr = format!("{}:{}", self.host, self.port);

        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect(&addr))
            .await
            .context("Connection timeout")?
            .context("Failed to connect")?;

        tracing::info!("Connected to Logstash at {}", addr);
        Ok(stream)
    }

    /// Send data to the Logstash server.
    ///
    /// If the connection is lost, attempts to reconnect once before failing.
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

        // Connection lost or didn't exist, reconnect and retry
        tokio::time::sleep(self.reconnect_delay).await;
        let mut stream = self.connect().await?;
        stream
            .write_all(data)
            .await
            .context("Failed to write after reconnection")?;
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

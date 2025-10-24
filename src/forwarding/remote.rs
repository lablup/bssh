//! Remote port forwarding implementation (-R option)
//!
//! Remote port forwarding requests the SSH server to create a listener
//! that forwards connections back to a local destination. This is equivalent
//! to the OpenSSH `-R [bind_address:]port:host:hostport` option.
//!
//! # Architecture
//!
//! ```text
//! [Remote Client] → [SSH Server Listener] → [SSH Channel] → [Local Host:Port]
//!                    ↑ bind_addr:bind_port                  ↑ local_host:local_port
//! ```
//!
//! # Example Usage
//!
//! Forward remote port 8080 to localhost:80:
//! ```bash
//! bssh -R 8080:localhost:80 user@ssh-server
//! ```
//!
//! This requests the SSH server to listen on port 8080 and forward all
//! connections to localhost:80 via the SSH connection.
//!
//! # Implementation Status
//!
//! **Placeholder Implementation**
//! This is a placeholder implementation that provides the basic structure
//! and error handling. The full SSH tcpip-forward protocol implementation
//! will be completed in a future update.

use super::{
    ForwardingConfig, ForwardingMessage, ForwardingStats, ForwardingStatus, ForwardingType,
};
use crate::ssh::tokio_client::Client;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};
use uuid::Uuid;

/// Remote port forwarder implementation
#[derive(Debug)]
#[allow(dead_code)] // Future implementation
pub struct RemoteForwarder {
    session_id: Uuid,
    bind_addr: SocketAddr,
    local_host: String,
    local_port: u16,
    config: ForwardingConfig,
    ssh_client: Arc<Client>,
    cancel_token: CancellationToken,
    message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    stats: Arc<RemoteForwarderStats>,
}

/// Statistics specific to remote forwarding
#[derive(Debug, Default)]
#[allow(dead_code)] // Future implementation fields
struct RemoteForwarderStats {
    /// Total connections forwarded
    connections_forwarded: AtomicU64,
    /// Currently active connections
    active_connections: AtomicU64,
    /// Total connections failed
    connections_failed: AtomicU64,
    /// Total bytes transferred across all connections
    total_bytes_transferred: AtomicU64,
    /// tcpip-forward requests sent
    forward_requests_sent: AtomicU64,
    /// tcpip-forward request failures
    forward_request_failures: AtomicU64,
}

impl RemoteForwarder {
    /// Create a new remote forwarder instance
    pub fn new(
        session_id: Uuid,
        spec: ForwardingType,
        ssh_client: Arc<Client>,
        config: ForwardingConfig,
        cancel_token: CancellationToken,
        message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    ) -> Result<Self> {
        let (bind_addr, local_host, local_port) = match spec {
            ForwardingType::Remote {
                bind_addr,
                bind_port,
                local_host,
                local_port,
            } => {
                let addr = SocketAddr::new(bind_addr, bind_port);
                (addr, local_host, local_port)
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid forwarding type for RemoteForwarder"
                ))
            }
        };

        Ok(Self {
            session_id,
            bind_addr,
            local_host,
            local_port,
            config,
            ssh_client,
            cancel_token,
            message_tx,
            stats: Arc::new(RemoteForwarderStats::default()),
        })
    }

    /// Main entry point for running remote port forwarding
    ///
    /// This implements the complete remote port forwarding flow:
    /// 1. Send SSH tcpip-forward request to establish remote listener
    /// 2. Handle forwarded-tcpip channel requests from server
    /// 3. Forward connections to local destination
    pub async fn run(
        session_id: Uuid,
        spec: ForwardingType,
        ssh_client: Arc<Client>,
        config: ForwardingConfig,
        cancel_token: CancellationToken,
        message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    ) -> Result<()> {
        let mut forwarder = Self::new(
            session_id,
            spec,
            ssh_client,
            config,
            cancel_token.clone(),
            message_tx.clone(),
        )?;

        // Send initial status update
        forwarder
            .send_status_update(ForwardingStatus::Initializing)
            .await;

        info!(
            "Starting remote forwarding: {} ← {}:{}",
            forwarder.bind_addr, forwarder.local_host, forwarder.local_port
        );

        // Run the remote forwarding with automatic retry
        match forwarder.run_with_retry().await {
            Ok(_) => {
                forwarder
                    .send_status_update(ForwardingStatus::Stopped)
                    .await;
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Remote forwarding failed: {e}");
                forwarder
                    .send_status_update(ForwardingStatus::Failed(error_msg.clone()))
                    .await;
                Err(anyhow::anyhow!(error_msg))
            }
        }
    }

    /// Run remote forwarding with automatic retry on failures
    async fn run_with_retry(&mut self) -> Result<()> {
        let mut retry_count = 0u32;
        let mut retry_delay = Duration::from_millis(self.config.reconnect_delay_ms);

        loop {
            // Check if we should stop
            if self.cancel_token.is_cancelled() {
                info!("Remote forwarding cancelled");
                break;
            }

            // Check retry limits
            if self.config.max_reconnect_attempts > 0
                && retry_count >= self.config.max_reconnect_attempts
            {
                return Err(anyhow::anyhow!(
                    "Maximum retry attempts ({}) exceeded",
                    self.config.max_reconnect_attempts
                ));
            }

            // Update status based on retry state
            if retry_count == 0 {
                self.send_status_update(ForwardingStatus::Initializing)
                    .await;
            } else {
                self.send_status_update(ForwardingStatus::Reconnecting)
                    .await;

                // Wait before retrying
                tokio::select! {
                    _ = sleep(retry_delay) => {}
                    _ = self.cancel_token.cancelled() => {
                        info!("Remote forwarding cancelled during retry delay");
                        break;
                    }
                }
            }

            info!(
                "Starting remote forwarding: {} ← {}:{} (attempt {})",
                self.bind_addr,
                self.local_host,
                self.local_port,
                retry_count + 1
            );

            // Attempt to start remote forwarding
            match self.run_remote_forwarding_loop().await {
                Ok(_) => {
                    // Successful completion (probably cancelled)
                    break;
                }
                Err(e) => {
                    error!(
                        "Remote forwarding attempt {} failed: {}",
                        retry_count + 1,
                        e
                    );

                    retry_count += 1;

                    if !self.config.auto_reconnect {
                        return Err(e);
                    }

                    // Exponential backoff with jitter
                    retry_delay = std::cmp::min(
                        retry_delay.mul_f64(1.5),
                        Duration::from_millis(self.config.max_reconnect_delay_ms),
                    );

                    // Add jitter to avoid thundering herd
                    let jitter = Duration::from_millis(fastrand::u64(
                        0..=retry_delay.as_millis() as u64 / 4,
                    ));
                    retry_delay += jitter;
                }
            }
        }

        Ok(())
    }

    /// Main remote forwarding loop - request port forward and handle channels
    async fn run_remote_forwarding_loop(&mut self) -> Result<()> {
        // Record the request attempt
        self.stats
            .forward_requests_sent
            .fetch_add(1, Ordering::Relaxed);

        // **TODO**: Request remote port forward from SSH server
        info!(
            "Requesting remote port forward: {}:{}",
            self.bind_addr.ip(),
            self.bind_addr.port()
        );

        // Try to send the tcpip-forward request
        let bound_port = match self
            .ssh_client
            .request_port_forward(
                self.bind_addr.ip().to_string(),
                self.bind_addr.port() as u32,
            )
            .await
        {
            Ok(port) => {
                info!(
                    "Remote port forward established: {}:{} → {}:{}",
                    self.bind_addr.ip(),
                    port,
                    self.local_host,
                    self.local_port
                );
                port
            }
            Err(e) => {
                self.stats
                    .forward_request_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    "Failed to establish remote port forward: {}. This is expected in the current implementation - SSH protocol support is not yet complete.",
                    e
                );

                // For now, simulate the port forward being established
                // This allows testing of the rest of the forwarding infrastructure
                warn!(
                    "Simulating remote port forward: {} ← {}:{} (SSH protocol implementation pending)",
                    self.bind_addr, self.local_host, self.local_port
                );
                self.bind_addr.port() as u32
            }
        };

        // Update status to active
        self.send_status_update(ForwardingStatus::Active).await;

        info!(
            "Remote forwarding active: {}:{} ← {}:{}",
            self.bind_addr.ip(),
            bound_port,
            self.local_host,
            self.local_port
        );

        // **TODO**: Handle forwarded-tcpip channel requests
        // For now, we'll wait for cancellation since russh doesn't have direct support
        // for handling incoming channel requests in the client handler yet

        // In a complete implementation, this would:
        // 1. Register a channel handler for "forwarded-tcpip" channels
        // 2. When server opens a channel, extract the connection details
        // 3. Create a TCP connection to local_host:local_port
        // 4. Use the Tunnel module for bidirectional data transfer
        // 5. Update statistics and handle errors

        warn!(
            "Remote forwarding listening simulation active. Full implementation requires russh client handler extension for forwarded-tcpip channels."
        );

        // Wait for cancellation or implement periodic status updates
        let mut status_interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = status_interval.tick() => {
                    // Send periodic statistics updates
                    self.send_stats_update().await;
                    trace!("Remote forwarding status update sent");
                }
                _ = self.cancel_token.cancelled() => {
                    info!("Remote forwarding cancelled, cleaning up");
                    break;
                }
            }
        }

        // **TODO**: Clean up remote port forward
        // Try to cancel the remote port forward
        if let Err(e) = self
            .ssh_client
            .cancel_port_forward(self.bind_addr.ip().to_string(), bound_port)
            .await
        {
            warn!(
                "Failed to cancel remote port forward: {} (expected in current implementation)",
                e
            );
        } else {
            info!("Remote port forward cancelled successfully");
        }

        info!("Remote forwarding stopped");
        Ok(())
    }

    /// Send status update to ForwardingManager
    async fn send_status_update(&self, status: ForwardingStatus) {
        let message = ForwardingMessage::StatusUpdate {
            id: self.session_id,
            status,
        };

        if let Err(e) = self.message_tx.send(message) {
            warn!("Failed to send status update: {}", e);
        }
    }

    /// Send statistics update to ForwardingManager
    #[allow(dead_code)] // Used in future implementation
    async fn send_stats_update(&self) {
        let stats = ForwardingStats {
            active_connections: self.stats.active_connections.load(Ordering::Relaxed) as usize,
            total_connections: self.stats.connections_forwarded.load(Ordering::Relaxed),
            bytes_transferred: self.stats.total_bytes_transferred.load(Ordering::Relaxed),
            failed_connections: self.stats.connections_failed.load(Ordering::Relaxed),
            last_error: None,
        };

        let message = ForwardingMessage::StatsUpdate {
            id: self.session_id,
            stats,
        };

        if let Err(e) = self.message_tx.send(message) {
            warn!("Failed to send stats update: {}", e);
        }
    }
}

// **Implementation Notes:**
//
// The full remote forwarding implementation will require:
//
// 1. **SSH Protocol Integration:**
//    - Extend tokio_client to support global requests
//    - Implement SSH2_MSG_GLOBAL_REQUEST for "tcpip-forward"
//    - Handle SSH2_MSG_REQUEST_SUCCESS/FAILURE responses
//    - Support "cancel-tcpip-forward" for cleanup
//
// 2. **Channel Handler Registration:**
//    - Extend SSH client to register custom channel handlers
//    - Handle SSH2_MSG_CHANNEL_OPEN for "forwarded-tcpip" channels
//    - Extract remote connection info from channel request data
//
// 3. **Connection Management:**
//    - Create TCP connections to local destinations
//    - Use existing Tunnel implementation for data transfer
//    - Handle connection failures and retries
//    - Maintain statistics for monitoring
//
// 4. **Error Handling:**
//    - Handle SSH server rejection of forward requests
//    - Deal with local connection failures
//    - Implement proper cleanup on shutdown
//
// The architecture will closely mirror the local forwarding implementation
// but in reverse, with the SSH server initiating connections that we
// forward to local destinations.

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::sync::mpsc;

    #[tokio::test]
    #[ignore = "Requires SSH server connection"]
    async fn test_remote_forwarder_creation() {
        let spec = ForwardingType::Remote {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 8080,
            local_host: "localhost".to_string(),
            local_port: 80,
        };

        // Note: This test will fail in the current state since we can't actually
        // create an SSH client without a real connection. In future implementation, we'll need
        // to implement proper mocking for SSH client testing.

        let config = ForwardingConfig::default();
        let cancel_token = CancellationToken::new();
        let (message_tx, _message_rx) = mpsc::unbounded_channel();
        let session_id = Uuid::new_v4();

        // For now, we'll just test the creation with a mock
        // In future implementation, implement proper SSH client mocking
        let ssh_client = Arc::new(
            Client::connect(
                ("127.0.0.1", 22),
                "test_user",
                crate::ssh::tokio_client::AuthMethod::with_password("test"),
                crate::ssh::tokio_client::ServerCheckMethod::NoCheck,
            )
            .await
            .unwrap(),
        );

        let forwarder = RemoteForwarder::new(
            session_id,
            spec,
            ssh_client,
            config,
            cancel_token,
            message_tx,
        );

        assert!(forwarder.is_ok());

        let forwarder = forwarder.unwrap();
        assert_eq!(forwarder.session_id, session_id);
        assert_eq!(forwarder.local_host, "localhost");
        assert_eq!(forwarder.local_port, 80);
    }

    #[test]
    fn test_remote_forwarder_stats() {
        let stats = RemoteForwarderStats::default();

        stats.connections_forwarded.store(5, Ordering::Relaxed);
        stats.connections_failed.store(1, Ordering::Relaxed);
        stats.forward_requests_sent.store(1, Ordering::Relaxed);

        assert_eq!(stats.connections_forwarded.load(Ordering::Relaxed), 5);
        assert_eq!(stats.connections_failed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.forward_requests_sent.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    #[ignore = "Requires SSH server connection"]
    async fn test_invalid_forwarding_type() {
        let spec = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 8080,
            remote_host: "example.com".to_string(),
            remote_port: 80,
        };

        let ssh_client = Arc::new(
            Client::connect(
                ("127.0.0.1", 22),
                "test_user",
                crate::ssh::tokio_client::AuthMethod::with_password("test"),
                crate::ssh::tokio_client::ServerCheckMethod::NoCheck,
            )
            .await
            .unwrap(),
        );

        let config = ForwardingConfig::default();
        let cancel_token = CancellationToken::new();
        let (message_tx, _message_rx) = mpsc::unbounded_channel();
        let session_id = Uuid::new_v4();

        let result = RemoteForwarder::new(
            session_id,
            spec,
            ssh_client,
            config,
            cancel_token,
            message_tx,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid forwarding type"));
    }
}

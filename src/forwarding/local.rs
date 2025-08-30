//! Local port forwarding implementation (-L option)
//!
//! Local port forwarding creates a local TCP listener that accepts connections
//! and forwards them to a remote destination via SSH tunneling. This is equivalent
//! to the OpenSSH `-L [bind_address:]port:host:hostport` option.
//!
//! # Architecture
//!
//! ```text
//! [Client] → [Local Listener] → [SSH Channel] → [Remote Host:Port]
//!              ↑ bind_addr:bind_port              ↑ remote_host:remote_port
//! ```
//!
//! # Example Usage
//!
//! Forward local port 8080 to example.com:80 via SSH:
//! ```bash
//! bssh -L 8080:example.com:80 user@ssh-server
//! ```
//!
//! This creates a local listener on 127.0.0.1:8080 that forwards all
//! connections to example.com:80 through the SSH connection.
//!
//! # Implementation Details
//!
//! - Creates a `TcpListener` bound to the specified local address and port
//! - For each incoming connection, creates a new SSH channel to the remote destination
//! - Uses the `Tunnel` module for bidirectional data transfer
//! - Supports concurrent connections with configurable limits
//! - Provides comprehensive error handling and connection cleanup

use super::tunnel::{Tunnel, TunnelStats};
use super::{
    ForwardingConfig, ForwardingMessage, ForwardingStats, ForwardingStatus, ForwardingType,
};
use crate::ssh::tokio_client::Client;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

/// Local port forwarder implementation
#[derive(Debug)]
pub struct LocalForwarder {
    session_id: Uuid,
    bind_addr: SocketAddr,
    remote_host: String,
    remote_port: u16,
    config: ForwardingConfig,
    ssh_client: Arc<Client>,
    cancel_token: CancellationToken,
    message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    stats: Arc<LocalForwarderStats>,
}

/// Statistics specific to local forwarding
#[derive(Debug, Default)]
#[allow(dead_code)] // Future monitoring fields
struct LocalForwarderStats {
    /// Total connections accepted
    connections_accepted: AtomicU64,
    /// Currently active connections
    active_connections: AtomicU64,
    /// Total connections failed
    connections_failed: AtomicU64,
    /// Total bytes transferred across all connections
    total_bytes_transferred: AtomicU64,
    /// Listener bind attempts
    bind_attempts: AtomicU64,
    /// SSH channel creation failures
    channel_failures: AtomicU64,
}

impl LocalForwarder {
    /// Create a new local forwarder instance
    pub fn new(
        session_id: Uuid,
        spec: ForwardingType,
        ssh_client: Arc<Client>,
        config: ForwardingConfig,
        cancel_token: CancellationToken,
        message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    ) -> Result<Self> {
        let (bind_addr, remote_host, remote_port) = match spec {
            ForwardingType::Local {
                bind_addr,
                bind_port,
                remote_host,
                remote_port,
            } => {
                let addr = SocketAddr::new(bind_addr, bind_port);
                (addr, remote_host, remote_port)
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid forwarding type for LocalForwarder"
                ))
            }
        };

        Ok(Self {
            session_id,
            bind_addr,
            remote_host,
            remote_port,
            config,
            ssh_client,
            cancel_token,
            message_tx,
            stats: Arc::new(LocalForwarderStats::default()),
        })
    }

    /// Main entry point for running local port forwarding
    ///
    /// This is the function called by the ForwardingManager to start
    /// a local forwarding session.
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

        // Run the forwarding loop with automatic retry
        match forwarder.run_with_retry().await {
            Ok(_) => {
                forwarder
                    .send_status_update(ForwardingStatus::Stopped)
                    .await;
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Local forwarding failed: {e}");
                forwarder
                    .send_status_update(ForwardingStatus::Failed(error_msg.clone()))
                    .await;
                Err(anyhow::anyhow!(error_msg))
            }
        }
    }

    /// Run forwarding with automatic retry on failures
    async fn run_with_retry(&mut self) -> Result<()> {
        let mut retry_count = 0u32;
        let mut retry_delay = Duration::from_millis(self.config.reconnect_delay_ms);

        loop {
            // Check if we should stop
            if self.cancel_token.is_cancelled() {
                info!("Local forwarding cancelled");
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
                        info!("Local forwarding cancelled during retry delay");
                        break;
                    }
                }
            }

            info!(
                "Starting local forwarding: {} → {}:{} (attempt {})",
                self.bind_addr,
                self.remote_host,
                self.remote_port,
                retry_count + 1
            );

            // Attempt to start forwarding
            match self.run_forwarding_loop().await {
                Ok(_) => {
                    // Successful completion (probably cancelled)
                    break;
                }
                Err(e) => {
                    error!("Local forwarding attempt {} failed: {}", retry_count + 1, e);

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

    /// Main forwarding loop - bind listener and handle connections
    async fn run_forwarding_loop(&mut self) -> Result<()> {
        // Create TCP listener
        self.stats.bind_attempts.fetch_add(1, Ordering::Relaxed);
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", self.bind_addr))?;

        let local_addr = listener
            .local_addr()
            .with_context(|| "Failed to get local address")?;

        info!("Local forwarding listening on {}", local_addr);
        self.send_status_update(ForwardingStatus::Active).await;

        // Create semaphore to limit concurrent connections
        let connection_semaphore = Arc::new(Semaphore::new(self.config.max_connections));

        loop {
            tokio::select! {
                // Accept new connections
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            trace!("Accepted connection from {}", peer_addr);
                            self.stats.connections_accepted.fetch_add(1, Ordering::Relaxed);

                            // Spawn connection handler
                            self.spawn_connection_handler(stream, peer_addr, Arc::clone(&connection_semaphore));
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                            self.stats.connections_failed.fetch_add(1, Ordering::Relaxed);

                            // Brief pause to avoid busy loop on persistent errors
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                // Handle cancellation
                _ = self.cancel_token.cancelled() => {
                    info!("Local forwarding cancelled, stopping listener");
                    break;
                }
            }
        }

        info!("Local forwarding stopped");
        Ok(())
    }

    /// Spawn a task to handle an individual connection
    fn spawn_connection_handler(
        &self,
        tcp_stream: TcpStream,
        peer_addr: SocketAddr,
        connection_semaphore: Arc<Semaphore>,
    ) {
        let _session_id = self.session_id;
        let remote_host = self.remote_host.clone();
        let remote_port = self.remote_port;
        let ssh_client = Arc::clone(&self.ssh_client);
        let stats = Arc::clone(&self.stats);
        let cancel_token = self.cancel_token.clone();
        let buffer_size = self.config.buffer_size;

        tokio::spawn(async move {
            // Acquire connection semaphore permit
            let _permit = match connection_semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    warn!("Failed to acquire connection permit for {}", peer_addr);
                    return;
                }
            };

            stats.active_connections.fetch_add(1, Ordering::Relaxed);

            debug!(
                "Handling connection from {} → {}:{}",
                peer_addr, remote_host, remote_port
            );

            // Handle the connection
            let result = Self::handle_connection(
                tcp_stream,
                peer_addr,
                &remote_host,
                remote_port,
                &ssh_client,
                cancel_token,
                buffer_size,
            )
            .await;

            // Update statistics
            stats.active_connections.fetch_sub(1, Ordering::Relaxed);

            match result {
                Ok(tunnel_stats) => {
                    debug!(
                        "Connection from {} completed: {} bytes transferred",
                        peer_addr,
                        tunnel_stats.total_bytes()
                    );
                    stats
                        .total_bytes_transferred
                        .fetch_add(tunnel_stats.total_bytes(), Ordering::Relaxed);
                }
                Err(e) => {
                    error!("Connection from {} failed: {}", peer_addr, e);
                    stats.connections_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    /// Handle a single connection by creating SSH channel and starting tunnel
    async fn handle_connection(
        tcp_stream: TcpStream,
        peer_addr: SocketAddr,
        remote_host: &str,
        remote_port: u16,
        ssh_client: &Client,
        cancel_token: CancellationToken,
        _buffer_size: usize,
    ) -> Result<TunnelStats> {
        // Create SSH channel for this connection
        debug!("Creating SSH channel to {}:{}", remote_host, remote_port);

        let target = format!("{remote_host}:{remote_port}");
        let ssh_channel = ssh_client
            .open_direct_tcpip_channel(target, None)
            .await
            .with_context(|| {
                format!("Failed to create SSH channel to {remote_host}:{remote_port}")
            })?;

        trace!("SSH channel created for connection from {}", peer_addr);

        // Start bidirectional tunnel
        let tunnel_result = Tunnel::run(tcp_stream, ssh_channel, cancel_token).await;

        match tunnel_result {
            Ok(stats) => {
                trace!(
                    "Tunnel completed for {}: {} bytes in {:?}",
                    peer_addr,
                    stats.total_bytes(),
                    stats.duration()
                );
                Ok(stats)
            }
            Err(e) => {
                warn!("Tunnel failed for {}: {}", peer_addr, e);
                Err(e)
            }
        }
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
    #[allow(dead_code)] // Used for monitoring
    async fn send_stats_update(&self) {
        let stats = ForwardingStats {
            active_connections: self.stats.active_connections.load(Ordering::Relaxed) as usize,
            total_connections: self.stats.connections_accepted.load(Ordering::Relaxed),
            bytes_transferred: self.stats.total_bytes_transferred.load(Ordering::Relaxed),
            failed_connections: self.stats.connections_failed.load(Ordering::Relaxed),
            last_error: None, // Could be enhanced to track last error
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_local_forwarder_creation() {
        let spec = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 8080,
            remote_host: "example.com".to_string(),
            remote_port: 80,
        };

        let ssh_client = Arc::new(
            Client::connect(
                ("test", 22),
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

        let forwarder = LocalForwarder::new(
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
        assert_eq!(forwarder.remote_host, "example.com");
        assert_eq!(forwarder.remote_port, 80);
    }

    #[test]
    fn test_local_forwarder_stats() {
        let stats = LocalForwarderStats::default();

        stats.connections_accepted.store(10, Ordering::Relaxed);
        stats.connections_failed.store(2, Ordering::Relaxed);
        stats.total_bytes_transferred.store(1024, Ordering::Relaxed);

        assert_eq!(stats.connections_accepted.load(Ordering::Relaxed), 10);
        assert_eq!(stats.connections_failed.load(Ordering::Relaxed), 2);
        assert_eq!(stats.total_bytes_transferred.load(Ordering::Relaxed), 1024);
    }

    #[tokio::test]
    async fn test_invalid_forwarding_type() {
        let spec = ForwardingType::Remote {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 8080,
            local_host: "localhost".to_string(),
            local_port: 80,
        };

        let ssh_client = Arc::new(
            Client::connect(
                ("test", 22),
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

        let result = LocalForwarder::new(
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

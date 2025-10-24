//! Main dynamic forwarder implementation

use super::{connection::ConnectionHandler, stats::DynamicForwarderStats};
use crate::{
    forwarding::{
        ForwardingConfig, ForwardingMessage, ForwardingStats, ForwardingStatus, ForwardingType,
        SocksVersion,
    },
    ssh::tokio_client::Client,
};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Dynamic port forwarder implementation (SOCKS proxy)
#[derive(Debug)]
#[allow(dead_code)] // Future implementation
pub struct DynamicForwarder {
    pub(crate) session_id: Uuid,
    pub(crate) bind_addr: SocketAddr,
    pub(crate) socks_version: SocksVersion,
    config: ForwardingConfig,
    ssh_client: Arc<Client>,
    cancel_token: CancellationToken,
    message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    stats: Arc<DynamicForwarderStats>,
}

impl DynamicForwarder {
    /// Create a new dynamic forwarder instance
    pub fn new(
        session_id: Uuid,
        spec: ForwardingType,
        ssh_client: Arc<Client>,
        config: ForwardingConfig,
        cancel_token: CancellationToken,
        message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    ) -> Result<Self> {
        let (bind_addr, socks_version) = match spec {
            ForwardingType::Dynamic {
                bind_addr,
                bind_port,
                socks_version,
            } => {
                let addr = SocketAddr::new(bind_addr, bind_port);
                (addr, socks_version)
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid forwarding type for DynamicForwarder"
                ))
            }
        };

        Ok(Self {
            session_id,
            bind_addr,
            socks_version,
            config,
            ssh_client,
            cancel_token,
            message_tx,
            stats: Arc::new(DynamicForwarderStats::default()),
        })
    }

    /// Main entry point for running dynamic port forwarding
    ///
    /// **Implementation Note:**
    /// This is currently a placeholder implementation. The full implementation
    /// will include:
    /// 1. SOCKS v4/v5 protocol parser
    /// 2. SOCKS server with authentication support
    /// 3. DNS resolution through remote connection
    /// 4. Dynamic SSH channel creation per request
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
            "Starting dynamic forwarding: SOCKS{:?} proxy on {}",
            forwarder.socks_version, forwarder.bind_addr
        );

        // Run the complete SOCKS proxy implementation
        match forwarder.run_with_retry().await {
            Ok(_) => {
                forwarder
                    .send_status_update(ForwardingStatus::Stopped)
                    .await;
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Dynamic forwarding failed: {e}");
                forwarder
                    .send_status_update(ForwardingStatus::Failed(error_msg.clone()))
                    .await;
                Err(anyhow::anyhow!(error_msg))
            }
        }
    }

    /// Run SOCKS proxy with automatic retry on failures
    async fn run_with_retry(&mut self) -> Result<()> {
        let mut retry_count = 0u32;
        let mut retry_delay = Duration::from_millis(self.config.reconnect_delay_ms);

        loop {
            // Check if we should stop
            if self.cancel_token.is_cancelled() {
                info!("SOCKS proxy cancelled");
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
                    _ = tokio::time::sleep(retry_delay) => {}
                    _ = self.cancel_token.cancelled() => {
                        info!("SOCKS proxy cancelled during retry delay");
                        break;
                    }
                }
            }

            info!(
                "Starting SOCKS{:?} proxy on {} (attempt {})",
                self.socks_version,
                self.bind_addr,
                retry_count + 1
            );

            // Attempt to start SOCKS proxy
            match self.run_socks_proxy_loop().await {
                Ok(_) => {
                    // Successful completion (probably cancelled)
                    break;
                }
                Err(e) => {
                    error!("SOCKS proxy attempt {} failed: {}", retry_count + 1, e);

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

    /// Main SOCKS proxy loop - create listener and handle connections
    async fn run_socks_proxy_loop(&mut self) -> Result<()> {
        // Create TCP listener for SOCKS proxy
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind SOCKS proxy to {}", self.bind_addr))?;

        let local_addr = listener
            .local_addr()
            .with_context(|| "Failed to get local address for SOCKS proxy")?;

        info!(
            "SOCKS{:?} proxy listening on {}",
            self.socks_version, local_addr
        );

        self.send_status_update(ForwardingStatus::Active).await;

        // Create semaphore to limit concurrent connections
        let connection_semaphore = Arc::new(Semaphore::new(self.config.max_connections));

        // Create connection handler
        let handler = ConnectionHandler::new(
            self.session_id,
            self.socks_version,
            Arc::clone(&self.ssh_client),
            Arc::clone(&self.stats),
            self.cancel_token.clone(),
            &self.config,
        );

        // Run the accept loop
        handler.accept_loop(listener, connection_semaphore).await?;

        info!("SOCKS proxy stopped");
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
            active_connections: self.stats.active_connections() as usize,
            total_connections: self.stats.total_accepted(),
            bytes_transferred: self.stats.bytes_transferred(),
            failed_connections: self
                .stats
                .socks_connections_failed
                .load(std::sync::atomic::Ordering::Relaxed),
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

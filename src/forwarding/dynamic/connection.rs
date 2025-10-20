//! Connection management for dynamic port forwarding

use super::socks::{handle_socks4_connection, handle_socks5_connection};
use super::stats::DynamicForwarderStats;
use crate::{
    forwarding::{ForwardingConfig, SocksVersion},
    ssh::tokio_client::Client,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};
use uuid::Uuid;

/// Handle SOCKS connection spawning and lifecycle
pub struct ConnectionHandler {
    session_id: Uuid,
    socks_version: SocksVersion,
    ssh_client: Arc<Client>,
    stats: Arc<DynamicForwarderStats>,
    cancel_token: CancellationToken,
    buffer_size: usize,
}

impl ConnectionHandler {
    /// Create a new connection handler
    pub fn new(
        session_id: Uuid,
        socks_version: SocksVersion,
        ssh_client: Arc<Client>,
        stats: Arc<DynamicForwarderStats>,
        cancel_token: CancellationToken,
        config: &ForwardingConfig,
    ) -> Self {
        Self {
            session_id,
            socks_version,
            ssh_client,
            stats,
            cancel_token,
            buffer_size: config.buffer_size,
        }
    }

    /// Spawn a handler for a new SOCKS connection
    pub fn spawn_handler(
        &self,
        tcp_stream: TcpStream,
        peer_addr: SocketAddr,
        connection_semaphore: Arc<Semaphore>,
    ) {
        let _session_id = self.session_id;
        let socks_version = self.socks_version;
        let ssh_client = Arc::clone(&self.ssh_client);
        let stats = Arc::clone(&self.stats);
        let cancel_token = self.cancel_token.clone();
        let buffer_size = self.buffer_size;

        tokio::spawn(async move {
            // Acquire connection semaphore permit
            let _permit = match connection_semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    warn!(
                        "Failed to acquire connection permit for SOCKS client {}",
                        peer_addr
                    );
                    return;
                }
            };

            stats.inc_active();

            match socks_version {
                SocksVersion::V4 => stats.inc_socks4(),
                SocksVersion::V5 => stats.inc_socks5(),
            };

            debug!(
                "Handling SOCKS{:?} connection from {}",
                socks_version, peer_addr
            );

            // Handle the SOCKS connection
            let result = Self::handle_socks_connection(
                tcp_stream,
                peer_addr,
                socks_version,
                &ssh_client,
                cancel_token,
                buffer_size,
            )
            .await;

            // Update statistics
            stats.dec_active();

            match result {
                Ok(tunnel_stats) => {
                    debug!(
                        "SOCKS connection from {} completed: {} bytes transferred",
                        peer_addr,
                        tunnel_stats.total_bytes()
                    );
                    stats.add_bytes(tunnel_stats.total_bytes());
                }
                Err(e) => {
                    error!("SOCKS connection from {} failed: {}", peer_addr, e);
                    stats.inc_failed();
                }
            }
        });
    }

    /// Handle individual SOCKS connection
    async fn handle_socks_connection(
        tcp_stream: TcpStream,
        peer_addr: SocketAddr,
        socks_version: SocksVersion,
        ssh_client: &Client,
        cancel_token: CancellationToken,
        _buffer_size: usize,
    ) -> anyhow::Result<crate::forwarding::tunnel::TunnelStats> {
        match socks_version {
            SocksVersion::V4 => {
                handle_socks4_connection(tcp_stream, peer_addr, ssh_client, cancel_token).await
            }
            SocksVersion::V5 => {
                handle_socks5_connection(tcp_stream, peer_addr, ssh_client, cancel_token).await
            }
        }
    }

    /// Accept and process incoming SOCKS connections
    pub async fn accept_loop(
        &self,
        listener: tokio::net::TcpListener,
        connection_semaphore: Arc<Semaphore>,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                // Accept new SOCKS connections
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            trace!("Accepted SOCKS connection from {}", peer_addr);
                            self.stats.inc_accepted();

                            // Spawn SOCKS connection handler
                            self.spawn_handler(stream, peer_addr, Arc::clone(&connection_semaphore));
                        }
                        Err(e) => {
                            error!("Failed to accept SOCKS connection: {}", e);
                            self.stats.inc_failed();

                            // Brief pause to avoid busy loop on persistent errors
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                // Handle cancellation
                _ = self.cancel_token.cancelled() => {
                    debug!("SOCKS proxy cancelled, stopping listener");
                    break;
                }
            }
        }

        Ok(())
    }
}

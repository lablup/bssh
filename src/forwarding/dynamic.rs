//! Dynamic port forwarding implementation (-D option)
//!
//! Dynamic port forwarding creates a local SOCKS proxy that accepts connections
//! and dynamically forwards them to destinations via SSH tunneling based on
//! SOCKS protocol requests. This is equivalent to the OpenSSH `-D [bind_address:]port` option.
//!
//! # Architecture
//!
//! ```text
//! [Client] → [SOCKS Proxy] → [SSH Channel] → [Dynamic Destination]
//!              ↑ bind_addr:bind_port          ↑ Per-request destination
//! ```
//!
//! # Example Usage
//!
//! Create SOCKS proxy on localhost:1080:
//! ```bash
//! bssh -D 1080 user@ssh-server
//! ```
//!
//! Configure applications to use 127.0.0.1:1080 as SOCKS proxy.
//! All traffic will be forwarded through the SSH connection with
//! destinations determined by SOCKS requests.
//!
//! # Implementation Status
//!
//! **Phase 2 - Placeholder Implementation**
//! This is a placeholder implementation that provides the basic structure.
//! The full SOCKS protocol implementation will be completed in Phase 2.
//!
//! # SOCKS Protocol Support
//!
//! **Phase 2 Features:**
//! - SOCKS4 protocol support
//! - SOCKS5 protocol support with authentication
//! - DNS resolution through remote connection
//! - IPv4 and IPv6 destination support

use super::{
    ForwardingConfig, ForwardingMessage, ForwardingStats, ForwardingStatus, ForwardingType,
    SocksVersion,
};
use crate::ssh::tokio_client::Client;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

/// Dynamic port forwarder implementation (SOCKS proxy)
#[derive(Debug)]
#[allow(dead_code)] // Phase 2 implementation
pub struct DynamicForwarder {
    session_id: Uuid,
    bind_addr: SocketAddr,
    socks_version: SocksVersion,
    config: ForwardingConfig,
    ssh_client: Arc<Client>,
    cancel_token: CancellationToken,
    message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    stats: Arc<DynamicForwarderStats>,
}

/// Statistics specific to dynamic forwarding
#[derive(Debug, Default)]
#[allow(dead_code)] // Phase 2 fields
struct DynamicForwarderStats {
    /// Total SOCKS connections accepted
    socks_connections_accepted: AtomicU64,
    /// Currently active SOCKS connections
    active_connections: AtomicU64,
    /// Total SOCKS connections failed
    socks_connections_failed: AtomicU64,
    /// Total bytes transferred across all connections
    total_bytes_transferred: AtomicU64,
    /// SOCKS4 protocol requests
    socks4_requests: AtomicU64,
    /// SOCKS5 protocol requests
    socks5_requests: AtomicU64,
    /// DNS resolution requests
    dns_resolutions: AtomicU64,
    /// Failed DNS resolutions
    dns_failures: AtomicU64,
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
    /// **Phase 2 Implementation Note:**
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
        use tokio::net::TcpListener;

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

        loop {
            tokio::select! {
                // Accept new SOCKS connections
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            trace!("Accepted SOCKS connection from {}", peer_addr);
                            self.stats.socks_connections_accepted.fetch_add(1, Ordering::Relaxed);

                            // Spawn SOCKS connection handler
                            self.spawn_socks_handler(stream, peer_addr, Arc::clone(&connection_semaphore));
                        }
                        Err(e) => {
                            error!("Failed to accept SOCKS connection: {}", e);
                            self.stats.socks_connections_failed.fetch_add(1, Ordering::Relaxed);

                            // Brief pause to avoid busy loop on persistent errors
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                // Handle cancellation
                _ = self.cancel_token.cancelled() => {
                    info!("SOCKS proxy cancelled, stopping listener");
                    break;
                }
            }
        }

        info!("SOCKS proxy stopped");
        Ok(())
    }

    /// Spawn SOCKS connection handler
    ///
    /// This handles the complete SOCKS protocol flow:
    /// 1. Parse SOCKS protocol handshake
    /// 2. Handle authentication if required (SOCKS5)
    /// 3. Parse connection request (CONNECT command)
    /// 4. Create SSH channel to destination
    /// 5. Send SOCKS response
    /// 6. Start bidirectional tunnel
    fn spawn_socks_handler(
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
        let buffer_size = self.config.buffer_size;

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

            stats.active_connections.fetch_add(1, Ordering::Relaxed);

            match socks_version {
                SocksVersion::V4 => stats.socks4_requests.fetch_add(1, Ordering::Relaxed),
                SocksVersion::V5 => stats.socks5_requests.fetch_add(1, Ordering::Relaxed),
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
            stats.active_connections.fetch_sub(1, Ordering::Relaxed);

            match result {
                Ok(tunnel_stats) => {
                    debug!(
                        "SOCKS connection from {} completed: {} bytes transferred",
                        peer_addr,
                        tunnel_stats.total_bytes()
                    );
                    stats
                        .total_bytes_transferred
                        .fetch_add(tunnel_stats.total_bytes(), Ordering::Relaxed);
                }
                Err(e) => {
                    error!("SOCKS connection from {} failed: {}", peer_addr, e);
                    stats
                        .socks_connections_failed
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    /// Handle individual SOCKS connection
    ///
    /// This implements the SOCKS protocol handling:
    /// - SOCKS5: Full implementation with authentication negotiation
    /// - SOCKS4: Basic implementation for compatibility
    async fn handle_socks_connection(
        tcp_stream: TcpStream,
        peer_addr: SocketAddr,
        socks_version: SocksVersion,
        ssh_client: &Client,
        cancel_token: CancellationToken,
        _buffer_size: usize,
    ) -> Result<super::tunnel::TunnelStats> {
        match socks_version {
            SocksVersion::V4 => {
                Self::handle_socks4_connection(tcp_stream, peer_addr, ssh_client, cancel_token)
                    .await
            }
            SocksVersion::V5 => {
                Self::handle_socks5_connection(tcp_stream, peer_addr, ssh_client, cancel_token)
                    .await
            }
        }
    }

    /// Handle SOCKS4 connection protocol
    async fn handle_socks4_connection(
        mut tcp_stream: TcpStream,
        peer_addr: SocketAddr,
        ssh_client: &Client,
        cancel_token: CancellationToken,
    ) -> Result<super::tunnel::TunnelStats> {
        use super::tunnel::Tunnel;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        debug!("Handling SOCKS4 connection from {}", peer_addr);

        // Read SOCKS4 request: VER(1) + CMD(1) + DSTPORT(2) + DSTIP(4) + USERID(variable) + NULL(1)
        let mut request_header = [0u8; 8]; // First 8 bytes (VER + CMD + DSTPORT + DSTIP)
        tcp_stream.read_exact(&mut request_header).await?;

        let version = request_header[0];
        let command = request_header[1];
        let dest_port = u16::from_be_bytes([request_header[2], request_header[3]]);
        let dest_ip = std::net::Ipv4Addr::from([
            request_header[4],
            request_header[5],
            request_header[6],
            request_header[7],
        ]);

        // Verify SOCKS4 version
        if version != 4 {
            debug!("Invalid SOCKS4 version: {} from {}", version, peer_addr);
            // Send failure response
            let response = [0, 0x5B, 0, 0, 0, 0, 0, 0]; // 0x5B = request rejected
            tcp_stream.write_all(&response).await?;
            return Err(anyhow::anyhow!("Invalid SOCKS4 version: {version}"));
        }

        // Only support CONNECT command (0x01)
        if command != 0x01 {
            debug!("Unsupported SOCKS4 command: {} from {}", command, peer_addr);
            let response = [0, 0x5C, 0, 0, 0, 0, 0, 0]; // 0x5C = request failed
            tcp_stream.write_all(&response).await?;
            return Err(anyhow::anyhow!("Unsupported SOCKS4 command: {command}"));
        }

        // Read USERID (until NULL byte)
        let mut userid = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            tcp_stream.read_exact(&mut byte).await?;
            if byte[0] == 0 {
                break; // NULL terminator
            }
            userid.push(byte[0]);
            if userid.len() > 255 {
                // Prevent excessive memory usage
                let response = [0, 0x5B, 0, 0, 0, 0, 0, 0]; // Request rejected
                tcp_stream.write_all(&response).await?;
                return Err(anyhow::anyhow!("USERID too long"));
            }
        }

        let destination = format!("{dest_ip}:{dest_port}");
        debug!("SOCKS4 CONNECT to {} from {}", destination, peer_addr);

        // Create SSH channel to destination
        let ssh_channel = match ssh_client
            .open_direct_tcpip_channel(destination.as_str(), None)
            .await
        {
            Ok(channel) => channel,
            Err(e) => {
                debug!("Failed to create SSH channel to {}: {}", destination, e);
                // Send failure response
                let response = [0, 0x5B, 0, 0, 0, 0, 0, 0]; // Request rejected
                tcp_stream.write_all(&response).await?;
                return Err(e.into());
            }
        };

        // Send success response: VER(1) + REP(1) + DSTPORT(2) + DSTIP(4)
        let response = [
            0,    // VER (should be 0 for response)
            0x5A, // REP (0x5A = success)
            (dest_port >> 8) as u8,
            (dest_port & 0xff) as u8, // DSTPORT
            dest_ip.octets()[0],
            dest_ip.octets()[1],
            dest_ip.octets()[2],
            dest_ip.octets()[3], // DSTIP
        ];
        tcp_stream.write_all(&response).await?;

        debug!("SOCKS4 tunnel established: {} ↔ {}", peer_addr, destination);

        // Start bidirectional tunnel
        Tunnel::run(tcp_stream, ssh_channel, cancel_token).await
    }

    /// Handle SOCKS5 connection protocol  
    async fn handle_socks5_connection(
        mut tcp_stream: TcpStream,
        peer_addr: SocketAddr,
        ssh_client: &Client,
        cancel_token: CancellationToken,
    ) -> Result<super::tunnel::TunnelStats> {
        use super::tunnel::Tunnel;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        debug!("Handling SOCKS5 connection from {}", peer_addr);

        // Phase 1: Authentication negotiation
        // Read client's authentication methods: VER(1) + NMETHODS(1) + METHODS(1-255)
        let mut auth_request = [0u8; 2];
        tcp_stream.read_exact(&mut auth_request).await?;

        let version = auth_request[0];
        let nmethods = auth_request[1];

        if version != 5 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version: {version}"));
        }

        // Read authentication methods
        let mut methods = vec![0u8; nmethods as usize];
        tcp_stream.read_exact(&mut methods).await?;

        // We only support "no authentication required" (0x00)
        let selected_method = if methods.contains(&0x00) {
            0x00 // No authentication required
        } else {
            0xFF // No acceptable methods
        };

        // Send authentication method selection response: VER(1) + METHOD(1)
        let auth_response = [5, selected_method];
        tcp_stream.write_all(&auth_response).await?;

        if selected_method == 0xFF {
            return Err(anyhow::anyhow!("No acceptable authentication method"));
        }

        // Phase 2: Connection request
        // Read SOCKS5 request: VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2)
        let mut request_header = [0u8; 4];
        tcp_stream.read_exact(&mut request_header).await?;

        let version = request_header[0];
        let command = request_header[1];
        let _reserved = request_header[2];
        let address_type = request_header[3];

        if version != 5 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 request version: {version}"));
        }

        // Only support CONNECT command (0x01)
        if command != 0x01 {
            // Send error response
            let response = [5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0]; // Command not supported
            tcp_stream.write_all(&response).await?;
            return Err(anyhow::anyhow!("Unsupported SOCKS5 command: {command}"));
        }

        // Parse destination address based on address type
        let destination = match address_type {
            0x01 => {
                // IPv4 address: 4 bytes
                let mut addr_bytes = [0u8; 4];
                tcp_stream.read_exact(&mut addr_bytes).await?;
                let mut port_bytes = [0u8; 2];
                tcp_stream.read_exact(&mut port_bytes).await?;

                let ip = std::net::Ipv4Addr::from(addr_bytes);
                let port = u16::from_be_bytes(port_bytes);
                format!("{ip}:{port}")
            }
            0x03 => {
                // Domain name: 1 byte length + domain name + 2 bytes port
                let mut len_byte = [0u8; 1];
                tcp_stream.read_exact(&mut len_byte).await?;
                let domain_len = len_byte[0] as usize;

                let mut domain_bytes = vec![0u8; domain_len];
                tcp_stream.read_exact(&mut domain_bytes).await?;
                let domain = String::from_utf8_lossy(&domain_bytes);

                let mut port_bytes = [0u8; 2];
                tcp_stream.read_exact(&mut port_bytes).await?;
                let port = u16::from_be_bytes(port_bytes);

                format!("{domain}:{port}")
            }
            0x04 => {
                // IPv6 address: 16 bytes + 2 bytes port (not fully implemented)
                let response = [5, 0x08, 0, 1, 0, 0, 0, 0, 0, 0]; // Address type not supported
                tcp_stream.write_all(&response).await?;
                return Err(anyhow::anyhow!("IPv6 address type not yet supported"));
            }
            _ => {
                let response = [5, 0x08, 0, 1, 0, 0, 0, 0, 0, 0]; // Address type not supported
                tcp_stream.write_all(&response).await?;
                return Err(anyhow::anyhow!("Unsupported address type: {address_type}"));
            }
        };

        debug!("SOCKS5 CONNECT to {} from {}", destination, peer_addr);

        // Create SSH channel to destination
        let ssh_channel = match ssh_client
            .open_direct_tcpip_channel(destination.as_str(), None)
            .await
        {
            Ok(channel) => channel,
            Err(e) => {
                debug!("Failed to create SSH channel to {}: {}", destination, e);
                // Send failure response: VER + REP + RSV + ATYP + BND.ADDR + BND.PORT
                let response = [5, 0x05, 0, 1, 0, 0, 0, 0, 0, 0]; // Connection refused
                tcp_stream.write_all(&response).await?;
                return Err(e.into());
            }
        };

        // Send success response: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
        let response = [5, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]; // Success, bound to 0.0.0.0:0
        tcp_stream.write_all(&response).await?;

        debug!("SOCKS5 tunnel established: {} ↔ {}", peer_addr, destination);

        // Start bidirectional tunnel
        Tunnel::run(tcp_stream, ssh_channel, cancel_token).await
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
    #[allow(dead_code)] // Used in Phase 2
    async fn send_stats_update(&self) {
        let stats = ForwardingStats {
            active_connections: self.stats.active_connections.load(Ordering::Relaxed) as usize,
            total_connections: self
                .stats
                .socks_connections_accepted
                .load(Ordering::Relaxed),
            bytes_transferred: self.stats.total_bytes_transferred.load(Ordering::Relaxed),
            failed_connections: self.stats.socks_connections_failed.load(Ordering::Relaxed),
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

// **Phase 2 Implementation Notes:**
//
// The full dynamic forwarding implementation will require:
//
// 1. **SOCKS Protocol Implementation:**
//    - SOCKS4: Simple protocol with IP addresses only
//      * Request format: [VER, CMD, DST.PORT, DST.IP, USER_ID, NULL]
//      * Response format: [VER, STATUS, DST.PORT, DST.IP]
//    - SOCKS5: Advanced protocol with authentication and hostname support
//      * Authentication negotiation phase
//      * Connection request phase with multiple address types
//      * Support for CONNECT, BIND, and UDP ASSOCIATE commands
//
// 2. **DNS Resolution:**
//    - For SOCKS5 hostname requests, resolve through remote SSH connection
//    - Implement DNS-over-SSH for accurate remote resolution
//    - Cache resolved addresses for performance
//
// 3. **Connection Management:**
//    - Parse SOCKS requests to extract destination info
//    - Create SSH channels dynamically for each connection
//    - Handle connection failures gracefully with SOCKS error responses
//    - Support concurrent connections with proper resource limits
//
// 4. **Authentication Support (SOCKS5):**
//    - No authentication (method 0x00)
//    - Username/password authentication (method 0x02)
//    - Future: GSSAPI authentication (method 0x01)
//
// The implementation will follow the existing patterns established by
// LocalForwarder but with the added complexity of SOCKS protocol parsing
// and dynamic destination resolution.

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::sync::mpsc;

    #[tokio::test]
    #[ignore = "Requires SSH server connection"]
    async fn test_dynamic_forwarder_creation() {
        let spec = ForwardingType::Dynamic {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 1080,
            socks_version: SocksVersion::V5,
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

        let forwarder = DynamicForwarder::new(
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
        assert_eq!(forwarder.socks_version, SocksVersion::V5);
    }

    #[test]
    fn test_dynamic_forwarder_stats() {
        let stats = DynamicForwarderStats::default();

        stats
            .socks_connections_accepted
            .store(10, Ordering::Relaxed);
        stats.socks4_requests.store(3, Ordering::Relaxed);
        stats.socks5_requests.store(7, Ordering::Relaxed);
        stats.dns_resolutions.store(5, Ordering::Relaxed);

        assert_eq!(stats.socks_connections_accepted.load(Ordering::Relaxed), 10);
        assert_eq!(stats.socks4_requests.load(Ordering::Relaxed), 3);
        assert_eq!(stats.socks5_requests.load(Ordering::Relaxed), 7);
        assert_eq!(stats.dns_resolutions.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    #[ignore = "Requires SSH server connection"]
    async fn test_socks_version_handling() {
        for socks_version in [SocksVersion::V4, SocksVersion::V5] {
            let spec = ForwardingType::Dynamic {
                bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                bind_port: 1080,
                socks_version,
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

            let forwarder = DynamicForwarder::new(
                session_id,
                spec,
                ssh_client,
                config,
                cancel_token,
                message_tx,
            )
            .unwrap();

            assert_eq!(forwarder.socks_version, socks_version);
        }
    }
}

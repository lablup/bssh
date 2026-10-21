//! Connection management for dynamic port forwarding

use super::socks::{handle_socks4_connection_with, handle_socks5_connection_with};
use super::stats::DynamicForwarderStats;
use crate::{
    forwarding::tunnel::{Tunnel, TunnelStats},
    forwarding::{ForwardingConfig, SocksVersion},
    ssh::tokio_client::{AddressFamily, Client},
};
use anyhow::Context as _;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};
use uuid::Uuid;

fn admit_connection(
    stream: TcpStream,
    semaphore: &Arc<Semaphore>,
) -> Option<(TcpStream, OwnedSemaphorePermit)> {
    let permit = Arc::clone(semaphore).try_acquire_owned().ok()?;
    Some((stream, permit))
}

/// Handle SOCKS connection spawning and lifecycle
pub struct ConnectionHandler {
    session_id: Uuid,
    socks_version: SocksVersion,
    ssh_client: Arc<Client>,
    stats: Arc<DynamicForwarderStats>,
    cancel_token: CancellationToken,
    buffer_size: usize,
    address_family: AddressFamily,
    connect_timeout: Duration,
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
            address_family: config.address_family,
            connect_timeout: Duration::from_secs(config.connect_timeout_secs),
        }
    }

    /// Spawn a handler for a new SOCKS connection
    pub fn spawn_handler(
        &self,
        tcp_stream: TcpStream,
        peer_addr: SocketAddr,
        connection_permit: OwnedSemaphorePermit,
        connections: &mut JoinSet<()>,
    ) {
        let _session_id = self.session_id;
        let socks_version = self.socks_version;
        let ssh_client = Arc::clone(&self.ssh_client);
        let stats = Arc::clone(&self.stats);
        let cancel_token = self.cancel_token.clone();
        let buffer_size = self.buffer_size;
        let address_family = self.address_family;
        let connect_timeout = self.connect_timeout;

        connections.spawn(async move {
            let _connection_permit = connection_permit;

            stats.inc_active();

            // Handle the SOCKS connection
            let result = async {
                let deadline = tokio::time::Instant::now() + connect_timeout;
                let socks_version =
                    Self::detect_socks_version(&tcp_stream, socks_version, deadline, &cancel_token)
                        .await?;
                match socks_version {
                    SocksVersion::V4 => stats.inc_socks4(),
                    SocksVersion::V5 => stats.inc_socks5(),
                    SocksVersion::Auto => unreachable!("autodetection must select a protocol"),
                };

                debug!(
                    "Handling SOCKS{:?} connection from {}",
                    socks_version, peer_addr
                );
                Self::handle_socks_connection(
                    tcp_stream,
                    peer_addr,
                    socks_version,
                    &ssh_client,
                    cancel_token,
                    buffer_size,
                    address_family,
                    deadline,
                )
                .await
            }
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

    async fn detect_socks_version(
        tcp_stream: &TcpStream,
        configured: SocksVersion,
        deadline: tokio::time::Instant,
        cancel_token: &CancellationToken,
    ) -> anyhow::Result<SocksVersion> {
        if configured != SocksVersion::Auto {
            return Ok(configured);
        }

        let mut version = [0_u8; 1];
        let read = tokio::select! {
            result = tokio::time::timeout_at(deadline, tcp_stream.peek(&mut version)) => result
                .context("Timed out waiting for local dynamic SOCKS greeting")??,
            _ = cancel_token.cancelled() => anyhow::bail!("Dynamic forwarding was cancelled"),
        };
        anyhow::ensure!(read == 1, "SOCKS client closed before sending a greeting");
        match version[0] {
            4 => Ok(SocksVersion::V4),
            5 => Ok(SocksVersion::V5),
            other => anyhow::bail!("Unsupported SOCKS protocol version: {other}"),
        }
    }

    /// Handle individual SOCKS connection
    #[allow(clippy::too_many_arguments)]
    async fn handle_socks_connection(
        tcp_stream: TcpStream,
        peer_addr: SocketAddr,
        socks_version: SocksVersion,
        ssh_client: &Client,
        cancel_token: CancellationToken,
        _buffer_size: usize,
        address_family: AddressFamily,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<TunnelStats> {
        match socks_version {
            SocksVersion::Auto => {
                unreachable!("SOCKS protocol must be detected before dispatch")
            }
            SocksVersion::V4 => {
                let (ready_tx, ready_rx) = oneshot::channel();
                let open_cancel = cancel_token.clone();
                let handler_cancel = cancel_token.clone();
                let handler = handle_socks4_connection_with(
                    tcp_stream,
                    peer_addr,
                    handler_cancel,
                    address_family,
                    move |destination, address_family| async move {
                        tokio::select! {
                            result = ssh_client.open_direct_tcpip_channel_with_family(
                                destination.as_str(),
                                None,
                                address_family,
                            ) => result.map_err(anyhow::Error::from),
                            _ = open_cancel.cancelled() => {
                                anyhow::bail!("Dynamic forwarding was cancelled")
                            }
                        }
                    },
                    move |tcp_stream, ssh_channel, cancel_token| async move {
                        let _ = ready_tx.send(());
                        Tunnel::run(tcp_stream, ssh_channel, cancel_token).await
                    },
                );
                complete_socks_handshake(handler, ready_rx, deadline, cancel_token).await
            }
            SocksVersion::V5 => {
                let (ready_tx, ready_rx) = oneshot::channel();
                let open_cancel = cancel_token.clone();
                let handler_cancel = cancel_token.clone();
                let handler = handle_socks5_connection_with(
                    tcp_stream,
                    peer_addr,
                    address_family,
                    move |destination, address_family| {
                        let open_cancel = open_cancel.clone();
                        async move {
                            tokio::select! {
                                result = ssh_client.open_direct_tcpip_channel_with_family(
                                    destination.as_str(),
                                    None,
                                    address_family,
                                ) => result.map_err(anyhow::Error::from),
                                _ = open_cancel.cancelled() => {
                                    anyhow::bail!("Dynamic forwarding was cancelled")
                                }
                            }
                        }
                    },
                    move |tcp_stream, ssh_channel, cancel_token| async move {
                        let _ = ready_tx.send(());
                        Tunnel::run(tcp_stream, ssh_channel, cancel_token).await
                    },
                    handler_cancel,
                );
                complete_socks_handshake(handler, ready_rx, deadline, cancel_token).await
            }
        }
    }

    /// Accept and process incoming SOCKS connections
    pub async fn accept_loop(
        &self,
        listener: tokio::net::TcpListener,
        connection_semaphore: Arc<Semaphore>,
    ) -> anyhow::Result<()> {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                // Accept new SOCKS connections
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            trace!("Accepted SOCKS connection from {}", peer_addr);
                            self.stats.inc_accepted();

                            let Some((stream, connection_permit)) =
                                admit_connection(stream, &connection_semaphore)
                            else {
                                warn!(
                                    "Rejecting SOCKS client {} because the dynamic forwarding connection limit was reached",
                                    peer_addr
                                );
                                self.stats.inc_failed();
                                continue;
                            };

                            // Spawn SOCKS connection handler
                            self.spawn_handler(
                                stream,
                                peer_addr,
                                connection_permit,
                                &mut connections,
                            );
                        }
                        Err(e) => {
                            error!("Failed to accept SOCKS connection: {}", e);
                            self.stats.inc_failed();

                            // Brief pause to avoid busy loop on persistent errors
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
                // Handle cancellation
                _ = self.cancel_token.cancelled() => {
                    debug!("SOCKS proxy cancelled, stopping listener");
                    break;
                }
            }
        }

        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }
}

async fn complete_socks_handshake<Handler>(
    handler: Handler,
    ready: oneshot::Receiver<()>,
    deadline: tokio::time::Instant,
    cancel_token: CancellationToken,
) -> anyhow::Result<TunnelStats>
where
    Handler: Future<Output = anyhow::Result<TunnelStats>>,
{
    tokio::pin!(handler);
    tokio::select! {
        biased;
        result = &mut handler => result,
        ready = tokio::time::timeout_at(deadline, ready) => match ready {
            Ok(Ok(())) => handler.await,
            Ok(Err(_)) => handler.await,
            Err(_) => anyhow::bail!("Timed out completing local dynamic SOCKS handshake"),
        },
        _ = cancel_token.cancelled() => anyhow::bail!("Dynamic forwarding was cancelled"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncReadExt;

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind SOCKS detection listener");
        let address = listener.local_addr().expect("SOCKS detection address");
        let client = TcpStream::connect(address)
            .await
            .expect("connect SOCKS client");
        let (server, _) = listener.accept().await.expect("accept SOCKS client");
        (client, server)
    }

    async fn detect_socks_version(
        stream: &TcpStream,
        configured: SocksVersion,
    ) -> anyhow::Result<SocksVersion> {
        ConnectionHandler::detect_socks_version(
            stream,
            configured,
            tokio::time::Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await
    }

    #[tokio::test]
    async fn auto_detects_socks4_and_socks5_greetings() {
        use tokio::io::AsyncWriteExt as _;

        for (greeting, expected) in [(4_u8, SocksVersion::V4), (5_u8, SocksVersion::V5)] {
            let (mut client, server) = tcp_pair().await;
            client
                .write_all(&[greeting])
                .await
                .expect("write SOCKS greeting");
            assert_eq!(
                detect_socks_version(&server, SocksVersion::Auto)
                    .await
                    .expect("detect supported SOCKS greeting"),
                expected
            );
        }
    }

    #[tokio::test]
    async fn auto_rejects_unknown_socks_greetings() {
        use tokio::io::AsyncWriteExt as _;

        let (mut client, server) = tcp_pair().await;
        client
            .write_all(&[6])
            .await
            .expect("write unsupported SOCKS greeting");
        let error = detect_socks_version(&server, SocksVersion::Auto)
            .await
            .expect_err("unknown SOCKS greeting must fail closed");
        assert_eq!(error.to_string(), "Unsupported SOCKS protocol version: 6");
    }

    #[tokio::test(start_paused = true)]
    async fn silent_auto_detection_expires_at_the_connection_deadline() {
        let (_client, server) = tcp_pair().await;
        let cancel = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let detection = tokio::spawn(async move {
            ConnectionHandler::detect_socks_version(&server, SocksVersion::Auto, deadline, &cancel)
                .await
        });

        tokio::time::advance(Duration::from_secs(1)).await;

        let error = detection
            .await
            .expect("SOCKS detection task")
            .expect_err("silent SOCKS client must time out");
        assert_eq!(
            error.to_string(),
            "Timed out waiting for local dynamic SOCKS greeting"
        );
    }

    #[tokio::test]
    async fn saturated_dynamic_limit_rejects_immediately_and_recovers() {
        let semaphore = Arc::new(Semaphore::new(1));
        let active = Arc::clone(&semaphore)
            .try_acquire_owned()
            .expect("first dynamic forwarding connection permit");
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind dynamic saturation listener");
        let address = listener.local_addr().expect("dynamic saturation address");
        let (saturated_client, saturated_server) =
            tokio::join!(TcpStream::connect(address), listener.accept());
        let mut saturated_client = saturated_client.expect("connect saturated SOCKS client");
        let (saturated_server, _) = saturated_server.expect("accept saturated SOCKS client");

        assert!(
            admit_connection(saturated_server, &semaphore).is_none(),
            "saturation must be detected before a SOCKS connection task is spawned"
        );
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), saturated_client.read(&mut byte))
            .await
            .expect("saturated SOCKS socket must close immediately")
            .expect("read saturated SOCKS socket");
        assert_eq!(read, 0, "a rejected SOCKS socket must be dropped");

        drop(active);
        let (next_client, next_server) =
            tokio::join!(TcpStream::connect(address), listener.accept());
        let next_client = next_client.expect("connect later SOCKS client");
        let (next_server, _) = next_server.expect("accept later SOCKS client");
        let admitted = admit_connection(next_server, &semaphore);
        assert!(
            admitted.is_some(),
            "permit release must admit a later SOCKS connection"
        );
        drop(admitted);
        drop(next_client);
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_socks_handshake_expires_at_the_connection_deadline() {
        let (_ready_tx, ready_rx) = oneshot::channel();
        let cancel = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let handshake = tokio::spawn(complete_socks_handshake(
            std::future::pending(),
            ready_rx,
            deadline,
            cancel,
        ));

        tokio::time::advance(Duration::from_secs(1)).await;

        let error = handshake
            .await
            .expect("handshake deadline task")
            .expect_err("incomplete SOCKS handshake must time out");
        assert_eq!(
            error.to_string(),
            "Timed out completing local dynamic SOCKS handshake"
        );
    }
}

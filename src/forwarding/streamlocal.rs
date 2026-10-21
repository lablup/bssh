//! Unix-domain socket ("streamlocal") forwarding.
//!
//! OpenSSH lets either side of a `-L`/`-R` forwarding be a Unix-domain
//! socket path instead of a TCP endpoint. This module owns the local
//! listener side of those forwardings and the remote `streamlocal-forward`
//! request lifecycle; connections arriving on a remote Unix listener are
//! routed through [`RemoteForwardRegistry`](super::remote::RemoteForwardRegistry)
//! exactly like `forwarded-tcpip` channels.
//!
//! # Socket path safety
//!
//! A listener path is never unlinked before binding: if anything exists at
//! the path (a stale socket, a regular file, or a symlink) the bind fails,
//! matching OpenSSH with `StreamLocalBindUnlink no`. `bind(2)` would follow a
//! dangling symlink and create the socket wherever it points, so the bound
//! node is re-checked afterwards and the forwarding fails closed if it is not
//! a plain socket. Removal on shutdown only unlinks a node that is a socket.
//! The socket is restricted to its owner (mode 0600, OpenSSH's default
//! `StreamLocalBindMask` of 0177) right after it is bound. The process umask
//! is deliberately left alone: it is shared by every thread, and narrowing it
//! around `bind(2)` would also narrow files and directories another runtime
//! thread creates at that moment.

use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::{Channel, client::Msg};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::either::Either;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::remote::RemoteForwardTarget;
use super::tunnel::Tunnel;
use super::{
    ForwardingConfig, ForwardingMessage, ForwardingStatus, ForwardingType, StreamEndpoint,
    StreamListener,
};
use crate::ssh::tokio_client::{AddressFamily, Client};

/// Size of `sockaddr_un::sun_path`, including the terminating NUL.
#[cfg(target_os = "linux")]
pub const MAX_SOCKET_PATH_LEN: usize = 108;
/// Size of `sockaddr_un::sun_path`, including the terminating NUL.
#[cfg(not(target_os = "linux"))]
pub const MAX_SOCKET_PATH_LEN: usize = 104;

/// Owner-only socket mode, the result of OpenSSH's default
/// `StreamLocalBindMask` 0177.
const SOCKET_MODE: u32 = 0o600;

/// Bind a Unix-domain listener at `path` without following symlinks or
/// unlinking an existing node.
pub(crate) fn bind_unix_listener(path: &str) -> Result<UnixListener> {
    super::ForwardingSpec::validate_socket_path(path)?;
    let socket_path = Path::new(path);
    match std::fs::symlink_metadata(socket_path) {
        Ok(_) => anyhow::bail!(
            "cannot bind Unix-domain listener {path}: the path already exists and bssh does not unlink existing socket paths"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect socket path {path}"));
        }
    }

    let listener = std::os::unix::net::UnixListener::bind(socket_path)
        .with_context(|| format!("cannot bind Unix-domain listener {path}"))?;

    // `bind(2)` resolves symlinks, so a path that became a dangling symlink
    // between the check above and the bind would have created the socket at
    // the link target. Refuse to serve anything that is not the plain socket
    // node this call meant to create, and only then restrict its mode, so
    // the chmod never follows a planted link either.
    let bound = std::fs::symlink_metadata(socket_path)
        .with_context(|| format!("cannot verify Unix-domain listener {path}"))?;
    if bound.file_type().is_symlink() || !bound.file_type().is_socket() {
        drop(listener);
        anyhow::bail!(
            "refusing Unix-domain listener {path}: the bound path is not a plain socket node"
        );
    }
    // The node exists with the umask-derived mode until this call returns;
    // a restrictive umask closes that window entirely.
    std::fs::set_permissions(
        socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(SOCKET_MODE),
    )
    .with_context(|| format!("cannot restrict permissions of Unix-domain listener {path}"))?;

    listener
        .set_nonblocking(true)
        .with_context(|| format!("cannot configure Unix-domain listener {path}"))?;
    UnixListener::from_std(listener)
        .with_context(|| format!("cannot register Unix-domain listener {path}"))
}

/// Remove the socket node at `path` if, and only if, it is a socket.
///
/// `unlink(2)` never follows symlinks, and the type check keeps a listener
/// cleanup from removing a regular file that replaced the socket.
pub(crate) fn remove_unix_socket(path: &str) {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            if let Err(error) = std::fs::remove_file(path) {
                tracing::warn!("Could not remove Unix-domain listener {path}: {error}");
            }
        }
        Ok(_) => {
            tracing::warn!("Not removing {path}: it is no longer a socket");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!("Could not inspect Unix-domain listener {path} for removal: {error}");
        }
    }
}

/// Open the SSH channel that reaches `endpoint` on the server side.
pub(crate) async fn open_stream_channel(
    client: &Client,
    endpoint: &StreamEndpoint,
    address_family: AddressFamily,
) -> Result<Channel<Msg>> {
    match endpoint {
        StreamEndpoint::Tcp { host, port } => client
            .open_direct_tcpip_channel_with_family(
                super::format_host_port(host, *port),
                None,
                address_family,
            )
            .await
            .with_context(|| format!("Failed to create SSH channel to {host}:{port}")),
        StreamEndpoint::Unix { path } => client
            .open_direct_streamlocal_channel(path)
            .await
            .with_context(|| format!("Failed to create SSH channel to Unix socket {path}")),
    }
}

enum BoundListener {
    Tcp(TcpListener),
    Unix {
        listener: UnixListener,
        path: String,
    },
}

impl BoundListener {
    async fn bind(listen: &StreamListener) -> Result<Self> {
        match listen {
            StreamListener::Tcp {
                bind_addr,
                bind_port,
            } => {
                let address = std::net::SocketAddr::new(*bind_addr, *bind_port);
                TcpListener::bind(address)
                    .await
                    .map(Self::Tcp)
                    .with_context(|| format!("Failed to bind to {address}"))
            }
            StreamListener::Unix { path } => Ok(Self::Unix {
                listener: bind_unix_listener(path)?,
                path: path.clone(),
            }),
        }
    }

    async fn accept(&self) -> std::io::Result<(Either<TcpStream, UnixStream>, String)> {
        match self {
            Self::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((Either::Left(stream), peer.to_string()))
            }
            Self::Unix { listener, path } => {
                let (stream, _) = listener.accept().await?;
                Ok((Either::Right(stream), format!("unix client of {path}")))
            }
        }
    }

    fn close(self) {
        if let Self::Unix { listener, path } = self {
            drop(listener);
            remove_unix_socket(&path);
        }
    }
}

/// Local listener (TCP or Unix-domain) relayed to a remote TCP endpoint or
/// Unix socket through `direct-tcpip` / `direct-streamlocal@openssh.com`.
pub struct LocalStreamForwarder;

impl LocalStreamForwarder {
    /// Run a [`ForwardingType::LocalStream`] forwarding until cancelled.
    pub async fn run(
        session_id: Uuid,
        spec: ForwardingType,
        ssh_client: Arc<Client>,
        config: ForwardingConfig,
        cancel_token: CancellationToken,
        message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    ) -> Result<()> {
        let ForwardingType::LocalStream { listen, connect } = spec else {
            anyhow::bail!("Invalid forwarding type for LocalStreamForwarder");
        };
        let send_status = |status| {
            let _ = message_tx.send(ForwardingMessage::StatusUpdate {
                id: session_id,
                status,
            });
        };
        send_status(ForwardingStatus::Initializing);

        let listener = match BoundListener::bind(&listen).await {
            Ok(listener) => listener,
            Err(error) => {
                let message = format!("Local forwarding failed: {error:#}");
                send_status(ForwardingStatus::Failed(message.clone()));
                anyhow::bail!(message);
            }
        };
        tracing::info!("Local forwarding listening on {listen} for {connect}");
        send_status(ForwardingStatus::Active);

        let connect = Arc::new(connect);
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                            tracing::warn!(
                                "Rejecting connection from {peer} because the local forwarding connection limit was reached"
                            );
                            continue;
                        };
                        let client = Arc::clone(&ssh_client);
                        let connect = Arc::clone(&connect);
                        let cancel = cancel_token.clone();
                        let address_family = config.address_family;
                        connections.spawn(async move {
                            let _permit = permit;
                            let channel = match open_stream_channel(&client, &connect, address_family).await {
                                Ok(channel) => channel,
                                Err(error) => {
                                    tracing::warn!("Connection from {peer} failed: {error:#}");
                                    return;
                                }
                            };
                            match Tunnel::run(stream, channel, cancel).await {
                                Ok(stats) => tracing::debug!(
                                    "Connection from {peer} completed: {} bytes transferred",
                                    stats.total_bytes()
                                ),
                                Err(error) => tracing::warn!("Tunnel for {peer} failed: {error}"),
                            }
                        });
                    }
                    Err(error) => {
                        tracing::error!("Failed to accept forwarded connection on {listen}: {error}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
                _ = connections.join_next(), if !connections.is_empty() => {}
                _ = cancel_token.cancelled() => break,
            }
        }

        connections.abort_all();
        while connections.join_next().await.is_some() {}
        listener.close();
        tracing::info!("Local forwarding on {listen} stopped");
        send_status(ForwardingStatus::Stopped);
        Ok(())
    }
}

/// Run a [`ForwardingType::RemoteStream`] forwarding whose listener is a
/// Unix-domain socket on the server (`streamlocal-forward@openssh.com`).
pub(super) async fn run_remote_unix_listener(
    session_id: Uuid,
    path: String,
    connect: StreamEndpoint,
    ssh_client: Arc<Client>,
    config: ForwardingConfig,
    cancel: CancellationToken,
    messages: mpsc::UnboundedSender<ForwardingMessage>,
) -> Result<()> {
    let request_timeout = Duration::from_secs(config.connect_timeout_secs);
    let send_status = |status| {
        let _ = messages.send(ForwardingMessage::StatusUpdate {
            id: session_id,
            status,
        });
    };
    send_status(ForwardingStatus::Initializing);

    let target = Arc::new(RemoteForwardTarget::for_endpoint(
        connect.clone(),
        cancel.clone(),
        request_timeout,
        config.max_connections,
    ));
    let registry = ssh_client.remote_forward_registry();
    registry
        .register_unix(path.clone(), Arc::clone(&target))
        .await?;

    let request_result: Result<()> = tokio::select! {
        result = tokio::time::timeout(
            request_timeout,
            ssh_client.request_streamlocal_forward(path.clone()),
        ) => match result {
            Ok(result) => result.map_err(|error| anyhow::anyhow!(error)),
            Err(_) => Err(anyhow::anyhow!("Timed out requesting remote forwarding {path}")),
        },
        _ = cancel.cancelled() => {
            registry.unregister(&target).await;
            send_status(ForwardingStatus::Stopped);
            return Ok(());
        }
    };
    if let Err(error) = request_result {
        registry.unregister(&target).await;
        let message = format!("Remote forwarding request failed: {error}");
        send_status(ForwardingStatus::Failed(message.clone()));
        anyhow::bail!(message);
    }
    tracing::info!("Remote forwarding active on Unix socket {path} to {connect}");
    send_status(ForwardingStatus::Active);

    cancel.cancelled().await;

    let cancel_result = tokio::time::timeout(
        request_timeout,
        ssh_client.cancel_streamlocal_forward(path.clone()),
    )
    .await
    .with_context(|| format!("Timed out cancelling remote forwarding {path}"))
    .and_then(|result| result.map_err(|error| anyhow::anyhow!(error)));
    registry.unregister(&target).await;
    if let Err(error) = cancel_result {
        let message = format!("Failed to cancel remote forwarding {path}: {error}");
        send_status(ForwardingStatus::Failed(message.clone()));
        anyhow::bail!(message);
    }
    send_status(ForwardingStatus::Stopped);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn unix_listener_refuses_existing_paths_and_symlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let occupied = dir.path().join("file.sock");
        std::fs::write(&occupied, b"not a socket").expect("write placeholder");
        let error = bind_unix_listener(occupied.to_str().expect("utf-8 path"))
            .expect_err("an existing path must not be bound over");
        assert!(error.to_string().contains("already exists"), "{error:#}");
        assert_eq!(
            std::fs::read(&occupied).expect("placeholder survives"),
            b"not a socket"
        );

        let link = dir.path().join("dangling.sock");
        std::os::unix::fs::symlink(dir.path().join("elsewhere.sock"), &link).expect("symlink");
        let error = bind_unix_listener(link.to_str().expect("utf-8 path"))
            .expect_err("a dangling symlink must not be followed by bind");
        assert!(error.to_string().contains("already exists"), "{error:#}");
        assert!(
            !dir.path().join("elsewhere.sock").exists(),
            "bind must not create the symlink target"
        );
    }

    #[tokio::test]
    async fn unix_listener_is_owner_only_and_removed_only_when_still_a_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("listen.sock");
        let path_str = path.to_str().expect("utf-8 path");
        let listener = bind_unix_listener(path_str).expect("bind fresh path");
        let mode = std::fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the listener socket must be owner-only");
        drop(listener);
        remove_unix_socket(path_str);
        assert!(!path.exists(), "a socket node is removed on cleanup");

        std::fs::write(&path, b"replaced").expect("write regular file");
        remove_unix_socket(path_str);
        assert!(path.exists(), "a non-socket node must never be removed");
    }

    #[test]
    fn socket_path_limit_matches_sockaddr_un() {
        let longest = "x".repeat(MAX_SOCKET_PATH_LEN - 1);
        assert!(super::super::ForwardingSpec::validate_socket_path(&longest).is_ok());
        let too_long = "x".repeat(MAX_SOCKET_PATH_LEN);
        assert!(super::super::ForwardingSpec::validate_socket_path(&too_long).is_err());
        assert!(super::super::ForwardingSpec::validate_socket_path("a\0b").is_err());
    }
}

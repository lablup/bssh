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
//! matching OpenSSH with `StreamLocalBindUnlink no`. The bound node is
//! re-checked afterwards and the forwarding fails closed if it is not a plain
//! socket. Removal on shutdown only unlinks a node that is a socket.
//!
//! The socket is restricted to its owner (mode 0600, OpenSSH's default
//! `StreamLocalBindMask` of 0177) without ever changing a mode through the
//! path name, so a writer of the socket directory cannot redirect the change
//! through a symlink swapped in after `bind(2)`:
//!
//! - On Linux the unbound socket is `fchmod`ed first. `unix_bind` creates the
//!   node with the socket inode's mode minus the umask, so the path never
//!   exists with a wider mode and nothing is changed after the bind.
//! - Elsewhere `bind(2)` ignores the socket inode's mode, so the node is
//!   created with the umask-derived mode. It is therefore bound as `s` inside
//!   a private `mkdtemp` directory (mode 0700) next to the target, where no
//!   other user can reach it, narrowed there with
//!   `fchmodat(AT_SYMLINK_NOFOLLOW)` and verified, and only then moved to the
//!   configured path without overwriting anything: `renamex_np(RENAME_EXCL)`
//!   on Apple platforms, `link(2)` and `unlink(2)` of the temporary name on
//!   other BSDs. The private directory is removed on every path. A
//!   temporary path longer than `sun_path` allows fails closed.
//!
//! The process umask is deliberately left alone: it is shared by every
//! thread, and narrowing it around `bind(2)` would also narrow files and
//! directories another runtime thread creates at that moment.

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

    let listener = bind_owner_only(socket_path)
        .with_context(|| format!("cannot bind Unix-domain listener {path}"))?;

    // Refuse to serve anything that is not the plain socket node this call
    // created, and make sure no group or other permission bit is left.
    if let Err(error) = restrict_bound_socket(socket_path) {
        drop(listener);
        return Err(error.context(format!("refusing Unix-domain listener {path}")));
    }

    listener
        .set_nonblocking(true)
        .with_context(|| format!("cannot configure Unix-domain listener {path}"))?;
    UnixListener::from_std(listener)
        .with_context(|| format!("cannot register Unix-domain listener {path}"))
}

/// Create a listening socket at `path` whose node is created owner-only.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_owner_only(path: &Path) -> std::io::Result<std::os::unix::net::UnixListener> {
    use socket2::{Domain, SockAddr, Socket, Type};

    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    // Linux creates the node with the socket inode's mode minus the umask,
    // so narrowing the unbound socket narrows the node `bind(2)` creates.
    nix::sys::stat::fchmod(
        &socket,
        nix::sys::stat::Mode::from_bits_truncate(SOCKET_MODE as nix::libc::mode_t),
    )
    .map_err(std::io::Error::from)?;
    socket.bind(&SockAddr::unix(path)?)?;
    socket.listen(nix::libc::SOMAXCONN)?;
    Ok(socket.into())
}

/// Create a listening socket at `path` whose node is owner-only before it
/// appears there: it is bound and narrowed in a private sibling directory,
/// then moved into place without replacing an existing node.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bind_owner_only(path: &Path) -> Result<std::os::unix::net::UnixListener> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let private = PrivateBindDir::create(parent)?;
    let temporary = private.socket_path();
    // `sun_path` holds the path and its terminating NUL.
    if temporary.as_os_str().len() >= MAX_SOCKET_PATH_LEN {
        anyhow::bail!(
            "the temporary socket path {} exceeds the {MAX_SOCKET_PATH_LEN}-byte Unix socket path limit (including the terminating NUL); use a shorter listener path",
            temporary.display()
        );
    }
    let listener = std::os::unix::net::UnixListener::bind(&temporary)
        .context("cannot bind the socket in its private directory")?;
    restrict_bound_socket(&temporary)?;
    move_without_replacing(&temporary, path)
        .context("cannot move the owner-only socket into place")?;
    Ok(listener)
}

/// A `mkdtemp` directory (mode 0700) beside the listener path. Dropping it
/// removes the temporary socket name, if still present, and the directory.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
struct PrivateBindDir(std::path::PathBuf);

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl PrivateBindDir {
    fn create(parent: &Path) -> Result<Self> {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let template = parent.join(".bsshXXXXXX");
        let mut template = std::ffi::CString::new(template.as_os_str().as_bytes())
            .context("the socket directory path contains a NUL byte")?
            .into_bytes_with_nul();
        // SAFETY: `template` is a writable, NUL-terminated buffer that ends in
        // the six `X` characters mkdtemp replaces in place; it outlives the
        // call and mkdtemp keeps no reference to it.
        let created = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        if created.is_null() {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("cannot create a private directory in {}", parent.display())
            });
        }
        template.pop();
        Ok(Self(std::ffi::OsString::from_vec(template).into()))
    }

    fn socket_path(&self) -> std::path::PathBuf {
        self.0.join("s")
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl Drop for PrivateBindDir {
    fn drop(&mut self) {
        let socket = self.socket_path();
        match std::fs::remove_file(&socket) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    "Could not remove temporary socket {}: {error}",
                    socket.display()
                );
            }
        }
        if let Err(error) = std::fs::remove_dir(&self.0) {
            tracing::warn!(
                "Could not remove private socket directory {}: {error}",
                self.0.display()
            );
        }
    }
}

/// Atomically rename `from` to `to`, failing with `EEXIST` instead of
/// replacing whatever exists at `to`.
#[cfg(target_vendor = "apple")]
fn move_without_replacing(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let from = std::ffi::CString::new(from.as_os_str().as_bytes())?;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes())?;
    // SAFETY: both arguments are valid NUL-terminated strings that live until
    // the call returns; renamex_np keeps no reference to them.
    if unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Hard-link `from` at `to` and drop the temporary name. `link(2)` fails
/// with `EEXIST` instead of replacing whatever exists at `to`.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn move_without_replacing(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::hard_link(from, to)?;
    std::fs::remove_file(from)
}

/// Verify that `path` is a socket node and leave it with no permission bit
/// outside [`SOCKET_MODE`]. The mode is changed only with
/// `AT_SYMLINK_NOFOLLOW`, so a symlink swapped in after the bind is never
/// followed; the node is then checked again and anything other than an
/// owner-only socket fails closed.
fn restrict_bound_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let is_owner_only_socket = |metadata: &std::fs::Metadata| {
        metadata.file_type().is_socket()
            && metadata.permissions().mode() & 0o7777 & !SOCKET_MODE == 0
    };
    let bound = std::fs::symlink_metadata(path).context("cannot verify the bound socket")?;
    if !bound.file_type().is_socket() {
        anyhow::bail!("the bound path is not a plain socket node");
    }
    if is_owner_only_socket(&bound) {
        return Ok(());
    }
    nix::sys::stat::fchmodat(
        nix::fcntl::AT_FDCWD,
        path,
        nix::sys::stat::Mode::from_bits_truncate(SOCKET_MODE as nix::libc::mode_t),
        nix::sys::stat::FchmodatFlags::NoFollowSymlink,
    )
    .map_err(std::io::Error::from)
    .context("cannot restrict the socket to its owner")?;
    let restricted =
        std::fs::symlink_metadata(path).context("cannot verify the restricted socket")?;
    if !is_owner_only_socket(&restricted) {
        anyhow::bail!("the bound path is not an owner-only socket node");
    }
    Ok(())
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

    /// On Linux the node must be born owner-only, so there is no window in
    /// which another local user can connect before the mode is narrowed.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_socket_node_is_created_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("born.sock");
        let _listener = bind_owner_only(&path).expect("bind");
        let mode = std::fs::symlink_metadata(&path)
            .expect("socket")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "mode {mode:o} grants group or other access"
        );
    }

    /// On macOS `bind(2)` ignores the socket inode's mode, so the node is
    /// bound and narrowed in a private directory and moved into place. The
    /// configured path never holds a wider mode, an existing node is never
    /// replaced, and no private directory is left behind.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_socket_node_is_owner_only_before_it_appears() {
        use std::os::unix::fs::MetadataExt;

        let entries = |dir: &Path| {
            let mut names = std::fs::read_dir(dir)
                .expect("read_dir")
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .into_string()
                        .expect("utf-8")
                })
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("born.sock");
        let listener = bind_owner_only(&path).expect("bind");
        let bound = std::fs::symlink_metadata(&path).expect("socket");
        assert!(bound.file_type().is_socket());
        let mode = bound.permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "mode {mode:o} grants group or other access"
        );
        assert_eq!(entries(dir.path()), ["born.sock"]);
        std::os::unix::net::UnixStream::connect(&path).expect("connect through the moved node");
        drop(listener);

        let file = dir.path().join("file");
        std::fs::write(&file, b"keep").expect("write file");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("target"), &link).expect("symlink");
        for occupied in [&path, &file, &link] {
            let before = std::fs::symlink_metadata(occupied).expect("before");
            bind_owner_only(occupied).expect_err("an existing node must not be replaced");
            let after = std::fs::symlink_metadata(occupied).expect("after");
            assert_eq!(
                (before.ino(), before.mode()),
                (after.ino(), after.mode()),
                "{} was modified",
                occupied.display()
            );
            assert_eq!(entries(dir.path()), ["born.sock", "file", "link"]);
        }
        assert_eq!(std::fs::read(&file).expect("file"), b"keep");
        assert!(!dir.path().join("target").exists());

        // A listener path that fits sun_path but whose private sibling does
        // not fails closed and leaves nothing behind.
        let base_len = dir.path().as_os_str().len();
        let parent_len = MAX_SOCKET_PATH_LEN - 6;
        assert!(
            parent_len > base_len + 1,
            "temporary directory path is too long"
        );
        let parent = dir.path().join("p".repeat(parent_len - base_len - 1));
        std::fs::create_dir(&parent).expect("parent");
        let target = parent.join("x");
        let error = bind_unix_listener(target.to_str().expect("utf-8"))
            .expect_err("the temporary path exceeds sun_path");
        assert!(
            format!("{error:#}").contains(&format!("{MAX_SOCKET_PATH_LEN}-byte")),
            "{error:#}"
        );
        assert!(entries(&parent).is_empty(), "{:?}", entries(&parent));
    }

    #[test]
    fn restricting_a_bound_socket_never_follows_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"data").expect("write victim");
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644))
            .expect("chmod victim");
        let link = dir.path().join("swapped.sock");
        std::os::unix::fs::symlink(&victim, &link).expect("symlink");
        let error = restrict_bound_socket(&link).expect_err("a symlink is not a socket node");
        assert!(
            error.to_string().contains("not a plain socket"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::metadata(&victim)
                .expect("victim")
                .permissions()
                .mode()
                & 0o777,
            0o644,
            "the symlink target's mode must be untouched"
        );

        // A socket left with a wide mode is narrowed in place.
        let path = dir.path().join("wide.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).expect("widen");
        restrict_bound_socket(&path).expect("narrow a wide socket");
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .expect("socket")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
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

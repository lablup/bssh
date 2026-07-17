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

//! SSH server implementation using russh.
//!
//! This module provides the core SSH server functionality for bssh-server,
//! including connection handling, authentication, and session management.
//!
//! # Overview
//!
//! The server module consists of:
//!
//! - [`BsshServer`]: Main server struct that accepts connections
//! - [`SshHandler`]: Handles SSH protocol events for each connection
//! - [`SessionManager`]: Tracks active sessions
//! - [`ServerConfig`]: Server configuration options
//! - [`auth`]: Authentication providers (public key, password)
//!
//! # Example
//!
//! ```no_run
//! use bssh::server::{BsshServer, ServerConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = ServerConfig::builder()
//!         .host_key("/path/to/ssh_host_ed25519_key")
//!         .listen_address("0.0.0.0:2222")
//!         .build();
//!
//!     let server = BsshServer::new(config);
//!     server.run().await
//! }
//! ```

pub mod audit;
pub mod auth;
pub mod config;
pub mod exec;
pub mod filter;
pub mod handler;
pub mod pty;
pub mod scp;
pub mod security;
pub mod session;
pub mod sftp;
pub mod shell;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::server::Server;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::RwLock;

use crate::shared::rate_limit::RateLimiter;

pub use self::config::{ServerConfig, ServerConfigBuilder};
pub use self::exec::{CommandExecutor, ExecConfig};
pub use self::handler::SshHandler;
pub use self::pty::{PtyConfig as PtyMasterConfig, PtyMaster};
pub use self::security::{
    AccessPolicy, AuthRateLimitConfig, AuthRateLimiter, IpAccessControl, SharedIpAccessControl,
};
pub use self::session::{
    ChannelMode, ChannelState, PtyConfig, SessionConfig, SessionError, SessionId, SessionInfo,
    SessionManager, SessionStats,
};
pub use self::shell::ShellSession;

/// The main SSH server struct.
///
/// `BsshServer` manages the SSH server lifecycle, including accepting
/// connections and creating handlers for each client.
pub struct BsshServer {
    /// Server configuration.
    config: Arc<ServerConfig>,

    /// Shared session manager for tracking active connections.
    sessions: Arc<RwLock<SessionManager>>,
}

impl BsshServer {
    /// Create a new SSH server with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    ///
    /// # Example
    ///
    /// ```
    /// use bssh::server::{BsshServer, ServerConfig};
    ///
    /// let config = ServerConfig::builder()
    ///     .host_key("/etc/ssh/ssh_host_ed25519_key")
    ///     .build();
    /// let server = BsshServer::new(config);
    /// ```
    pub fn new(config: ServerConfig) -> Self {
        let session_config = config.session_config();
        let sessions = SessionManager::with_config(session_config);
        Self {
            config: Arc::new(config),
            sessions: Arc::new(RwLock::new(sessions)),
        }
    }

    /// Get the server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the session manager.
    pub fn sessions(&self) -> &Arc<RwLock<SessionManager>> {
        &self.sessions
    }

    /// Run the SSH server, listening on the configured address.
    ///
    /// This method starts the server and blocks until it is shut down.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No host keys are configured
    /// - Host keys cannot be loaded
    /// - The server fails to bind to the configured address
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bssh::server::{BsshServer, ServerConfig};
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let config = ServerConfig::builder()
    ///         .host_key("/etc/ssh/ssh_host_ed25519_key")
    ///         .listen_address("0.0.0.0:2222")
    ///         .build();
    ///
    ///     let server = BsshServer::new(config);
    ///     server.run().await
    /// }
    /// ```
    pub async fn run(&self) -> Result<()> {
        let addr = &self.config.listen_address;
        tracing::info!(address = %addr, "Starting SSH server");

        let russh_config = self.build_russh_config()?;
        self.run_on_address(Arc::new(russh_config), addr).await
    }

    /// Run the SSH server on a specific address.
    ///
    /// This allows running on a different address than the one in the config.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to listen on
    pub async fn run_at(&self, addr: impl ToSocketAddrs + std::fmt::Debug) -> Result<()> {
        tracing::info!(address = ?addr, "Starting SSH server");

        let russh_config = self.build_russh_config()?;
        self.run_on_address(Arc::new(russh_config), addr).await
    }

    /// Build the russh server configuration from our config.
    fn build_russh_config(&self) -> Result<russh::server::Config> {
        if !self.config.has_host_keys() {
            anyhow::bail!("No host keys configured. At least one host key is required.");
        }

        let mut keys = Vec::new();
        for key_path in &self.config.host_keys {
            let key = load_host_key(key_path)?;
            keys.push(key);
        }

        tracing::info!(key_count = keys.len(), "Loaded host keys");

        // russh's delayed zlib (`zlib@openssh.com`) compression desyncs and
        // corrupts the channel stream after a few packets, so any client that
        // negotiates compression (Cyberduck, `sftp -C`) fails mid-session
        // with "SshEncoding: length invalid" (reproducible in russh 0.61.1 and
        // 0.62.1). By default, advertise only "none" so clients fall back to
        // the uncompressed transport, matching the Dropbear/OpenSSH
        // sftp-server defaults used in Backend.AI containers. Operators can
        // opt back in via the `compression` config option once the upstream
        // russh bug is fixed. See https://github.com/lablup/bssh/issues/215
        // and https://github.com/lablup/bssh/issues/220.
        let preferred = if self.config.compression {
            tracing::warn!(
                "SSH transport compression enabled; russh's delayed-zlib \
                 (zlib@openssh.com) desync may drop clients that negotiate \
                 compression mid-session (see issue #215)"
            );
            russh::Preferred::DEFAULT
        } else {
            const NO_COMPRESSION: &[russh::compression::Name] = &[russh::compression::NONE];
            russh::Preferred {
                compression: std::borrow::Cow::Borrowed(NO_COMPRESSION),
                ..russh::Preferred::DEFAULT
            }
        };

        // Channel sizing (issue #187): russh's library defaults
        // (maximum_packet_size 32768, window_size 2 MiB) fragment a 256 KiB
        // SFTP write into 8 CHANNEL_DATA packets, multiplying per-packet
        // cipher and copy overhead. Advertise larger, configurable values.
        // russh rejects channel packets above a TCP frame, so clamp there.
        const RUSSH_MAX_PACKET_SIZE: u32 = 65535;
        // Floor keeps a misconfiguration from advertising a packet size that
        // cannot even carry an SFTP header round trip.
        const MIN_PACKET_SIZE: u32 = 4096;
        let maximum_packet_size = self
            .config
            .maximum_packet_size
            .clamp(MIN_PACKET_SIZE, RUSSH_MAX_PACKET_SIZE);
        if maximum_packet_size != self.config.maximum_packet_size {
            tracing::warn!(
                configured = self.config.maximum_packet_size,
                effective = maximum_packet_size,
                "maximum_packet_size out of range [{MIN_PACKET_SIZE}, {RUSSH_MAX_PACKET_SIZE}], clamped"
            );
        }
        // A window smaller than one packet would deadlock the channel before
        // the first packet completes; keep it at least one packet wide.
        let window_size = self.config.window_size.max(maximum_packet_size);
        if window_size != self.config.window_size {
            tracing::warn!(
                configured = self.config.window_size,
                effective = window_size,
                "window_size smaller than maximum_packet_size, raised"
            );
        }

        Ok(russh::server::Config {
            keys,
            preferred,
            auth_rejection_time: Duration::from_secs(3),
            auth_rejection_time_initial: Some(Duration::from_secs(0)),
            max_auth_attempts: self.config.max_auth_attempts as usize,
            inactivity_timeout: self.config.idle_timeout(),
            maximum_packet_size,
            window_size,
            // TCP_NODELAY on accepted sockets, matching OpenSSH. russh
            // defaults this off, which leaves Nagle's algorithm to interact
            // with delayed ACKs: request/response SFTP traffic then stalls
            // ~40 ms per round trip, and paramiko's read prefetch hangs
            // outright (issue #227).
            nodelay: true,
            ..Default::default()
        })
    }

    /// Internal method to run the server on an address.
    async fn run_on_address(
        &self,
        russh_config: Arc<russh::server::Config>,
        addr: impl ToSocketAddrs,
    ) -> Result<()> {
        let socket = TcpListener::bind(addr)
            .await
            .context("Failed to bind to address")?;

        tracing::info!(
            local_addr = ?socket.local_addr(),
            "SSH server listening"
        );

        // Create shared rate limiter for all handlers
        // Allow burst of 100 auth attempts, refill 10 attempts per second
        // This allows rapid testing while still providing protection against brute force
        let rate_limiter = RateLimiter::with_simple_config(100, 10.0);

        // Create auth rate limiter with configuration
        // Parse whitelist IPs from config
        let whitelist_ips: Vec<std::net::IpAddr> = self
            .config
            .whitelist_ips
            .iter()
            .filter_map(|s| {
                s.parse().map_err(|e| {
                    tracing::warn!(ip = %s, error = %e, "Invalid whitelist IP address in config, skipping");
                    e
                }).ok()
            })
            .collect();

        let auth_config = AuthRateLimitConfig::new(
            self.config.max_auth_attempts,
            self.config.auth_window_secs,
            self.config.ban_time_secs,
        )
        .with_whitelist(whitelist_ips);

        let auth_rate_limiter = AuthRateLimiter::new(auth_config);

        tracing::info!(
            max_attempts = self.config.max_auth_attempts,
            auth_window_secs = self.config.auth_window_secs,
            ban_time_secs = self.config.ban_time_secs,
            whitelist_count = self.config.whitelist_ips.len(),
            "Auth rate limiter configured"
        );

        // Create IP access control from configuration
        let ip_access_control =
            IpAccessControl::from_config(&self.config.allowed_ips, &self.config.blocked_ips)
                .context("Failed to configure IP access control")?;

        let shared_ip_access = SharedIpAccessControl::new(ip_access_control);

        // Start background cleanup task for auth rate limiter
        let cleanup_limiter = auth_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_limiter.cleanup().await;
            }
        });

        let mut server = BsshServerRunner {
            config: Arc::clone(&self.config),
            sessions: Arc::clone(&self.sessions),
            rate_limiter,
            auth_rate_limiter,
            ip_access_control: shared_ip_access,
        };

        // Use run_on_socket which handles the server loop
        server
            .run_on_socket(russh_config, &socket)
            .await
            .map_err(|e| anyhow::anyhow!("Server error: {}", e))
    }

    /// Get the number of active sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.session_count()
    }

    /// Check if the server is at connection capacity.
    pub async fn is_at_capacity(&self) -> bool {
        self.sessions.read().await.is_at_capacity()
    }
}

/// Internal struct that implements the russh::server::Server trait.
///
/// This is separate from BsshServer to allow BsshServer to be !Clone
/// while still implementing the Server trait which requires Clone.
#[derive(Clone)]
struct BsshServerRunner {
    config: Arc<ServerConfig>,
    sessions: Arc<RwLock<SessionManager>>,
    /// Shared rate limiter for authentication attempts across all handlers
    rate_limiter: RateLimiter<String>,
    /// Auth rate limiter with ban support (fail2ban-like)
    auth_rate_limiter: AuthRateLimiter,
    /// IP-based access control
    ip_access_control: SharedIpAccessControl,
}

impl russh::server::Server for BsshServerRunner {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        // Check IP access control before creating handler
        if let Some(addr) = peer_addr {
            let ip = addr.ip();

            // Check IP access control (synchronous to avoid blocking)
            if self.ip_access_control.check_sync(&ip) == AccessPolicy::Deny {
                tracing::info!(
                    ip = %ip,
                    "Connection rejected by IP access control"
                );
                // Return a handler that will immediately reject
                // We can't return None here due to trait constraints,
                // so we'll mark it for rejection in the handler
                return SshHandler::rejected(
                    peer_addr,
                    Arc::clone(&self.config),
                    Arc::clone(&self.sessions),
                );
            }

            // Check if banned by auth rate limiter
            // Use try_is_banned to avoid blocking the async runtime
            if self.auth_rate_limiter.try_is_banned(&ip).unwrap_or(false) {
                tracing::info!(
                    ip = %ip,
                    "Connection rejected from banned IP"
                );
                return SshHandler::rejected(
                    peer_addr,
                    Arc::clone(&self.config),
                    Arc::clone(&self.sessions),
                );
            }
        }

        tracing::info!(
            peer = ?peer_addr,
            "New client connection"
        );

        SshHandler::with_rate_limiters(
            peer_addr,
            Arc::clone(&self.config),
            Arc::clone(&self.sessions),
            self.rate_limiter.clone(),
            self.auth_rate_limiter.clone(),
        )
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        if is_client_disconnect_error(&error) {
            tracing::debug!(
                error = %error,
                "Session ended by client disconnect"
            );
        } else {
            tracing::error!(
                error = %error,
                "Session error"
            );
        }
    }
}

/// Whether a session error is an ordinary client-side disconnect (abrupt
/// client exit, network cut) rather than a server fault. These used to be
/// logged at ERROR, which was noise (issue #227). russh's `Error::IO` is
/// `#[error(transparent)]`, which forwards `source()` past the contained
/// io::Error, so the io::Error never appears in the anyhow chain on its own;
/// it has to be matched through `russh::Error` as well.
fn is_client_disconnect_error(error: &anyhow::Error) -> bool {
    fn is_disconnect_io(io: &std::io::Error) -> bool {
        matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        )
    }
    error.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return is_disconnect_io(io);
        }
        if let Some(russh_error) = cause.downcast_ref::<russh::Error>() {
            return matches!(russh_error, russh::Error::IO(io) if is_disconnect_io(io));
        }
        false
    })
}

/// Load an SSH host key from a file.
///
/// # Arguments
///
/// * `path` - Path to the private key file
///
/// # Errors
///
/// Returns an error if the key file cannot be read or parsed.
fn load_host_key(path: impl AsRef<Path>) -> Result<russh::keys::PrivateKey> {
    let path = path.as_ref();
    tracing::debug!(path = %path.display(), "Loading host key");

    russh::keys::PrivateKey::read_openssh_file(path)
        .with_context(|| format!("Failed to load host key from {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = ServerConfig::builder()
            .listen_address("127.0.0.1:2222")
            .max_connections(50)
            .build();

        let server = BsshServer::new(config);

        assert_eq!(server.config().listen_address, "127.0.0.1:2222");
        assert_eq!(server.config().max_connections, 50);
    }

    #[test]
    fn test_build_russh_config_no_keys() {
        let config = ServerConfig::builder().build();
        let server = BsshServer::new(config);

        let result = server.build_russh_config();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No host keys"));
    }

    #[test]
    fn test_build_russh_config_advertises_only_none_compression() {
        // Regression guard for #215: by default the server must advertise
        // only `none` compression so clients that prefer `zlib@openssh.com`
        // (Cyberduck, `sftp -C`) fall back to the uncompressed transport
        // instead of hitting russh's delayed-zlib desync. The default config
        // leaves `compression` off, so this covers the disabled setting.
        let key = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_keys/ssh_host_ed25519_key"
        );
        let config = ServerConfig::builder().host_key(key).build();
        assert!(
            !config.compression,
            "compression must default to off (see #215/#220)"
        );
        let server = BsshServer::new(config);

        let russh_config = server
            .build_russh_config()
            .expect("config should build with a valid host key");
        assert_eq!(
            russh_config.preferred.compression.as_ref(),
            [russh::compression::NONE],
            "server must advertise only `none` compression (see #215)"
        );
    }

    #[test]
    fn test_build_russh_config_compression_opt_in_advertises_zlib() {
        // #220: opting in via the `compression` config option restores the
        // russh default advertisement (none, zlib, zlib@openssh.com) so
        // clients may negotiate a compressed transport.
        let key = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_keys/ssh_host_ed25519_key"
        );
        let config = ServerConfig::builder()
            .host_key(key)
            .compression(true)
            .build();
        let server = BsshServer::new(config);

        let russh_config = server
            .build_russh_config()
            .expect("config should build with a valid host key");
        assert_eq!(
            russh_config.preferred.compression,
            russh::Preferred::DEFAULT.compression,
            "opt-in must advertise russh's default compression list"
        );
        assert!(
            russh_config
                .preferred
                .compression
                .as_ref()
                .contains(&russh::compression::ZLIB_LEGACY),
            "opt-in advertisement must include zlib@openssh.com"
        );
    }

    #[test]
    fn test_build_russh_config_channel_sizing_defaults() {
        // #187: by default the server advertises the russh packet-size cap
        // and an 8 MiB window instead of the library defaults (32768 / 2 MiB)
        // so SFTP writes are not fragmented into 8 packets each.
        let key = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_keys/ssh_host_ed25519_key"
        );
        let config = ServerConfig::builder().host_key(key).build();
        let server = BsshServer::new(config);

        let russh_config = server
            .build_russh_config()
            .expect("config should build with a valid host key");
        assert_eq!(russh_config.maximum_packet_size, 65535);
        assert_eq!(russh_config.window_size, 8 * 1024 * 1024);
    }

    #[test]
    fn test_build_russh_config_channel_sizing_clamped() {
        // Out-of-range values are clamped: packet size to [4096, 65535] and
        // the window to at least one packet.
        let key = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_keys/ssh_host_ed25519_key"
        );
        let config = ServerConfig::builder()
            .host_key(key)
            .maximum_packet_size(1_000_000)
            .window_size(1024)
            .build();
        let server = BsshServer::new(config);

        let russh_config = server
            .build_russh_config()
            .expect("config should build with a valid host key");
        assert_eq!(russh_config.maximum_packet_size, 65535);
        assert_eq!(
            russh_config.window_size, 65535,
            "window must be raised to at least one packet"
        );

        let config = ServerConfig::builder()
            .host_key(key)
            .maximum_packet_size(16)
            .build();
        let server = BsshServer::new(config);
        let russh_config = server
            .build_russh_config()
            .expect("config should build with a valid host key");
        assert_eq!(russh_config.maximum_packet_size, 4096);
    }

    #[test]
    fn test_build_russh_config_channel_sizing_custom() {
        // In-range custom values pass through unchanged.
        let key = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_keys/ssh_host_ed25519_key"
        );
        let config = ServerConfig::builder()
            .host_key(key)
            .maximum_packet_size(32768)
            .window_size(2 * 1024 * 1024)
            .build();
        let server = BsshServer::new(config);

        let russh_config = server
            .build_russh_config()
            .expect("config should build with a valid host key");
        assert_eq!(russh_config.maximum_packet_size, 32768);
        assert_eq!(russh_config.window_size, 2 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_session_count() {
        let config = ServerConfig::builder().host_key("/nonexistent/key").build();
        let server = BsshServer::new(config);

        assert_eq!(server.session_count().await, 0);
        assert!(!server.is_at_capacity().await);
    }

    #[tokio::test]
    async fn test_session_manager_access() {
        let config = ServerConfig::builder()
            .max_connections(10)
            .host_key("/nonexistent/key")
            .build();
        let server = BsshServer::new(config);

        {
            let mut sessions = server.sessions().write().await;
            let info = sessions.create_session(None);
            assert!(info.is_some());
        }

        assert_eq!(server.session_count().await, 1);
    }

    #[test]
    fn client_disconnect_errors_are_classified() {
        // russh wraps disconnect I/O errors in its transparent `IO` variant.
        let reset = anyhow::Error::from(russh::Error::IO(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        )));
        assert!(is_client_disconnect_error(&reset));

        // A bare io::Error in the chain must be recognized too.
        let pipe = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        assert!(is_client_disconnect_error(&pipe));

        // Genuine server faults stay at ERROR.
        let decrypt = anyhow::Error::from(russh::Error::DecryptionError);
        assert!(!is_client_disconnect_error(&decrypt));
        let denied =
            anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(!is_client_disconnect_error(&denied));
    }
}

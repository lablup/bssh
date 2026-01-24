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

pub mod auth;
pub mod config;
pub mod exec;
pub mod handler;
pub mod pty;
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
pub use self::session::{
    ChannelMode, ChannelState, PtyConfig, SessionId, SessionInfo, SessionManager,
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
        let sessions = SessionManager::with_max_sessions(config.max_connections);
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

        Ok(russh::server::Config {
            keys,
            auth_rejection_time: Duration::from_secs(3),
            auth_rejection_time_initial: Some(Duration::from_secs(0)),
            max_auth_attempts: self.config.max_auth_attempts as usize,
            inactivity_timeout: self.config.idle_timeout(),
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

        let mut server = BsshServerRunner {
            config: Arc::clone(&self.config),
            sessions: Arc::clone(&self.sessions),
            rate_limiter,
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
}

impl russh::server::Server for BsshServerRunner {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        tracing::info!(
            peer = ?peer_addr,
            "New client connection"
        );

        SshHandler::with_rate_limiter(
            peer_addr,
            Arc::clone(&self.config),
            Arc::clone(&self.sessions),
            self.rate_limiter.clone(),
        )
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        tracing::error!(
            error = %error,
            "Session error"
        );
    }
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
}

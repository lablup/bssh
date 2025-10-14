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

use super::connection::JumpHostConnection;
use super::parser::{get_max_jump_hosts, JumpHost};
use super::rate_limiter::ConnectionRateLimiter;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::client::ClientHandler;
use crate::ssh::tokio_client::{AuthMethod, Client};
use anyhow::{Context, Result};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

// Maximum number of jump hosts is now determined dynamically via get_max_jump_hosts()
// See parser::get_max_jump_hosts() for configuration details

/// A connection through the jump host chain
///
/// Represents an active connection that may go through multiple jump hosts
/// to reach the final destination. This can be either a direct connection
/// or a connection through one or more jump hosts.
#[derive(Debug)]
pub struct JumpConnection {
    /// The final client connection (either direct or through jump hosts)
    pub client: Client,
    /// Information about the jump path taken
    pub jump_info: JumpInfo,
}

/// Information about the jump host path used for a connection
#[derive(Debug, Clone)]
pub enum JumpInfo {
    /// Direct connection (no jump hosts)
    Direct { host: String, port: u16 },
    /// Connection through jump hosts
    Jumped {
        /// The jump hosts in the chain
        jump_hosts: Vec<JumpHost>,
        /// Final destination
        destination: String,
        destination_port: u16,
    },
}

impl JumpInfo {
    /// Get a human-readable description of the connection path
    pub fn path_description(&self) -> String {
        match self {
            JumpInfo::Direct { host, port } => {
                format!("Direct connection to {host}:{port}")
            }
            JumpInfo::Jumped {
                jump_hosts,
                destination,
                destination_port,
            } => {
                let jump_chain: Vec<String> = jump_hosts
                    .iter()
                    .map(|j| j.to_connection_string())
                    .collect();
                format!(
                    "Jump path: {} -> {}:{}",
                    jump_chain.join(" -> "),
                    destination,
                    destination_port
                )
            }
        }
    }

    /// Get the final destination host and port
    pub fn destination(&self) -> (&str, u16) {
        match self {
            JumpInfo::Direct { host, port } => (host, *port),
            JumpInfo::Jumped {
                destination,
                destination_port,
                ..
            } => (destination, *destination_port),
        }
    }
}

/// Manages SSH jump host chains for establishing connections
///
/// This struct handles the complexity of connecting through one or more jump hosts
/// to reach a final destination. It supports:
/// * Connection caching and reuse
/// * Per-host authentication
/// * Automatic retry with exponential backoff
/// * Connection health monitoring
/// * Thread-safe credential prompting
#[derive(Debug)]
pub struct JumpHostChain {
    /// The jump hosts in order (empty for direct connections)
    jump_hosts: Vec<JumpHost>,
    /// Connection timeout for each hop
    connect_timeout: Duration,
    /// Command timeout for operations
    command_timeout: Duration,
    /// Maximum retry attempts for failed connections
    max_retries: u32,
    /// Base delay for exponential backoff (in milliseconds)
    base_retry_delay: u64,
    /// Active connections cache
    connections: Arc<RwLock<Vec<Arc<JumpHostConnection>>>>,
    /// Rate limiter for connection attempts
    rate_limiter: ConnectionRateLimiter,
    /// Maximum idle time before connection cleanup (default: 5 minutes)
    max_idle_time: Duration,
    /// Maximum connection age before forced renewal (default: 30 minutes)
    max_connection_age: Duration,
    /// Mutex to serialize authentication prompts
    /// SECURITY: Prevents credential prompt race conditions with multiple jump hosts
    auth_mutex: Arc<Mutex<()>>,
}

impl JumpHostChain {
    /// Create a new jump host chain
    /// Truncates to maximum allowed hosts if limit is exceeded
    pub fn new(jump_hosts: Vec<JumpHost>) -> Self {
        let max_jump_hosts = get_max_jump_hosts();

        // Log warning if approaching the limit
        if jump_hosts.len() > max_jump_hosts {
            warn!(
                "Jump host chain has {} hosts, which exceeds the maximum of {} (BSSH_MAX_JUMP_HOSTS). Chain will be truncated.",
                jump_hosts.len(),
                max_jump_hosts
            );
        }

        // Truncate to maximum allowed hosts
        let jump_hosts = if jump_hosts.len() > max_jump_hosts {
            jump_hosts.into_iter().take(max_jump_hosts).collect()
        } else {
            jump_hosts
        };

        Self {
            jump_hosts,
            connect_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(300),
            max_retries: 3,
            base_retry_delay: 1000,
            connections: Arc::new(RwLock::new(Vec::new())),
            rate_limiter: ConnectionRateLimiter::new(),
            max_idle_time: Duration::from_secs(300), // 5 minutes
            max_connection_age: Duration::from_secs(1800), // 30 minutes
            auth_mutex: Arc::new(Mutex::new(())),
        }
    }

    /// Create a direct connection chain (no jump hosts)
    pub fn direct() -> Self {
        Self::new(Vec::new())
    }

    /// Set connection timeout for each hop
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set command execution timeout
    pub fn with_command_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }

    /// Set retry configuration
    pub fn with_retry_config(mut self, max_retries: u32, base_delay_ms: u64) -> Self {
        self.max_retries = max_retries;
        self.base_retry_delay = base_delay_ms;
        self
    }

    /// Set rate limiting configuration
    ///
    /// * `max_burst` - Maximum number of connections allowed in a burst
    /// * `refill_rate` - Number of connections allowed per second (sustained rate)
    pub fn with_rate_limit(mut self, max_burst: u32, refill_rate: f64) -> Self {
        self.rate_limiter = ConnectionRateLimiter::with_config(max_burst, refill_rate);
        self
    }

    /// Check if this is a direct connection (no jump hosts)
    pub fn is_direct(&self) -> bool {
        self.jump_hosts.is_empty()
    }

    /// Get the number of jump hosts in the chain
    pub fn jump_count(&self) -> usize {
        self.jump_hosts.len()
    }

    /// Clean up stale connections from the pool
    ///
    /// Removes connections that are:
    /// - No longer alive
    /// - Idle for too long
    /// - Too old
    pub async fn cleanup_connections(&self) {
        let mut connections = self.connections.write().await;
        let mut to_remove = Vec::new();

        for (i, conn) in connections.iter().enumerate() {
            // Check if connection should be removed
            let should_remove = !conn.is_alive().await
                || conn.idle_time().await > self.max_idle_time
                || conn.age() > self.max_connection_age;

            if should_remove {
                to_remove.push(i);
                debug!(
                    "Removing stale connection to {:?} (age: {:?}, idle: {:?})",
                    conn.destination,
                    conn.age(),
                    conn.idle_time().await
                );
            }
        }

        // Remove connections in reverse order to maintain indices
        for i in to_remove.iter().rev() {
            connections.remove(*i);
        }

        if !to_remove.is_empty() {
            info!("Cleaned up {} stale connections", to_remove.len());
        }
    }

    /// Get the number of active connections in the pool
    pub async fn active_connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    /// Connect to the destination through the jump host chain
    ///
    /// TODO: This is currently a stub implementation. Full jump host support
    /// will be implemented in subsequent iterations.
    ///
    /// This method handles the full connection process:
    /// 1. For direct connections, connects directly to the destination
    /// 2. For jump host connections, establishes each hop in sequence
    /// 3. Creates direct-tcpip channels through each jump host
    /// 4. Returns a client connected to the final destination
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &self,
        destination_host: &str,
        destination_port: u16,
        destination_user: &str,
        dest_auth_method: AuthMethod,
        dest_key_path: Option<&Path>,
        dest_strict_mode: Option<StrictHostKeyChecking>,
        dest_use_agent: bool,
        dest_use_password: bool,
    ) -> Result<JumpConnection> {
        // Clean up stale connections periodically
        if self.active_connection_count().await > 10 {
            self.cleanup_connections().await;
        }

        if self.is_direct() {
            self.connect_direct(
                destination_host,
                destination_port,
                destination_user,
                dest_auth_method,
                dest_strict_mode,
            )
            .await
        } else {
            self.connect_through_jumps(
                destination_host,
                destination_port,
                destination_user,
                dest_auth_method,
                dest_key_path,
                dest_strict_mode,
                dest_use_agent,
                dest_use_password,
            )
            .await
        }
    }

    /// Establish a direct connection (no jump hosts)
    async fn connect_direct(
        &self,
        host: &str,
        port: u16,
        username: &str,
        auth_method: AuthMethod,
        strict_mode: Option<StrictHostKeyChecking>,
    ) -> Result<JumpConnection> {
        debug!("Establishing direct connection to {}:{}", host, port);

        // Apply rate limiting to prevent DoS attacks
        self.rate_limiter
            .try_acquire(host)
            .await
            .with_context(|| format!("Rate limited for host {host}"))?;

        let check_method = strict_mode.map_or_else(
            || crate::ssh::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew),
            crate::ssh::known_hosts::get_check_method,
        );

        let client = tokio::time::timeout(
            self.connect_timeout,
            Client::connect((host, port), username, auth_method, check_method),
        )
        .await
        .with_context(|| {
            format!(
                "Connection timeout: Failed to connect to {}:{} after {}s",
                host,
                port,
                self.connect_timeout.as_secs()
            )
        })?
        .with_context(|| format!("Failed to establish direct connection to {host}:{port}"))?;

        info!("Direct connection established to {}:{}", host, port);

        Ok(JumpConnection {
            client,
            jump_info: JumpInfo::Direct {
                host: host.to_string(),
                port,
            },
        })
    }

    /// Establish connection through jump hosts
    #[allow(clippy::too_many_arguments)]
    async fn connect_through_jumps(
        &self,
        destination_host: &str,
        destination_port: u16,
        destination_user: &str,
        dest_auth_method: AuthMethod,
        dest_key_path: Option<&Path>,
        dest_strict_mode: Option<StrictHostKeyChecking>,
        dest_use_agent: bool,
        dest_use_password: bool,
    ) -> Result<JumpConnection> {
        info!(
            "Establishing jump host connection through {} hop(s) to {}:{}",
            self.jump_hosts.len(),
            destination_host,
            destination_port
        );

        if self.jump_hosts.is_empty() {
            anyhow::bail!("No jump hosts specified for jump connection");
        }

        // Step 1: Connect to the first jump host directly
        let mut current_client = self
            .connect_to_first_jump(
                dest_key_path,
                dest_strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew),
                dest_use_agent,
                dest_use_password,
            )
            .await
            .with_context(|| {
                format!(
                    "Failed to connect to first jump host: {}",
                    self.jump_hosts[0]
                )
            })?;

        debug!("Connected to first jump host: {}", self.jump_hosts[0]);

        // Step 2: Chain through intermediate jump hosts
        for (i, jump_host) in self.jump_hosts.iter().skip(1).enumerate() {
            debug!(
                "Connecting to intermediate jump host {} of {}: {}",
                i + 2,
                self.jump_hosts.len(),
                jump_host
            );

            current_client = self
                .connect_to_next_jump(
                    &current_client,
                    jump_host,
                    dest_key_path,
                    dest_use_agent,
                    dest_use_password,
                    dest_strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew),
                )
                .await
                .with_context(|| {
                    format!(
                        "Failed to connect to jump host {} (hop {}): {}",
                        jump_host,
                        i + 2,
                        jump_host
                    )
                })?;

            debug!("Connected through jump host: {}", jump_host);
        }

        // Step 3: Connect to final destination through the last jump host
        let final_client = self
            .connect_to_destination(
                &current_client,
                destination_host,
                destination_port,
                destination_user,
                dest_auth_method,
                dest_strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew),
            )
            .await
            .with_context(|| {
                format!(
                    "Failed to connect to destination {destination_host}:{destination_port} through jump host chain"
                )
            })?;

        info!(
            "Successfully established jump connection: {} -> {}:{}",
            self.jump_hosts
                .iter()
                .map(|j| j.to_connection_string())
                .collect::<Vec<_>>()
                .join(" -> "),
            destination_host,
            destination_port
        );

        Ok(JumpConnection {
            client: final_client,
            jump_info: JumpInfo::Jumped {
                jump_hosts: self.jump_hosts.clone(),
                destination: destination_host.to_string(),
                destination_port,
            },
        })
    }

    /// Connect to the first jump host directly
    async fn connect_to_first_jump(
        &self,
        key_path: Option<&Path>,
        strict_mode: StrictHostKeyChecking,
        use_agent: bool,
        use_password: bool,
    ) -> Result<Client> {
        let jump_host = &self.jump_hosts[0];

        debug!(
            "Connecting to first jump host: {} ({}:{})",
            jump_host,
            jump_host.host,
            jump_host.effective_port()
        );

        // Apply rate limiting to prevent DoS attacks on jump hosts
        self.rate_limiter
            .try_acquire(&jump_host.host)
            .await
            .with_context(|| format!("Rate limited for jump host {}", jump_host.host))?;

        let auth_method = self
            .determine_jump_auth_method(jump_host, key_path, use_agent, use_password)
            .await?;
        let check_method = crate::ssh::known_hosts::get_check_method(strict_mode);

        let client = tokio::time::timeout(
            self.connect_timeout,
            Client::connect(
                (jump_host.host.as_str(), jump_host.effective_port()),
                &jump_host.effective_user(),
                auth_method,
                check_method,
            ),
        )
        .await
        .with_context(|| {
            format!(
                "Connection timeout: Failed to connect to jump host {}:{} after {}s",
                jump_host.host,
                jump_host.effective_port(),
                self.connect_timeout.as_secs()
            )
        })?
        .with_context(|| {
            format!(
                "Failed to establish connection to first jump host: {}:{}",
                jump_host.host,
                jump_host.effective_port()
            )
        })?;

        Ok(client)
    }

    /// Connect to a subsequent jump host through the previous connection
    async fn connect_to_next_jump(
        &self,
        previous_client: &Client,
        jump_host: &JumpHost,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
        strict_mode: StrictHostKeyChecking,
    ) -> Result<Client> {
        debug!(
            "Opening tunnel to jump host: {} ({}:{})",
            jump_host,
            jump_host.host,
            jump_host.effective_port()
        );

        // Apply rate limiting for intermediate jump hosts
        self.rate_limiter
            .try_acquire(&jump_host.host)
            .await
            .with_context(|| format!("Rate limited for jump host {}", jump_host.host))?;

        // Create a direct-tcpip channel through the previous connection
        let channel = tokio::time::timeout(
            self.connect_timeout,
            previous_client.open_direct_tcpip_channel(
                (jump_host.host.as_str(), jump_host.effective_port()),
                None,
            ),
        )
        .await
        .with_context(|| {
            format!(
                "Timeout opening tunnel to jump host {}:{} after {}s",
                jump_host.host,
                jump_host.effective_port(),
                self.connect_timeout.as_secs()
            )
        })?
        .with_context(|| {
            format!(
                "Failed to open direct-tcpip channel to jump host {}:{}",
                jump_host.host,
                jump_host.effective_port()
            )
        })?;

        // Convert the channel to a stream
        let stream = channel.into_stream();

        // Create SSH client over the tunnel stream
        let auth_method = self
            .determine_jump_auth_method(jump_host, key_path, use_agent, use_password)
            .await?;

        // Create a basic russh client config
        let config = std::sync::Arc::new(russh::client::Config::default());

        // Create a simple handler for the connection
        let socket_addr: SocketAddr = format!("{}:{}", jump_host.host, jump_host.effective_port())
            .to_socket_addrs()
            .with_context(|| {
                format!(
                    "Failed to resolve jump host address: {}:{}",
                    jump_host.host,
                    jump_host.effective_port()
                )
            })?
            .next()
            .with_context(|| {
                format!(
                    "No addresses resolved for jump host: {}:{}",
                    jump_host.host,
                    jump_host.effective_port()
                )
            })?;

        // SECURITY: Always verify host keys for jump hosts to prevent MITM attacks
        let check_method = crate::ssh::known_hosts::get_check_method(strict_mode);

        let handler = ClientHandler::new(jump_host.host.clone(), socket_addr, check_method);

        // Connect through the stream
        let handle = tokio::time::timeout(
            self.connect_timeout,
            russh::client::connect_stream(config, stream, handler),
        )
        .await
        .with_context(|| {
            format!(
                "Timeout establishing SSH over tunnel to {}:{} after {}s",
                jump_host.host,
                jump_host.effective_port(),
                self.connect_timeout.as_secs()
            )
        })?
        .with_context(|| {
            format!(
                "Failed to establish SSH connection over tunnel to {}:{}",
                jump_host.host,
                jump_host.effective_port()
            )
        })?;

        // Authenticate
        let mut handle = handle;
        self.authenticate_jump_host(&mut handle, &jump_host.effective_user(), auth_method)
            .await
            .with_context(|| {
                format!(
                    "Failed to authenticate to jump host {}:{} as user {}",
                    jump_host.host,
                    jump_host.effective_port(),
                    jump_host.effective_user()
                )
            })?;

        // Create our Client wrapper
        let client = Client::from_handle_and_address(
            std::sync::Arc::new(handle),
            jump_host.effective_user(),
            socket_addr,
        );

        Ok(client)
    }

    /// Connect to the final destination through the last jump host
    async fn connect_to_destination(
        &self,
        jump_client: &Client,
        destination_host: &str,
        destination_port: u16,
        destination_user: &str,
        dest_auth_method: AuthMethod,
        strict_mode: StrictHostKeyChecking,
    ) -> Result<Client> {
        debug!(
            "Opening tunnel to destination: {}:{} as user {}",
            destination_host, destination_port, destination_user
        );

        // Apply rate limiting for final destination
        self.rate_limiter
            .try_acquire(destination_host)
            .await
            .with_context(|| format!("Rate limited for destination {destination_host}"))?;

        // Create a direct-tcpip channel to the final destination
        let channel = tokio::time::timeout(
            self.connect_timeout,
            jump_client.open_direct_tcpip_channel((destination_host, destination_port), None),
        )
        .await
        .with_context(|| {
            format!(
                "Timeout opening tunnel to destination {}:{} after {}s",
                destination_host,
                destination_port,
                self.connect_timeout.as_secs()
            )
        })?
        .with_context(|| {
            format!(
                "Failed to open direct-tcpip channel to destination {destination_host}:{destination_port}"
            )
        })?;

        // Convert the channel to a stream
        let stream = channel.into_stream();

        // Create SSH client over the tunnel stream
        let config = std::sync::Arc::new(russh::client::Config::default());
        let check_method = match strict_mode {
            StrictHostKeyChecking::No => crate::ssh::tokio_client::ServerCheckMethod::NoCheck,
            _ => crate::ssh::known_hosts::get_check_method(strict_mode),
        };

        let socket_addr: SocketAddr = format!("{destination_host}:{destination_port}")
            .to_socket_addrs()
            .with_context(|| {
                format!(
                    "Failed to resolve destination address: {destination_host}:{destination_port}"
                )
            })?
            .next()
            .with_context(|| {
                format!(
                    "No addresses resolved for destination: {destination_host}:{destination_port}"
                )
            })?;

        let handler = ClientHandler::new(destination_host.to_string(), socket_addr, check_method);

        // Connect through the stream
        let handle = tokio::time::timeout(
            self.connect_timeout,
            russh::client::connect_stream(config, stream, handler),
        )
        .await
        .with_context(|| {
            format!(
                "Timeout establishing SSH to destination {}:{} after {}s",
                destination_host,
                destination_port,
                self.connect_timeout.as_secs()
            )
        })?
        .with_context(|| {
            format!(
                "Failed to establish SSH connection to destination {destination_host}:{destination_port}"
            )
        })?;

        // Authenticate to the final destination
        let mut handle = handle;
        self.authenticate_destination(&mut handle, destination_user, dest_auth_method)
            .await
            .with_context(|| {
                format!(
                    "Failed to authenticate to destination {destination_host}:{destination_port} as user {destination_user}"
                )
            })?;

        // Create our Client wrapper
        let client = Client::from_handle_and_address(
            std::sync::Arc::new(handle),
            destination_user.to_string(),
            socket_addr,
        );

        Ok(client)
    }

    /// Determine authentication method for a jump host
    ///
    /// For now, uses the same authentication method as the destination.
    /// In the future, this could be enhanced to support per-host authentication.
    #[allow(dead_code)]
    async fn determine_jump_auth_method(
        &self,
        jump_host: &JumpHost,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<AuthMethod> {
        // For now, use the same auth method determination logic as the main SSH client
        // This could be enhanced to support per-jump-host authentication in the future

        if use_password {
            // SECURITY: Acquire mutex to serialize password prompts
            // This prevents multiple simultaneous prompts that could confuse users
            let _guard = self.auth_mutex.lock().await;

            // Display which jump host we're authenticating to
            let prompt = format!(
                "Enter password for jump host {} ({}@{}): ",
                jump_host.to_connection_string(),
                jump_host.effective_user(),
                jump_host.host
            );

            let password = Zeroizing::new(
                rpassword::prompt_password(prompt).with_context(|| "Failed to read password")?,
            );
            return Ok(AuthMethod::with_password(&password));
        }

        if use_agent {
            #[cfg(not(target_os = "windows"))]
            {
                if std::env::var("SSH_AUTH_SOCK").is_ok() {
                    return Ok(AuthMethod::Agent);
                }
            }
        }

        if let Some(key_path) = key_path {
            // SECURITY: Use Zeroizing to ensure key contents are cleared from memory
            let key_contents = Zeroizing::new(
                std::fs::read_to_string(key_path)
                    .with_context(|| format!("Failed to read SSH key file: {key_path:?}"))?,
            );

            let passphrase = if key_contents.contains("ENCRYPTED")
                || key_contents.contains("Proc-Type: 4,ENCRYPTED")
            {
                // SECURITY: Acquire mutex to serialize passphrase prompts
                let _guard = self.auth_mutex.lock().await;

                let prompt = format!(
                    "Enter passphrase for key {key_path:?} (jump host {}): ",
                    jump_host.to_connection_string()
                );

                let pass = Zeroizing::new(
                    rpassword::prompt_password(prompt)
                        .with_context(|| "Failed to read passphrase")?,
                );
                Some(pass)
            } else {
                None
            };

            return Ok(AuthMethod::with_key_file(
                key_path,
                passphrase.as_ref().map(|p| p.as_str()),
            ));
        }

        // Fallback to SSH agent if available
        #[cfg(not(target_os = "windows"))]
        if std::env::var("SSH_AUTH_SOCK").is_ok() {
            return Ok(AuthMethod::Agent);
        }

        // Try default key files
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let home_path = Path::new(&home).join(".ssh");
        let default_keys = [
            home_path.join("id_ed25519"),
            home_path.join("id_rsa"),
            home_path.join("id_ecdsa"),
            home_path.join("id_dsa"),
        ];

        for default_key in &default_keys {
            if default_key.exists() {
                // SECURITY: Use Zeroizing to ensure key contents are cleared from memory
                let key_contents =
                    Zeroizing::new(std::fs::read_to_string(default_key).with_context(|| {
                        format!("Failed to read SSH key file: {default_key:?}")
                    })?);

                let passphrase = if key_contents.contains("ENCRYPTED")
                    || key_contents.contains("Proc-Type: 4,ENCRYPTED")
                {
                    // SECURITY: Acquire mutex to serialize passphrase prompts
                    let _guard = self.auth_mutex.lock().await;

                    let prompt = format!(
                        "Enter passphrase for key {default_key:?} (jump host {}): ",
                        jump_host.to_connection_string()
                    );

                    let pass = Zeroizing::new(
                        rpassword::prompt_password(prompt)
                            .with_context(|| "Failed to read passphrase")?,
                    );
                    Some(pass)
                } else {
                    None
                };

                return Ok(AuthMethod::with_key_file(
                    default_key,
                    passphrase.as_ref().map(|p| p.as_str()),
                ));
            }
        }

        anyhow::bail!("No authentication method available for jump host")
    }

    /// Authenticate to a jump host  
    async fn authenticate_jump_host(
        &self,
        handle: &mut russh::client::Handle<ClientHandler>,
        username: &str,
        auth_method: AuthMethod,
    ) -> Result<()> {
        use crate::ssh::tokio_client::AuthMethod;

        match auth_method {
            AuthMethod::Password(password) => {
                let auth_result = handle
                    .authenticate_password(username, &**password)
                    .await
                    .map_err(|e| anyhow::anyhow!("Password authentication failed: {e}"))?;

                if !auth_result.success() {
                    anyhow::bail!("Password authentication rejected by jump host");
                }
            }

            AuthMethod::PrivateKey { key_data, key_pass } => {
                let private_key =
                    russh::keys::decode_secret_key(&key_data, key_pass.as_ref().map(|p| &***p))
                        .map_err(|e| anyhow::anyhow!("Failed to decode private key: {e}"))?;

                let auth_result = handle
                    .authenticate_publickey(
                        username,
                        russh::keys::PrivateKeyWithHashAlg::new(
                            std::sync::Arc::new(private_key),
                            handle.best_supported_rsa_hash().await?.flatten(),
                        ),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("Private key authentication failed: {e}"))?;

                if !auth_result.success() {
                    anyhow::bail!("Private key authentication rejected by jump host");
                }
            }

            AuthMethod::PrivateKeyFile {
                key_file_path,
                key_pass,
            } => {
                let private_key =
                    russh::keys::load_secret_key(key_file_path, key_pass.as_ref().map(|p| &***p))
                        .map_err(|e| anyhow::anyhow!("Failed to load private key from file: {e}"))?;

                let auth_result = handle
                    .authenticate_publickey(
                        username,
                        russh::keys::PrivateKeyWithHashAlg::new(
                            std::sync::Arc::new(private_key),
                            handle.best_supported_rsa_hash().await?.flatten(),
                        ),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("Private key file authentication failed: {e}"))?;

                if !auth_result.success() {
                    anyhow::bail!("Private key file authentication rejected by jump host");
                }
            }

            #[cfg(not(target_os = "windows"))]
            AuthMethod::Agent => {
                let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                    .await
                    .map_err(|_| anyhow::anyhow!("Failed to connect to SSH agent"))?;

                let identities = agent
                    .request_identities()
                    .await
                    .map_err(|_| anyhow::anyhow!("Failed to request identities from SSH agent"))?;

                if identities.is_empty() {
                    anyhow::bail!("No identities available in SSH agent");
                }

                let mut auth_success = false;
                for identity in identities {
                    let result = handle
                        .authenticate_publickey_with(
                            username,
                            identity.clone(),
                            handle.best_supported_rsa_hash().await?.flatten(),
                            &mut agent,
                        )
                        .await;

                    if let Ok(auth_result) = result {
                        if auth_result.success() {
                            auth_success = true;
                            break;
                        }
                    }
                }

                if !auth_success {
                    anyhow::bail!("SSH agent authentication rejected by jump host");
                }
            }

            _ => {
                anyhow::bail!("Unsupported authentication method for jump host");
            }
        }

        Ok(())
    }

    /// Authenticate to the destination host
    async fn authenticate_destination(
        &self,
        handle: &mut russh::client::Handle<ClientHandler>,
        username: &str,
        auth_method: AuthMethod,
    ) -> Result<()> {
        // Use the same authentication logic as jump hosts for now
        // In the future, we might want different behavior for destination vs jump hosts
        self.authenticate_jump_host(handle, username, auth_method)
            .await
    }

    /// Clean up any cached connections
    pub async fn cleanup(&self) {
        let mut connections = self.connections.write().await;
        connections.clear();
        debug!("Cleaned up jump host connection cache");
    }
}

impl Drop for JumpHostChain {
    fn drop(&mut self) {
        // Note: We cannot await async operations in Drop, but we can log for debugging
        // The connections will be properly closed when the Client instances are dropped
        debug!(
            "JumpHostChain dropped, {} connections will be cleaned up",
            self.connections.try_read().map(|c| c.len()).unwrap_or(0)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jump_host_chain_creation() {
        let chain = JumpHostChain::direct();
        assert!(chain.is_direct());
        assert_eq!(chain.jump_count(), 0);

        let jump_hosts = vec![
            JumpHost::new(
                "jump1.example.com".to_string(),
                Some("user".to_string()),
                Some(22),
            ),
            JumpHost::new("jump2.example.com".to_string(), None, None),
        ];
        let chain = JumpHostChain::new(jump_hosts);
        assert!(!chain.is_direct());
        assert_eq!(chain.jump_count(), 2);
    }

    #[test]
    fn test_jump_info_path_description() {
        let direct = JumpInfo::Direct {
            host: "example.com".to_string(),
            port: 22,
        };
        assert_eq!(
            direct.path_description(),
            "Direct connection to example.com:22"
        );

        let jumped = JumpInfo::Jumped {
            jump_hosts: vec![
                JumpHost::new("jump1".to_string(), Some("user".to_string()), Some(22)),
                JumpHost::new("jump2".to_string(), None, Some(2222)),
            ],
            destination: "target.com".to_string(),
            destination_port: 22,
        };
        assert_eq!(
            jumped.path_description(),
            "Jump path: user@jump1:22 -> jump2:2222 -> target.com:22"
        );
    }

    #[test]
    fn test_jump_info_destination() {
        let direct = JumpInfo::Direct {
            host: "example.com".to_string(),
            port: 2222,
        };
        let (host, port) = direct.destination();
        assert_eq!(host, "example.com");
        assert_eq!(port, 2222);

        let jumped = JumpInfo::Jumped {
            jump_hosts: vec![],
            destination: "target.com".to_string(),
            destination_port: 22,
        };
        let (host, port) = jumped.destination();
        assert_eq!(host, "target.com");
        assert_eq!(port, 22);
    }

    #[test]
    fn test_chain_configuration() {
        let chain = JumpHostChain::direct()
            .with_connect_timeout(Duration::from_secs(45))
            .with_command_timeout(Duration::from_secs(600))
            .with_retry_config(5, 2000);

        assert_eq!(chain.connect_timeout, Duration::from_secs(45));
        assert_eq!(chain.command_timeout, Duration::from_secs(600));
        assert_eq!(chain.max_retries, 5);
        assert_eq!(chain.base_retry_delay, 2000);
    }
}

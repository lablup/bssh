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

mod auth;
mod chain_connection;
mod cleanup;
mod tunnel;
mod types;

// Re-export public types
pub use types::{JumpConnection, JumpInfo};

use super::connection::JumpHostConnection;
use super::parser::{get_max_jump_hosts, JumpHost};
use super::rate_limiter::ConnectionRateLimiter;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::{AuthMethod, SshConnectionConfig};
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Manages SSH jump host chains for establishing connections
///
/// This struct handles the complexity of connecting through one or more jump hosts
/// to reach a final destination. It supports:
/// * Connection caching and reuse
/// * Per-host authentication
/// * Automatic retry with exponential backoff
/// * Connection health monitoring
/// * Thread-safe credential prompting
/// * SSH keepalive configuration to prevent idle connection timeouts
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
    /// SSH connection configuration (keepalive settings)
    ssh_connection_config: SshConnectionConfig,
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
            ssh_connection_config: SshConnectionConfig::default(),
        }
    }

    /// Set SSH connection configuration (keepalive settings)
    ///
    /// Configures keepalive interval and maximum attempts to prevent
    /// idle connection timeouts during jump host operations.
    pub fn with_ssh_connection_config(mut self, config: SshConnectionConfig) -> Self {
        self.ssh_connection_config = config;
        self
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
    pub async fn cleanup_connections(&self) {
        cleanup::cleanup_connections(
            &self.connections,
            self.max_idle_time,
            self.max_connection_age,
        )
        .await
    }

    /// Get the number of active connections in the pool
    pub async fn active_connection_count(&self) -> usize {
        cleanup::get_active_connection_count(&self.connections).await
    }

    /// Connect to the destination through the jump host chain
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
            chain_connection::connect_direct(
                destination_host,
                destination_port,
                destination_user,
                dest_auth_method,
                dest_strict_mode,
                self.connect_timeout,
                &self.rate_limiter,
                &self.ssh_connection_config,
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

            current_client = tunnel::connect_through_tunnel(
                &current_client,
                jump_host,
                dest_key_path,
                dest_use_agent,
                dest_use_password,
                dest_strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew),
                self.connect_timeout,
                &self.rate_limiter,
                &self.auth_mutex,
                &self.ssh_connection_config,
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
        let final_client = tunnel::connect_to_destination(
            &current_client,
            destination_host,
            destination_port,
            destination_user,
            dest_auth_method,
            dest_strict_mode.unwrap_or(StrictHostKeyChecking::AcceptNew),
            self.connect_timeout,
            &self.rate_limiter,
            &self.ssh_connection_config,
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
    ) -> Result<crate::ssh::tokio_client::Client> {
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

        // Log the effective username being used, especially helpful when auto-detected
        let effective_user = jump_host.effective_user();
        if jump_host.user.is_none() {
            tracing::info!(
                "Connecting to jump host {}:{} as user '{}' (auto-detected from current user)",
                jump_host.host,
                jump_host.effective_port(),
                effective_user
            );
        } else {
            tracing::info!(
                "Connecting to jump host {}:{} as user '{}'",
                jump_host.host,
                jump_host.effective_port(),
                effective_user
            );
        }

        let auth_method = auth::determine_auth_method(
            jump_host,
            key_path,
            use_agent,
            use_password,
            &self.auth_mutex,
        )
        .await?;
        let check_method = crate::ssh::known_hosts::get_check_method(strict_mode);

        let client = tokio::time::timeout(
            self.connect_timeout,
            crate::ssh::tokio_client::Client::connect_with_ssh_config(
                (jump_host.host.as_str(), jump_host.effective_port()),
                &effective_user,
                auth_method,
                check_method,
                &self.ssh_connection_config,
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

    /// Clean up any cached connections
    pub async fn cleanup(&self) {
        cleanup::cleanup_all(&self.connections).await
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

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

//! Connection pooling for SSH/SFTP connections
//!
//! This module provides connection pooling capabilities for SSH sessions
//! using the direct russh implementation. Unlike the previous placeholder
//! implementation, this provides actual pooling functionality.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, trace, warn};

use super::auth::AuthMethod;
use super::error::{SftpError, SftpResult};
use super::host_verification::HostKeyVerification;
use super::session::SshSession;
use crate::ssh::known_hosts::StrictHostKeyChecking;

/// Connection key for pooling
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ConnectionKey {
    host: String,
    port: u16,
    username: String,
}

/// Pooled connection wrapper
#[derive(Debug)]
struct PooledConnection {
    session: SshSession,
    created_at: Instant,
    last_used: Instant,
}

impl PooledConnection {
    fn new(session: SshSession) -> Self {
        let now = Instant::now();
        Self {
            session,
            created_at: now,
            last_used: now,
        }
    }

    fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.last_used.elapsed() > ttl
    }
}

/// Connection pool for SSH/SFTP connections
pub struct SftpConnectionPool {
    connections: Arc<RwLock<HashMap<ConnectionKey, Vec<PooledConnection>>>>,
    ttl: Duration,
    max_connections_per_host: usize,
    max_total_connections: usize,
    enabled: bool,
}

impl SftpConnectionPool {
    /// Create a new connection pool
    pub fn new(
        ttl: Duration,
        max_connections_per_host: usize,
        max_total_connections: usize,
        enabled: bool,
    ) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            max_connections_per_host,
            max_total_connections,
            enabled,
        }
    }

    /// Create a disabled connection pool
    pub fn disabled() -> Self {
        Self::new(Duration::from_secs(0), 0, 0, false)
    }

    /// Create a connection pool with default settings
    pub fn with_defaults() -> Self {
        Self::new(
            Duration::from_secs(300), // 5 minutes TTL
            5,                        // max 5 connections per host
            50,                       // max 50 total connections
            true,                     // enabled by default for russh
        )
    }

    /// Get or create a connection
    pub async fn get_or_create(
        &self,
        host: &str,
        port: u16,
        username: &str,
        auth_method: &AuthMethod,
        strict_mode: StrictHostKeyChecking,
    ) -> SftpResult<SshSession> {
        let key = ConnectionKey {
            host: host.to_string(),
            port,
            username: username.to_string(),
        };

        if !self.enabled {
            trace!("Connection pooling disabled, creating new connection");
            return self.create_new_connection(host, port, username, auth_method, strict_mode).await;
        }

        // Try to get an existing connection
        if let Some(session) = self.try_get_connection(&key).await {
            debug!("Reusing pooled connection to {}@{}:{}", username, host, port);
            return Ok(session);
        }

        // Create new connection if pool miss
        debug!("Creating new connection to {}@{}:{}", username, host, port);
        let session = self.create_new_connection(host, port, username, auth_method, strict_mode).await?;

        Ok(session)
    }

    /// Return a connection to the pool
    pub async fn return_connection(
        &self,
        host: &str,
        port: u16,
        username: &str,
        session: SshSession,
    ) {
        if !self.enabled {
            trace!("Connection pooling disabled, dropping connection");
            return;
        }

        let key = ConnectionKey {
            host: host.to_string(),
            port,
            username: username.to_string(),
        };

        let mut connections = self.connections.write().await;
        
        // Check total connection count first
        let total_connections: usize = connections.values().map(|v| v.len()).sum();
        if total_connections >= self.max_total_connections {
            debug!("Total connection limit reached, dropping connection to {}@{}:{}", username, host, port);
            return;
        }

        let host_connections = connections.entry(key.clone()).or_insert_with(Vec::new);

        // Check if we're at the per-host limit
        if host_connections.len() >= self.max_connections_per_host {
            debug!("Per-host connection limit reached for {}@{}:{}, dropping connection", username, host, port);
            return;
        }

        host_connections.push(PooledConnection::new(session));
        debug!("Returned connection to pool for {}@{}:{}", username, host, port);
    }

    /// Try to get a connection from the pool
    async fn try_get_connection(&self, key: &ConnectionKey) -> Option<SshSession> {
        let mut connections = self.connections.write().await;
        
        if let Some(host_connections) = connections.get_mut(key) {
            // Remove expired connections
            host_connections.retain(|conn| !conn.is_expired(self.ttl));
            
            // Get a connection if available
            if let Some(mut pooled_conn) = host_connections.pop() {
                pooled_conn.touch();
                trace!("Retrieved connection from pool for {}@{}:{}", key.username, key.host, key.port);
                return Some(pooled_conn.session);
            }
        }

        None
    }

    /// Create a new SSH connection
    async fn create_new_connection(
        &self,
        host: &str,
        port: u16,
        username: &str,
        auth_method: &AuthMethod,
        strict_mode: StrictHostKeyChecking,
    ) -> SftpResult<SshSession> {
        let host_key_verification = HostKeyVerification::new(strict_mode);
        
        let mut session = SshSession::new(
            host.to_string(),
            port,
            username.to_string(),
            host_key_verification,
        ).await?;

        // Authenticate
        let auth_result = super::auth::authenticate_with_server(
            session.handle_mut(),
            username,
            auth_method,
        ).await?;

        if !auth_result {
            return Err(SftpError::authentication(format!(
                "Authentication failed for {}@{}:{}",
                username, host, port
            )));
        }

        debug!("Created and authenticated new connection to {}@{}:{}", username, host, port);
        Ok(session)
    }

    /// Clean up expired connections
    pub async fn cleanup_expired(&self) {
        if !self.enabled {
            return;
        }

        let mut connections = self.connections.write().await;
        let mut total_removed = 0;

        for (key, host_connections) in connections.iter_mut() {
            let before_count = host_connections.len();
            host_connections.retain(|conn| !conn.is_expired(self.ttl));
            let removed_count = before_count - host_connections.len();
            total_removed += removed_count;
            
            if removed_count > 0 {
                debug!("Removed {} expired connections for {}@{}:{}", removed_count, key.username, key.host, key.port);
            }
        }

        // Remove empty host entries
        connections.retain(|_, host_connections| !host_connections.is_empty());

        if total_removed > 0 {
            debug!("Cleanup completed: removed {} expired connections", total_removed);
        }
    }

    /// Clear all connections from the pool
    pub async fn clear(&self) {
        if !self.enabled {
            return;
        }

        let mut connections = self.connections.write().await;
        let total_connections: usize = connections.values().map(|v| v.len()).sum();
        connections.clear();
        
        if total_connections > 0 {
            debug!("Cleared {} connections from pool", total_connections);
        }
    }

    /// Get the number of pooled connections
    pub async fn size(&self) -> usize {
        if !self.enabled {
            return 0;
        }

        let connections = self.connections.read().await;
        connections.values().map(|v| v.len()).sum()
    }

    /// Get detailed pool statistics
    pub async fn stats(&self) -> PoolStats {
        if !self.enabled {
            return PoolStats::default();
        }

        let connections = self.connections.read().await;
        let total_connections = connections.values().map(|v| v.len()).sum();
        let host_count = connections.len();
        
        let mut connections_per_host = HashMap::new();
        for (key, host_connections) in connections.iter() {
            let host_key = format!("{}@{}:{}", key.username, key.host, key.port);
            connections_per_host.insert(host_key, host_connections.len());
        }

        PoolStats {
            total_connections,
            host_count,
            connections_per_host,
            max_connections_per_host: self.max_connections_per_host,
            max_total_connections: self.max_total_connections,
            ttl_seconds: self.ttl.as_secs(),
            enabled: self.enabled,
        }
    }

    /// Check if the pool is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable the connection pool
    pub fn enable(&mut self) {
        self.enabled = true;
        debug!("Connection pooling enabled");
    }

    /// Disable the connection pool
    pub fn disable(&mut self) {
        self.enabled = false;
        debug!("Connection pooling disabled");
    }

    /// Start a background task to periodically clean up expired connections
    pub fn start_cleanup_task(&self, cleanup_interval: Duration) -> tokio::task::JoinHandle<()> {
        let pool = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                pool.cleanup_expired().await;
            }
        })
    }
}

impl Clone for SftpConnectionPool {
    fn clone(&self) -> Self {
        Self {
            connections: Arc::clone(&self.connections),
            ttl: self.ttl,
            max_connections_per_host: self.max_connections_per_host,
            max_total_connections: self.max_total_connections,
            enabled: self.enabled,
        }
    }
}

impl Default for SftpConnectionPool {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub host_count: usize,
    pub connections_per_host: HashMap<String, usize>,
    pub max_connections_per_host: usize,
    pub max_total_connections: usize,
    pub ttl_seconds: u64,
    pub enabled: bool,
}

impl Default for PoolStats {
    fn default() -> Self {
        Self {
            total_connections: 0,
            host_count: 0,
            connections_per_host: HashMap::new(),
            max_connections_per_host: 0,
            max_total_connections: 0,
            ttl_seconds: 0,
            enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_disabled() {
        let pool = SftpConnectionPool::disabled();
        assert!(!pool.is_enabled());
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_enabled_by_default() {
        let pool = SftpConnectionPool::with_defaults();
        assert!(pool.is_enabled());
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_cleanup() {
        let pool = SftpConnectionPool::new(Duration::from_millis(100), 10, 50, true);

        // Pool starts empty
        assert_eq!(pool.size().await, 0);

        // Cleanup should work even on empty pool
        pool.cleanup_expired().await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_clear() {
        let pool = SftpConnectionPool::new(Duration::from_secs(60), 10, 50, true);

        pool.clear().await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let pool = SftpConnectionPool::with_defaults();
        let stats = pool.stats().await;
        
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.host_count, 0);
        assert!(stats.enabled);
        assert_eq!(stats.max_connections_per_host, 5);
        assert_eq!(stats.max_total_connections, 50);
    }
}
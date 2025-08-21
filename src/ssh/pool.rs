//! Connection pooling module for SSH connections.
//!
//! NOTE: This is a placeholder implementation. The async-ssh2-tokio Client
//! doesn't support connection reuse or cloning, so actual pooling is not
//! currently possible. This module provides the infrastructure for future
//! connection pooling when the underlying library supports it.
//!
//! The current implementation always creates new connections but provides
//! the API surface for connection pooling to minimize future refactoring.

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

use anyhow::Result;
use async_ssh2_tokio::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, trace};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ConnectionKey {
    host: String,
    port: u16,
    user: String,
}

/// Connection pool for SSH connections.
///
/// Currently a placeholder implementation due to async-ssh2-tokio limitations.
/// Always creates new connections regardless of the `enabled` flag.
pub struct ConnectionPool {
    /// Placeholder for future connection storage
    _connections: Arc<RwLock<Vec<ConnectionKey>>>,
    #[allow(dead_code)]
    ttl: Duration,
    #[allow(dead_code)]
    enabled: bool,
    #[allow(dead_code)]
    max_connections: usize,
}

impl ConnectionPool {
    /// Create a new connection pool.
    ///
    /// Note: Pooling is not actually implemented due to library limitations.
    pub fn new(ttl: Duration, max_connections: usize, enabled: bool) -> Self {
        Self {
            _connections: Arc::new(RwLock::new(Vec::new())),
            ttl,
            enabled,
            max_connections,
        }
    }

    pub fn disabled() -> Self {
        Self::new(Duration::from_secs(0), 0, false)
    }

    pub fn with_defaults() -> Self {
        Self::new(
            Duration::from_secs(300), // 5 minutes TTL
            50,                       // max 50 connections
            false,                    // disabled by default
        )
    }

    /// Get or create a connection.
    ///
    /// Currently always creates a new connection due to async-ssh2-tokio limitations.
    /// The Client type doesn't support cloning or connection reuse.
    pub async fn get_or_create<F>(
        &self,
        host: &str,
        port: u16,
        user: &str,
        create_fn: F,
    ) -> Result<Client>
    where
        F: FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Client>> + Send>>,
    {
        let _key = ConnectionKey {
            host: host.to_string(),
            port,
            user: user.to_string(),
        };

        if self.enabled {
            trace!("Connection pooling enabled (placeholder mode)");
            // In the future, we would check for existing connections here
            // For now, we always create new connections
        } else {
            trace!("Connection pooling disabled");
        }

        // Always create new connection (pooling not possible with current library)
        debug!("Creating new SSH connection to {}@{}:{}", user, host, port);
        create_fn().await
    }

    /// Return a connection to the pool.
    ///
    /// Currently a no-op due to connection reuse limitations.
    pub async fn return_connection(&self, _host: &str, _port: u16, _user: &str, _client: Client) {
        // No-op: Client cannot be reused
        if self.enabled {
            trace!("Connection return requested (no-op in placeholder mode)");
        }
    }

    /// Clean up expired connections.
    ///
    /// Currently a no-op.
    pub async fn cleanup_expired(&self) {
        if self.enabled {
            trace!("Cleanup requested (no-op in placeholder mode)");
        }
    }

    /// Clear all connections from the pool.
    ///
    /// Currently a no-op.
    pub async fn clear(&self) {
        if self.enabled {
            trace!("Clear requested (no-op in placeholder mode)");
        }
    }

    /// Get the number of pooled connections.
    ///
    /// Always returns 0 in the current implementation.
    pub async fn size(&self) -> usize {
        0 // No actual pooling
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn enable(&mut self) {
        self.enabled = true;
        debug!("Connection pooling enabled");
    }

    pub fn disable(&mut self) {
        self.enabled = false;
        debug!("Connection pooling disabled");
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_disabled_by_default() {
        let pool = ConnectionPool::with_defaults();
        assert!(!pool.is_enabled());
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_cleanup() {
        let pool = ConnectionPool::new(Duration::from_millis(100), 10, true);

        // Pool starts empty
        assert_eq!(pool.size().await, 0);

        // Cleanup should work even on empty pool
        pool.cleanup_expired().await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_clear() {
        let pool = ConnectionPool::new(Duration::from_secs(60), 10, true);

        pool.clear().await;
        assert_eq!(pool.size().await, 0);
    }
}

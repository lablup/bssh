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

use crate::jump::connection::JumpHostConnection;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Clean up stale connections from the pool
///
/// Removes connections that are:
/// - No longer alive
/// - Idle for too long
/// - Too old
pub(super) async fn cleanup_connections(
    connections: &RwLock<Vec<Arc<JumpHostConnection>>>,
    max_idle_time: Duration,
    max_connection_age: Duration,
) {
    let mut connections = connections.write().await;
    let mut to_remove = Vec::new();

    for (i, conn) in connections.iter().enumerate() {
        // Check if connection should be removed
        let should_remove = !conn.is_alive().await
            || conn.idle_time().await > max_idle_time
            || conn.age() > max_connection_age;

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
pub(super) async fn get_active_connection_count(
    connections: &RwLock<Vec<Arc<JumpHostConnection>>>,
) -> usize {
    let connections = connections.read().await;
    connections.len()
}

/// Clean up all cached connections
pub(super) async fn cleanup_all(connections: &RwLock<Vec<Arc<JumpHostConnection>>>) {
    let mut connections = connections.write().await;
    connections.clear();
    debug!("Cleaned up jump host connection cache");
}

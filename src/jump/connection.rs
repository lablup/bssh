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

use super::parser::JumpHost;
use crate::ssh::tokio_client::Client;
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Represents an active connection through jump hosts
///
/// This struct manages the lifecycle of a single SSH connection that may
/// go through one or more jump hosts. It provides connection health monitoring,
/// automatic retry, and resource cleanup.
#[derive(Debug)]
pub struct JumpHostConnection {
    /// The SSH client connected to the final destination
    pub client: Client,
    /// The jump host path used for this connection
    pub jump_path: Vec<JumpHost>,
    /// Final destination host and port
    pub destination: (String, u16),
    /// Connection establishment timestamp
    created_at: Instant,
    /// Last successful operation timestamp
    last_used: Arc<Mutex<Instant>>,
    /// Connection health status
    health_status: Arc<Mutex<ConnectionHealth>>,
}

/// Health status of a jump host connection
#[derive(Debug, Clone)]
pub enum ConnectionHealth {
    /// Connection is healthy and ready for use
    Healthy,
    /// Connection is experiencing issues but may recover
    Degraded {
        error_count: u32,
        last_error: String,
    },
    /// Connection is failed and should be replaced
    Failed { reason: String },
}

impl JumpHostConnection {
    /// Create a new jump host connection
    pub fn new(client: Client, jump_path: Vec<JumpHost>, destination: (String, u16)) -> Self {
        let now = Instant::now();
        Self {
            client,
            jump_path,
            destination,
            created_at: now,
            last_used: Arc::new(Mutex::new(now)),
            health_status: Arc::new(Mutex::new(ConnectionHealth::Healthy)),
        }
    }

    /// Get the age of this connection
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Update the last used timestamp
    pub async fn mark_used(&self) {
        let mut last_used = self.last_used.lock().await;
        *last_used = Instant::now();
    }

    /// Get the time since last use
    pub async fn idle_time(&self) -> Duration {
        let last_used = self.last_used.lock().await;
        last_used.elapsed()
    }

    /// Check if the connection is still alive
    pub async fn is_alive(&self) -> bool {
        !self.client.is_closed()
    }

    /// Perform a health check on the connection
    pub async fn health_check(&self) -> Result<()> {
        if self.client.is_closed() {
            let mut health = self.health_status.lock().await;
            *health = ConnectionHealth::Failed {
                reason: "SSH connection closed".to_string(),
            };
            anyhow::bail!("Connection is closed");
        }

        // Try a simple command to verify the connection
        match self.client.execute("echo bssh-health-check").await {
            Ok(result) => {
                if result.exit_status == 0 {
                    let mut health = self.health_status.lock().await;
                    *health = ConnectionHealth::Healthy;
                    self.mark_used().await;
                    debug!(
                        "Health check passed for connection to {:?}",
                        self.destination
                    );
                    Ok(())
                } else {
                    self.mark_degraded("Health check command failed").await;
                    anyhow::bail!(
                        "Health check command returned exit status {}",
                        result.exit_status
                    );
                }
            }
            Err(e) => {
                self.mark_degraded(&format!("Health check failed: {e}"))
                    .await;
                Err(e).context("Health check failed")
            }
        }
    }

    /// Mark the connection as degraded
    async fn mark_degraded(&self, error_message: &str) {
        let mut health = self.health_status.lock().await;
        match &*health {
            ConnectionHealth::Healthy => {
                *health = ConnectionHealth::Degraded {
                    error_count: 1,
                    last_error: error_message.to_string(),
                };
                warn!(
                    "Connection to {:?} marked as degraded: {}",
                    self.destination, error_message
                );
            }
            ConnectionHealth::Degraded { error_count, .. } => {
                let new_count = error_count + 1;
                if new_count >= 3 {
                    *health = ConnectionHealth::Failed {
                        reason: format!("Too many errors: {error_message}"),
                    };
                    warn!(
                        "Connection to {:?} marked as failed after {} errors",
                        self.destination, new_count
                    );
                } else {
                    *health = ConnectionHealth::Degraded {
                        error_count: new_count,
                        last_error: error_message.to_string(),
                    };
                    warn!(
                        "Connection to {:?} error count increased to {}: {}",
                        self.destination, new_count, error_message
                    );
                }
            }
            ConnectionHealth::Failed { .. } => {
                // Already failed, no change needed
            }
        }
    }

    /// Check if the connection is healthy enough to use
    pub async fn is_healthy(&self) -> bool {
        let health = self.health_status.lock().await;
        match &*health {
            ConnectionHealth::Healthy => true,
            ConnectionHealth::Degraded { error_count, .. } => *error_count < 3,
            ConnectionHealth::Failed { .. } => false,
        }
    }

    /// Get a description of the connection path
    pub fn path_description(&self) -> String {
        if self.jump_path.is_empty() {
            format!("Direct -> {}:{}", self.destination.0, self.destination.1)
        } else {
            let jump_chain: Vec<String> = self
                .jump_path
                .iter()
                .map(|j| j.to_connection_string())
                .collect();
            format!(
                "{} -> {}:{}",
                jump_chain.join(" -> "),
                self.destination.0,
                self.destination.1
            )
        }
    }

    /// Get connection statistics
    pub async fn stats(&self) -> ConnectionStats {
        let health = self.health_status.lock().await;
        let last_used = self.last_used.lock().await;

        ConnectionStats {
            destination: self.destination.clone(),
            jump_count: self.jump_path.len(),
            age: self.age(),
            idle_time: last_used.elapsed(),
            is_alive: !self.client.is_closed(),
            health_status: health.clone(),
        }
    }

    /// Gracefully close the connection
    pub async fn close(&self) -> Result<()> {
        debug!("Closing jump host connection to {:?}", self.destination);

        self.client
            .disconnect()
            .await
            .context("Failed to disconnect SSH client")?;

        let mut health = self.health_status.lock().await;
        *health = ConnectionHealth::Failed {
            reason: "Connection closed".to_string(),
        };

        debug!("Jump host connection closed successfully");
        Ok(())
    }
}

/// Statistics about a jump host connection
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub destination: (String, u16),
    pub jump_count: usize,
    pub age: Duration,
    pub idle_time: Duration,
    pub is_alive: bool,
    pub health_status: ConnectionHealth,
}

impl std::fmt::Display for ConnectionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} (jumps: {}, age: {:?}, idle: {:?}, alive: {}, health: {:?})",
            self.destination.0,
            self.destination.1,
            self.jump_count,
            self.age,
            self.idle_time,
            self.is_alive,
            self.health_status
        )
    }
}

impl Drop for JumpHostConnection {
    fn drop(&mut self) {
        debug!("JumpHostConnection to {:?} dropped", self.destination);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jump::parser::JumpHost;

    // Note: These tests would require actual SSH connections to run
    // They are mainly here to verify the API structure

    #[tokio::test]
    async fn test_connection_stats() {
        // This test would require a mock client
        // For now, just test the basic structure
        let jump_path = [JumpHost::new(
            "jump1.example.com".to_string(),
            Some("user".to_string()),
            Some(22),
        )];

        // We can't create an actual connection without a real client
        // So we'll just test the jump_path structure
        assert_eq!(jump_path.len(), 1);
        assert_eq!(jump_path[0].host, "jump1.example.com");
    }

    #[test]
    fn test_connection_health() {
        let healthy = ConnectionHealth::Healthy;
        match healthy {
            ConnectionHealth::Healthy => {} // Expected healthy status
            _ => panic!("Expected healthy status"),
        }

        let degraded = ConnectionHealth::Degraded {
            error_count: 2,
            last_error: "Test error".to_string(),
        };
        match degraded {
            ConnectionHealth::Degraded { error_count, .. } => assert_eq!(error_count, 2),
            _ => panic!("Expected degraded status"),
        }
    }
}

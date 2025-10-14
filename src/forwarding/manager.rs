//! ForwardingManager - Central coordination for port forwarding sessions
//!
//! The ForwardingManager is the core component responsible for managing the lifecycle
//! of all port forwarding sessions. It provides a unified interface for starting,
//! monitoring, and stopping multiple port forwards simultaneously.
//!
//! # Features
//!
//! - **Lifecycle Management**: Start, stop, and monitor forwarding sessions
//! - **Concurrent Sessions**: Handle multiple forwards simultaneously
//! - **Status Monitoring**: Real-time status and statistics reporting
//! - **Error Recovery**: Automatic reconnection with exponential backoff
//! - **Resource Cleanup**: Proper cleanup on shutdown or failure
//! - **Thread Safety**: Safe concurrent access from multiple contexts
//!
//! # Example Usage
//!
//! ```no_run
//! use bssh::forwarding::{ForwardingManager, ForwardingType, ForwardingConfig};
//! use bssh::ssh::tokio_client::Client;
//! use std::sync::Arc;
//! use std::net::IpAddr;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let mut manager = ForwardingManager::new(ForwardingConfig::default());
//!
//! // Add local port forwarding
//! let forward_id = manager.add_forwarding(ForwardingType::Local {
//!     bind_addr: "127.0.0.1".parse::<IpAddr>().unwrap(),
//!     bind_port: 8080,
//!     remote_host: "example.com".to_string(),
//!     remote_port: 80,
//! }).await?;
//!
//! // Create SSH client (example - requires actual connection)
//! # let ssh_client = Arc::new(Client::connect(
//! #     ("example.com", 22),
//! #     "user",
//! #     bssh::ssh::tokio_client::AuthMethod::with_agent(),
//! #     bssh::ssh::tokio_client::ServerCheckMethod::NoCheck,
//! # ).await?);
//!
//! // Start all forwarding sessions
//! manager.start_all(ssh_client).await?;
//!
//! // Monitor status
//! let status = manager.get_status(forward_id).await?;
//! println!("Forward status: {}", status);
//! # Ok(())
//! # }
//! ```

use super::{ForwardingConfig, ForwardingStats, ForwardingStatus, ForwardingType};
use crate::ssh::tokio_client::Client;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Unique identifier for a forwarding session
pub type ForwardingId = Uuid;

/// Messages for internal communication between manager and forwarding tasks
#[derive(Debug)]
pub enum ForwardingMessage {
    /// Status update from a forwarding session
    StatusUpdate {
        id: ForwardingId,
        status: ForwardingStatus,
    },
    /// Statistics update from a forwarding session
    StatsUpdate {
        id: ForwardingId,
        stats: ForwardingStats,
    },
    /// Forwarding session has terminated
    SessionTerminated {
        id: ForwardingId,
        reason: Option<String>,
    },
}

/// Internal state for a forwarding session
#[derive(Debug)]
#[allow(dead_code)] // Future monitoring fields
struct ForwardingSession {
    /// Unique identifier
    id: ForwardingId,
    /// Forwarding specification
    spec: ForwardingType,
    /// Current status
    status: ForwardingStatus,
    /// Session statistics
    stats: ForwardingStats,
    /// Task handle for the forwarding loop
    task_handle: Option<JoinHandle<Result<()>>>,
    /// Cancellation token for clean shutdown
    cancel_token: CancellationToken,
    /// Creation time
    created_at: Instant,
    /// Last update time
    updated_at: Instant,
}

/// Central manager for all port forwarding sessions
///
/// The ForwardingManager coordinates multiple port forwarding sessions,
/// providing lifecycle management, monitoring, and error recovery.
pub struct ForwardingManager {
    /// Configuration for forwarding behavior
    config: ForwardingConfig,
    /// Active forwarding sessions
    sessions: Arc<RwLock<HashMap<ForwardingId, Arc<Mutex<ForwardingSession>>>>>,
    /// Message channel for communication with forwarding tasks
    message_tx: mpsc::UnboundedSender<ForwardingMessage>,
    message_rx: Arc<Mutex<mpsc::UnboundedReceiver<ForwardingMessage>>>,
    /// Global cancellation token for shutdown
    shutdown_token: CancellationToken,
    /// Manager task handle
    manager_task: Option<JoinHandle<()>>,
}

impl ForwardingManager {
    /// Create a new ForwardingManager with the specified configuration
    pub fn new(config: ForwardingConfig) -> Self {
        let (message_tx, message_rx) = mpsc::unbounded_channel();

        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
            message_rx: Arc::new(Mutex::new(message_rx)),
            shutdown_token: CancellationToken::new(),
            manager_task: None,
        }
    }

    /// Start the manager's internal message processing loop
    pub async fn start(&mut self) -> Result<()> {
        if self.manager_task.is_some() {
            return Err(anyhow::anyhow!("ForwardingManager is already started"));
        }

        let sessions = Arc::clone(&self.sessions);
        let message_rx = Arc::clone(&self.message_rx);
        let shutdown_token = self.shutdown_token.clone();

        let task = tokio::spawn(async move {
            Self::message_loop(sessions, message_rx, shutdown_token).await;
        });

        self.manager_task = Some(task);
        tracing::info!("ForwardingManager started");
        Ok(())
    }

    /// Internal message processing loop
    async fn message_loop(
        sessions: Arc<RwLock<HashMap<ForwardingId, Arc<Mutex<ForwardingSession>>>>>,
        message_rx: Arc<Mutex<mpsc::UnboundedReceiver<ForwardingMessage>>>,
        shutdown_token: CancellationToken,
    ) {
        let mut rx = message_rx.lock().await;

        loop {
            tokio::select! {
                // Handle incoming messages
                msg = rx.recv() => {
                    match msg {
                        Some(message) => {
                            if let Err(e) = Self::handle_message(&sessions, message).await {
                                tracing::error!("Error handling forwarding message: {}", e);
                            }
                        }
                        None => {
                            tracing::info!("Message channel closed, stopping manager");
                            break;
                        }
                    }
                }
                // Handle shutdown signal
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Shutdown requested, stopping manager");
                    break;
                }
            }
        }

        tracing::info!("ForwardingManager message loop stopped");
    }

    /// Handle a single forwarding message
    #[allow(clippy::type_complexity)] // Acceptable for internal state management
    async fn handle_message(
        sessions: &Arc<RwLock<HashMap<ForwardingId, Arc<Mutex<ForwardingSession>>>>>,
        message: ForwardingMessage,
    ) -> Result<()> {
        match message {
            ForwardingMessage::StatusUpdate { id, status } => {
                let sessions_read = sessions.read().await;
                if let Some(session_arc) = sessions_read.get(&id) {
                    let mut session = session_arc.lock().await;
                    session.status = status;
                    session.updated_at = Instant::now();
                    tracing::debug!("Updated status for forwarding {}: {}", id, session.status);
                }
            }
            ForwardingMessage::StatsUpdate { id, stats } => {
                let sessions_read = sessions.read().await;
                if let Some(session_arc) = sessions_read.get(&id) {
                    let mut session = session_arc.lock().await;
                    session.stats = stats;
                    session.updated_at = Instant::now();
                }
            }
            ForwardingMessage::SessionTerminated { id, reason } => {
                let sessions_write = sessions.write().await;
                if let Some(session_arc) = sessions_write.get(&id) {
                    let mut session = session_arc.lock().await;
                    session.status = if let Some(err) = reason {
                        ForwardingStatus::Failed(err)
                    } else {
                        ForwardingStatus::Stopped
                    };
                    session.updated_at = Instant::now();
                    session.task_handle = None; // Task has finished
                    tracing::info!("Forwarding session {} terminated: {}", id, session.status);
                }
            }
        }
        Ok(())
    }

    /// Add a new forwarding session
    ///
    /// Returns the unique identifier for the forwarding session.
    /// The session is created but not started until `start_forwarding` is called.
    pub async fn add_forwarding(&mut self, spec: ForwardingType) -> Result<ForwardingId> {
        // Validate the forwarding specification
        super::spec::ForwardingSpec::validate(&spec)
            .with_context(|| "Invalid forwarding specification")?;

        let id = Uuid::new_v4();
        let now = Instant::now();

        let session = ForwardingSession {
            id,
            spec,
            status: ForwardingStatus::Initializing,
            stats: ForwardingStats::default(),
            task_handle: None,
            cancel_token: CancellationToken::new(),
            created_at: now,
            updated_at: now,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(id, Arc::new(Mutex::new(session)));

        tracing::info!("Added forwarding session {}", id);
        Ok(id)
    }

    /// Start a specific forwarding session
    pub async fn start_forwarding(&self, id: ForwardingId, ssh_client: Arc<Client>) -> Result<()> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("Forwarding session {id} not found"))?;

        let mut session = session_arc.lock().await;

        if session.task_handle.is_some() {
            return Err(anyhow::anyhow!(
                "Forwarding session {id} is already started"
            ));
        }

        // Clone data needed for the forwarding task
        let session_id = session.id;
        let spec = session.spec.clone();
        let config = self.config.clone();
        let cancel_token = session.cancel_token.clone();
        let message_tx = self.message_tx.clone();

        // Start the appropriate forwarding task based on type
        let task = match &spec {
            ForwardingType::Local { .. } => tokio::spawn(async move {
                super::local::LocalForwarder::run(
                    session_id,
                    spec.clone(),
                    ssh_client,
                    config,
                    cancel_token,
                    message_tx,
                )
                .await
            }),
            ForwardingType::Remote { .. } => tokio::spawn(async move {
                super::remote::RemoteForwarder::run(
                    session_id,
                    spec.clone(),
                    ssh_client,
                    config,
                    cancel_token,
                    message_tx,
                )
                .await
            }),
            ForwardingType::Dynamic { .. } => tokio::spawn(async move {
                super::dynamic::DynamicForwarder::run(
                    session_id,
                    spec.clone(),
                    ssh_client,
                    config,
                    cancel_token,
                    message_tx,
                )
                .await
            }),
        };

        session.task_handle = Some(task);
        session.status = ForwardingStatus::Initializing;
        session.updated_at = Instant::now();

        tracing::info!("Started forwarding session {}", id);
        Ok(())
    }

    /// Start all configured forwarding sessions
    pub async fn start_all(&self, ssh_client: Arc<Client>) -> Result<()> {
        let sessions = self.sessions.read().await;
        let ids: Vec<ForwardingId> = sessions.keys().copied().collect();
        drop(sessions);

        for id in ids {
            if let Err(e) = self.start_forwarding(id, Arc::clone(&ssh_client)).await {
                tracing::error!("Failed to start forwarding session {}: {}", id, e);
            }
        }

        Ok(())
    }

    /// Stop a specific forwarding session
    pub async fn stop_forwarding(&self, id: ForwardingId) -> Result<()> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("Forwarding session {id} not found"))?;

        let mut session = session_arc.lock().await;

        // Cancel the forwarding task
        session.cancel_token.cancel();

        // Wait for task to complete if it exists
        if let Some(task) = session.task_handle.take() {
            let _ = task.await; // Ignore join errors
        }

        session.status = ForwardingStatus::Stopped;
        session.updated_at = Instant::now();

        tracing::info!("Stopped forwarding session {}", id);
        Ok(())
    }

    /// Stop all forwarding sessions
    pub async fn stop_all(&self) -> Result<()> {
        let sessions = self.sessions.read().await;
        let ids: Vec<ForwardingId> = sessions.keys().copied().collect();
        drop(sessions);

        for id in ids {
            if let Err(e) = self.stop_forwarding(id).await {
                tracing::error!("Failed to stop forwarding session {}: {}", id, e);
            }
        }

        Ok(())
    }

    /// Get the current status of a forwarding session
    pub async fn get_status(&self, id: ForwardingId) -> Result<ForwardingStatus> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("Forwarding session {id} not found"))?;

        let session = session_arc.lock().await;
        Ok(session.status.clone())
    }

    /// Get statistics for a forwarding session
    pub async fn get_stats(&self, id: ForwardingId) -> Result<ForwardingStats> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("Forwarding session {id} not found"))?;

        let session = session_arc.lock().await;
        Ok(session.stats.clone())
    }

    /// List all forwarding sessions with their current status
    pub async fn list_sessions(&self) -> HashMap<ForwardingId, (ForwardingType, ForwardingStatus)> {
        let sessions = self.sessions.read().await;
        let mut result = HashMap::new();

        for (id, session_arc) in sessions.iter() {
            if let Ok(session) = session_arc.try_lock() {
                result.insert(*id, (session.spec.clone(), session.status.clone()));
            }
        }

        result
    }

    /// Remove a forwarding session (must be stopped first)
    pub async fn remove_forwarding(&mut self, id: ForwardingId) -> Result<()> {
        // Ensure session is stopped first
        let _ = self.stop_forwarding(id).await;

        let mut sessions = self.sessions.write().await;
        sessions
            .remove(&id)
            .ok_or_else(|| anyhow::anyhow!("Forwarding session {id} not found"))?;

        tracing::info!("Removed forwarding session {}", id);
        Ok(())
    }

    /// Shutdown the ForwardingManager and all active sessions
    pub async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("Shutting down ForwardingManager");

        // Stop all forwarding sessions
        self.stop_all().await?;

        // Signal shutdown to manager task
        self.shutdown_token.cancel();

        // Wait for manager task to complete
        if let Some(task) = self.manager_task.take() {
            let _ = task.await;
        }

        // Clear all sessions
        let mut sessions = self.sessions.write().await;
        sessions.clear();

        tracing::info!("ForwardingManager shutdown complete");
        Ok(())
    }
}

impl Drop for ForwardingManager {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        self.shutdown_token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_manager_lifecycle() {
        let mut manager = ForwardingManager::new(ForwardingConfig::default());

        // Start manager
        assert!(manager.start().await.is_ok());

        // Add a forwarding session
        let spec = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 8080,
            remote_host: "example.com".to_string(),
            remote_port: 80,
        };

        let id = manager.add_forwarding(spec.clone()).await.unwrap();

        // Check initial status
        let status = manager.get_status(id).await.unwrap();
        assert_eq!(status, ForwardingStatus::Initializing);

        // List sessions
        let sessions = manager.list_sessions().await;
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&id));

        // Remove session
        manager.remove_forwarding(id).await.unwrap();

        let sessions = manager.list_sessions().await;
        assert_eq!(sessions.len(), 0);

        // Shutdown
        assert!(manager.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_forwarding_spec() {
        let mut manager = ForwardingManager::new(ForwardingConfig::default());

        // Test invalid specification (port 0)
        let invalid_spec = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 0, // Invalid
            remote_host: "example.com".to_string(),
            remote_port: 80,
        };

        let result = manager.add_forwarding(invalid_spec).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_duplicate_start() {
        let mut manager = ForwardingManager::new(ForwardingConfig::default());

        // Starting twice should fail
        assert!(manager.start().await.is_ok());
        assert!(manager.start().await.is_err());

        let _ = manager.shutdown().await;
    }
}

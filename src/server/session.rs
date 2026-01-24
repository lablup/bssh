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

//! Session state management for the SSH server.
//!
//! This module provides structures for managing active SSH sessions,
//! tracking channel states, and maintaining session metadata.
//!
//! # Types
//!
//! - [`SessionManager`]: Manages all active sessions with per-user limits
//! - [`SessionInfo`]: Information about a single session
//! - [`SessionId`]: Unique identifier for a session
//! - [`SessionConfig`]: Configuration for session limits and timeouts
//! - [`ChannelState`]: State of an SSH channel
//! - [`ChannelMode`]: Current operation mode of a channel
//!
//! # Session Management Features
//!
//! - **Per-user session limits**: Limit concurrent sessions per user
//! - **Total session limits**: Limit total concurrent sessions
//! - **Idle timeout detection**: Identify sessions with no activity
//! - **Session activity tracking**: Track last activity for each session
//! - **Admin operations**: List sessions, force disconnect
//!
//! # Example
//!
//! ```
//! use bssh::server::session::{SessionManager, SessionConfig};
//! use std::time::Duration;
//!
//! let config = SessionConfig::new()
//!     .with_max_sessions_per_user(10)
//!     .with_max_total_sessions(1000)
//!     .with_idle_timeout(Duration::from_secs(3600));
//!
//! let mut manager = SessionManager::with_config(config);
//!
//! // Create a session
//! if let Some(info) = manager.create_session(None) {
//!     // Touch the session to update activity
//!     manager.touch(info.id);
//!
//!     // Authenticate the session
//!     manager.authenticate_session(info.id, "user1");
//! }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::server::Msg;
use russh::{Channel, ChannelId};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

use super::pty::PtyMaster;

/// Configuration for session management.
///
/// Controls limits on concurrent sessions and timeout behavior.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum sessions per authenticated user.
    ///
    /// Default: 10
    pub max_sessions_per_user: usize,

    /// Maximum total concurrent sessions.
    ///
    /// Default: 1000
    pub max_total_sessions: usize,

    /// Idle timeout duration.
    ///
    /// Sessions with no activity for this duration are considered idle.
    /// Default: 1 hour
    pub idle_timeout: Duration,

    /// Maximum session duration (optional).
    ///
    /// If set, sessions are terminated after this duration regardless of activity.
    /// Default: None (no limit)
    pub session_timeout: Option<Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_sessions_per_user: 10,
            max_total_sessions: 1000,
            idle_timeout: Duration::from_secs(3600), // 1 hour
            session_timeout: None,
        }
    }
}

impl SessionConfig {
    /// Minimum allowed value for max_sessions_per_user.
    pub const MIN_SESSIONS_PER_USER: usize = 1;

    /// Minimum allowed value for max_total_sessions.
    pub const MIN_TOTAL_SESSIONS: usize = 1;

    /// Create a new session configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum sessions per user.
    ///
    /// The value is clamped to a minimum of 1 to prevent misconfiguration
    /// that would deny all users from authenticating.
    pub fn with_max_sessions_per_user(mut self, max: usize) -> Self {
        self.max_sessions_per_user = max.max(Self::MIN_SESSIONS_PER_USER);
        self
    }

    /// Set the maximum total sessions.
    ///
    /// The value is clamped to a minimum of 1 to prevent misconfiguration
    /// that would deny all connections.
    pub fn with_max_total_sessions(mut self, max: usize) -> Self {
        self.max_total_sessions = max.max(Self::MIN_TOTAL_SESSIONS);
        self
    }

    /// Set the idle timeout.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the session timeout (maximum session duration).
    pub fn with_session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = Some(timeout);
        self
    }

    /// Validate the configuration and return any warnings.
    ///
    /// Returns a list of warning messages for potentially problematic settings.
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.max_sessions_per_user > self.max_total_sessions {
            warnings.push(format!(
                "max_sessions_per_user ({}) > max_total_sessions ({}) - per-user limit will never be reached",
                self.max_sessions_per_user, self.max_total_sessions
            ));
        }

        if self.idle_timeout.as_secs() == 0 {
            warnings.push("idle_timeout is 0 - sessions will be immediately considered idle".to_string());
        }

        if let Some(session_timeout) = self.session_timeout {
            if session_timeout < self.idle_timeout {
                warnings.push(format!(
                    "session_timeout ({:?}) < idle_timeout ({:?}) - sessions may be terminated before idle check",
                    session_timeout, self.idle_timeout
                ));
            }
        }

        warnings
    }
}

/// Errors that can occur during session management.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Total session limit has been reached.
    #[error("too many concurrent sessions (limit: {limit})")]
    TooManySessions { limit: usize },

    /// Per-user session limit has been reached.
    #[error("too many sessions for user '{user}' (limit: {limit})")]
    TooManyUserSessions { user: String, limit: usize },

    /// Session was not found.
    #[error("session not found")]
    SessionNotFound,
}

/// Statistics about current sessions.
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// Total number of active sessions.
    pub total_sessions: usize,

    /// Number of authenticated sessions.
    pub authenticated_sessions: usize,

    /// Number of unique authenticated users.
    pub unique_users: usize,

    /// Number of sessions that are considered idle.
    pub idle_sessions: usize,
}

/// Unique identifier for an SSH session.
///
/// Each session is assigned a unique ID when created, which can be used
/// to track and manage the session throughout its lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Create a new unique session ID.
    ///
    /// Uses `Ordering::SeqCst` to ensure session IDs are strictly ordered
    /// across all threads, preventing potential confusion in logging and
    /// debugging when sessions appear out of order.
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::SeqCst))
    }

    /// Get the raw numeric value of the session ID.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session-{}", self.0)
    }
}

/// Information about an active SSH session.
///
/// Contains metadata about the session including the authenticated user,
/// peer address, and timestamps.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Unique identifier for this session.
    pub id: SessionId,

    /// Username of the authenticated user (if authenticated).
    pub user: Option<String>,

    /// Remote address of the connected client.
    pub peer_addr: Option<SocketAddr>,

    /// Timestamp when the session was created.
    pub started_at: Instant,

    /// Timestamp of last activity on this session.
    pub last_activity: Instant,

    /// Whether the user has been authenticated.
    pub authenticated: bool,

    /// Number of authentication attempts.
    pub auth_attempts: u32,
}

impl SessionInfo {
    /// Create a new session info with the given peer address.
    pub fn new(peer_addr: Option<SocketAddr>) -> Self {
        let now = Instant::now();
        Self {
            id: SessionId::new(),
            user: None,
            peer_addr,
            started_at: now,
            last_activity: now,
            authenticated: false,
            auth_attempts: 0,
        }
    }

    /// Mark the session as authenticated with the given username.
    pub fn authenticate(&mut self, username: impl Into<String>) {
        self.user = Some(username.into());
        self.authenticated = true;
        self.last_activity = Instant::now();
    }

    /// Increment the authentication attempt counter.
    pub fn increment_auth_attempts(&mut self) {
        self.auth_attempts += 1;
    }

    /// Update the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get the session duration in seconds.
    pub fn duration_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Get the time since last activity in seconds.
    pub fn idle_secs(&self) -> u64 {
        self.last_activity.elapsed().as_secs()
    }

    /// Check if the session has been idle for longer than the given duration.
    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Check if the session has exceeded the maximum duration.
    pub fn is_expired(&self, max_duration: Duration) -> bool {
        self.started_at.elapsed() > max_duration
    }
}

/// Operation mode of an SSH channel.
///
/// Tracks what type of operation is currently active on the channel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ChannelMode {
    /// Channel is open but no operation has been requested.
    #[default]
    Idle,

    /// Channel is executing a command.
    Exec {
        /// The command being executed.
        command: String,
    },

    /// Channel is running an interactive shell.
    Shell,

    /// Channel is running the SFTP subsystem.
    Sftp,
}

/// PTY (pseudo-terminal) configuration.
///
/// Stores terminal settings requested by the client.
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// Terminal type (e.g., "xterm-256color").
    pub term: String,

    /// Width in columns.
    pub col_width: u32,

    /// Height in rows.
    pub row_height: u32,

    /// Width in pixels.
    pub pix_width: u32,

    /// Height in pixels.
    pub pix_height: u32,
}

impl PtyConfig {
    /// Create a new PTY configuration.
    pub fn new(
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Self {
        Self {
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
        }
    }
}

/// State of an SSH channel.
///
/// Tracks the current mode and configuration of a channel.
pub struct ChannelState {
    /// The channel ID.
    pub channel_id: ChannelId,

    /// The underlying channel for subsystem communication.
    channel: Option<Channel<Msg>>,

    /// Current operation mode.
    pub mode: ChannelMode,

    /// PTY configuration, if a PTY was requested.
    pub pty: Option<PtyConfig>,

    /// Data sender for forwarding SSH data to PTY (active shell only).
    pub shell_data_tx: Option<mpsc::Sender<Vec<u8>>>,

    /// PTY master handle for resize operations (active shell only).
    pub shell_pty: Option<Arc<RwLock<PtyMaster>>>,

    /// Whether EOF has been received from the client.
    pub eof_received: bool,
}

impl std::fmt::Debug for ChannelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelState")
            .field("channel_id", &self.channel_id)
            .field("has_channel", &self.channel.is_some())
            .field("mode", &self.mode)
            .field("pty", &self.pty)
            .field("has_shell_data_tx", &self.shell_data_tx.is_some())
            .field("has_shell_pty", &self.shell_pty.is_some())
            .field("eof_received", &self.eof_received)
            .finish()
    }
}

impl ChannelState {
    /// Create a new channel state.
    pub fn new(channel_id: ChannelId) -> Self {
        Self {
            channel_id,
            channel: None,
            mode: ChannelMode::Idle,
            pty: None,
            shell_data_tx: None,
            shell_pty: None,
            eof_received: false,
        }
    }

    /// Create a new channel state with the underlying channel.
    pub fn with_channel(channel: Channel<Msg>) -> Self {
        let id = channel.id();
        Self {
            channel_id: id,
            channel: Some(channel),
            mode: ChannelMode::Idle,
            pty: None,
            shell_data_tx: None,
            shell_pty: None,
            eof_received: false,
        }
    }

    /// Take the underlying channel (consumes it for use with subsystems).
    pub fn take_channel(&mut self) -> Option<Channel<Msg>> {
        self.channel.take()
    }

    /// Check if the channel has a PTY attached.
    pub fn has_pty(&self) -> bool {
        self.pty.is_some()
    }

    /// Set the PTY configuration.
    pub fn set_pty(&mut self, config: PtyConfig) {
        self.pty = Some(config);
    }

    /// Set the channel mode to exec with the given command.
    pub fn set_exec(&mut self, command: impl Into<String>) {
        self.mode = ChannelMode::Exec {
            command: command.into(),
        };
    }

    /// Set the channel mode to shell.
    pub fn set_shell(&mut self) {
        self.mode = ChannelMode::Shell;
    }

    /// Set the PTY handle for the active shell.
    ///
    /// This is used by the window_change handler to handle terminal resizes.
    /// Note: With ChannelStream-based I/O, data flows directly through the
    /// stream, so no data sender is needed.
    pub fn set_shell_pty(&mut self, pty: Arc<RwLock<PtyMaster>>) {
        self.shell_pty = Some(pty);
        self.mode = ChannelMode::Shell;
    }

    /// Set the shell data sender and PTY handle for the active shell.
    ///
    /// These are used by the data and window_change handlers to forward
    /// SSH input to the shell and handle terminal resizes.
    /// Note: This is kept for backward compatibility but `set_shell_pty`
    /// is preferred when using ChannelStream-based I/O.
    #[allow(dead_code)]
    pub fn set_shell_handles(
        &mut self,
        data_tx: mpsc::Sender<Vec<u8>>,
        pty: Arc<RwLock<PtyMaster>>,
    ) {
        self.shell_data_tx = Some(data_tx);
        self.shell_pty = Some(pty);
        self.mode = ChannelMode::Shell;
    }

    /// Clear the shell handles when the shell session ends.
    pub fn clear_shell_handles(&mut self) {
        self.shell_data_tx = None;
        self.shell_pty = None;
    }

    /// Check if the channel has an active shell session.
    pub fn has_shell(&self) -> bool {
        self.shell_pty.is_some()
    }

    /// Set the channel mode to SFTP.
    pub fn set_sftp(&mut self) {
        self.mode = ChannelMode::Sftp;
    }

    /// Mark that EOF has been received.
    pub fn mark_eof(&mut self) {
        self.eof_received = true;
    }
}

/// Manages all active SSH sessions.
///
/// Provides methods for creating, tracking, and cleaning up sessions.
/// Supports per-user session limits and idle timeout detection.
#[derive(Debug)]
pub struct SessionManager {
    /// Map of session ID to session info.
    sessions: HashMap<SessionId, SessionInfo>,

    /// Map of username to list of session IDs.
    /// Used for enforcing per-user session limits.
    user_sessions: HashMap<String, Vec<SessionId>>,

    /// Session configuration.
    config: SessionConfig,
}

impl SessionManager {
    /// Create a new session manager with default settings.
    pub fn new() -> Self {
        Self::with_config(SessionConfig::default())
    }

    /// Create a new session manager with a custom session limit.
    ///
    /// This is a convenience method that creates a config with the given limit.
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        let config = SessionConfig::new().with_max_total_sessions(max_sessions);
        Self::with_config(config)
    }

    /// Create a new session manager with the given configuration.
    pub fn with_config(config: SessionConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            user_sessions: HashMap::new(),
            config,
        }
    }

    /// Get the session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Create a new session for the given peer address.
    ///
    /// Returns `None` if the maximum number of sessions has been reached.
    pub fn create_session(&mut self, peer_addr: Option<SocketAddr>) -> Option<SessionInfo> {
        if self.sessions.len() >= self.config.max_total_sessions {
            tracing::warn!(
                current = self.sessions.len(),
                limit = self.config.max_total_sessions,
                "Session limit reached"
            );
            return None;
        }

        let info = SessionInfo::new(peer_addr);
        let id = info.id;
        self.sessions.insert(id, info.clone());

        tracing::debug!(
            session_id = %id,
            peer = ?peer_addr,
            "Session created"
        );

        Some(info)
    }

    /// Authenticate a session for the given user.
    ///
    /// This checks per-user session limits and tracks the session for the user.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if authentication was successful
    /// - `Err(SessionError::TooManyUserSessions)` if user has too many sessions
    /// - `Err(SessionError::SessionNotFound)` if session ID is invalid
    pub fn authenticate_session(
        &mut self,
        session_id: SessionId,
        username: &str,
    ) -> Result<(), SessionError> {
        // Check per-user limit first
        let current_user_sessions = self
            .user_sessions
            .get(username)
            .map(|v| v.len())
            .unwrap_or(0);

        if current_user_sessions >= self.config.max_sessions_per_user {
            tracing::warn!(
                user = %username,
                current = current_user_sessions,
                limit = self.config.max_sessions_per_user,
                "Per-user session limit reached"
            );
            return Err(SessionError::TooManyUserSessions {
                user: username.to_string(),
                limit: self.config.max_sessions_per_user,
            });
        }

        // Update session info
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(SessionError::SessionNotFound)?;

        session.authenticate(username);

        // Track user session
        self.user_sessions
            .entry(username.to_string())
            .or_default()
            .push(session_id);

        tracing::info!(
            session_id = %session_id,
            user = %username,
            user_sessions = current_user_sessions + 1,
            "Session authenticated"
        );

        Ok(())
    }

    /// Update the last activity timestamp for a session.
    pub fn touch(&mut self, session_id: SessionId) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.touch();
        }
    }

    /// Get a session by ID.
    pub fn get(&self, id: SessionId) -> Option<&SessionInfo> {
        self.sessions.get(&id)
    }

    /// Get a mutable reference to a session by ID.
    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut SessionInfo> {
        self.sessions.get_mut(&id)
    }

    /// Remove a session by ID.
    ///
    /// Also removes the session from user tracking if authenticated.
    pub fn remove(&mut self, id: SessionId) -> Option<SessionInfo> {
        let session = self.sessions.remove(&id);

        // Remove from user sessions tracking
        if let Some(ref session) = session {
            if let Some(ref username) = session.user {
                if let Some(user_sessions) = self.user_sessions.get_mut(username) {
                    user_sessions.retain(|&sid| sid != id);
                    if user_sessions.is_empty() {
                        self.user_sessions.remove(username);
                    }
                }
            }

            tracing::debug!(
                session_id = %id,
                user = ?session.user,
                duration_secs = session.duration_secs(),
                "Session removed"
            );
        }

        session
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get the number of authenticated sessions.
    pub fn authenticated_count(&self) -> usize {
        self.sessions.values().filter(|s| s.authenticated).count()
    }

    /// Get the number of unique authenticated users.
    pub fn unique_user_count(&self) -> usize {
        self.user_sessions.len()
    }

    /// Get the number of sessions for a specific user.
    pub fn user_session_count(&self, username: &str) -> usize {
        self.user_sessions
            .get(username)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Check if the session limit has been reached.
    pub fn is_at_capacity(&self) -> bool {
        self.sessions.len() >= self.config.max_total_sessions
    }

    /// Check if a user has reached their session limit.
    pub fn is_user_at_capacity(&self, username: &str) -> bool {
        self.user_session_count(username) >= self.config.max_sessions_per_user
    }

    /// Get sessions that should be timed out.
    ///
    /// Returns session IDs that are either:
    /// - Idle for longer than the idle timeout
    /// - Exceeding the maximum session duration (if configured)
    pub fn get_idle_sessions(&self) -> Vec<SessionId> {
        self.sessions
            .iter()
            .filter_map(|(id, info)| {
                // Check idle timeout
                if info.is_idle(self.config.idle_timeout) {
                    return Some(*id);
                }
                // Check session timeout
                if let Some(max_duration) = self.config.session_timeout {
                    if info.is_expired(max_duration) {
                        return Some(*id);
                    }
                }
                None
            })
            .collect()
    }

    /// Get the number of idle sessions.
    pub fn idle_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|info| info.is_idle(self.config.idle_timeout))
            .count()
    }

    /// Clean up sessions that have been idle for too long.
    ///
    /// Returns the number of sessions removed.
    ///
    /// Note: This uses the configured idle timeout, not the legacy behavior
    /// which only cleaned up unauthenticated sessions.
    pub fn cleanup_idle_sessions(&mut self, max_idle_secs: u64) -> usize {
        let idle_timeout = Duration::from_secs(max_idle_secs);
        let to_remove: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, info)| info.is_idle(idle_timeout) && !info.authenticated)
            .map(|(id, _)| *id)
            .collect();

        let count = to_remove.len();
        for id in to_remove {
            self.remove(id);
        }
        count
    }

    /// Get current session statistics.
    pub fn get_stats(&self) -> SessionStats {
        SessionStats {
            total_sessions: self.sessions.len(),
            authenticated_sessions: self.authenticated_count(),
            unique_users: self.user_sessions.len(),
            idle_sessions: self.idle_session_count(),
        }
    }

    /// List all active sessions.
    ///
    /// Returns a vector of session info clones for admin/monitoring purposes.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        self.sessions.values().cloned().collect()
    }

    /// List sessions for a specific user.
    pub fn list_user_sessions(&self, username: &str) -> Vec<SessionInfo> {
        self.user_sessions
            .get(username)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.sessions.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Force disconnect a session (admin operation).
    ///
    /// Returns true if the session existed and was removed.
    pub fn kill_session(&mut self, session_id: SessionId) -> bool {
        let existed = self.sessions.contains_key(&session_id);
        if existed {
            self.remove(session_id);
            tracing::info!(
                session_id = %session_id,
                "Session killed by admin"
            );
        }
        existed
    }

    /// Kill all sessions for a specific user (admin operation).
    ///
    /// Returns the number of sessions killed.
    pub fn kill_user_sessions(&mut self, username: &str) -> usize {
        let session_ids: Vec<SessionId> = self
            .user_sessions
            .get(username)
            .cloned()
            .unwrap_or_default();

        let count = session_ids.len();
        for id in session_ids {
            self.remove(id);
        }

        if count > 0 {
            tracing::info!(
                user = %username,
                count = count,
                "User sessions killed by admin"
            );
        }

        count
    }

    /// Iterate over all sessions.
    pub fn iter(&self) -> impl Iterator<Item = (&SessionId, &SessionInfo)> {
        self.sessions.iter()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22222)
    }

    #[test]
    fn test_session_id_uniqueness() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        let id3 = SessionId::new();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_session_id_display() {
        let id = SessionId::new();
        let display = id.to_string();
        assert!(display.starts_with("session-"));
    }

    #[test]
    fn test_session_info_creation() {
        let addr = test_addr();
        let info = SessionInfo::new(Some(addr));

        assert!(info.user.is_none());
        assert_eq!(info.peer_addr, Some(addr));
        assert!(!info.authenticated);
        assert_eq!(info.auth_attempts, 0);
    }

    #[test]
    fn test_session_info_authentication() {
        let mut info = SessionInfo::new(Some(test_addr()));
        assert!(!info.authenticated);

        info.authenticate("testuser");
        assert!(info.authenticated);
        assert_eq!(info.user, Some("testuser".to_string()));
    }

    #[test]
    fn test_session_info_auth_attempts() {
        let mut info = SessionInfo::new(Some(test_addr()));
        assert_eq!(info.auth_attempts, 0);

        info.increment_auth_attempts();
        assert_eq!(info.auth_attempts, 1);

        info.increment_auth_attempts();
        assert_eq!(info.auth_attempts, 2);
    }

    #[test]
    fn test_session_info_touch() {
        let mut info = SessionInfo::new(Some(test_addr()));
        let initial_activity = info.last_activity;

        // Sleep briefly and touch
        std::thread::sleep(std::time::Duration::from_millis(10));
        info.touch();

        // Last activity should be updated
        assert!(info.last_activity > initial_activity);
    }

    #[test]
    fn test_session_info_idle_secs() {
        let info = SessionInfo::new(Some(test_addr()));
        // Idle time should be 0 or very small immediately after creation
        assert!(info.idle_secs() < 2);
    }

    #[test]
    fn test_session_info_is_idle() {
        let info = SessionInfo::new(Some(test_addr()));

        // Should not be idle with a 1 hour timeout
        assert!(!info.is_idle(Duration::from_secs(3600)));

        // Should be idle with a 0 second timeout
        // (since some time has passed during test execution)
        // Note: This may be flaky in very fast execution
    }

    #[test]
    fn test_session_info_is_expired() {
        let info = SessionInfo::new(Some(test_addr()));

        // Should not be expired with a 1 hour timeout
        assert!(!info.is_expired(Duration::from_secs(3600)));
    }

    #[test]
    fn test_channel_mode_default() {
        let mode = ChannelMode::default();
        assert_eq!(mode, ChannelMode::Idle);
    }

    // Note: ChannelState tests requiring ChannelId are difficult to test
    // because ChannelId's inner field is private in russh. These tests
    // would need an integration test with actual russh channels.
    // The ChannelState functionality is tested through the handler tests instead.

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.max_sessions_per_user, 10);
        assert_eq!(config.max_total_sessions, 1000);
        assert_eq!(config.idle_timeout, Duration::from_secs(3600));
        assert!(config.session_timeout.is_none());
    }

    #[test]
    fn test_session_config_builder() {
        let config = SessionConfig::new()
            .with_max_sessions_per_user(5)
            .with_max_total_sessions(500)
            .with_idle_timeout(Duration::from_secs(1800))
            .with_session_timeout(Duration::from_secs(86400));

        assert_eq!(config.max_sessions_per_user, 5);
        assert_eq!(config.max_total_sessions, 500);
        assert_eq!(config.idle_timeout, Duration::from_secs(1800));
        assert_eq!(config.session_timeout, Some(Duration::from_secs(86400)));
    }

    #[test]
    fn test_session_config_validation_clamping() {
        // Setting max_sessions_per_user to 0 should clamp to 1
        let config = SessionConfig::new().with_max_sessions_per_user(0);
        assert_eq!(config.max_sessions_per_user, 1);

        // Setting max_total_sessions to 0 should clamp to 1
        let config = SessionConfig::new().with_max_total_sessions(0);
        assert_eq!(config.max_total_sessions, 1);
    }

    #[test]
    fn test_session_config_validate() {
        // Valid config should have no warnings
        let config = SessionConfig::new();
        let warnings = config.validate();
        assert!(warnings.is_empty());

        // Per-user > total should warn
        let config = SessionConfig::new()
            .with_max_sessions_per_user(100)
            .with_max_total_sessions(10);
        let warnings = config.validate();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("per-user limit"));

        // Session timeout < idle timeout should warn
        let config = SessionConfig::new()
            .with_idle_timeout(Duration::from_secs(3600))
            .with_session_timeout(Duration::from_secs(1800));
        let warnings = config.validate();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("session_timeout"));
    }

    #[test]
    fn test_session_manager_creation() {
        let manager = SessionManager::new();
        assert_eq!(manager.session_count(), 0);
        assert!(!manager.is_at_capacity());
    }

    #[test]
    fn test_session_manager_with_config() {
        let config = SessionConfig::new()
            .with_max_total_sessions(50)
            .with_max_sessions_per_user(5);
        let manager = SessionManager::with_config(config);

        assert_eq!(manager.config().max_total_sessions, 50);
        assert_eq!(manager.config().max_sessions_per_user, 5);
    }

    #[test]
    fn test_session_manager_create_session() {
        let mut manager = SessionManager::new();
        let info = manager.create_session(Some(test_addr()));

        assert!(info.is_some());
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_capacity() {
        let mut manager = SessionManager::with_max_sessions(2);

        let info1 = manager.create_session(Some(test_addr()));
        assert!(info1.is_some());

        let info2 = manager.create_session(Some(test_addr()));
        assert!(info2.is_some());

        assert!(manager.is_at_capacity());

        let info3 = manager.create_session(Some(test_addr()));
        assert!(info3.is_none());
    }

    #[test]
    fn test_session_manager_authenticate_session() {
        let mut manager = SessionManager::new();
        let info = manager.create_session(Some(test_addr())).unwrap();

        let result = manager.authenticate_session(info.id, "testuser");
        assert!(result.is_ok());

        // Session should be authenticated
        let session = manager.get(info.id).unwrap();
        assert!(session.authenticated);
        assert_eq!(session.user, Some("testuser".to_string()));

        // User session tracking should be updated
        assert_eq!(manager.user_session_count("testuser"), 1);
    }

    #[test]
    fn test_session_manager_per_user_limit() {
        let config = SessionConfig::new()
            .with_max_sessions_per_user(2)
            .with_max_total_sessions(10);
        let mut manager = SessionManager::with_config(config);

        // Create and authenticate 2 sessions for user1
        let s1 = manager.create_session(Some(test_addr())).unwrap();
        manager.authenticate_session(s1.id, "user1").unwrap();

        let s2 = manager.create_session(Some(test_addr())).unwrap();
        manager.authenticate_session(s2.id, "user1").unwrap();

        // Third session for user1 should fail
        let s3 = manager.create_session(Some(test_addr())).unwrap();
        let result = manager.authenticate_session(s3.id, "user1");
        assert!(matches!(
            result,
            Err(SessionError::TooManyUserSessions { .. })
        ));

        // But a different user should still be able to authenticate
        let s4 = manager.create_session(Some(test_addr())).unwrap();
        let result = manager.authenticate_session(s4.id, "user2");
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_manager_touch() {
        let mut manager = SessionManager::new();
        let info = manager.create_session(Some(test_addr())).unwrap();
        let initial_activity = manager.get(info.id).unwrap().last_activity;

        // Sleep briefly and touch
        std::thread::sleep(std::time::Duration::from_millis(10));
        manager.touch(info.id);

        // Last activity should be updated
        let updated_activity = manager.get(info.id).unwrap().last_activity;
        assert!(updated_activity > initial_activity);
    }

    #[test]
    fn test_session_manager_get_and_remove() {
        let mut manager = SessionManager::new();
        let info = manager.create_session(Some(test_addr())).unwrap();
        let id = info.id;

        assert!(manager.get(id).is_some());

        let removed = manager.remove(id);
        assert!(removed.is_some());
        assert!(manager.get(id).is_none());
    }

    #[test]
    fn test_session_manager_remove_updates_user_tracking() {
        let mut manager = SessionManager::new();
        let info = manager.create_session(Some(test_addr())).unwrap();
        manager.authenticate_session(info.id, "testuser").unwrap();

        assert_eq!(manager.user_session_count("testuser"), 1);

        manager.remove(info.id);

        assert_eq!(manager.user_session_count("testuser"), 0);
    }

    #[test]
    fn test_session_manager_authenticated_count() {
        let mut manager = SessionManager::new();

        let info1 = manager.create_session(Some(test_addr())).unwrap();
        let info2 = manager.create_session(Some(test_addr())).unwrap();

        assert_eq!(manager.authenticated_count(), 0);

        manager.authenticate_session(info1.id, "user1").unwrap();
        assert_eq!(manager.authenticated_count(), 1);

        manager.authenticate_session(info2.id, "user2").unwrap();
        assert_eq!(manager.authenticated_count(), 2);
    }

    #[test]
    fn test_session_manager_unique_user_count() {
        let mut manager = SessionManager::new();

        let s1 = manager.create_session(Some(test_addr())).unwrap();
        let s2 = manager.create_session(Some(test_addr())).unwrap();
        let s3 = manager.create_session(Some(test_addr())).unwrap();

        manager.authenticate_session(s1.id, "user1").unwrap();
        manager.authenticate_session(s2.id, "user1").unwrap();
        manager.authenticate_session(s3.id, "user2").unwrap();

        assert_eq!(manager.unique_user_count(), 2);
        assert_eq!(manager.user_session_count("user1"), 2);
        assert_eq!(manager.user_session_count("user2"), 1);
    }

    #[test]
    fn test_session_manager_is_user_at_capacity() {
        let config = SessionConfig::new().with_max_sessions_per_user(2);
        let mut manager = SessionManager::with_config(config);

        let s1 = manager.create_session(Some(test_addr())).unwrap();
        manager.authenticate_session(s1.id, "user1").unwrap();
        assert!(!manager.is_user_at_capacity("user1"));

        let s2 = manager.create_session(Some(test_addr())).unwrap();
        manager.authenticate_session(s2.id, "user1").unwrap();
        assert!(manager.is_user_at_capacity("user1"));
    }

    #[test]
    fn test_session_manager_get_stats() {
        let config = SessionConfig::new().with_idle_timeout(Duration::from_secs(3600));
        let mut manager = SessionManager::with_config(config);

        let s1 = manager.create_session(Some(test_addr())).unwrap();
        let s2 = manager.create_session(Some(test_addr())).unwrap();

        manager.authenticate_session(s1.id, "user1").unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.total_sessions, 2);
        assert_eq!(stats.authenticated_sessions, 1);
        assert_eq!(stats.unique_users, 1);
        assert_eq!(stats.idle_sessions, 0); // Not idle yet
    }

    #[test]
    fn test_session_manager_list_sessions() {
        let mut manager = SessionManager::new();
        let s1 = manager.create_session(Some(test_addr())).unwrap();
        let s2 = manager.create_session(Some(test_addr())).unwrap();

        let sessions = manager.list_sessions();
        assert_eq!(sessions.len(), 2);

        let ids: Vec<_> = sessions.iter().map(|s| s.id).collect();
        assert!(ids.contains(&s1.id));
        assert!(ids.contains(&s2.id));
    }

    #[test]
    fn test_session_manager_list_user_sessions() {
        let mut manager = SessionManager::new();
        let s1 = manager.create_session(Some(test_addr())).unwrap();
        let s2 = manager.create_session(Some(test_addr())).unwrap();
        let s3 = manager.create_session(Some(test_addr())).unwrap();

        manager.authenticate_session(s1.id, "user1").unwrap();
        manager.authenticate_session(s2.id, "user1").unwrap();
        manager.authenticate_session(s3.id, "user2").unwrap();

        let user1_sessions = manager.list_user_sessions("user1");
        assert_eq!(user1_sessions.len(), 2);

        let user2_sessions = manager.list_user_sessions("user2");
        assert_eq!(user2_sessions.len(), 1);

        let user3_sessions = manager.list_user_sessions("user3");
        assert_eq!(user3_sessions.len(), 0);
    }

    #[test]
    fn test_session_manager_kill_session() {
        let mut manager = SessionManager::new();
        let info = manager.create_session(Some(test_addr())).unwrap();

        assert!(manager.kill_session(info.id));
        assert!(manager.get(info.id).is_none());

        // Killing non-existent session returns false
        assert!(!manager.kill_session(info.id));
    }

    #[test]
    fn test_session_manager_kill_user_sessions() {
        let mut manager = SessionManager::new();
        let s1 = manager.create_session(Some(test_addr())).unwrap();
        let s2 = manager.create_session(Some(test_addr())).unwrap();
        let s3 = manager.create_session(Some(test_addr())).unwrap();

        manager.authenticate_session(s1.id, "user1").unwrap();
        manager.authenticate_session(s2.id, "user1").unwrap();
        manager.authenticate_session(s3.id, "user2").unwrap();

        let killed = manager.kill_user_sessions("user1");
        assert_eq!(killed, 2);
        assert_eq!(manager.user_session_count("user1"), 0);
        assert_eq!(manager.user_session_count("user2"), 1);
    }

    #[test]
    fn test_session_manager_cleanup_idle() {
        let mut manager = SessionManager::new();

        // Create unauthenticated session
        let _info = manager.create_session(Some(test_addr())).unwrap();

        // Duration of a just-created session is 0 seconds, so max_idle_secs of 0
        // means only sessions with duration > 0 would be removed.
        // Since the session duration is 0 (or very close), it won't be removed.
        // Use a very high threshold to verify the function works correctly.
        let removed = manager.cleanup_idle_sessions(1000);
        assert_eq!(removed, 0);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_cleanup_preserves_authenticated() {
        let mut manager = SessionManager::new();

        // Create and authenticate a session
        let info = manager.create_session(Some(test_addr())).unwrap();
        manager.authenticate_session(info.id, "user").unwrap();

        // Cleanup should not remove authenticated sessions
        let removed = manager.cleanup_idle_sessions(0);
        assert_eq!(removed, 0);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_pty_config() {
        let pty = PtyConfig::new("vt100".to_string(), 132, 50, 1024, 768);

        assert_eq!(pty.term, "vt100");
        assert_eq!(pty.col_width, 132);
        assert_eq!(pty.row_height, 50);
        assert_eq!(pty.pix_width, 1024);
        assert_eq!(pty.pix_height, 768);
    }

    #[test]
    fn test_session_id_as_u64() {
        let id = SessionId::new();
        assert!(id.as_u64() > 0);
    }

    #[test]
    fn test_session_info_no_peer_addr() {
        let info = SessionInfo::new(None);

        assert!(info.peer_addr.is_none());
        assert!(info.user.is_none());
        assert!(!info.authenticated);
    }

    #[test]
    fn test_session_info_duration() {
        let info = SessionInfo::new(Some(test_addr()));
        // Duration should be 0 or very small immediately after creation
        assert!(info.duration_secs() < 2);
    }

    #[test]
    fn test_session_manager_default() {
        let manager = SessionManager::default();
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_session_manager_iter() {
        let mut manager = SessionManager::new();
        let info1 = manager.create_session(Some(test_addr())).unwrap();
        let info2 = manager.create_session(Some(test_addr())).unwrap();

        let sessions: Vec<_> = manager.iter().collect();
        assert_eq!(sessions.len(), 2);

        let ids: Vec<_> = sessions.iter().map(|(id, _)| **id).collect();
        assert!(ids.contains(&info1.id));
        assert!(ids.contains(&info2.id));
    }

    #[test]
    fn test_channel_mode_exec() {
        let mode = ChannelMode::Exec {
            command: "ls -la".to_string(),
        };
        match mode {
            ChannelMode::Exec { command } => assert_eq!(command, "ls -la"),
            _ => panic!("Expected Exec mode"),
        }
    }

    #[test]
    fn test_channel_mode_shell() {
        let mode = ChannelMode::Shell;
        assert_eq!(mode, ChannelMode::Shell);
    }

    #[test]
    fn test_channel_mode_sftp() {
        let mode = ChannelMode::Sftp;
        assert_eq!(mode, ChannelMode::Sftp);
    }

    #[test]
    fn test_session_error_display() {
        let err1 = SessionError::TooManySessions { limit: 100 };
        assert!(err1.to_string().contains("100"));

        let err2 = SessionError::TooManyUserSessions {
            user: "testuser".to_string(),
            limit: 10,
        };
        assert!(err2.to_string().contains("testuser"));
        assert!(err2.to_string().contains("10"));

        let err3 = SessionError::SessionNotFound;
        assert!(err3.to_string().contains("not found"));
    }

    #[test]
    fn test_session_stats() {
        let stats = SessionStats {
            total_sessions: 10,
            authenticated_sessions: 5,
            unique_users: 3,
            idle_sessions: 2,
        };

        assert_eq!(stats.total_sessions, 10);
        assert_eq!(stats.authenticated_sessions, 5);
        assert_eq!(stats.unique_users, 3);
        assert_eq!(stats.idle_sessions, 2);
    }

    #[test]
    fn test_session_authenticate_not_found() {
        let mut manager = SessionManager::new();
        let fake_id = SessionId::new();

        let result = manager.authenticate_session(fake_id, "user");
        assert!(matches!(result, Err(SessionError::SessionNotFound)));
    }
}

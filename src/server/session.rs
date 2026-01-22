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
//! - [`SessionManager`]: Manages all active sessions
//! - [`SessionInfo`]: Information about a single session
//! - [`SessionId`]: Unique identifier for a session
//! - [`ChannelState`]: State of an SSH channel
//! - [`ChannelMode`]: Current operation mode of a channel

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use russh::ChannelId;

/// Unique identifier for an SSH session.
///
/// Each session is assigned a unique ID when created, which can be used
/// to track and manage the session throughout its lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Create a new unique session ID.
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
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

    /// Whether the user has been authenticated.
    pub authenticated: bool,

    /// Number of authentication attempts.
    pub auth_attempts: u32,
}

impl SessionInfo {
    /// Create a new session info with the given peer address.
    pub fn new(peer_addr: Option<SocketAddr>) -> Self {
        Self {
            id: SessionId::new(),
            user: None,
            peer_addr,
            started_at: Instant::now(),
            authenticated: false,
            auth_attempts: 0,
        }
    }

    /// Mark the session as authenticated with the given username.
    pub fn authenticate(&mut self, username: impl Into<String>) {
        self.user = Some(username.into());
        self.authenticated = true;
    }

    /// Increment the authentication attempt counter.
    pub fn increment_auth_attempts(&mut self) {
        self.auth_attempts += 1;
    }

    /// Get the session duration in seconds.
    pub fn duration_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
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
#[derive(Debug)]
pub struct ChannelState {
    /// The channel ID.
    pub channel_id: ChannelId,

    /// Current operation mode.
    pub mode: ChannelMode,

    /// PTY configuration, if a PTY was requested.
    pub pty: Option<PtyConfig>,

    /// Whether EOF has been received from the client.
    pub eof_received: bool,
}

impl ChannelState {
    /// Create a new channel state.
    pub fn new(channel_id: ChannelId) -> Self {
        Self {
            channel_id,
            mode: ChannelMode::Idle,
            pty: None,
            eof_received: false,
        }
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
#[derive(Debug)]
pub struct SessionManager {
    /// Map of session ID to session info.
    sessions: HashMap<SessionId, SessionInfo>,

    /// Maximum number of concurrent sessions allowed.
    max_sessions: usize,
}

impl SessionManager {
    /// Create a new session manager with default settings.
    pub fn new() -> Self {
        Self::with_max_sessions(1000)
    }

    /// Create a new session manager with a custom session limit.
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// Create a new session for the given peer address.
    ///
    /// Returns `None` if the maximum number of sessions has been reached.
    pub fn create_session(&mut self, peer_addr: Option<SocketAddr>) -> Option<SessionInfo> {
        if self.sessions.len() >= self.max_sessions {
            return None;
        }

        let info = SessionInfo::new(peer_addr);
        let id = info.id;
        self.sessions.insert(id, info.clone());
        Some(info)
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
    pub fn remove(&mut self, id: SessionId) -> Option<SessionInfo> {
        self.sessions.remove(&id)
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get the number of authenticated sessions.
    pub fn authenticated_count(&self) -> usize {
        self.sessions.values().filter(|s| s.authenticated).count()
    }

    /// Check if the session limit has been reached.
    pub fn is_at_capacity(&self) -> bool {
        self.sessions.len() >= self.max_sessions
    }

    /// Clean up sessions that have been idle for too long.
    ///
    /// Returns the number of sessions removed.
    pub fn cleanup_idle_sessions(&mut self, max_idle_secs: u64) -> usize {
        let to_remove: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, info)| info.duration_secs() > max_idle_secs && !info.authenticated)
            .map(|(id, _)| *id)
            .collect();

        let count = to_remove.len();
        for id in to_remove {
            self.sessions.remove(&id);
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
    fn test_channel_mode_default() {
        let mode = ChannelMode::default();
        assert_eq!(mode, ChannelMode::Idle);
    }

    // Note: ChannelState tests requiring ChannelId are difficult to test
    // because ChannelId's inner field is private in russh. These tests
    // would need an integration test with actual russh channels.
    // The ChannelState functionality is tested through the handler tests instead.

    #[test]
    fn test_session_manager_creation() {
        let manager = SessionManager::new();
        assert_eq!(manager.session_count(), 0);
        assert!(!manager.is_at_capacity());
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
    fn test_session_manager_authenticated_count() {
        let mut manager = SessionManager::new();

        let info1 = manager.create_session(Some(test_addr())).unwrap();
        let info2 = manager.create_session(Some(test_addr())).unwrap();

        assert_eq!(manager.authenticated_count(), 0);

        if let Some(session) = manager.get_mut(info1.id) {
            session.authenticate("user1");
        }
        assert_eq!(manager.authenticated_count(), 1);

        if let Some(session) = manager.get_mut(info2.id) {
            session.authenticate("user2");
        }
        assert_eq!(manager.authenticated_count(), 2);
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
        if let Some(session) = manager.get_mut(info.id) {
            session.authenticate("user");
        }

        // Cleanup should not remove authenticated sessions
        let removed = manager.cleanup_idle_sessions(0);
        assert_eq!(removed, 0);
        assert_eq!(manager.session_count(), 1);
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
}

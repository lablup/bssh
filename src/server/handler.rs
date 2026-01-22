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

//! SSH handler implementation for the russh server.
//!
//! This module implements the `russh::server::Handler` trait which handles
//! all SSH protocol events for a single connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use russh::keys::ssh_key;
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
use tokio::sync::RwLock;

use super::config::ServerConfig;
use super::session::{ChannelState, PtyConfig, SessionId, SessionInfo, SessionManager};

/// SSH handler for a single client connection.
///
/// This struct implements the `russh::server::Handler` trait to handle
/// SSH protocol events such as authentication, channel operations, and data transfer.
pub struct SshHandler {
    /// Remote address of the connected client.
    peer_addr: Option<SocketAddr>,

    /// Server configuration.
    config: Arc<ServerConfig>,

    /// Shared session manager.
    sessions: Arc<RwLock<SessionManager>>,

    /// Session information for this connection.
    session_info: Option<SessionInfo>,

    /// Active channels for this connection.
    channels: HashMap<ChannelId, ChannelState>,
}

impl SshHandler {
    /// Create a new SSH handler for a client connection.
    pub fn new(
        peer_addr: Option<SocketAddr>,
        config: Arc<ServerConfig>,
        sessions: Arc<RwLock<SessionManager>>,
    ) -> Self {
        Self {
            peer_addr,
            config,
            sessions,
            session_info: None,
            channels: HashMap::new(),
        }
    }

    /// Get the peer address of the connected client.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Get the session ID, if the session has been created.
    pub fn session_id(&self) -> Option<SessionId> {
        self.session_info.as_ref().map(|s| s.id)
    }

    /// Check if the connection is authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.session_info.as_ref().is_some_and(|s| s.authenticated)
    }

    /// Get the authenticated username, if any.
    pub fn username(&self) -> Option<&str> {
        self.session_info
            .as_ref()
            .and_then(|s| s.user.as_deref())
    }

    /// Build the method set of allowed authentication methods.
    fn allowed_methods(&self) -> MethodSet {
        let mut methods = MethodSet::empty();

        if self.config.allow_publickey_auth {
            methods.push(MethodKind::PublicKey);
        }
        if self.config.allow_password_auth {
            methods.push(MethodKind::Password);
        }
        if self.config.allow_keyboard_interactive {
            methods.push(MethodKind::KeyboardInteractive);
        }

        methods
    }

    /// Check if the maximum authentication attempts has been exceeded.
    fn auth_attempts_exceeded(&self) -> bool {
        self.session_info
            .as_ref()
            .is_some_and(|s| s.auth_attempts >= self.config.max_auth_attempts)
    }
}

impl russh::server::Handler for SshHandler {
    type Error = anyhow::Error;

    /// Called when a new session channel is created.
    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let channel_id = channel.id();
        tracing::debug!(
            peer = ?self.peer_addr,
            "Channel opened for session"
        );

        self.channels.insert(channel_id, ChannelState::new(channel_id));
        async { Ok(true) }
    }

    /// Handle 'none' authentication.
    ///
    /// Always rejects and advertises available authentication methods.
    fn auth_none(
        &mut self,
        user: &str,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        tracing::debug!(
            user = %user,
            peer = ?self.peer_addr,
            "Auth none attempt"
        );

        // Create session info if not already created
        let peer_addr = self.peer_addr;
        let sessions = Arc::clone(&self.sessions);
        let methods = self.allowed_methods();

        // We need to handle session creation
        let session_info_ref = &mut self.session_info;

        async move {
            if session_info_ref.is_none() {
                let mut sessions_guard = sessions.write().await;
                if let Some(info) = sessions_guard.create_session(peer_addr) {
                    tracing::info!(
                        session_id = %info.id,
                        peer = ?peer_addr,
                        "New session created"
                    );
                    *session_info_ref = Some(info);
                } else {
                    tracing::warn!(
                        peer = ?peer_addr,
                        "Session limit reached, rejecting connection"
                    );
                    return Ok(Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    });
                }
            }

            // Reject with available methods
            tracing::debug!(
                methods = ?methods,
                "Rejecting auth_none, advertising methods"
            );

            Ok(Auth::Reject {
                proceed_with_methods: Some(methods),
                partial_success: false,
            })
        }
    }

    /// Handle public key authentication.
    ///
    /// Placeholder implementation - will be implemented in a future issue.
    fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        tracing::debug!(
            user = %user,
            peer = ?self.peer_addr,
            key_type = %public_key.algorithm(),
            "Public key authentication attempt"
        );

        // Increment auth attempts
        if let Some(ref mut info) = self.session_info {
            info.increment_auth_attempts();
        }

        // Check if max attempts exceeded
        let exceeded = self.auth_attempts_exceeded();
        let mut methods = self.allowed_methods();
        methods.remove(MethodKind::PublicKey);

        async move {
            if exceeded {
                tracing::warn!(
                    "Max authentication attempts exceeded"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }

            // Placeholder - reject but allow other methods
            // Will be implemented in #126
            let proceed = if methods.is_empty() {
                None
            } else {
                Some(methods)
            };

            Ok(Auth::Reject {
                proceed_with_methods: proceed,
                partial_success: false,
            })
        }
    }

    /// Handle password authentication.
    ///
    /// Placeholder implementation - will be implemented in a future issue.
    fn auth_password(
        &mut self,
        user: &str,
        _password: &str,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        tracing::debug!(
            user = %user,
            peer = ?self.peer_addr,
            "Password authentication attempt"
        );

        // Increment auth attempts
        if let Some(ref mut info) = self.session_info {
            info.increment_auth_attempts();
        }

        // Check if max attempts exceeded
        let exceeded = self.auth_attempts_exceeded();
        let mut methods = self.allowed_methods();
        methods.remove(MethodKind::Password);

        async move {
            if exceeded {
                tracing::warn!(
                    "Max authentication attempts exceeded"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }

            // Placeholder - reject but allow other methods
            // Will be implemented in #127
            let proceed = if methods.is_empty() {
                None
            } else {
                Some(methods)
            };

            Ok(Auth::Reject {
                proceed_with_methods: proceed,
                partial_success: false,
            })
        }
    }

    /// Handle PTY request.
    ///
    /// Stores the PTY configuration for the channel.
    #[allow(clippy::too_many_arguments)]
    fn pty_request(
        &mut self,
        channel_id: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(
            term = %term,
            cols = %col_width,
            rows = %row_height,
            "PTY request"
        );

        if let Some(channel_state) = self.channels.get_mut(&channel_id) {
            let pty_config = PtyConfig::new(
                term.to_string(),
                col_width,
                row_height,
                pix_width,
                pix_height,
            );
            channel_state.set_pty(pty_config);
            let _ = session.channel_success(channel_id);
        } else {
            tracing::warn!(
                "PTY request for unknown channel"
            );
            let _ = session.channel_failure(channel_id);
        }

        async { Ok(()) }
    }

    /// Handle exec request.
    ///
    /// Placeholder implementation - will be implemented in a future issue.
    fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let command = String::from_utf8_lossy(data);
        tracing::debug!(
            command = %command,
            "Exec request"
        );

        if let Some(channel_state) = self.channels.get_mut(&channel_id) {
            channel_state.set_exec(command.to_string());
        }

        // Placeholder - reject for now
        // Will be implemented in #128
        let _ = session.channel_failure(channel_id);
        async { Ok(()) }
    }

    /// Handle shell request.
    ///
    /// Placeholder implementation - will be implemented in a future issue.
    fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(
            "Shell request"
        );

        if let Some(channel_state) = self.channels.get_mut(&channel_id) {
            channel_state.set_shell();
        }

        // Placeholder - reject for now
        // Will be implemented in #129
        let _ = session.channel_failure(channel_id);
        async { Ok(()) }
    }

    /// Handle subsystem request.
    ///
    /// Placeholder implementation - will be implemented in a future issue.
    fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(
            subsystem = %name,
            "Subsystem request"
        );

        if name == "sftp" {
            if let Some(channel_state) = self.channels.get_mut(&channel_id) {
                channel_state.set_sftp();
            }
        }

        // Placeholder - reject for now
        // Will be implemented in #132 for SFTP
        let _ = session.channel_failure(channel_id);
        async { Ok(()) }
    }

    /// Handle incoming data from the client.
    fn data(
        &mut self,
        _channel_id: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::trace!(
            bytes = %data.len(),
            "Received data"
        );

        // Placeholder - data handling will be implemented with exec/shell/sftp
        async { Ok(()) }
    }

    /// Handle channel EOF from the client.
    fn channel_eof(
        &mut self,
        channel_id: ChannelId,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(
            "Channel EOF received"
        );

        if let Some(channel_state) = self.channels.get_mut(&channel_id) {
            channel_state.mark_eof();
        }

        async { Ok(()) }
    }

    /// Handle channel close from the client.
    fn channel_close(
        &mut self,
        channel_id: ChannelId,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(
            "Channel closed"
        );

        self.channels.remove(&channel_id);
        async { Ok(()) }
    }
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        if let Some(ref info) = self.session_info {
            tracing::info!(
                session_id = %info.id,
                peer = ?self.peer_addr,
                duration_secs = %info.duration_secs(),
                authenticated = %info.authenticated,
                "Session ended"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22222)
    }

    fn test_config() -> Arc<ServerConfig> {
        Arc::new(
            ServerConfig::builder()
                .allow_password_auth(true)
                .allow_publickey_auth(true)
                .build(),
        )
    }

    fn test_sessions() -> Arc<RwLock<SessionManager>> {
        Arc::new(RwLock::new(SessionManager::new()))
    }

    #[test]
    fn test_handler_creation() {
        let handler = SshHandler::new(Some(test_addr()), test_config(), test_sessions());

        assert_eq!(handler.peer_addr(), Some(test_addr()));
        assert!(handler.session_id().is_none());
        assert!(!handler.is_authenticated());
        assert!(handler.username().is_none());
    }

    #[test]
    fn test_allowed_methods_all() {
        let config = Arc::new(
            ServerConfig::builder()
                .allow_password_auth(true)
                .allow_publickey_auth(true)
                .allow_keyboard_interactive(true)
                .build(),
        );
        let handler = SshHandler::new(Some(test_addr()), config, test_sessions());
        let methods = handler.allowed_methods();

        assert!(methods.contains(&MethodKind::Password));
        assert!(methods.contains(&MethodKind::PublicKey));
        assert!(methods.contains(&MethodKind::KeyboardInteractive));
    }

    #[test]
    fn test_allowed_methods_none() {
        let config = Arc::new(
            ServerConfig::builder()
                .allow_password_auth(false)
                .allow_publickey_auth(false)
                .allow_keyboard_interactive(false)
                .build(),
        );
        let handler = SshHandler::new(Some(test_addr()), config, test_sessions());
        let methods = handler.allowed_methods();

        assert!(methods.is_empty());
    }

    #[test]
    fn test_auth_attempts_not_exceeded() {
        let config = Arc::new(
            ServerConfig::builder()
                .max_auth_attempts(3)
                .build(),
        );
        let handler = SshHandler::new(Some(test_addr()), config, test_sessions());

        assert!(!handler.auth_attempts_exceeded());
    }
}

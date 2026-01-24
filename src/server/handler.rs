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

use futures::FutureExt;
use russh::keys::ssh_key;
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use super::auth::AuthProvider;
use super::config::ServerConfig;
use super::exec::CommandExecutor;
use super::pty::PtyConfig as PtyMasterConfig;
use super::security::AuthRateLimiter;
use super::session::{ChannelState, PtyConfig, SessionError, SessionId, SessionInfo, SessionManager};
use super::sftp::SftpHandler;
use super::shell::ShellSession;
use crate::shared::rate_limit::RateLimiter;

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

    /// Authentication provider for verifying credentials.
    auth_provider: Arc<dyn AuthProvider>,

    /// Rate limiter for authentication attempts.
    rate_limiter: RateLimiter<String>,

    /// Auth rate limiter with ban support (fail2ban-like).
    auth_rate_limiter: Option<AuthRateLimiter>,

    /// Session information for this connection.
    session_info: Option<SessionInfo>,

    /// Active channels for this connection.
    channels: HashMap<ChannelId, ChannelState>,

    /// Whether this connection should be immediately rejected.
    /// Set when IP access control denies the connection.
    rejected: bool,
}

impl SshHandler {
    /// Create a new SSH handler for a client connection.
    pub fn new(
        peer_addr: Option<SocketAddr>,
        config: Arc<ServerConfig>,
        sessions: Arc<RwLock<SessionManager>>,
    ) -> Self {
        let auth_provider = config.create_auth_provider();
        // Rate limiter: allow burst of 5 attempts, refill 1 attempt per second
        // Note: This creates a per-handler rate limiter. For production use,
        // prefer with_rate_limiter() to share a rate limiter across handlers.
        let rate_limiter = RateLimiter::with_simple_config(5, 1.0);

        Self {
            peer_addr,
            config,
            sessions,
            auth_provider,
            rate_limiter,
            auth_rate_limiter: None,
            session_info: Some(SessionInfo::new(peer_addr)),
            channels: HashMap::new(),
            rejected: false,
        }
    }

    /// Create a new SSH handler with a shared rate limiter.
    ///
    /// This is the preferred constructor for production use as it shares
    /// the rate limiter across all handlers, providing server-wide rate limiting.
    pub fn with_rate_limiter(
        peer_addr: Option<SocketAddr>,
        config: Arc<ServerConfig>,
        sessions: Arc<RwLock<SessionManager>>,
        rate_limiter: RateLimiter<String>,
    ) -> Self {
        let auth_provider = config.create_auth_provider();

        Self {
            peer_addr,
            config,
            sessions,
            auth_provider,
            rate_limiter,
            auth_rate_limiter: None,
            session_info: Some(SessionInfo::new(peer_addr)),
            channels: HashMap::new(),
            rejected: false,
        }
    }

    /// Create a new SSH handler with shared rate limiters including auth ban support.
    ///
    /// This is the preferred constructor for production use as it shares
    /// both rate limiters across all handlers, providing server-wide rate limiting
    /// and fail2ban-like functionality.
    pub fn with_rate_limiters(
        peer_addr: Option<SocketAddr>,
        config: Arc<ServerConfig>,
        sessions: Arc<RwLock<SessionManager>>,
        rate_limiter: RateLimiter<String>,
        auth_rate_limiter: AuthRateLimiter,
    ) -> Self {
        let auth_provider = config.create_auth_provider();

        Self {
            peer_addr,
            config,
            sessions,
            auth_provider,
            rate_limiter,
            auth_rate_limiter: Some(auth_rate_limiter),
            session_info: Some(SessionInfo::new(peer_addr)),
            channels: HashMap::new(),
            rejected: false,
        }
    }

    /// Create a new SSH handler with a custom auth provider.
    ///
    /// This is useful for testing or when you need a different auth provider.
    pub fn with_auth_provider(
        peer_addr: Option<SocketAddr>,
        config: Arc<ServerConfig>,
        sessions: Arc<RwLock<SessionManager>>,
        auth_provider: Arc<dyn AuthProvider>,
    ) -> Self {
        let rate_limiter = RateLimiter::with_simple_config(5, 1.0);

        Self {
            peer_addr,
            config,
            sessions,
            auth_provider,
            rate_limiter,
            auth_rate_limiter: None,
            session_info: Some(SessionInfo::new(peer_addr)),
            channels: HashMap::new(),
            rejected: false,
        }
    }

    /// Create a handler for a rejected connection.
    ///
    /// This handler will immediately reject all authentication attempts.
    /// Used when IP access control denies a connection.
    pub fn rejected(
        peer_addr: Option<SocketAddr>,
        config: Arc<ServerConfig>,
        sessions: Arc<RwLock<SessionManager>>,
    ) -> Self {
        let auth_provider = config.create_auth_provider();
        let rate_limiter = RateLimiter::with_simple_config(1, 0.1);

        Self {
            peer_addr,
            config,
            sessions,
            auth_provider,
            rate_limiter,
            auth_rate_limiter: None,
            session_info: None, // No session for rejected connections
            channels: HashMap::new(),
            rejected: true,
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
        self.session_info.as_ref().and_then(|s| s.user.as_deref())
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
            channel = ?channel_id,
            "Channel opened for session"
        );

        // Store the channel itself so we can use it for subsystems like SFTP
        self.channels
            .insert(channel_id, ChannelState::with_channel(channel));
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

        // If connection was rejected by IP access control, immediately reject
        if self.rejected {
            tracing::debug!(
                peer = ?self.peer_addr,
                "Rejecting auth for IP-blocked connection"
            );
            return std::future::ready(Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }))
            .left_future();
        }

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
        .right_future()
    }

    /// Handle public key authentication.
    ///
    /// Verifies the public key against the user's authorized_keys file.
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

        // Clone what we need for the async block
        let auth_provider = Arc::clone(&self.auth_provider);
        let sessions = Arc::clone(&self.sessions);
        let rate_limiter = self.rate_limiter.clone();
        let auth_rate_limiter = self.auth_rate_limiter.clone();
        let peer_addr = self.peer_addr;
        let user = user.to_string();
        let public_key = public_key.clone();

        // Get mutable reference to session_info for authentication update
        let session_info = &mut self.session_info;

        async move {
            // Check if IP is banned (fail2ban-like check)
            if let Some(ref limiter) = auth_rate_limiter {
                if let Some(ip) = peer_addr.map(|a| a.ip()) {
                    if limiter.is_banned(&ip).await {
                        tracing::warn!(
                            user = %user,
                            peer = ?peer_addr,
                            "Rejected auth from banned IP"
                        );
                        return Ok(Auth::Reject {
                            proceed_with_methods: None,
                            partial_success: false,
                        });
                    }
                }
            }

            if exceeded {
                tracing::warn!(
                    user = %user,
                    peer = ?peer_addr,
                    "Max authentication attempts exceeded"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }

            // Check rate limiting based on peer address
            let rate_key = peer_addr
                .map(|addr| addr.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            if rate_limiter.is_rate_limited(&rate_key).await {
                tracing::warn!(
                    user = %user,
                    peer = ?peer_addr,
                    "Rate limited authentication attempt"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }

            // Try to acquire a rate limit token
            if rate_limiter.try_acquire(&rate_key).await.is_err() {
                tracing::warn!(
                    user = %user,
                    peer = ?peer_addr,
                    "Rate limit exceeded"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }

            // Verify public key using auth provider
            match auth_provider.verify_publickey(&user, &public_key).await {
                Ok(result) if result.is_accepted() => {
                    tracing::info!(
                        user = %user,
                        peer = ?peer_addr,
                        key_type = %public_key.algorithm(),
                        "Public key authentication successful"
                    );

                    // Try to authenticate session with per-user limits
                    if let Some(ref info) = session_info {
                        let mut sessions_guard = sessions.write().await;
                        match sessions_guard.authenticate_session(info.id, &user) {
                            Ok(()) => {
                                // Also update local session info
                                drop(sessions_guard);
                                if let Some(ref mut local_info) = session_info {
                                    local_info.authenticate(&user);
                                }
                            }
                            Err(SessionError::TooManyUserSessions { user: u, limit }) => {
                                tracing::warn!(
                                    user = %u,
                                    limit = limit,
                                    peer = ?peer_addr,
                                    "Per-user session limit reached, rejecting authentication"
                                );
                                return Ok(Auth::Reject {
                                    proceed_with_methods: None,
                                    partial_success: false,
                                });
                            }
                            Err(e) => {
                                tracing::error!(
                                    user = %user,
                                    error = %e,
                                    "Failed to authenticate session"
                                );
                                return Ok(Auth::Reject {
                                    proceed_with_methods: None,
                                    partial_success: false,
                                });
                            }
                        }
                    }

                    // Record success to reset failure counter
                    if let Some(ref limiter) = auth_rate_limiter {
                        if let Some(ip) = peer_addr.map(|a| a.ip()) {
                            limiter.record_success(&ip).await;
                        }
                    }

                    Ok(Auth::Accept)
                }
                Ok(_) => {
                    tracing::debug!(
                        user = %user,
                        peer = ?peer_addr,
                        key_type = %public_key.algorithm(),
                        "Public key authentication rejected"
                    );

                    // Record failure for ban tracking
                    if let Some(ref limiter) = auth_rate_limiter {
                        if let Some(ip) = peer_addr.map(|a| a.ip()) {
                            let banned = limiter.record_failure(ip).await;
                            if banned {
                                tracing::warn!(
                                    user = %user,
                                    peer = ?peer_addr,
                                    "IP banned due to too many failed auth attempts"
                                );
                            }
                        }
                    }

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
                Err(e) => {
                    tracing::error!(
                        user = %user,
                        peer = ?peer_addr,
                        error = %e,
                        "Error during public key verification"
                    );

                    // Record failure for ban tracking
                    if let Some(ref limiter) = auth_rate_limiter {
                        if let Some(ip) = peer_addr.map(|a| a.ip()) {
                            limiter.record_failure(ip).await;
                        }
                    }

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
        }
    }

    /// Handle password authentication.
    ///
    /// Verifies the password against configured users using the auth provider.
    /// Implements rate limiting and tracks failed authentication attempts.
    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
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

        // Clone what we need for the async block
        let auth_provider = Arc::clone(&self.auth_provider);
        let sessions = Arc::clone(&self.sessions);
        let rate_limiter = self.rate_limiter.clone();
        let auth_rate_limiter = self.auth_rate_limiter.clone();
        let peer_addr = self.peer_addr;
        let user = user.to_string();
        // Use Zeroizing to ensure password is securely cleared from memory when dropped
        let password = Zeroizing::new(password.to_string());
        let allow_password = self.config.allow_password_auth;

        // Get mutable reference to session_info for authentication update
        let session_info = &mut self.session_info;

        async move {
            // Check if IP is banned (fail2ban-like check)
            if let Some(ref limiter) = auth_rate_limiter {
                if let Some(ip) = peer_addr.map(|a| a.ip()) {
                    if limiter.is_banned(&ip).await {
                        tracing::warn!(
                            user = %user,
                            peer = ?peer_addr,
                            "Rejected password auth from banned IP"
                        );
                        return Ok(Auth::Reject {
                            proceed_with_methods: None,
                            partial_success: false,
                        });
                    }
                }
            }

            // Check if password auth is enabled
            if !allow_password {
                tracing::debug!(
                    user = %user,
                    "Password authentication disabled"
                );
                let proceed = if methods.is_empty() {
                    None
                } else {
                    Some(methods)
                };
                return Ok(Auth::Reject {
                    proceed_with_methods: proceed,
                    partial_success: false,
                });
            }

            if exceeded {
                tracing::warn!(
                    user = %user,
                    peer = ?peer_addr,
                    "Max authentication attempts exceeded"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }

            // Check rate limiting based on peer address
            let rate_key = peer_addr
                .map(|addr| addr.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            if rate_limiter.is_rate_limited(&rate_key).await {
                tracing::warn!(
                    user = %user,
                    peer = ?peer_addr,
                    "Rate limited password authentication attempt"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }

            // Try to acquire a rate limit token
            if rate_limiter.try_acquire(&rate_key).await.is_err() {
                tracing::warn!(
                    user = %user,
                    peer = ?peer_addr,
                    "Rate limit exceeded for password authentication"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }

            // Verify password using auth provider
            match auth_provider.verify_password(&user, &password).await {
                Ok(result) if result.is_accepted() => {
                    tracing::info!(
                        user = %user,
                        peer = ?peer_addr,
                        "Password authentication successful"
                    );

                    // Try to authenticate session with per-user limits
                    if let Some(ref info) = session_info {
                        let mut sessions_guard = sessions.write().await;
                        match sessions_guard.authenticate_session(info.id, &user) {
                            Ok(()) => {
                                // Also update local session info
                                drop(sessions_guard);
                                if let Some(ref mut local_info) = session_info {
                                    local_info.authenticate(&user);
                                }
                            }
                            Err(SessionError::TooManyUserSessions { user: u, limit }) => {
                                tracing::warn!(
                                    user = %u,
                                    limit = limit,
                                    peer = ?peer_addr,
                                    "Per-user session limit reached, rejecting authentication"
                                );
                                return Ok(Auth::Reject {
                                    proceed_with_methods: None,
                                    partial_success: false,
                                });
                            }
                            Err(e) => {
                                tracing::error!(
                                    user = %user,
                                    error = %e,
                                    "Failed to authenticate session"
                                );
                                return Ok(Auth::Reject {
                                    proceed_with_methods: None,
                                    partial_success: false,
                                });
                            }
                        }
                    }

                    // Record success to reset failure counter
                    if let Some(ref limiter) = auth_rate_limiter {
                        if let Some(ip) = peer_addr.map(|a| a.ip()) {
                            limiter.record_success(&ip).await;
                        }
                    }

                    Ok(Auth::Accept)
                }
                Ok(_) => {
                    tracing::debug!(
                        user = %user,
                        peer = ?peer_addr,
                        "Password authentication rejected"
                    );

                    // Record failure for ban tracking
                    if let Some(ref limiter) = auth_rate_limiter {
                        if let Some(ip) = peer_addr.map(|a| a.ip()) {
                            let banned = limiter.record_failure(ip).await;
                            if banned {
                                tracing::warn!(
                                    user = %user,
                                    peer = ?peer_addr,
                                    "IP banned due to too many failed password auth attempts"
                                );
                            }
                        }
                    }

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
                Err(e) => {
                    tracing::error!(
                        user = %user,
                        peer = ?peer_addr,
                        error = %e,
                        "Error during password verification"
                    );

                    // Record failure for ban tracking
                    if let Some(ref limiter) = auth_rate_limiter {
                        if let Some(ip) = peer_addr.map(|a| a.ip()) {
                            limiter.record_failure(ip).await;
                        }
                    }

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
            tracing::warn!("PTY request for unknown channel");
            let _ = session.channel_failure(channel_id);
        }

        async { Ok(()) }
    }

    /// Handle exec request.
    ///
    /// Executes the requested command and streams output back to the client.
    /// The command is executed via the configured shell with proper environment
    /// setup based on the authenticated user.
    fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        // Parse command from data
        let command = match std::str::from_utf8(data) {
            Ok(cmd) => cmd.to_string(),
            Err(e) => {
                tracing::warn!(
                    channel = ?channel_id,
                    error = %e,
                    "Invalid UTF-8 in exec command"
                );
                let _ = session.channel_failure(channel_id);
                return async { Ok(()) }.boxed();
            }
        };

        tracing::debug!(
            channel = ?channel_id,
            command = %command,
            "Exec request received"
        );

        // Update channel state
        if let Some(channel_state) = self.channels.get_mut(&channel_id) {
            channel_state.set_exec(command.clone());
        }

        // Get authenticated user info
        let username = match self.session_info.as_ref().and_then(|s| s.user.clone()) {
            Some(user) => user,
            None => {
                tracing::warn!(
                    channel = ?channel_id,
                    "Exec request without authenticated user"
                );
                let _ = session.channel_failure(channel_id);
                return async { Ok(()) }.boxed();
            }
        };

        // Clone what we need for the async block
        let auth_provider = Arc::clone(&self.auth_provider);
        let exec_config = self.config.exec.clone();
        let handle = session.handle();
        let peer_addr = self.peer_addr;

        // Signal channel success before executing
        let _ = session.channel_success(channel_id);

        async move {
            // Get user info from auth provider
            let user_info = match auth_provider.get_user_info(&username).await {
                Ok(Some(info)) => info,
                Ok(None) => {
                    tracing::error!(
                        user = %username,
                        "User not found after authentication"
                    );
                    let _ = handle.exit_status_request(channel_id, 1).await;
                    let _ = handle.eof(channel_id).await;
                    let _ = handle.close(channel_id).await;
                    return Ok(());
                }
                Err(e) => {
                    tracing::error!(
                        user = %username,
                        error = %e,
                        "Failed to get user info"
                    );
                    let _ = handle.exit_status_request(channel_id, 1).await;
                    let _ = handle.eof(channel_id).await;
                    let _ = handle.close(channel_id).await;
                    return Ok(());
                }
            };

            tracing::info!(
                user = %username,
                peer = ?peer_addr,
                command = %command,
                "Executing command"
            );

            // Create executor and run command
            let executor = CommandExecutor::new(exec_config);
            let exit_code = match executor
                .execute(&command, &user_info, channel_id, handle.clone())
                .await
            {
                Ok(code) => code,
                Err(e) => {
                    tracing::error!(
                        user = %username,
                        command = %command,
                        error = %e,
                        "Command execution failed"
                    );
                    1 // Default error exit code
                }
            };

            tracing::debug!(
                user = %username,
                command = %command,
                exit_code = %exit_code,
                "Command completed"
            );

            // Send exit status, EOF, and close channel
            let _ = handle
                .exit_status_request(channel_id, exit_code as u32)
                .await;
            let _ = handle.eof(channel_id).await;
            let _ = handle.close(channel_id).await;

            Ok(())
        }
        .boxed()
    }

    /// Handle shell request.
    ///
    /// Starts an interactive shell session for the authenticated user.
    /// Uses Handle-based I/O for PTY output to avoid notify_waiters() race conditions.
    /// The key insight is that Handle::data() uses notify_one() which stores a permit
    /// if no task is waiting, while ChannelTx uses notify_waiters() which only wakes
    /// tasks that are currently waiting. This causes intermittent failures with rapid
    /// connections when using ChannelStream-based I/O.
    fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(channel = ?channel_id, "Shell request");

        // Get authenticated user info
        let username = match self.session_info.as_ref().and_then(|s| s.user.clone()) {
            Some(user) => user,
            None => {
                tracing::warn!(
                    channel = ?channel_id,
                    "Shell request without authenticated user"
                );
                let _ = session.channel_failure(channel_id);
                return async { Ok(()) }.boxed();
            }
        };

        // Get PTY configuration
        let pty_config = match self.channels.get_mut(&channel_id) {
            Some(state) => {
                let config = state
                    .pty
                    .as_ref()
                    .map(|pty| {
                        PtyMasterConfig::new(
                            pty.term.clone(),
                            pty.col_width,
                            pty.row_height,
                            pty.pix_width,
                            pty.pix_height,
                        )
                    })
                    .unwrap_or_default();
                state.set_shell();
                config
            }
            None => {
                tracing::warn!(
                    channel = ?channel_id,
                    "Shell request but channel state not found"
                );
                let _ = session.channel_failure(channel_id);
                return async { Ok(()) }.boxed();
            }
        };

        // Create shell session (sync) to get the PTY
        let shell_session = match ShellSession::new(channel_id, pty_config.clone()) {
            Ok(session) => session,
            Err(e) => {
                tracing::error!(
                    channel = ?channel_id,
                    error = %e,
                    "Failed to create shell session"
                );
                let _ = session.channel_failure(channel_id);
                return async { Ok(()) }.boxed();
            }
        };

        // Get PTY reference for window_change_request
        let pty = Arc::clone(shell_session.pty());

        // Create channel for SSH -> PTY data (client input)
        let (data_tx, data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

        // Store handles in channel state for window_change callbacks and data forwarding
        if let Some(state) = self.channels.get_mut(&channel_id) {
            state.set_shell_handles(data_tx, Arc::clone(&pty));
        }

        // Clone what we need for the async block
        let auth_provider = Arc::clone(&self.auth_provider);
        let peer_addr = self.peer_addr;
        let handle = session.handle();

        // Signal success before starting shell
        let _ = session.channel_success(channel_id);

        async move {
            // Get user info from auth provider
            let user_info = match auth_provider.get_user_info(&username).await {
                Ok(Some(info)) => info,
                Ok(None) => {
                    tracing::error!(
                        user = %username,
                        "User not found after authentication for shell"
                    );
                    return Ok(());
                }
                Err(e) => {
                    tracing::error!(
                        user = %username,
                        error = %e,
                        "Failed to get user info for shell"
                    );
                    return Ok(());
                }
            };

            tracing::info!(
                user = %username,
                peer = ?peer_addr,
                term = %pty_config.term,
                size = %format!("{}x{}", pty_config.col_width, pty_config.row_height),
                "Starting shell session"
            );

            // Spawn shell process (async part)
            let mut shell_session = shell_session;
            if let Err(e) = shell_session.spawn_shell_process(&user_info).await {
                tracing::error!(
                    user = %username,
                    error = %e,
                    "Failed to spawn shell process"
                );
                return Ok(());
            }

            // Get child process for the I/O loop
            let child = shell_session.take_child();

            tracing::debug!(
                channel = ?channel_id,
                "Spawning shell I/O task with Handle-based approach"
            );

            // IMPORTANT: Spawn the I/O loop instead of awaiting it!
            // The session loop needs to keep running to flush Handle::data() messages
            // to the network. If we await here, the session loop is blocked.
            tokio::spawn(async move {
                let exit_code = crate::server::shell::run_shell_io_loop_with_handle(
                    channel_id,
                    pty,
                    child,
                    handle.clone(),
                    data_rx,
                )
                .await;

                tracing::info!(
                    channel = ?channel_id,
                    exit_code = exit_code,
                    "Shell session completed"
                );

                // Send exit status, EOF, and close channel (same as exec_request)
                // This is critical - without these, the SSH client waits indefinitely
                let _ = handle
                    .exit_status_request(channel_id, exit_code as u32)
                    .await;
                let _ = handle.eof(channel_id).await;
                let _ = handle.close(channel_id).await;
            });

            tracing::debug!(
                channel = ?channel_id,
                "Shell I/O task spawned, handler returning"
            );

            Ok(())
        }
        .boxed()
    }

    /// Handle subsystem request.
    ///
    /// Handles SFTP subsystem requests by creating an SftpHandler and running
    /// the SFTP server on the channel stream.
    fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(
            subsystem = %name,
            channel = ?channel_id,
            peer = ?self.peer_addr,
            "Subsystem request"
        );

        // Handle SFTP subsystem
        if name == "sftp" {
            // Check if SFTP is enabled (default: enabled)
            // In future, this should check config.sftp.enabled

            // Get the channel from our stored channels
            let channel = self.channels.get_mut(&channel_id).and_then(|state| {
                state.set_sftp();
                state.take_channel()
            });

            let channel = match channel {
                Some(ch) => ch,
                None => {
                    tracing::warn!(
                        channel = ?channel_id,
                        "SFTP request but channel not found or already taken"
                    );
                    let _ = session.channel_failure(channel_id);
                    return async { Ok(()) }.boxed();
                }
            };

            // Get authenticated user info
            let username = match self.session_info.as_ref().and_then(|s| s.user.clone()) {
                Some(user) => user,
                None => {
                    tracing::warn!(
                        channel = ?channel_id,
                        "SFTP request without authenticated user"
                    );
                    let _ = session.channel_failure(channel_id);
                    return async { Ok(()) }.boxed();
                }
            };

            // Clone what we need for the async block
            let auth_provider = Arc::clone(&self.auth_provider);
            let peer_addr = self.peer_addr;

            // Signal success before spawning the SFTP handler
            let _ = session.channel_success(channel_id);

            return async move {
                // Get user info from auth provider
                let user_info = match auth_provider.get_user_info(&username).await {
                    Ok(Some(info)) => info,
                    Ok(None) => {
                        tracing::error!(
                            user = %username,
                            "User not found after authentication for SFTP"
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::error!(
                            user = %username,
                            error = %e,
                            "Failed to get user info for SFTP"
                        );
                        return Ok(());
                    }
                };

                tracing::info!(
                    user = %username,
                    peer = ?peer_addr,
                    home = %user_info.home_dir.display(),
                    "Starting SFTP session"
                );

                // Create SFTP handler with user's home directory as root
                let sftp_handler = SftpHandler::new(user_info.clone(), Some(user_info.home_dir));

                // Run SFTP server on the channel stream
                russh_sftp::server::run(channel.into_stream(), sftp_handler).await;

                tracing::info!(
                    user = %username,
                    peer = ?peer_addr,
                    "SFTP session ended"
                );

                Ok(())
            }
            .boxed();
        }

        // Unknown subsystem - reject
        tracing::debug!(
            subsystem = %name,
            "Unknown subsystem, rejecting"
        );
        let _ = session.channel_failure(channel_id);
        async { Ok(()) }.boxed()
    }

    /// Handle incoming data from the client.
    ///
    /// Forwards data to the active shell session if one exists.
    fn data(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(
            channel = ?channel_id,
            bytes = %data.len(),
            "Received data from client"
        );

        // Get the data sender if there's an active shell session
        let data_sender = self
            .channels
            .get(&channel_id)
            .and_then(|state| state.shell_data_tx.clone());

        if let Some(tx) = data_sender {
            tracing::debug!(
                channel = ?channel_id,
                bytes = %data.len(),
                "Forwarding data to shell via mpsc"
            );
            let data = data.to_vec();
            return async move {
                if let Err(e) = tx.send(data).await {
                    tracing::debug!(
                        channel = ?channel_id,
                        error = %e,
                        "Error forwarding data to shell"
                    );
                } else {
                    tracing::debug!(
                        channel = ?channel_id,
                        "Data forwarded to shell successfully"
                    );
                }
                Ok(())
            }
            .boxed();
        } else {
            tracing::debug!(
                channel = ?channel_id,
                "No shell_data_tx found for channel, dropping data"
            );
        }

        async { Ok(()) }.boxed()
    }

    /// Handle window size change request.
    ///
    /// Updates the PTY window size for active shell sessions.
    #[allow(clippy::too_many_arguments)]
    fn window_change_request(
        &mut self,
        channel_id: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(
            channel = ?channel_id,
            cols = col_width,
            rows = row_height,
            "Window change request"
        );

        // Update stored PTY config
        if let Some(state) = self.channels.get_mut(&channel_id) {
            if let Some(ref mut pty) = state.pty {
                pty.col_width = col_width;
                pty.row_height = row_height;
                pty.pix_width = pix_width;
                pty.pix_height = pix_height;
            }
        }

        // Get the PTY mutex if there's an active shell session
        let pty_mutex = self
            .channels
            .get(&channel_id)
            .and_then(|state| state.shell_pty.clone());

        if let Some(pty) = pty_mutex {
            return async move {
                let mut pty_guard = pty.write().await;
                if let Err(e) = pty_guard.resize(col_width, row_height) {
                    tracing::debug!(
                        channel = ?channel_id,
                        error = %e,
                        "Error resizing shell PTY"
                    );
                }
                Ok(())
            }
            .boxed();
        }

        async { Ok(()) }.boxed()
    }

    /// Handle channel EOF from the client.
    fn channel_eof(
        &mut self,
        channel_id: ChannelId,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!("Channel EOF received");

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
        tracing::debug!("Channel closed");

        self.channels.remove(&channel_id);
        async { Ok(()) }
    }
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        if let Some(ref info) = self.session_info {
            let session_id = info.id;

            tracing::info!(
                session_id = %session_id,
                peer = ?self.peer_addr,
                duration_secs = %info.duration_secs(),
                authenticated = %info.authenticated,
                "Session ended"
            );

            // Remove session from manager
            // Note: This uses try_write which is safe here because:
            // 1. Drop is called outside of async context (during connection cleanup)
            // 2. The lock is held only briefly to remove the session
            // 3. This prevents resource leaks by ensuring cleanup always happens
            if let Ok(mut sessions_guard) = self.sessions.try_write() {
                sessions_guard.remove(session_id);
                tracing::debug!(
                    session_id = %session_id,
                    "Session removed from manager"
                );
            } else {
                tracing::warn!(
                    session_id = %session_id,
                    "Failed to acquire lock to remove session (lock contention)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::auth_types::{AuthResult, UserInfo};
    use async_trait::async_trait;
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

    /// Test auth provider that always accepts
    struct AcceptAllAuthProvider;

    #[async_trait]
    impl AuthProvider for AcceptAllAuthProvider {
        async fn verify_publickey(
            &self,
            _username: &str,
            _key: &ssh_key::PublicKey,
        ) -> anyhow::Result<AuthResult> {
            Ok(AuthResult::Accept)
        }

        async fn verify_password(
            &self,
            _username: &str,
            _password: &str,
        ) -> anyhow::Result<AuthResult> {
            Ok(AuthResult::Accept)
        }

        async fn get_user_info(&self, username: &str) -> anyhow::Result<Option<UserInfo>> {
            Ok(Some(UserInfo::new(username)))
        }

        async fn user_exists(&self, _username: &str) -> anyhow::Result<bool> {
            Ok(true)
        }
    }

    /// Test auth provider that always rejects
    #[allow(dead_code)] // May be used in future tests
    struct RejectAllAuthProvider;

    #[async_trait]
    impl AuthProvider for RejectAllAuthProvider {
        async fn verify_publickey(
            &self,
            _username: &str,
            _key: &ssh_key::PublicKey,
        ) -> anyhow::Result<AuthResult> {
            Ok(AuthResult::Reject)
        }

        async fn verify_password(
            &self,
            _username: &str,
            _password: &str,
        ) -> anyhow::Result<AuthResult> {
            Ok(AuthResult::Reject)
        }

        async fn get_user_info(&self, _username: &str) -> anyhow::Result<Option<UserInfo>> {
            Ok(None)
        }

        async fn user_exists(&self, _username: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn test_handler_creation() {
        let handler = SshHandler::new(Some(test_addr()), test_config(), test_sessions());

        assert_eq!(handler.peer_addr(), Some(test_addr()));
        // Session ID is assigned at creation time
        assert!(handler.session_id().is_some());
        assert!(!handler.is_authenticated());
        assert!(handler.username().is_none());
    }

    #[test]
    fn test_handler_with_custom_auth_provider() {
        let handler = SshHandler::with_auth_provider(
            Some(test_addr()),
            test_config(),
            test_sessions(),
            Arc::new(AcceptAllAuthProvider),
        );

        assert_eq!(handler.peer_addr(), Some(test_addr()));
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
        let config = Arc::new(ServerConfig::builder().max_auth_attempts(3).build());
        let handler = SshHandler::new(Some(test_addr()), config, test_sessions());

        assert!(!handler.auth_attempts_exceeded());
    }

    #[test]
    fn test_handler_no_peer_addr() {
        let handler = SshHandler::new(None, test_config(), test_sessions());

        assert!(handler.peer_addr().is_none());
        // Session ID is assigned at creation time even without peer address
        assert!(handler.session_id().is_some());
        assert!(!handler.is_authenticated());
    }

    #[test]
    fn test_allowed_methods_publickey_only() {
        let config = Arc::new(
            ServerConfig::builder()
                .allow_password_auth(false)
                .allow_publickey_auth(true)
                .allow_keyboard_interactive(false)
                .build(),
        );
        let handler = SshHandler::new(Some(test_addr()), config, test_sessions());
        let methods = handler.allowed_methods();

        assert!(methods.contains(&MethodKind::PublicKey));
        assert!(!methods.contains(&MethodKind::Password));
        assert!(!methods.contains(&MethodKind::KeyboardInteractive));
    }

    #[test]
    fn test_allowed_methods_password_only() {
        let config = Arc::new(
            ServerConfig::builder()
                .allow_password_auth(true)
                .allow_publickey_auth(false)
                .allow_keyboard_interactive(false)
                .build(),
        );
        let handler = SshHandler::new(Some(test_addr()), config, test_sessions());
        let methods = handler.allowed_methods();

        assert!(!methods.contains(&MethodKind::PublicKey));
        assert!(methods.contains(&MethodKind::Password));
        assert!(!methods.contains(&MethodKind::KeyboardInteractive));
    }
}

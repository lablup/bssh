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

//! SSH connection establishment for interactive sessions

use anyhow::{Context, Result};
use crossterm::terminal;
use russh::Channel;
use russh::client::Msg;
use std::io::{self, IsTerminal, Write};
use tokio::time::{Duration, timeout};
use zeroize::Zeroizing;

use crate::jump::{JumpHostChain, parse_jump_hosts, parser::JumpHost};
use crate::node::Node;
use crate::ssh::{
    SessionPolicy, SessionPurpose, SessionRequest,
    known_hosts::get_check_method_for_target,
    tokio_client::{
        AuthMethod, Client, Error as SshError, ServerCheckMethod, SshConnectionConfig,
        SshConnectionConfigResolver,
    },
};

use super::types::{InteractiveCommand, NodeSession};

fn build_interactive_jump_chain(
    jump_hosts: Vec<JumpHost>,
    adjusted_timeout: Duration,
    ssh_connection_config: &SshConnectionConfig,
    resolver: Option<&SshConnectionConfigResolver>,
    session_purpose: SessionPurpose,
) -> JumpHostChain {
    let mut chain = JumpHostChain::new(jump_hosts)
        .with_connect_timeout(adjusted_timeout)
        .with_command_timeout(Duration::from_secs(300))
        .with_ssh_connection_config(ssh_connection_config.clone())
        .with_session_purpose(session_purpose);
    if let Some(resolver) = resolver {
        chain = chain.with_ssh_connection_config_resolver(resolver.clone());
    }
    chain
}

fn interactive_session_purpose(session_policy: Option<&SessionPolicy>) -> SessionPurpose {
    session_policy.map_or(SessionPurpose::Interactive, SessionPolicy::purpose)
}

impl InteractiveCommand {
    /// Helper function to establish SSH connection with proper error handling and rate limiting
    /// This eliminates code duplication across different connection paths and prevents brute-force attacks
    ///
    /// If `allow_password_fallback` is true and key authentication fails, it will prompt for password
    /// and retry with password authentication (matching OpenSSH behavior).
    ///
    /// The `ssh_config` parameter allows configuring SSH connection settings like keepalive intervals.
    #[allow(clippy::too_many_arguments)]
    async fn establish_connection(
        addr: (&str, u16),
        username: &str,
        auth_method: AuthMethod,
        check_method: ServerCheckMethod,
        host: &str,
        port: u16,
        allow_password_fallback: bool,
        ssh_config: &SshConnectionConfig,
        session_purpose: SessionPurpose,
    ) -> Result<Client> {
        const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;
        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);
        let ssh_config = ssh_config.clone().with_session_purpose(session_purpose);

        // SECURITY: Add a small delay before connection attempts to prevent rapid-fire attempts
        // This helps mitigate brute-force attacks and prevents triggering fail2ban too quickly
        // Using exponential backoff would be ideal for retries, but since we don't retry here,
        // a fixed small delay is sufficient to prevent abuse
        const RATE_LIMIT_DELAY: Duration = Duration::from_millis(100);
        tokio::time::sleep(RATE_LIMIT_DELAY).await;

        // SECURITY: Capture start time for timing attack mitigation
        let start_time = std::time::Instant::now();

        // Use connect_with_ssh_config to properly apply keepalive settings
        let result = timeout(
            connect_timeout,
            Client::connect_with_ssh_config(
                addr,
                username,
                auth_method,
                check_method.clone(),
                &ssh_config,
            ),
        )
        .await
        .map_err(|_| SshError::ConnectionTimeout {
            host: host.to_string(),
            port,
            seconds: SSH_CONNECT_TIMEOUT_SECS,
            stage: "connection setup or authentication",
        })?;

        // Check if authentication failed and password fallback is allowed
        // This matches SSH key failures as well as SSH agent authentication failures
        // Also handles the case where russh disconnects during authentication failure
        // (which returns SshError(Disconnect) instead of KeyAuthFailed)
        let result = match result {
            Err(ref err)
                if allow_password_fallback
                    && !ssh_config.auth_policy.batch_mode
                    && ssh_config.auth_policy.method_enabled("password")
                    && io::stdin().is_terminal()
                    && is_auth_error_for_password_fallback(err) =>
            {
                tracing::debug!(
                    "SSH authentication failed for {username}@{host}:{port} ({err}), attempting password fallback"
                );

                // Prompt for password (matching OpenSSH behavior)
                let password = Self::prompt_password(username, host).await?;

                // Retry with password authentication
                let password_auth = AuthMethod::with_password(&password);

                // Small delay before retry to prevent rapid attempts
                tokio::time::sleep(Duration::from_millis(500)).await;

                // Use connect_with_ssh_config for password retry as well
                timeout(
                    connect_timeout,
                    Client::connect_with_ssh_config(
                        addr,
                        username,
                        password_auth,
                        check_method,
                        &ssh_config,
                    ),
                )
                .await
                .map_err(|_| SshError::ConnectionTimeout {
                    host: host.to_string(),
                    port,
                    seconds: SSH_CONNECT_TIMEOUT_SECS,
                    stage: "password authentication retry",
                })?
                .with_context(|| format!("SSH connection failed to {host}:{port}"))
            }
            other => other.with_context(|| format!("SSH connection failed to {host}:{port}")),
        };

        // SECURITY: Normalize timing to prevent timing attacks
        // Ensure all authentication attempts take at least 500ms to complete
        // This prevents attackers from inferring whether authentication failed due to
        // invalid username vs invalid password based on response time
        const MIN_AUTH_DURATION: Duration = Duration::from_millis(500);
        let elapsed = start_time.elapsed();
        if elapsed < MIN_AUTH_DURATION {
            tokio::time::sleep(MIN_AUTH_DURATION - elapsed).await;
        }

        result
    }

    fn session_purpose(&self) -> SessionPurpose {
        interactive_session_purpose(self.session_policy.as_ref())
    }

    fn build_jump_chain(
        &self,
        jump_hosts: Vec<JumpHost>,
        adjusted_timeout: Duration,
    ) -> JumpHostChain {
        build_interactive_jump_chain(
            jump_hosts,
            adjusted_timeout,
            &self.ssh_connection_config,
            self.ssh_connection_config_resolver.as_ref(),
            self.session_purpose(),
        )
        .with_ssh_password(self.ssh_password.clone())
    }

    /// Prompt for password with secure handling
    async fn prompt_password(username: &str, host: &str) -> Result<Zeroizing<String>> {
        let username = username.to_string();
        let host = host.to_string();

        tokio::task::spawn_blocking(move || {
            let password = Zeroizing::new(
                rpassword::prompt_password(format!("{username}@{host}'s password: "))
                    .with_context(|| "Failed to read password")?,
            );
            Ok(password)
        })
        .await
        .with_context(|| "Password prompt task failed")?
    }

    /// Determine authentication method based on node and config (same logic as exec mode)
    pub(super) async fn determine_auth_method(&self, node: &Node) -> Result<AuthMethod> {
        // Use centralized authentication logic from auth module
        let mut auth_ctx = crate::ssh::AuthContext::new(node.username.clone(), node.host.clone())
            .with_context(|| {
            format!("Invalid credentials for {}@{}", node.username, node.host)
        })?;

        // Set key path if provided
        if let Some(ref path) = self.key_path {
            auth_ctx = auth_ctx
                .with_key_path(Some(path.clone()))
                .with_context(|| format!("Invalid SSH key path: {path:?}"))?;
        }

        auth_ctx = auth_ctx
            .with_agent(self.use_agent)
            .with_password(self.use_password)
            .with_password_fallback(!self.use_password) // Enable fallback only if not using explicit password
            .with_pre_collected_password(self.ssh_password.clone());
        auth_ctx = auth_ctx.with_policy(self.ssh_connection_config.auth_policy.clone());

        // Set macOS Keychain integration if available
        #[cfg(target_os = "macos")]
        {
            auth_ctx = auth_ctx.with_keychain(self.use_keychain);
        }

        auth_ctx.determine_method().await
    }

    /// Select nodes to connect to based on configuration
    pub(super) fn select_nodes_to_connect(&self) -> Result<Vec<Node>> {
        if self.single_node {
            // In single-node mode, let user select a node or use the first one
            if self.nodes.is_empty() {
                anyhow::bail!("No nodes available for connection");
            }

            if self.nodes.len() == 1 {
                Ok(vec![self.nodes[0].clone()])
            } else {
                // Show node selection menu
                println!("Available nodes:");
                for (i, node) in self.nodes.iter().enumerate() {
                    println!("  [{}] {}", i + 1, node);
                }
                print!("Select node (1-{}): ", self.nodes.len());
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                let selection: usize = input.trim().parse().context("Invalid node selection")?;

                if selection == 0 || selection > self.nodes.len() {
                    anyhow::bail!("Invalid node selection");
                }

                Ok(vec![self.nodes[selection - 1].clone()])
            }
        } else {
            Ok(self.nodes.clone())
        }
    }

    /// Run post-authentication policy and open a session channel while
    /// preserving ownership of the channel for the interactive byte-stream loop.
    async fn open_interactive_channel(
        &self,
        client: &Client,
        term_type: &str,
        width: u32,
        height: u32,
    ) -> Result<Channel<Msg>> {
        if let Some(policy) = self.session_policy.as_ref() {
            if !matches!(policy.request, SessionRequest::Shell) {
                anyhow::bail!("Interactive mode requires a shell session policy");
            }
            policy.run_local_command().await?;
        }

        client
            .request_interactive_shell(term_type, width, height)
            .await
            .context("Failed to open interactive session channel")
    }

    /// Connect to a single node and establish an interactive shell
    pub(super) async fn connect_to_node(&self, node: Node) -> Result<NodeSession> {
        // Determine authentication method using the same logic as exec mode
        let auth_method = self.determine_auth_method(&node).await?;

        // Set up host key checking using the configured strict mode
        let check_method = get_check_method_for_target(
            self.strict_mode,
            &self.ssh_connection_config,
            &node.host,
            node.port,
            &node.username,
        );

        // Connect with timeout
        let addr = (node.host.as_str(), node.port);

        // Create client connection - either direct or through jump hosts
        let client = if let Some(ref jump_spec) = self.jump_hosts {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection");

                // Use the helper function to establish connection
                // Enable password fallback for interactive mode (matches OpenSSH behavior)
                Self::establish_connection(
                    addr,
                    &node.username,
                    auth_method.clone(),
                    check_method.clone(),
                    &node.host,
                    node.port,
                    !self.use_password, // Allow fallback unless explicit password mode
                    &self.ssh_connection_config,
                    self.session_purpose(),
                )
                .await?
            } else {
                tracing::info!(
                    "Connecting to {}:{} via {} jump host(s) for interactive session",
                    node.host,
                    node.port,
                    jump_hosts.len()
                );

                // Create jump host chain with dynamic timeout based on hop count
                // SECURITY: Use saturating arithmetic to prevent integer overflow
                // Cap maximum timeout at 10 minutes to prevent DoS
                const MAX_TIMEOUT_SECS: u64 = 600; // 10 minutes max
                const BASE_TIMEOUT: u64 = 30;
                const PER_HOP_TIMEOUT: u64 = 15;

                let hop_count = jump_hosts.len();
                let adjusted_timeout = Duration::from_secs(
                    BASE_TIMEOUT
                        .saturating_add(PER_HOP_TIMEOUT.saturating_mul(hop_count as u64))
                        .min(MAX_TIMEOUT_SECS),
                );

                // Pass SSH connection config to jump host chain for keepalive settings.
                // Also pass the dispatcher's pre-collected password so jump-host
                // authentication consumes it instead of re-prompting per call. See #200.
                let chain = self.build_jump_chain(jump_hosts, adjusted_timeout);

                // Connect through the chain
                let connection = timeout(
                    adjusted_timeout,
                    chain.connect(
                        &node.host,
                        node.port,
                        &node.username,
                        auth_method.clone(),
                        self.key_path.as_deref(),
                        Some(self.strict_mode),
                        self.use_agent,
                        self.use_password,
                    ),
                )
                .await
                .map_err(|_| SshError::ConnectionTimeout {
                    host: node.host.clone(),
                    port: node.port,
                    seconds: adjusted_timeout.as_secs(),
                    stage: "jump-host connection setup or authentication",
                })?
                .with_context(|| {
                    format!(
                        "Failed to establish jump host connection to {}:{}",
                        node.host, node.port
                    )
                })?;

                tracing::info!(
                    "Jump host connection established for interactive session: {}",
                    connection.jump_info.path_description()
                );

                connection.client
            }
        } else {
            // Direct connection
            tracing::debug!("Using direct connection (no jump hosts)");

            // Use the helper function to establish connection
            // Enable password fallback for interactive mode (matches OpenSSH behavior)
            Self::establish_connection(
                addr,
                &node.username,
                auth_method,
                check_method,
                &node.host,
                node.port,
                !self.use_password, // Allow fallback unless explicit password mode
                &self.ssh_connection_config,
                self.session_purpose(),
            )
            .await?
        };

        // Get terminal dimensions
        let (width, height) = terminal::size().unwrap_or((80, 24));

        let channel = self
            .open_interactive_channel(
                &client,
                "xterm-256color",
                u32::from(width),
                u32::from(height),
            )
            .await?;
        channel
            .request_shell(false)
            .await
            .context("Failed to request interactive shell")?;

        // Note: Terminal resize handling would require channel cloning or Arc<Mutex>
        // which russh doesn't support directly. This is a limitation of the current implementation.

        // Set initial working directory if specified
        let working_dir = if let Some(ref dir) = self.work_dir {
            // Send cd command to set initial directory
            let cmd = format!("cd {dir} && pwd\n");
            channel.data(cmd.as_bytes()).await?;
            dir.clone()
        } else {
            // Get current directory
            let pwd_cmd = b"pwd\n";
            channel.data(&pwd_cmd[..]).await?;
            String::from("~")
        };

        Ok(NodeSession::new(node, client, channel, working_dir))
    }

    /// Connect to a single node and establish a PTY-enabled SSH channel
    pub(super) async fn connect_to_node_pty(&self, node: Node) -> Result<(Client, Channel<Msg>)> {
        // Determine authentication method using the same logic as exec mode
        let auth_method = self.determine_auth_method(&node).await?;

        // Set up host key checking using the configured strict mode
        let check_method = get_check_method_for_target(
            self.strict_mode,
            &self.ssh_connection_config,
            &node.host,
            node.port,
            &node.username,
        );

        // Connect with timeout
        let addr = (node.host.as_str(), node.port);

        // Create client connection - either direct or through jump hosts
        let client = if let Some(ref jump_spec) = self.jump_hosts {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection for PTY");

                // Use the helper function to establish connection
                // Enable password fallback for interactive mode (matches OpenSSH behavior)
                Self::establish_connection(
                    addr,
                    &node.username,
                    auth_method.clone(),
                    check_method.clone(),
                    &node.host,
                    node.port,
                    !self.use_password, // Allow fallback unless explicit password mode
                    &self.ssh_connection_config,
                    self.session_purpose(),
                )
                .await?
            } else {
                tracing::info!(
                    "Connecting to {}:{} via {} jump host(s) for PTY session",
                    node.host,
                    node.port,
                    jump_hosts.len()
                );

                // Create jump host chain with dynamic timeout based on hop count
                // SECURITY: Use saturating arithmetic to prevent integer overflow
                // Cap maximum timeout at 10 minutes to prevent DoS
                const MAX_TIMEOUT_SECS: u64 = 600; // 10 minutes max
                const BASE_TIMEOUT: u64 = 30;
                const PER_HOP_TIMEOUT: u64 = 15;

                let hop_count = jump_hosts.len();
                let adjusted_timeout = Duration::from_secs(
                    BASE_TIMEOUT
                        .saturating_add(PER_HOP_TIMEOUT.saturating_mul(hop_count as u64))
                        .min(MAX_TIMEOUT_SECS),
                );

                // Pass SSH connection config to jump host chain for keepalive settings.
                // Also pass the dispatcher's pre-collected password so jump-host
                // authentication consumes it instead of re-prompting per call. See #200.
                let chain = self.build_jump_chain(jump_hosts, adjusted_timeout);

                // Connect through the chain
                let connection = timeout(
                    adjusted_timeout,
                    chain.connect(
                        &node.host,
                        node.port,
                        &node.username,
                        auth_method.clone(),
                        self.key_path.as_deref(),
                        Some(self.strict_mode),
                        self.use_agent,
                        self.use_password,
                    ),
                )
                .await
                .map_err(|_| SshError::ConnectionTimeout {
                    host: node.host.clone(),
                    port: node.port,
                    seconds: adjusted_timeout.as_secs(),
                    stage: "jump-host connection setup or authentication",
                })?
                .with_context(|| {
                    format!(
                        "Failed to establish jump host connection to {}:{}",
                        node.host, node.port
                    )
                })?;

                tracing::info!(
                    "Jump host connection established for PTY session: {}",
                    connection.jump_info.path_description()
                );

                connection.client
            }
        } else {
            // Direct connection
            tracing::debug!("Using direct connection for PTY (no jump hosts)");

            // Use the helper function to establish connection
            // Enable password fallback for interactive mode (matches OpenSSH behavior)
            Self::establish_connection(
                addr,
                &node.username,
                auth_method,
                check_method,
                &node.host,
                node.port,
                !self.use_password, // Allow fallback unless explicit password mode
                &self.ssh_connection_config,
                self.session_purpose(),
            )
            .await?
        };

        // Get terminal dimensions
        let (width, height) = crate::pty::utils::get_terminal_size().unwrap_or((80, 24));

        // The PTY manager retains channel ownership for raw stdin, resize, and
        // byte-transparent output. It requests PTY and shell after policy env.
        let channel = self
            .open_interactive_channel(&client, &self.pty_config.term_type, width, height)
            .await
            .context("Failed to request interactive shell with PTY")?;

        Ok((client, channel))
    }
}

/// Check if an SSH error indicates an authentication failure that should trigger password fallback.
///
/// This function returns true for errors that occur when:
/// - SSH key authentication fails (server rejects the key)
/// - SSH agent authentication fails (agent has keys but server rejects them)
/// - SSH agent has no identities loaded
/// - SSH agent connection fails
/// - SSH agent identity request fails
/// - SSH server disconnects during authentication (russh::Error::Disconnect)
///   This is a common behavior when the server rejects key authentication
///   and the russh library drops the connection before returning the auth result.
///
/// These are all cases where falling back to password authentication makes sense,
/// matching OpenSSH's behavior.
///
/// # Important
/// The SshError(Disconnect) case is particularly important because russh may
/// disconnect the connection before returning the authentication failure result.
/// The log flow in this case is:
/// ```text
/// userauth_failure -> drop handle -> disconnected SshError(Disconnect)
/// ```
/// Without handling this case, password fallback would never be triggered when
/// key authentication fails on servers that disconnect after auth failure.
pub fn is_auth_error_for_password_fallback(error: &SshError) -> bool {
    match error {
        // Explicit authentication failures
        SshError::KeyAuthFailed
        | SshError::AgentAuthenticationFailed
        | SshError::AgentNoIdentities
        | SshError::AgentConnectionFailed
        | SshError::AgentRequestIdentitiesFailed => true,

        // russh may disconnect after auth failure, which manifests as these errors
        // This is a key fix for GitHub issue #113: the server may disconnect
        // during authentication, and we should treat this as an auth failure
        // that can be retried with password.
        SshError::SshError(russh::Error::Disconnect) => {
            tracing::debug!(
                "Treating SshError(Disconnect) as auth failure - server likely \
                 disconnected after key authentication rejection"
            );
            true
        }

        // RecvError can occur when the server closes the channel during auth
        SshError::SshError(russh::Error::RecvError) => {
            tracing::debug!(
                "Treating SshError(RecvError) as auth failure - server likely \
                 closed connection during authentication"
            );
            true
        }

        // All other errors should not trigger password fallback
        // This includes: PasswordWrong, ServerCheckFailed, IoError, etc.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::ssh_config::{IpQosPolicy, IpQosValue, SshConfig};

    #[test]
    fn no_pty_shell_uses_bulk_ipqos_for_direct_and_jump_connections() {
        let policy = SessionPolicy {
            environment: Vec::new(),
            local_command: None,
            request_pty: false,
            request: SessionRequest::Shell,
        };

        assert_eq!(
            interactive_session_purpose(Some(&policy)),
            SessionPurpose::Bulk
        );
        assert_eq!(
            interactive_session_purpose(None),
            SessionPurpose::Interactive
        );
        let config = SshConnectionConfig::new()
            .with_ip_qos(IpQosPolicy {
                interactive: IpQosValue::Class(0xb8),
                bulk: IpQosValue::Class(0x20),
            })
            .with_session_purpose(interactive_session_purpose(Some(&policy)));
        assert_eq!(config.selected_ip_qos(), IpQosValue::Class(0x20));
    }

    #[test]
    fn interactive_jump_chain_keeps_distinct_bastion_and_target_socket_policies() {
        let ssh_config = SshConfig::parse(
            r#"
Host bastion
    BindAddress 127.0.0.2
    BindInterface lo
    IPQoS cs5 cs1

Host target
    BindAddress 127.0.0.3
    BindInterface target0
    IPQoS ef cs2
"#,
        )
        .expect("valid ssh_config");
        let resolver = SshConnectionConfigResolver::new().with_ssh_config(Some(ssh_config));
        let chain = build_interactive_jump_chain(
            vec![JumpHost::new("bastion".to_string(), None, None)],
            Duration::from_secs(45),
            &SshConnectionConfig::default(),
            Some(&resolver),
            SessionPurpose::Bulk,
        );

        let bastion = chain.connection_config_for_host("bastion");
        assert_eq!(bastion.bind_address.as_deref(), Some("127.0.0.2"));
        assert_eq!(bastion.bind_interface.as_deref(), Some("lo"));
        assert_eq!(bastion.session_purpose, SessionPurpose::Bulk);
        assert_eq!(bastion.selected_ip_qos(), IpQosValue::Class(0x20));

        let target = chain.connection_config_for_host("target");
        assert_eq!(target.bind_address.as_deref(), Some("127.0.0.3"));
        assert_eq!(target.bind_interface.as_deref(), Some("target0"));
        assert_eq!(target.session_purpose, SessionPurpose::Bulk);
        assert_eq!(target.selected_ip_qos(), IpQosValue::Class(0x40));

        let fixed_config = SshConnectionConfig::new()
            .with_source_binding(Some("127.0.0.4".to_string()), Some("lo".to_string()))
            .with_ip_qos(IpQosPolicy {
                interactive: IpQosValue::Class(0xb8),
                bulk: IpQosValue::Class(0x60),
            });
        let fixed_chain = build_interactive_jump_chain(
            vec![JumpHost::new("manual-bastion".to_string(), None, None)],
            Duration::from_secs(45),
            &fixed_config,
            None,
            SessionPurpose::Bulk,
        );
        let manual_bastion = fixed_chain.connection_config_for_host("manual-bastion");
        assert_eq!(manual_bastion.bind_address.as_deref(), Some("127.0.0.4"));
        assert_eq!(manual_bastion.selected_ip_qos(), IpQosValue::Class(0x60));
    }

    #[test]
    fn test_key_auth_failed_triggers_password_fallback() {
        let error = SshError::KeyAuthFailed;
        assert!(
            is_auth_error_for_password_fallback(&error),
            "KeyAuthFailed should trigger password fallback"
        );
    }

    #[test]
    fn test_agent_auth_failed_triggers_password_fallback() {
        let error = SshError::AgentAuthenticationFailed;
        assert!(
            is_auth_error_for_password_fallback(&error),
            "AgentAuthenticationFailed should trigger password fallback"
        );
    }

    #[test]
    fn test_agent_no_identities_triggers_password_fallback() {
        let error = SshError::AgentNoIdentities;
        assert!(
            is_auth_error_for_password_fallback(&error),
            "AgentNoIdentities should trigger password fallback"
        );
    }

    #[test]
    fn test_agent_connection_failed_triggers_password_fallback() {
        let error = SshError::AgentConnectionFailed;
        assert!(
            is_auth_error_for_password_fallback(&error),
            "AgentConnectionFailed should trigger password fallback"
        );
    }

    #[test]
    fn test_agent_request_identities_failed_triggers_password_fallback() {
        let error = SshError::AgentRequestIdentitiesFailed;
        assert!(
            is_auth_error_for_password_fallback(&error),
            "AgentRequestIdentitiesFailed should trigger password fallback"
        );
    }

    #[test]
    fn test_password_wrong_does_not_trigger_fallback() {
        let error = SshError::PasswordWrong;
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "PasswordWrong should NOT trigger password fallback (already tried password)"
        );
    }

    #[test]
    fn test_server_check_failed_does_not_trigger_fallback() {
        let error = SshError::ServerCheckFailed;
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "ServerCheckFailed should NOT trigger password fallback (host key issue)"
        );
    }

    #[test]
    fn test_host_key_changed_does_not_trigger_fallback() {
        // A changed host key is a possible man-in-the-middle, not an auth
        // problem; retrying with a password would hand credentials to the
        // untrusted endpoint (#239).
        let error = SshError::HostKeyChanged {
            host: "node1.example.com".to_string(),
            port: 22,
            line: 3,
        };
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "HostKeyChanged should NOT trigger password fallback (host key issue)"
        );
    }

    #[test]
    fn test_host_key_revoked_does_not_trigger_fallback() {
        // Same reasoning as HostKeyChanged: a revoked host key is a possible
        // man-in-the-middle, not an auth problem (#239).
        let error = SshError::HostKeyRevoked {
            host: "node1.example.com".to_string(),
            port: 22,
            line: 3,
        };
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "HostKeyRevoked should NOT trigger password fallback (host key issue)"
        );
    }

    #[test]
    fn test_io_error_does_not_trigger_fallback() {
        let error = SshError::IoError(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "IoError should NOT trigger password fallback (network issue)"
        );
    }

    #[test]
    fn test_keyboard_interactive_auth_failed_does_not_trigger_fallback() {
        let error = SshError::KeyboardInteractiveAuthFailed;
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "KeyboardInteractiveAuthFailed should NOT trigger password fallback"
        );
    }

    // Tests for issue #113: Handle SshError(Disconnect) during authentication
    #[test]
    fn test_ssh_disconnect_triggers_password_fallback() {
        let error = SshError::SshError(russh::Error::Disconnect);
        assert!(
            is_auth_error_for_password_fallback(&error),
            "SshError(Disconnect) should trigger password fallback - \
             server may disconnect after key auth rejection"
        );
    }

    #[test]
    fn test_ssh_recv_error_triggers_password_fallback() {
        let error = SshError::SshError(russh::Error::RecvError);
        assert!(
            is_auth_error_for_password_fallback(&error),
            "SshError(RecvError) should trigger password fallback - \
             server may close connection during authentication"
        );
    }

    #[test]
    fn test_ssh_hup_does_not_trigger_fallback() {
        // HUP is a different type of disconnect that happens during normal operation
        let error = SshError::SshError(russh::Error::HUP);
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "SshError(HUP) should NOT trigger password fallback - \
             this indicates remote closed connection, not auth failure"
        );
    }

    #[test]
    fn test_ssh_connection_timeout_does_not_trigger_fallback() {
        let error = SshError::SshError(russh::Error::ConnectionTimeout);
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "SshError(ConnectionTimeout) should NOT trigger password fallback - \
             this is a network issue, not auth failure"
        );
    }

    #[test]
    fn test_ssh_not_authenticated_does_not_trigger_fallback() {
        // NotAuthenticated means we haven't tried auth yet, not that auth failed
        let error = SshError::SshError(russh::Error::NotAuthenticated);
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "SshError(NotAuthenticated) should NOT trigger password fallback - \
             this means auth hasn't been attempted yet"
        );
    }
}

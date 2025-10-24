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
use russh::client::Msg;
use russh::Channel;
use std::io::{self, Write};
use tokio::time::{timeout, Duration};

use crate::jump::{parse_jump_hosts, JumpHostChain};
use crate::node::Node;
use crate::ssh::{
    known_hosts::get_check_method,
    tokio_client::{AuthMethod, Client},
};

use super::types::{InteractiveCommand, NodeSession};

impl InteractiveCommand {
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
            .with_password(self.use_password);

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

    /// Connect to a single node and establish an interactive shell
    pub(super) async fn connect_to_node(&self, node: Node) -> Result<NodeSession> {
        // Determine authentication method using the same logic as exec mode
        let auth_method = self.determine_auth_method(&node).await?;

        // Set up host key checking using the configured strict mode
        let check_method = get_check_method(self.strict_mode);

        // Connect with timeout
        let addr = (node.host.as_str(), node.port);
        // SSH connection timeout design:
        // - 30 seconds balances user patience with network reliability
        // - Sufficient for slow networks, DNS resolution, SSH negotiation
        // - Industry standard timeout for interactive SSH connections
        // - Prevents indefinite hang on unreachable hosts
        const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;
        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);

        // Track if we should attempt password fallback
        let should_try_password_fallback = !self.use_password
            && !matches!(auth_method, AuthMethod::Password(_))
            && atty::is(atty::Stream::Stdin);

        // Create client connection - either direct or through jump hosts
        let client = if let Some(ref jump_spec) = self.jump_hosts {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection");

                // Try initial authentication method
                let connect_result = timeout(
                    connect_timeout,
                    Client::connect(
                        addr,
                        &node.username,
                        auth_method.clone(),
                        check_method.clone(),
                    ),
                )
                .await;

                // If initial authentication fails and we can try password, retry with password
                match connect_result {
                    Ok(Ok(client)) => client,
                    Ok(Err(_)) | Err(_) if should_try_password_fallback => {
                        tracing::info!(
                            "Initial authentication failed for {}@{}:{}, attempting password authentication",
                            node.username, node.host, node.port
                        );

                        // Retry with password authentication
                        let password_auth =
                            crate::ssh::AuthContext::new(node.username.clone(), node.host.clone())?
                                .with_password(true)
                                .determine_method()
                                .await?;

                        timeout(
                            connect_timeout,
                            Client::connect(addr, &node.username, password_auth, check_method),
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "Connection timeout: Failed to connect to {}:{} after 30 seconds",
                                node.host, node.port
                            )
                        })?
                        .with_context(|| {
                            format!("SSH connection failed to {}:{}", node.host, node.port)
                        })?
                    }
                    Ok(Err(e)) => {
                        return Err(e).with_context(|| {
                            format!("SSH connection failed to {}:{}", node.host, node.port)
                        });
                    }
                    Err(_) => {
                        anyhow::bail!(
                            "Connection timeout: Failed to connect to {}:{} after 30 seconds",
                            node.host,
                            node.port
                        );
                    }
                }
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

                let chain = JumpHostChain::new(jump_hosts)
                    .with_connect_timeout(adjusted_timeout)
                    .with_command_timeout(Duration::from_secs(300));

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
                .with_context(|| {
                    format!(
                        "Connection timeout: Failed to connect to {}:{} via jump hosts after {} seconds",
                        node.host, node.port, adjusted_timeout.as_secs()
                    )
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

            // Try initial authentication method
            let connect_result = timeout(
                connect_timeout,
                Client::connect(
                    addr,
                    &node.username,
                    auth_method.clone(),
                    check_method.clone(),
                ),
            )
            .await;

            // If initial authentication fails and we can try password, retry with password
            match connect_result {
                Ok(Ok(client)) => client,
                Ok(Err(_)) | Err(_) if should_try_password_fallback => {
                    tracing::info!(
                        "Initial authentication failed for {}@{}:{}, attempting password authentication",
                        node.username, node.host, node.port
                    );

                    // Retry with password authentication
                    let password_auth =
                        crate::ssh::AuthContext::new(node.username.clone(), node.host.clone())?
                            .with_password(true)
                            .determine_method()
                            .await?;

                    timeout(
                        connect_timeout,
                        Client::connect(addr, &node.username, password_auth, check_method),
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "Connection timeout: Failed to connect to {}:{} after 30 seconds",
                            node.host, node.port
                        )
                    })?
                    .with_context(|| {
                        format!("SSH connection failed to {}:{}", node.host, node.port)
                    })?
                }
                Ok(Err(e)) => {
                    return Err(e).with_context(|| {
                        format!("SSH connection failed to {}:{}", node.host, node.port)
                    });
                }
                Err(_) => {
                    anyhow::bail!(
                        "Connection timeout: Failed to connect to {}:{} after 30 seconds",
                        node.host,
                        node.port
                    );
                }
            }
        };

        // Get terminal dimensions
        let (width, height) = terminal::size().unwrap_or((80, 24));

        // Request interactive shell with PTY
        let channel = client
            .request_interactive_shell("xterm-256color", u32::from(width), u32::from(height))
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
    pub(super) async fn connect_to_node_pty(&self, node: Node) -> Result<Channel<Msg>> {
        // Determine authentication method using the same logic as exec mode
        let auth_method = self.determine_auth_method(&node).await?;

        // Set up host key checking using the configured strict mode
        let check_method = get_check_method(self.strict_mode);

        // Connect with timeout
        let addr = (node.host.as_str(), node.port);
        // SSH connection timeout design:
        // - 30 seconds balances user patience with network reliability
        // - Sufficient for slow networks, DNS resolution, SSH negotiation
        // - Industry standard timeout for interactive SSH connections
        // - Prevents indefinite hang on unreachable hosts
        const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;
        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);

        // Track if we should attempt password fallback
        let should_try_password_fallback = !self.use_password
            && !matches!(auth_method, AuthMethod::Password(_))
            && atty::is(atty::Stream::Stdin);

        // Create client connection - either direct or through jump hosts
        let client = if let Some(ref jump_spec) = self.jump_hosts {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection for PTY");

                // Try initial authentication method
                let connect_result = timeout(
                    connect_timeout,
                    Client::connect(
                        addr,
                        &node.username,
                        auth_method.clone(),
                        check_method.clone(),
                    ),
                )
                .await;

                // If initial authentication fails and we can try password, retry with password
                match connect_result {
                    Ok(Ok(client)) => client,
                    Ok(Err(_)) | Err(_) if should_try_password_fallback => {
                        tracing::info!(
                            "Initial authentication failed for {}@{}:{}, attempting password authentication",
                            node.username, node.host, node.port
                        );

                        // Retry with password authentication
                        let password_auth =
                            crate::ssh::AuthContext::new(node.username.clone(), node.host.clone())?
                                .with_password(true)
                                .determine_method()
                                .await?;

                        timeout(
                            connect_timeout,
                            Client::connect(addr, &node.username, password_auth, check_method),
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "Connection timeout: Failed to connect to {}:{} after 30 seconds",
                                node.host, node.port
                            )
                        })?
                        .with_context(|| {
                            format!("SSH connection failed to {}:{}", node.host, node.port)
                        })?
                    }
                    Ok(Err(e)) => {
                        return Err(e).with_context(|| {
                            format!("SSH connection failed to {}:{}", node.host, node.port)
                        });
                    }
                    Err(_) => {
                        anyhow::bail!(
                            "Connection timeout: Failed to connect to {}:{} after 30 seconds",
                            node.host,
                            node.port
                        );
                    }
                }
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

                let chain = JumpHostChain::new(jump_hosts)
                    .with_connect_timeout(adjusted_timeout)
                    .with_command_timeout(Duration::from_secs(300));

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
                .with_context(|| {
                    format!(
                        "Connection timeout: Failed to connect to {}:{} via jump hosts after {} seconds",
                        node.host, node.port, adjusted_timeout.as_secs()
                    )
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

            // Try initial authentication method
            let connect_result = timeout(
                connect_timeout,
                Client::connect(
                    addr,
                    &node.username,
                    auth_method.clone(),
                    check_method.clone(),
                ),
            )
            .await;

            // If initial authentication fails and we can try password, retry with password
            match connect_result {
                Ok(Ok(client)) => client,
                Ok(Err(_)) | Err(_) if should_try_password_fallback => {
                    tracing::info!(
                        "Initial authentication failed for {}@{}:{}, attempting password authentication",
                        node.username, node.host, node.port
                    );

                    // Retry with password authentication
                    let password_auth =
                        crate::ssh::AuthContext::new(node.username.clone(), node.host.clone())?
                            .with_password(true)
                            .determine_method()
                            .await?;

                    timeout(
                        connect_timeout,
                        Client::connect(addr, &node.username, password_auth, check_method),
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "Connection timeout: Failed to connect to {}:{} after 30 seconds",
                            node.host, node.port
                        )
                    })?
                    .with_context(|| {
                        format!("SSH connection failed to {}:{}", node.host, node.port)
                    })?
                }
                Ok(Err(e)) => {
                    return Err(e).with_context(|| {
                        format!("SSH connection failed to {}:{}", node.host, node.port)
                    });
                }
                Err(_) => {
                    anyhow::bail!(
                        "Connection timeout: Failed to connect to {}:{} after 30 seconds",
                        node.host,
                        node.port
                    );
                }
            }
        };

        // Get terminal dimensions
        let (width, height) = crate::pty::utils::get_terminal_size().unwrap_or((80, 24));

        // Request interactive shell with PTY using the SSH client's method
        let channel = client
            .request_interactive_shell(&self.pty_config.term_type, width, height)
            .await
            .context("Failed to request interactive shell with PTY")?;

        Ok(channel)
    }
}

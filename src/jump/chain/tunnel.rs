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

use super::auth::authenticate_connection;
use crate::jump::parser::JumpHost;
use crate::jump::rate_limiter::ConnectionRateLimiter;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::client::ClientHandler;
use crate::ssh::tokio_client::{AuthMethod, Client};
use anyhow::{Context, Result};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use tracing::debug;

/// Connect to a jump host through a previous SSH connection
#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_through_tunnel(
    previous_client: &Client,
    jump_host: &JumpHost,
    key_path: Option<&Path>,
    use_agent: bool,
    use_password: bool,
    strict_mode: StrictHostKeyChecking,
    connect_timeout: std::time::Duration,
    rate_limiter: &ConnectionRateLimiter,
    auth_mutex: &tokio::sync::Mutex<()>,
) -> Result<Client> {
    debug!(
        "Opening tunnel to jump host: {} ({}:{})",
        jump_host,
        jump_host.host,
        jump_host.effective_port()
    );

    // Apply rate limiting for intermediate jump hosts
    rate_limiter
        .try_acquire(&jump_host.host)
        .await
        .with_context(|| format!("Rate limited for jump host {}", jump_host.host))?;

    // Create a direct-tcpip channel through the previous connection
    let channel = tokio::time::timeout(
        connect_timeout,
        previous_client
            .open_direct_tcpip_channel((jump_host.host.as_str(), jump_host.effective_port()), None),
    )
    .await
    .with_context(|| {
        format!(
            "Timeout opening tunnel to jump host {}:{} after {}s",
            jump_host.host,
            jump_host.effective_port(),
            connect_timeout.as_secs()
        )
    })?
    .with_context(|| {
        format!(
            "Failed to open direct-tcpip channel to jump host {}:{}",
            jump_host.host,
            jump_host.effective_port()
        )
    })?;

    // Convert the channel to a stream
    let stream = channel.into_stream();

    // Create SSH client over the tunnel stream
    let auth_method = super::auth::determine_auth_method(
        jump_host,
        key_path,
        use_agent,
        use_password,
        auth_mutex,
    )
    .await?;

    // Create a basic russh client config
    let config = Arc::new(russh::client::Config::default());

    // Create a simple handler for the connection
    let socket_addr: SocketAddr = format!("{}:{}", jump_host.host, jump_host.effective_port())
        .to_socket_addrs()
        .with_context(|| {
            format!(
                "Failed to resolve jump host address: {}:{}",
                jump_host.host,
                jump_host.effective_port()
            )
        })?
        .next()
        .with_context(|| {
            format!(
                "No addresses resolved for jump host: {}:{}",
                jump_host.host,
                jump_host.effective_port()
            )
        })?;

    // SECURITY: Always verify host keys for jump hosts to prevent MITM attacks
    let check_method = crate::ssh::known_hosts::get_check_method(strict_mode);

    let handler = ClientHandler::new(jump_host.host.clone(), socket_addr, check_method);

    // Connect through the stream
    let handle = tokio::time::timeout(
        connect_timeout,
        russh::client::connect_stream(config, stream, handler),
    )
    .await
    .with_context(|| {
        format!(
            "Timeout establishing SSH over tunnel to {}:{} after {}s",
            jump_host.host,
            jump_host.effective_port(),
            connect_timeout.as_secs()
        )
    })?
    .with_context(|| {
        format!(
            "Failed to establish SSH connection over tunnel to {}:{}",
            jump_host.host,
            jump_host.effective_port()
        )
    })?;

    // Authenticate
    let mut handle = handle;
    authenticate_connection(&mut handle, &jump_host.effective_user(), auth_method)
        .await
        .with_context(|| {
            format!(
                "Failed to authenticate to jump host {}:{} as user {}",
                jump_host.host,
                jump_host.effective_port(),
                jump_host.effective_user()
            )
        })?;

    // Create our Client wrapper
    let client =
        Client::from_handle_and_address(Arc::new(handle), jump_host.effective_user(), socket_addr);

    Ok(client)
}

/// Connect to the final destination through the last jump host
#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_to_destination(
    jump_client: &Client,
    destination_host: &str,
    destination_port: u16,
    destination_user: &str,
    dest_auth_method: AuthMethod,
    strict_mode: StrictHostKeyChecking,
    connect_timeout: std::time::Duration,
    rate_limiter: &ConnectionRateLimiter,
) -> Result<Client> {
    debug!(
        "Opening tunnel to destination: {}:{} as user {}",
        destination_host, destination_port, destination_user
    );

    // Apply rate limiting for final destination
    rate_limiter
        .try_acquire(destination_host)
        .await
        .with_context(|| format!("Rate limited for destination {destination_host}"))?;

    // Create a direct-tcpip channel to the final destination
    let channel = tokio::time::timeout(
        connect_timeout,
        jump_client.open_direct_tcpip_channel((destination_host, destination_port), None),
    )
    .await
    .with_context(|| {
        format!(
            "Timeout opening tunnel to destination {}:{} after {}s",
            destination_host, destination_port, connect_timeout.as_secs()
        )
    })?
    .with_context(|| {
        format!(
            "Failed to open direct-tcpip channel to destination {destination_host}:{destination_port}"
        )
    })?;

    // Convert the channel to a stream
    let stream = channel.into_stream();

    // Create SSH client over the tunnel stream
    let config = Arc::new(russh::client::Config::default());
    let check_method = match strict_mode {
        StrictHostKeyChecking::No => crate::ssh::tokio_client::ServerCheckMethod::NoCheck,
        _ => crate::ssh::known_hosts::get_check_method(strict_mode),
    };

    let socket_addr: SocketAddr = format!("{destination_host}:{destination_port}")
        .to_socket_addrs()
        .with_context(|| {
            format!("Failed to resolve destination address: {destination_host}:{destination_port}")
        })?
        .next()
        .with_context(|| {
            format!("No addresses resolved for destination: {destination_host}:{destination_port}")
        })?;

    let handler = ClientHandler::new(destination_host.to_string(), socket_addr, check_method);

    // Connect through the stream
    let handle = tokio::time::timeout(
        connect_timeout,
        russh::client::connect_stream(config, stream, handler),
    )
    .await
    .with_context(|| {
        format!(
            "Timeout establishing SSH to destination {}:{} after {}s",
            destination_host, destination_port, connect_timeout.as_secs()
        )
    })?
    .with_context(|| {
        format!(
            "Failed to establish SSH connection to destination {destination_host}:{destination_port}"
        )
    })?;

    // Authenticate to the final destination
    let mut handle = handle;
    authenticate_connection(&mut handle, destination_user, dest_auth_method)
        .await
        .with_context(|| {
            format!(
                "Failed to authenticate to destination {destination_host}:{destination_port} as user {destination_user}"
            )
        })?;

    // Create our Client wrapper
    let client = Client::from_handle_and_address(
        Arc::new(handle),
        destination_user.to_string(),
        socket_addr,
    );

    Ok(client)
}

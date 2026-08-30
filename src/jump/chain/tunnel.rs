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
use crate::security::Password;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::connection::{
    KnownHostRuntimePolicy, apply_known_hosts_command_order,
};
use crate::ssh::tokio_client::{
    AddressFamily, AuthMethod, Client, ClientHandler, Error as SshError, SshConnectionConfig,
};
use anyhow::{Context, Result};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use tracing::debug;

/// Resolve `host:port` to the `SocketAddr` handed to [`ClientHandler`].
///
/// Hops past the first one connect over an already-open channel, so this
/// particular address is never dialed: it only supplies host key verification
/// context and display text. The channel itself is still opened locally
/// through `open_direct_tcpip_channel_with_family` on the previous hop. When a
/// family is forced, this function mirrors that preference for the address
/// recorded in known_hosts diagnostics. If no candidate matches, fall back to
/// the first resolved address rather than failing here; the channel-open path
/// is the authoritative family filter for the real connection attempt.
// `host:port` is deliberately left out of the messages below: every caller
// already wraps this function with a `.with_context()` that names the host
// and port, and repeating it here would print the same wording twice in the
// rendered chain (see issue #238).
fn resolve_handler_address(
    host: &str,
    port: u16,
    address_family: AddressFamily,
) -> Result<SocketAddr> {
    let candidates: Vec<SocketAddr> = format!("{host}:{port}").to_socket_addrs()?.collect();

    if address_family.is_forced()
        && let Some(addr) = address_family.first_match(&candidates)
    {
        return Ok(addr);
    }

    if address_family.is_forced() && !candidates.is_empty() {
        debug!(
            "No {address_family} address resolved for {host}:{port}; using {} for host key context",
            candidates[0]
        );
    }

    candidates
        .into_iter()
        .next()
        .context("No addresses resolved")
}

/// Connect to a jump host through a previous SSH connection
#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_through_tunnel(
    previous_client: &Client,
    jump_host: &JumpHost,
    key_path: Option<&Path>,
    use_agent: bool,
    use_password: bool,
    pre_collected_password: Option<Arc<Password>>,
    strict_mode: StrictHostKeyChecking,
    connect_timeout: std::time::Duration,
    rate_limiter: &ConnectionRateLimiter,
    ssh_connection_config: &SshConnectionConfig,
) -> Result<Client> {
    debug!(
        "Opening tunnel to jump host: {} ({}:{})",
        jump_host,
        jump_host.host,
        jump_host.effective_port()
    );

    // Apply rate limiting for intermediate jump hosts
    rate_limiter
        .try_acquire(&jump_host.host.clone())
        .await
        .with_context(|| format!("Rate limited for jump host {}", jump_host.host))?;

    // Create a direct-tcpip channel through the previous connection
    let channel = tokio::time::timeout(
        connect_timeout,
        previous_client.open_direct_tcpip_channel_with_family(
            (jump_host.host.as_str(), jump_host.effective_port()),
            None,
            ssh_connection_config.address_family,
        ),
    )
    .await
    .map_err(|_| SshError::ConnectionTimeout {
        host: jump_host.host.clone(),
        port: jump_host.effective_port(),
        seconds: connect_timeout.as_secs(),
        stage: "jump-host channel open",
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
        pre_collected_password,
        ssh_connection_config,
    )
    .await?;

    let policy = KnownHostRuntimePolicy::from_config(
        ssh_connection_config,
        &jump_host.effective_user(),
        &jump_host.host,
        &jump_host.host,
        jump_host.effective_port(),
    );
    let mut config = ssh_connection_config.to_russh_config();
    if ssh_connection_config.order_host_key_algorithms {
        apply_known_hosts_command_order(
            &mut config,
            &policy,
            ssh_connection_config.host_key_alias.as_deref(),
        )
        .await?;
    }
    let config = Arc::new(config);

    // Create a simple handler for the connection. The address is used for
    // host key verification context and display, not to open a socket: this
    // hop rides the direct-tcpip channel opened above. Picking a candidate of
    // the forced family keeps known_hosts diagnostics consistent with the
    // family the user asked for.
    let socket_addr = resolve_handler_address(
        &jump_host.host,
        jump_host.effective_port(),
        ssh_connection_config.address_family,
    )
    .with_context(|| {
        format!(
            "Failed to resolve jump host address: {}:{}",
            jump_host.host,
            jump_host.effective_port()
        )
    })?;

    // SECURITY: Always verify host keys for jump hosts to prevent MITM attacks
    let check_method = crate::ssh::known_hosts::get_check_method_for_target(
        strict_mode,
        ssh_connection_config,
        &jump_host.host,
        jump_host.effective_port(),
        &jump_host.effective_user(),
    );

    let handler =
        ClientHandler::new_with_policy(jump_host.host.clone(), socket_addr, check_method, policy);
    let fatal_transport = handler.fatal_transport_state();
    let hostkey_rotation = handler.hostkey_rotation_tasks();
    let remote_forward_registry = handler.remote_forward_registry();

    // Connect through the stream
    let handle = tokio::time::timeout(
        connect_timeout,
        russh::client::connect_stream(config, stream, handler),
    )
    .await
    .map_err(|_| SshError::ConnectionTimeout {
        host: jump_host.host.clone(),
        port: jump_host.effective_port(),
        seconds: connect_timeout.as_secs(),
        stage: "jump-host protocol negotiation",
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
    let host_desc = format!(
        "jump host '{}:{}'",
        jump_host.host,
        jump_host.effective_port()
    );
    authenticate_connection(
        &mut handle,
        &jump_host.effective_user(),
        auth_method,
        &host_desc,
    )
    .await
    .or_else(|error| {
        fatal_transport
            .take_error()
            .map(anyhow::Error::new)
            .map_or(Err(error), Err)
    })
    .with_context(|| {
        format!(
            "Failed to authenticate to {} as user '{}'",
            host_desc,
            jump_host.effective_user()
        )
    })?;

    // Create our Client wrapper
    let client = Client::from_authenticated_handle_with_policy_state(
        Arc::new(handle),
        jump_host.effective_user(),
        socket_addr,
        fatal_transport,
        hostkey_rotation,
        remote_forward_registry,
    )
    .await;

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
    ssh_connection_config: &SshConnectionConfig,
) -> Result<Client> {
    debug!(
        "Opening tunnel to destination: {}:{} as user {}",
        destination_host, destination_port, destination_user
    );

    // Apply rate limiting for final destination
    rate_limiter
        .try_acquire(&destination_host.to_string())
        .await
        .with_context(|| format!("Rate limited for destination {destination_host}"))?;

    // Create a direct-tcpip channel to the final destination
    let channel = tokio::time::timeout(
        connect_timeout,
        jump_client.open_direct_tcpip_channel_with_family(
            (destination_host, destination_port),
            None,
            ssh_connection_config.address_family,
        ),
    )
    .await
    .map_err(|_| SshError::ConnectionTimeout {
        host: destination_host.to_string(),
        port: destination_port,
        seconds: connect_timeout.as_secs(),
        stage: "destination channel open",
    })?
    .with_context(|| {
        format!(
            "Failed to open direct-tcpip channel to destination {destination_host}:{destination_port}"
        )
    })?;

    // Convert the channel to a stream
    let stream = channel.into_stream();

    let policy = KnownHostRuntimePolicy::from_config(
        ssh_connection_config,
        destination_user,
        destination_host,
        destination_host,
        destination_port,
    );
    let mut config = ssh_connection_config.to_russh_config();
    if ssh_connection_config.order_host_key_algorithms {
        apply_known_hosts_command_order(
            &mut config,
            &policy,
            ssh_connection_config.host_key_alias.as_deref(),
        )
        .await?;
    }
    let config = Arc::new(config);
    let check_method = crate::ssh::known_hosts::get_check_method_for_target(
        strict_mode,
        ssh_connection_config,
        destination_host,
        destination_port,
        destination_user,
    );

    // As in `connect_through_tunnel`, this address only supplies host key
    // verification context and display text for a connection that rides an
    // existing channel.
    let socket_addr = resolve_handler_address(
        destination_host,
        destination_port,
        ssh_connection_config.address_family,
    )
    .with_context(|| {
        format!("Failed to resolve destination address: {destination_host}:{destination_port}")
    })?;

    let handler = ClientHandler::new_with_policy(
        destination_host.to_string(),
        socket_addr,
        check_method,
        policy,
    );
    let fatal_transport = handler.fatal_transport_state();
    let hostkey_rotation = handler.hostkey_rotation_tasks();
    let remote_forward_registry = handler.remote_forward_registry();

    // Connect through the stream
    let handle = tokio::time::timeout(
        connect_timeout,
        russh::client::connect_stream(config, stream, handler),
    )
    .await
    .map_err(|_| SshError::ConnectionTimeout {
        host: destination_host.to_string(),
        port: destination_port,
        seconds: connect_timeout.as_secs(),
        stage: "destination protocol negotiation",
    })?
    .with_context(|| {
        format!(
            "Failed to establish SSH connection to destination {destination_host}:{destination_port}"
        )
    })?;

    // Authenticate to the final destination
    let mut handle = handle;
    let dest_desc = format!("destination '{}:{}'", destination_host, destination_port);
    authenticate_connection(&mut handle, destination_user, dest_auth_method, &dest_desc)
        .await
        .or_else(|error| {
            fatal_transport
                .take_error()
                .map(anyhow::Error::new)
                .map_or(Err(error), Err)
        })
        .with_context(|| {
            format!(
                "Failed to authenticate to {} as user '{}'",
                dest_desc, destination_user
            )
        })?;

    // Create our Client wrapper
    let client = Client::from_authenticated_handle_with_policy_state(
        Arc::new(handle),
        destination_user.to_string(),
        socket_addr,
        fatal_transport,
        hostkey_rotation,
        remote_forward_registry,
    )
    .await;
    client
        .initialize_forwarding(&ssh_connection_config.forwarding_plan)
        .await?;

    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A forced family that matches a candidate must be the one recorded for
    /// host key verification, instead of an unconditional first-resolved pick.
    #[test]
    fn handler_address_prefers_the_forced_family() {
        let addr =
            resolve_handler_address("::1", 2222, AddressFamily::V6).expect("IPv6 literal resolves");
        assert!(addr.is_ipv6());
        assert_eq!(addr.port(), 2222);

        let addr = resolve_handler_address("127.0.0.1", 2222, AddressFamily::V4)
            .expect("IPv4 literal resolves");
        assert!(addr.is_ipv4());
    }

    /// A hop with no candidate of the forced family must still produce an
    /// address (these hops never dial it), not panic and not fail the
    /// connection that the remote sshd is going to make anyway.
    #[test]
    fn handler_address_falls_back_when_no_candidate_matches() {
        let addr = resolve_handler_address("127.0.0.1", 22, AddressFamily::V6)
            .expect("must fall back rather than fail");
        assert!(addr.is_ipv4(), "expected the IPv4 fallback, got {addr}");

        let addr = resolve_handler_address("::1", 22, AddressFamily::V4)
            .expect("must fall back rather than fail");
        assert!(addr.is_ipv6(), "expected the IPv6 fallback, got {addr}");
    }

    #[test]
    fn handler_address_is_unchanged_when_no_family_is_forced() {
        let addr = resolve_handler_address("127.0.0.1", 22, AddressFamily::Any)
            .expect("IPv4 literal resolves");
        assert_eq!(addr.to_string(), "127.0.0.1:22");
    }

    /// Regression test for the chain-duplication defect issue #238 established
    /// a convention against: `resolve_handler_address`'s own error must not
    /// restate `host:port`, since every call site already wraps it with a
    /// `.with_context()` that names the host and port.
    #[test]
    fn handler_address_failure_does_not_duplicate_host_port_in_the_chain() {
        let host = "no-such-host.bssh-test.invalid";
        let port = 22;

        let err = resolve_handler_address(host, port, AddressFamily::Any)
            .with_context(|| format!("Failed to resolve jump host address: {host}:{port}"))
            .expect_err("a reserved .invalid hostname must not resolve");

        let rendered = format!("{err:#}");
        let needle = format!("{host}:{port}");
        assert_eq!(
            rendered.matches(needle.as_str()).count(),
            1,
            "host:port should appear exactly once in the rendered chain, got: {rendered}"
        );
    }
}

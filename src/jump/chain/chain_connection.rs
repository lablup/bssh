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

use super::types::{JumpConnection, JumpInfo};
use crate::jump::rate_limiter::ConnectionRateLimiter;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::{AuthMethod, Client, SshConnectionConfig};
use anyhow::{Context, Result};
use tracing::{debug, info};

/// Establish a direct connection (no jump hosts)
#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_direct(
    host: &str,
    port: u16,
    username: &str,
    auth_method: AuthMethod,
    strict_mode: Option<StrictHostKeyChecking>,
    connect_timeout: std::time::Duration,
    rate_limiter: &ConnectionRateLimiter,
    ssh_connection_config: &SshConnectionConfig,
) -> Result<JumpConnection> {
    debug!("Establishing direct connection to {}:{}", host, port);

    // Apply rate limiting to prevent DoS attacks
    rate_limiter
        .try_acquire(host)
        .await
        .with_context(|| format!("Rate limited for host {host}"))?;

    let check_method = strict_mode.map_or_else(
        || crate::ssh::known_hosts::get_check_method(StrictHostKeyChecking::AcceptNew),
        crate::ssh::known_hosts::get_check_method,
    );

    let client = tokio::time::timeout(
        connect_timeout,
        Client::connect_with_ssh_config(
            (host, port),
            username,
            auth_method,
            check_method,
            ssh_connection_config,
        ),
    )
    .await
    .with_context(|| {
        format!(
            "Connection timeout: Failed to connect to {}:{} after {}s",
            host,
            port,
            connect_timeout.as_secs()
        )
    })?
    .with_context(|| format!("Failed to establish direct connection to {host}:{port}"))?;

    info!("Direct connection established to {}:{}", host, port);

    Ok(JumpConnection {
        client,
        jump_info: JumpInfo::Direct {
            host: host.to_string(),
            port,
        },
    })
}

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

//! Main parser for jump host specifications

use anyhow::{Context, Result};

use super::config::get_max_jump_hosts;
use super::host::JumpHost;
use super::host_parser::parse_single_jump_host;

/// Parse jump host specifications from OpenSSH ProxyJump format
///
/// Supports the OpenSSH -J syntax:
/// * Single host: `hostname`, `user@hostname`, `hostname:port`, `user@hostname:port`
/// * Multiple hosts: Comma-separated list of the above
///
/// # Examples
/// ```rust
/// use bssh::jump::parse_jump_hosts;
///
/// // Single jump host
/// let jumps = parse_jump_hosts("bastion.example.com").unwrap();
/// assert_eq!(jumps.len(), 1);
/// assert_eq!(jumps[0].host, "bastion.example.com");
///
/// // With user and port
/// let jumps = parse_jump_hosts("admin@jump.example.com:2222").unwrap();
/// assert_eq!(jumps[0].user, Some("admin".to_string()));
/// assert_eq!(jumps[0].port, Some(2222));
///
/// // Multiple jump hosts
/// let jumps = parse_jump_hosts("jump1@host1,user@host2:2222").unwrap();
/// assert_eq!(jumps.len(), 2);
/// ```
pub fn parse_jump_hosts(jump_spec: &str) -> Result<Vec<JumpHost>> {
    if jump_spec.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut jump_hosts = Vec::new();

    for host_spec in jump_spec.split(',') {
        let host_spec = host_spec.trim();
        if host_spec.is_empty() {
            continue;
        }

        let jump_host = parse_single_jump_host(host_spec)
            .with_context(|| format!("Failed to parse jump host specification: '{host_spec}'"))?;
        jump_hosts.push(jump_host);
    }

    if jump_hosts.is_empty() {
        anyhow::bail!("No valid jump hosts found in specification: '{jump_spec}'");
    }

    // SECURITY: Validate jump host count to prevent resource exhaustion
    let max_jump_hosts = get_max_jump_hosts();
    if jump_hosts.len() > max_jump_hosts {
        anyhow::bail!(
            "Too many jump hosts specified: {} (maximum allowed: {}). Reduce the number of jump hosts in your chain or set BSSH_MAX_JUMP_HOSTS environment variable.",
            jump_hosts.len(),
            max_jump_hosts
        );
    }

    Ok(jump_hosts)
}

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

//! Configuration resolution and merging logic for SSH configuration
//!
//! This module handles finding matching host configurations and merging them
//! according to SSH configuration precedence rules.

use super::pattern::matches_host_pattern;
use super::types::SshHostConfig;
use std::path::PathBuf;

/// Find configuration for a specific hostname
pub(super) fn find_host_config(hosts: &[SshHostConfig], hostname: &str) -> SshHostConfig {
    let mut merged_config = SshHostConfig::default();

    for host_config in hosts {
        if matches_host_pattern(hostname, &host_config.host_patterns) {
            merge_host_config(&mut merged_config, host_config);
        }
    }

    merged_config
}

/// Merge two host configurations (second takes precedence)
pub(super) fn merge_host_config(base: &mut SshHostConfig, overlay: &SshHostConfig) {
    // For most options, overlay takes precedence if set
    if !overlay.host_patterns.is_empty() {
        base.host_patterns = overlay.host_patterns.clone();
    }
    if overlay.hostname.is_some() {
        base.hostname = overlay.hostname.clone();
    }
    if overlay.user.is_some() {
        base.user = overlay.user.clone();
    }
    if overlay.port.is_some() {
        base.port = overlay.port;
    }
    if !overlay.identity_files.is_empty() {
        // For identity files, we append them
        base.identity_files
            .extend(overlay.identity_files.iter().cloned());
    }
    if overlay.proxy_jump.is_some() {
        base.proxy_jump = overlay.proxy_jump.clone();
    }
    if overlay.proxy_command.is_some() {
        base.proxy_command = overlay.proxy_command.clone();
    }
    if overlay.strict_host_key_checking.is_some() {
        base.strict_host_key_checking = overlay.strict_host_key_checking.clone();
    }
    if overlay.user_known_hosts_file.is_some() {
        base.user_known_hosts_file = overlay.user_known_hosts_file.clone();
    }
    if overlay.global_known_hosts_file.is_some() {
        base.global_known_hosts_file = overlay.global_known_hosts_file.clone();
    }
    if overlay.forward_agent.is_some() {
        base.forward_agent = overlay.forward_agent;
    }
    if overlay.forward_x11.is_some() {
        base.forward_x11 = overlay.forward_x11;
    }
    if overlay.server_alive_interval.is_some() {
        base.server_alive_interval = overlay.server_alive_interval;
    }
    if overlay.server_alive_count_max.is_some() {
        base.server_alive_count_max = overlay.server_alive_count_max;
    }
    if overlay.connect_timeout.is_some() {
        base.connect_timeout = overlay.connect_timeout;
    }
    if overlay.connection_attempts.is_some() {
        base.connection_attempts = overlay.connection_attempts;
    }
    if overlay.batch_mode.is_some() {
        base.batch_mode = overlay.batch_mode;
    }
    if overlay.compression.is_some() {
        base.compression = overlay.compression;
    }
    if overlay.tcp_keep_alive.is_some() {
        base.tcp_keep_alive = overlay.tcp_keep_alive;
    }
    if !overlay.preferred_authentications.is_empty() {
        base.preferred_authentications = overlay.preferred_authentications.clone();
    }
    if overlay.pubkey_authentication.is_some() {
        base.pubkey_authentication = overlay.pubkey_authentication;
    }
    if overlay.password_authentication.is_some() {
        base.password_authentication = overlay.password_authentication;
    }
    if overlay.keyboard_interactive_authentication.is_some() {
        base.keyboard_interactive_authentication = overlay.keyboard_interactive_authentication;
    }
    if overlay.gssapi_authentication.is_some() {
        base.gssapi_authentication = overlay.gssapi_authentication;
    }
    if !overlay.host_key_algorithms.is_empty() {
        base.host_key_algorithms = overlay.host_key_algorithms.clone();
    }
    if !overlay.kex_algorithms.is_empty() {
        base.kex_algorithms = overlay.kex_algorithms.clone();
    }
    if !overlay.ciphers.is_empty() {
        base.ciphers = overlay.ciphers.clone();
    }
    if !overlay.macs.is_empty() {
        base.macs = overlay.macs.clone();
    }
    if !overlay.send_env.is_empty() {
        base.send_env.extend(overlay.send_env.iter().cloned());
    }
    if !overlay.set_env.is_empty() {
        base.set_env
            .extend(overlay.set_env.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    if !overlay.local_forward.is_empty() {
        base.local_forward
            .extend(overlay.local_forward.iter().cloned());
    }
    if !overlay.remote_forward.is_empty() {
        base.remote_forward
            .extend(overlay.remote_forward.iter().cloned());
    }
    if !overlay.dynamic_forward.is_empty() {
        base.dynamic_forward
            .extend(overlay.dynamic_forward.iter().cloned());
    }
    if overlay.request_tty.is_some() {
        base.request_tty = overlay.request_tty.clone();
    }
    if overlay.escape_char.is_some() {
        base.escape_char = overlay.escape_char.clone();
    }
    if overlay.log_level.is_some() {
        base.log_level = overlay.log_level.clone();
    }
    if overlay.syslog_facility.is_some() {
        base.syslog_facility = overlay.syslog_facility.clone();
    }
    if !overlay.protocol.is_empty() {
        base.protocol = overlay.protocol.clone();
    }
    if overlay.address_family.is_some() {
        base.address_family = overlay.address_family.clone();
    }
    if overlay.bind_address.is_some() {
        base.bind_address = overlay.bind_address.clone();
    }
    if overlay.clear_all_forwardings.is_some() {
        base.clear_all_forwardings = overlay.clear_all_forwardings;
    }
    if overlay.control_master.is_some() {
        base.control_master = overlay.control_master.clone();
    }
    if overlay.control_path.is_some() {
        base.control_path = overlay.control_path.clone();
    }
    if overlay.control_persist.is_some() {
        base.control_persist = overlay.control_persist.clone();
    }
}

/// Get the effective hostname (resolves HostName directive)
pub(super) fn get_effective_hostname(hosts: &[SshHostConfig], hostname: &str) -> String {
    let config = find_host_config(hosts, hostname);
    config.hostname.unwrap_or_else(|| hostname.to_string())
}

/// Get the effective username
pub(super) fn get_effective_user(
    hosts: &[SshHostConfig],
    hostname: &str,
    cli_user: Option<&str>,
) -> Option<String> {
    // CLI user takes precedence over SSH config
    if let Some(user) = cli_user {
        return Some(user.to_string());
    }

    let config = find_host_config(hosts, hostname);
    config.user
}

/// Get the effective port
pub(super) fn get_effective_port(
    hosts: &[SshHostConfig],
    hostname: &str,
    cli_port: Option<u16>,
) -> u16 {
    // CLI port takes precedence over SSH config
    if let Some(port) = cli_port {
        return port;
    }

    let config = find_host_config(hosts, hostname);
    config.port.unwrap_or(22)
}

/// Get identity files for a hostname
pub(super) fn get_identity_files(hosts: &[SshHostConfig], hostname: &str) -> Vec<PathBuf> {
    let config = find_host_config(hosts, hostname);
    config.identity_files
}

/// Get the effective StrictHostKeyChecking value
pub(super) fn get_strict_host_key_checking(
    hosts: &[SshHostConfig],
    hostname: &str,
) -> Option<String> {
    let config = find_host_config(hosts, hostname);
    config.strict_host_key_checking
}

/// Get ProxyJump configuration
pub(super) fn get_proxy_jump(hosts: &[SshHostConfig], hostname: &str) -> Option<String> {
    let config = find_host_config(hosts, hostname);
    config.proxy_jump
}

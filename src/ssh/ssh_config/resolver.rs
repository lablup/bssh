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

//! Configuration resolution and merging logic for SSH configuration with Match support
//!
//! This module handles finding matching host configurations and merging them
//! according to SSH configuration precedence rules, including Match blocks.

use super::match_directive::MatchContext;
use super::pattern::matches_host_pattern;
use super::types::{ConfigBlock, SshHostConfig};
use std::path::PathBuf;

/// Find configuration for a specific hostname
pub(super) fn find_host_config(hosts: &[SshHostConfig], hostname: &str) -> SshHostConfig {
    find_host_config_with_user(hosts, hostname, None)
}

/// Find configuration for a specific hostname with optional user
pub(super) fn find_host_config_with_user(
    hosts: &[SshHostConfig],
    hostname: &str,
    remote_user: Option<&str>,
) -> SshHostConfig {
    // Host blocks match the destination as written. Resolve those first so
    // Match host/user sees the effective HostName and remote user, as OpenSSH
    // does during its final configuration pass.
    let mut preliminary = SshHostConfig::default();
    for host_config in hosts {
        let current_hostname = preliminary
            .hostname
            .clone()
            .unwrap_or_else(|| hostname.to_string());
        let current_user = remote_user
            .map(str::to_string)
            .or_else(|| preliminary.user.clone())
            .or_else(|| whoami::username().ok());
        let preliminary_context = MatchContext::with_original_hostname(
            current_hostname,
            hostname.to_string(),
            current_user,
        )
        .ok();
        let is_host_match = match &host_config.block_type {
            Some(ConfigBlock::Host(patterns)) => matches_host_pattern(hostname, patterns),
            Some(ConfigBlock::Match(_)) => false,
            None => matches_host_pattern(hostname, &host_config.host_patterns),
        } && scopes_match(host_config, hostname, preliminary_context.as_ref());
        if is_host_match {
            merge_host_config(&mut preliminary, host_config);
        }
    }

    let effective_hostname = preliminary
        .hostname
        .clone()
        .unwrap_or_else(|| hostname.to_string());
    let effective_user = remote_user
        .map(str::to_string)
        .or_else(|| preliminary.user.clone())
        .or_else(|| whoami::username().ok());
    let mut merged_config = SshHostConfig::default();

    // Create match context for evaluating Match blocks
    let match_context = match MatchContext::with_original_hostname(
        effective_hostname,
        hostname.to_string(),
        effective_user,
    ) {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            tracing::warn!("Failed to create match context: {}", e);
            None
        }
    };

    for host_config in hosts {
        let should_apply = match &host_config.block_type {
            Some(ConfigBlock::Host(patterns)) => {
                // For Host blocks, check pattern matching
                matches_host_pattern(hostname, patterns)
            }
            Some(ConfigBlock::Match(conditions)) => {
                // For Match blocks, evaluate conditions
                if let Some(ref ctx) = match_context {
                    // Create a temporary MatchBlock to evaluate conditions
                    let match_block = super::match_directive::MatchBlock {
                        conditions: conditions.clone(),
                        config: host_config.clone(),
                        line_number: 0, // Not used for evaluation
                    };
                    match match_block.matches(ctx) {
                        Ok(matches) => matches,
                        Err(e) => {
                            tracing::debug!("Failed to evaluate Match conditions: {}", e);
                            false
                        }
                    }
                } else {
                    false
                }
            }
            None => {
                // Legacy format without block_type - use host_patterns
                matches_host_pattern(hostname, &host_config.host_patterns)
            }
        };

        if should_apply && scopes_match(host_config, hostname, match_context.as_ref()) {
            merge_host_config(&mut merged_config, host_config);
        }
    }

    merged_config
}

fn scopes_match(
    config: &SshHostConfig,
    original_hostname: &str,
    context: Option<&MatchContext>,
) -> bool {
    config.scope_guards.iter().all(|guard| match guard {
        ConfigBlock::Host(patterns) => matches_host_pattern(original_hostname, patterns),
        ConfigBlock::Match(conditions) => context.is_some_and(|context| {
            let block = super::match_directive::MatchBlock {
                conditions: conditions.clone(),
                config: SshHostConfig::default(),
                line_number: 0,
            };
            block.matches(context).unwrap_or(false)
        }),
    })
}

/// Merge a matching block using OpenSSH's first-obtained-value rule.
pub(super) fn merge_host_config(base: &mut SshHostConfig, overlay: &SshHostConfig) {
    for (keyword, value) in &overlay.unimplemented_options {
        base.unimplemented_options
            .entry(keyword.clone())
            .or_insert_with(|| value.clone());
    }
    for (keyword, value) in &overlay.unknown_options {
        base.unknown_options
            .entry(keyword.clone())
            .or_insert_with(|| value.clone());
    }
    // Blocks are visited in source order, so scalar values only fill empty slots.
    if base.host_patterns.is_empty() && !overlay.host_patterns.is_empty() {
        base.host_patterns = overlay.host_patterns.clone();
    }
    if base.hostname.is_none() && overlay.hostname.is_some() {
        base.hostname = overlay.hostname.clone();
    }
    if base.user.is_none() && overlay.user.is_some() {
        base.user = overlay.user.clone();
    }
    if base.port.is_none() && overlay.port.is_some() {
        base.port = overlay.port;
    }
    if !overlay.identity_files.is_empty() {
        // For identity files, we append them
        base.identity_files
            .extend(overlay.identity_files.iter().cloned());
    }
    // OpenSSH keeps the first obtained proxy directive. ProxyCommand and
    // ProxyJump compete for the same slot, so either one suppresses all later
    // occurrences of both directives.
    if base.proxy_jump.is_none() && base.proxy_command.is_none() {
        if base.proxy_jump.is_none() && overlay.proxy_jump.is_some() {
            base.proxy_jump = overlay.proxy_jump.clone();
        } else if base.proxy_command.is_none() && overlay.proxy_command.is_some() {
            base.proxy_command = overlay.proxy_command.clone();
        }
    }
    if base.proxy_use_fdpass.is_none() && overlay.proxy_use_fdpass.is_some() {
        base.proxy_use_fdpass = overlay.proxy_use_fdpass;
    }
    if base.strict_host_key_checking.is_none() && overlay.strict_host_key_checking.is_some() {
        base.strict_host_key_checking = overlay.strict_host_key_checking.clone();
    }
    if base.user_known_hosts_file.is_none() && overlay.user_known_hosts_file.is_some() {
        base.user_known_hosts_file = overlay.user_known_hosts_file.clone();
    }
    if base.global_known_hosts_file.is_none() && overlay.global_known_hosts_file.is_some() {
        base.global_known_hosts_file = overlay.global_known_hosts_file.clone();
    }
    if base.forward_agent.is_none() && overlay.forward_agent.is_some() {
        base.forward_agent = overlay.forward_agent;
    }
    if base.forward_x11.is_none() && overlay.forward_x11.is_some() {
        base.forward_x11 = overlay.forward_x11;
    }
    if base.server_alive_interval.is_none() && overlay.server_alive_interval.is_some() {
        base.server_alive_interval = overlay.server_alive_interval;
    }
    if base.server_alive_count_max.is_none() && overlay.server_alive_count_max.is_some() {
        base.server_alive_count_max = overlay.server_alive_count_max;
    }
    if base.connect_timeout.is_none() && overlay.connect_timeout.is_some() {
        base.connect_timeout = overlay.connect_timeout;
    }
    if base.connection_attempts.is_none() && overlay.connection_attempts.is_some() {
        base.connection_attempts = overlay.connection_attempts;
    }
    if base.batch_mode.is_none() && overlay.batch_mode.is_some() {
        base.batch_mode = overlay.batch_mode;
    }
    if base.compression.is_none() && overlay.compression.is_some() {
        base.compression = overlay.compression;
    }
    if base.tcp_keep_alive.is_none() && overlay.tcp_keep_alive.is_some() {
        base.tcp_keep_alive = overlay.tcp_keep_alive;
    }
    if base.preferred_authentications.is_empty() && !overlay.preferred_authentications.is_empty() {
        base.preferred_authentications = overlay.preferred_authentications.clone();
    }
    if base.pubkey_authentication.is_none() && overlay.pubkey_authentication.is_some() {
        base.pubkey_authentication = overlay.pubkey_authentication;
    }
    if base.password_authentication.is_none() && overlay.password_authentication.is_some() {
        base.password_authentication = overlay.password_authentication;
    }
    if base.keyboard_interactive_authentication.is_none()
        && overlay.keyboard_interactive_authentication.is_some()
    {
        base.keyboard_interactive_authentication = overlay.keyboard_interactive_authentication;
    }
    if base.gssapi_authentication.is_none() && overlay.gssapi_authentication.is_some() {
        base.gssapi_authentication = overlay.gssapi_authentication;
    }
    if base.host_key_algorithms.is_empty() && !overlay.host_key_algorithms.is_empty() {
        base.host_key_algorithms = overlay.host_key_algorithms.clone();
        base.resolved_host_key_algorithms = overlay.resolved_host_key_algorithms.clone();
    }
    if base.kex_algorithms.is_empty() && !overlay.kex_algorithms.is_empty() {
        base.kex_algorithms = overlay.kex_algorithms.clone();
        base.resolved_kex_algorithms = overlay.resolved_kex_algorithms.clone();
    }
    if base.ciphers.is_empty() && !overlay.ciphers.is_empty() {
        base.ciphers = overlay.ciphers.clone();
        base.resolved_ciphers = overlay.resolved_ciphers.clone();
    }
    if base.macs.is_empty() && !overlay.macs.is_empty() {
        base.macs = overlay.macs.clone();
        base.resolved_macs = overlay.resolved_macs.clone();
    }
    if !overlay.send_env.is_empty() {
        base.send_env.extend(overlay.send_env.iter().cloned());
    }
    for (name, value) in &overlay.set_env {
        base.set_env
            .entry(name.clone())
            .or_insert_with(|| value.clone());
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
    if !overlay.forwarding_directives.is_empty() {
        base.forwarding_directives
            .extend(overlay.forwarding_directives.iter().cloned());
    }
    if base.request_tty.is_none() && overlay.request_tty.is_some() {
        base.request_tty = overlay.request_tty.clone();
    }
    if base.escape_char.is_none() && overlay.escape_char.is_some() {
        base.escape_char = overlay.escape_char.clone();
    }
    if base.log_level.is_none() && overlay.log_level.is_some() {
        base.log_level = overlay.log_level.clone();
    }
    if base.syslog_facility.is_none() && overlay.syslog_facility.is_some() {
        base.syslog_facility = overlay.syslog_facility.clone();
    }
    if base.protocol.is_empty() && !overlay.protocol.is_empty() {
        base.protocol = overlay.protocol.clone();
    }
    if base.address_family.is_none() && overlay.address_family.is_some() {
        base.address_family = overlay.address_family.clone();
    }
    if base.bind_address.is_none() && overlay.bind_address.is_some() {
        base.bind_address = overlay.bind_address.clone();
    }
    if base.clear_all_forwardings.is_none() && overlay.clear_all_forwardings.is_some() {
        base.clear_all_forwardings = overlay.clear_all_forwardings;
    }
    if base.control_master.is_none() && overlay.control_master.is_some() {
        base.control_master = overlay.control_master.clone();
    }
    if base.control_path.is_none() && overlay.control_path.is_some() {
        base.control_path = overlay.control_path.clone();
    }
    if base.control_persist.is_none() && overlay.control_persist.is_some() {
        base.control_persist = overlay.control_persist.clone();
    }
    // Certificate authentication and advanced port forwarding options
    if !overlay.certificate_files.is_empty() {
        // For certificate files, we append them like identity files with deduplication and limit
        const MAX_CERTIFICATE_FILES: usize = 100; // Reasonable limit to prevent memory exhaustion

        for cert_file in &overlay.certificate_files {
            // Skip if already present (deduplication)
            if !base.certificate_files.contains(cert_file) {
                if base.certificate_files.len() >= MAX_CERTIFICATE_FILES {
                    tracing::warn!(
                        "Maximum number of certificate files ({}) reached, ignoring additional entries",
                        MAX_CERTIFICATE_FILES
                    );
                    break;
                }
                base.certificate_files.push(cert_file.clone());
            }
        }
    }
    if base.ca_signature_algorithms.is_empty() && !overlay.ca_signature_algorithms.is_empty() {
        base.ca_signature_algorithms = overlay.ca_signature_algorithms.clone();
    }
    if base.gateway_ports.is_none() && overlay.gateway_ports.is_some() {
        base.gateway_ports = overlay.gateway_ports.clone();
    }
    if base.exit_on_forward_failure.is_none() && overlay.exit_on_forward_failure.is_some() {
        base.exit_on_forward_failure = overlay.exit_on_forward_failure;
    }
    if !overlay.permit_remote_open.is_empty() {
        // For PermitRemoteOpen, we append them with deduplication and limit
        const MAX_PERMIT_REMOTE_OPEN: usize = 1000; // Reasonable limit to prevent memory exhaustion

        for entry in &overlay.permit_remote_open {
            // Skip if already present (deduplication)
            if !base.permit_remote_open.contains(entry) {
                if base.permit_remote_open.len() >= MAX_PERMIT_REMOTE_OPEN {
                    tracing::warn!(
                        "Maximum number of PermitRemoteOpen entries ({}) reached, ignoring additional entries",
                        MAX_PERMIT_REMOTE_OPEN
                    );
                    break;
                }
                base.permit_remote_open.push(entry.clone());
            }
        }
    }
    if base.hostbased_authentication.is_none() && overlay.hostbased_authentication.is_some() {
        base.hostbased_authentication = overlay.hostbased_authentication;
    }
    if base.hostbased_accepted_algorithms.is_empty()
        && !overlay.hostbased_accepted_algorithms.is_empty()
    {
        base.hostbased_accepted_algorithms = overlay.hostbased_accepted_algorithms.clone();
    }
    // Command execution and automation options
    if base.permit_local_command.is_none() && overlay.permit_local_command.is_some() {
        base.permit_local_command = overlay.permit_local_command;
    }
    if base.local_command.is_none() && overlay.local_command.is_some() {
        base.local_command = overlay.local_command.clone();
    }
    if base.remote_command.is_none() && overlay.remote_command.is_some() {
        base.remote_command = overlay.remote_command.clone();
    }
    if base.known_hosts_command.is_none() && overlay.known_hosts_command.is_some() {
        base.known_hosts_command = overlay.known_hosts_command.clone();
    }
    if base.fork_after_authentication.is_none() && overlay.fork_after_authentication.is_some() {
        base.fork_after_authentication = overlay.fork_after_authentication;
    }
    if base.session_type.is_none() && overlay.session_type.is_some() {
        base.session_type = overlay.session_type.clone();
    }
    if base.stdin_null.is_none() && overlay.stdin_null.is_some() {
        base.stdin_null = overlay.stdin_null;
    }
    // Host key verification, authentication, and network options
    // Host key verification & security
    if base.no_host_authentication_for_localhost.is_none()
        && overlay.no_host_authentication_for_localhost.is_some()
    {
        base.no_host_authentication_for_localhost = overlay.no_host_authentication_for_localhost;
    }
    if base.hash_known_hosts.is_none() && overlay.hash_known_hosts.is_some() {
        base.hash_known_hosts = overlay.hash_known_hosts;
    }
    if base.check_host_ip.is_none() && overlay.check_host_ip.is_some() {
        base.check_host_ip = overlay.check_host_ip;
    }
    if base.visual_host_key.is_none() && overlay.visual_host_key.is_some() {
        base.visual_host_key = overlay.visual_host_key;
    }
    if base.host_key_alias.is_none() && overlay.host_key_alias.is_some() {
        base.host_key_alias = overlay.host_key_alias.clone();
    }
    if base.verify_host_key_dns.is_none() && overlay.verify_host_key_dns.is_some() {
        base.verify_host_key_dns = overlay.verify_host_key_dns.clone();
    }
    if base.update_host_keys.is_none() && overlay.update_host_keys.is_some() {
        base.update_host_keys = overlay.update_host_keys.clone();
    }
    // Authentication
    if base.number_of_password_prompts.is_none() && overlay.number_of_password_prompts.is_some() {
        base.number_of_password_prompts = overlay.number_of_password_prompts;
    }
    if base.enable_ssh_keysign.is_none() && overlay.enable_ssh_keysign.is_some() {
        base.enable_ssh_keysign = overlay.enable_ssh_keysign;
    }
    // Network & connection
    if base.bind_interface.is_none() && overlay.bind_interface.is_some() {
        base.bind_interface = overlay.bind_interface.clone();
    }
    if base.ipqos.is_none() && overlay.ipqos.is_some() {
        base.ipqos = overlay.ipqos;
    }
    if base.rekey_limit.is_none() && overlay.rekey_limit.is_some() {
        base.rekey_limit = overlay.rekey_limit;
    }
    // X11 forwarding
    if base.forward_x11_timeout.is_none() && overlay.forward_x11_timeout.is_some() {
        base.forward_x11_timeout = overlay.forward_x11_timeout.clone();
    }
    if base.forward_x11_trusted.is_none() && overlay.forward_x11_trusted.is_some() {
        base.forward_x11_trusted = overlay.forward_x11_trusted;
    }
    // Authentication and security management options
    // Authentication & agent management
    if base.identities_only.is_none() && overlay.identities_only.is_some() {
        base.identities_only = overlay.identities_only;
    }
    if base.add_keys_to_agent.is_none() && overlay.add_keys_to_agent.is_some() {
        base.add_keys_to_agent = overlay.add_keys_to_agent.clone();
    }
    if base.identity_agent.is_none() && overlay.identity_agent.is_some() {
        base.identity_agent = overlay.identity_agent.clone();
    }
    #[cfg(target_os = "macos")]
    if base.use_keychain.is_none() && overlay.use_keychain.is_some() {
        base.use_keychain = overlay.use_keychain;
    }
    // Security & algorithm management
    if base.pubkey_accepted_algorithms.is_empty() && !overlay.pubkey_accepted_algorithms.is_empty()
    {
        base.pubkey_accepted_algorithms = overlay.pubkey_accepted_algorithms.clone();
        base.resolved_pubkey_accepted_algorithms =
            overlay.resolved_pubkey_accepted_algorithms.clone();
    }
    if base.required_rsa_size.is_none() && overlay.required_rsa_size.is_some() {
        base.required_rsa_size = overlay.required_rsa_size;
    }
    if base.fingerprint_hash.is_none() && overlay.fingerprint_hash.is_some() {
        base.fingerprint_hash = overlay.fingerprint_hash.clone();
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

/// Get the effective Compression value
pub(super) fn get_compression(hosts: &[SshHostConfig], hostname: &str) -> Option<bool> {
    let config = find_host_config(hosts, hostname);
    config.compression
}

/// Get the raw `AddressFamily` value for a hostname.
///
/// The value is returned unparsed; interpretation (and the warn-and-fall-back
/// handling of an unrecognized value) lives in
/// [`AddressFamily::from_config_value`](crate::ssh::tokio_client::AddressFamily::from_config_value)
/// so the CLI flag and the config keyword share one parser.
pub(super) fn get_address_family(hosts: &[SshHostConfig], hostname: &str) -> Option<String> {
    let config = find_host_config(hosts, hostname);
    config.address_family
}

/// Get ProxyJump configuration
pub(super) fn get_proxy_jump(hosts: &[SshHostConfig], hostname: &str) -> Option<String> {
    let config = find_host_config(hosts, hostname);
    config.proxy_jump
}

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
    let mut merged_config = SshHostConfig::default();

    // Create match context for evaluating Match blocks
    let match_context =
        match MatchContext::new(hostname.to_string(), remote_user.map(|s| s.to_string())) {
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

        if should_apply {
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
    if overlay.proxy_use_fdpass.is_some() {
        base.proxy_use_fdpass = overlay.proxy_use_fdpass;
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
    if !overlay.ca_signature_algorithms.is_empty() {
        base.ca_signature_algorithms = overlay.ca_signature_algorithms.clone();
    }
    if overlay.gateway_ports.is_some() {
        base.gateway_ports = overlay.gateway_ports.clone();
    }
    if overlay.exit_on_forward_failure.is_some() {
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
    if overlay.hostbased_authentication.is_some() {
        base.hostbased_authentication = overlay.hostbased_authentication;
    }
    if !overlay.hostbased_accepted_algorithms.is_empty() {
        base.hostbased_accepted_algorithms = overlay.hostbased_accepted_algorithms.clone();
    }
    // Command execution and automation options
    if overlay.permit_local_command.is_some() {
        base.permit_local_command = overlay.permit_local_command;
    }
    if overlay.local_command.is_some() {
        base.local_command = overlay.local_command.clone();
    }
    if overlay.remote_command.is_some() {
        base.remote_command = overlay.remote_command.clone();
    }
    if overlay.known_hosts_command.is_some() {
        base.known_hosts_command = overlay.known_hosts_command.clone();
    }
    if overlay.fork_after_authentication.is_some() {
        base.fork_after_authentication = overlay.fork_after_authentication;
    }
    if overlay.session_type.is_some() {
        base.session_type = overlay.session_type.clone();
    }
    if overlay.stdin_null.is_some() {
        base.stdin_null = overlay.stdin_null;
    }
    // Host key verification, authentication, and network options
    // Host key verification & security
    if overlay.no_host_authentication_for_localhost.is_some() {
        base.no_host_authentication_for_localhost = overlay.no_host_authentication_for_localhost;
    }
    if overlay.hash_known_hosts.is_some() {
        base.hash_known_hosts = overlay.hash_known_hosts;
    }
    if overlay.check_host_ip.is_some() {
        base.check_host_ip = overlay.check_host_ip;
    }
    if overlay.visual_host_key.is_some() {
        base.visual_host_key = overlay.visual_host_key;
    }
    if overlay.host_key_alias.is_some() {
        base.host_key_alias = overlay.host_key_alias.clone();
    }
    if overlay.verify_host_key_dns.is_some() {
        base.verify_host_key_dns = overlay.verify_host_key_dns.clone();
    }
    if overlay.update_host_keys.is_some() {
        base.update_host_keys = overlay.update_host_keys.clone();
    }
    // Authentication
    if overlay.number_of_password_prompts.is_some() {
        base.number_of_password_prompts = overlay.number_of_password_prompts;
    }
    if overlay.enable_ssh_keysign.is_some() {
        base.enable_ssh_keysign = overlay.enable_ssh_keysign;
    }
    // Network & connection
    if overlay.bind_interface.is_some() {
        base.bind_interface = overlay.bind_interface.clone();
    }
    if overlay.ipqos.is_some() {
        base.ipqos = overlay.ipqos.clone();
    }
    if overlay.rekey_limit.is_some() {
        base.rekey_limit = overlay.rekey_limit.clone();
    }
    // X11 forwarding
    if overlay.forward_x11_timeout.is_some() {
        base.forward_x11_timeout = overlay.forward_x11_timeout.clone();
    }
    if overlay.forward_x11_trusted.is_some() {
        base.forward_x11_trusted = overlay.forward_x11_trusted;
    }
    // Authentication and security management options
    // Authentication & agent management
    if overlay.identities_only.is_some() {
        base.identities_only = overlay.identities_only;
    }
    if overlay.add_keys_to_agent.is_some() {
        base.add_keys_to_agent = overlay.add_keys_to_agent.clone();
    }
    if overlay.identity_agent.is_some() {
        base.identity_agent = overlay.identity_agent.clone();
    }
    #[cfg(target_os = "macos")]
    if overlay.use_keychain.is_some() {
        base.use_keychain = overlay.use_keychain;
    }
    // Security & algorithm management
    if !overlay.pubkey_accepted_algorithms.is_empty() {
        base.pubkey_accepted_algorithms = overlay.pubkey_accepted_algorithms.clone();
    }
    if overlay.required_rsa_size.is_some() {
        base.required_rsa_size = overlay.required_rsa_size;
    }
    if overlay.fingerprint_hash.is_some() {
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

/// Get ProxyJump configuration
pub(super) fn get_proxy_jump(hosts: &[SshHostConfig], hostname: &str) -> Option<String> {
    let config = find_host_config(hosts, hostname);
    config.proxy_jump
}

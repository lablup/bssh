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
use super::types::{ConfigBlock, ConfigPass, SshHostConfig};
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
    let (mut merged_config, requests_final) =
        resolve_first_pass_with_user(hosts, hostname, remote_user);

    if requests_final || canonicalization_requested(&merged_config) {
        // OpenSSH fixes HostName to the first-pass effective destination before
        // reparsing. A Match final block therefore cannot obtain HostName when
        // it was otherwise unset during pass one.
        merged_config.hostname = Some(effective_hostname(&merged_config, hostname));
        for host_config in hosts
            .iter()
            .filter(|config| config.pass == ConfigPass::FinalOnly)
        {
            apply_source_block(&mut merged_config, host_config, hostname, remote_user, true);
        }
    }

    merged_config
}

/// Resolve only pass-one blocks without fixing an unset HostName or replaying
/// final-pass blocks. Source loaders use this between user and system files so
/// a later first-pass HostName can still be obtained in OpenSSH source order.
pub(super) fn find_host_config_first_pass(
    hosts: &[SshHostConfig],
    hostname: &str,
) -> SshHostConfig {
    resolve_first_pass_with_user(hosts, hostname, None).0
}

fn resolve_first_pass_with_user(
    hosts: &[SshHostConfig],
    hostname: &str,
    remote_user: Option<&str>,
) -> (SshHostConfig, bool) {
    let mut merged_config = SshHostConfig::default();
    let mut requests_final = false;
    for host_config in hosts.iter().filter(|config| config.pass == ConfigPass::Any) {
        requests_final |= apply_source_block(
            &mut merged_config,
            host_config,
            hostname,
            remote_user,
            false,
        );
    }
    (merged_config, requests_final)
}

fn apply_source_block(
    merged: &mut SshHostConfig,
    source: &SshHostConfig,
    original_hostname: &str,
    remote_user: Option<&str>,
    final_pass: bool,
) -> bool {
    let current_hostname = effective_hostname(merged, original_hostname);
    let current_user = remote_user
        .map(str::to_string)
        .or_else(|| merged.user.clone())
        .or_else(|| whoami::username().ok());
    let context = MatchContext::with_original_hostname(
        current_hostname,
        original_hostname.to_string(),
        current_user,
    )
    .map(|context| context.with_config(merged).with_final_pass(final_pass));
    let Ok(context) = context else {
        return false;
    };
    if !scopes_match(source, original_hostname, Some(&context)) {
        return false;
    }
    let evaluation = match &source.block_type {
        Some(ConfigBlock::Host(patterns)) => super::match_directive::MatchEvaluation {
            matched: matches_host_pattern(original_hostname, patterns),
            requests_final: false,
        },
        Some(ConfigBlock::Match(conditions)) => {
            if let Some(matched) = source.precomputed_match {
                super::match_directive::MatchEvaluation {
                    matched,
                    requests_final: source.precomputed_requests_final.unwrap_or(false),
                }
            } else {
                conditions_match(conditions, &context)
            }
        }
        None => super::match_directive::MatchEvaluation {
            matched: matches_host_pattern(original_hostname, &source.host_patterns),
            requests_final: false,
        },
    };
    if evaluation.matched {
        merge_host_config(merged, source);
    }
    evaluation.requests_final
}

fn effective_hostname(config: &SshHostConfig, original_hostname: &str) -> String {
    config.hostname.as_deref().map_or_else(
        || original_hostname.to_string(),
        |value| expand_hostname_value(value, original_hostname),
    )
}

pub(super) fn expand_hostname_value(value: &str, original_hostname: &str) -> String {
    let mut output = String::with_capacity(value.len() + original_hostname.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            output.push(ch);
            continue;
        }
        match chars.next() {
            Some('h') => output.push_str(original_hostname),
            Some('%') => output.push('%'),
            Some(other) => {
                output.push('%');
                output.push(other);
            }
            None => output.push('%'),
        }
    }
    output
}

fn conditions_match(
    conditions: &[super::match_directive::MatchCondition],
    context: &MatchContext,
) -> super::match_directive::MatchEvaluation {
    let block = super::match_directive::MatchBlock {
        conditions: conditions.to_vec(),
        config: SshHostConfig::default(),
        line_number: 0,
    };
    block
        .evaluate(context)
        .unwrap_or(super::match_directive::MatchEvaluation {
            matched: false,
            requests_final: false,
        })
}

pub(super) fn requests_final_pass(hosts: &[SshHostConfig]) -> bool {
    hosts.iter().any(|config| {
        (match &config.block_type {
            Some(ConfigBlock::Match(conditions)) => conditions.iter().any(requests_final),
            _ => false,
        }) || config.scope_guards.iter().any(|guard| match guard {
            ConfigBlock::Match(conditions) => conditions.iter().any(requests_final),
            ConfigBlock::Host(_) => false,
        })
    })
}

pub(super) fn requests_final_pass_for_host(hosts: &[SshHostConfig], hostname: &str) -> bool {
    let (merged, requests_final) = resolve_first_pass_with_user(hosts, hostname, None);
    requests_final || canonicalization_requested(&merged)
}

fn canonicalization_requested(config: &SshHostConfig) -> bool {
    config
        .unimplemented_options
        .get("canonicalizehostname")
        .and_then(|values| values.first())
        .is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "yes" | "true" | "always"
            )
        })
}

fn requests_final(condition: &super::match_directive::MatchCondition) -> bool {
    condition.requests_final_pass()
}

fn scopes_match(
    config: &SshHostConfig,
    original_hostname: &str,
    context: Option<&MatchContext>,
) -> bool {
    if let Some(active) = config.precomputed_scope_active {
        return active;
    }
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
        extend_paths_for_pass(
            &mut base.identity_files,
            &mut base.identity_file_args,
            &overlay.identity_files,
            &overlay.identity_file_args,
            overlay.pass,
        );
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
        extend_for_pass(&mut base.send_env, &overlay.send_env, overlay.pass);
    }
    for (name, value) in &overlay.set_env {
        base.set_env
            .entry(name.clone())
            .or_insert_with(|| value.clone());
    }
    if !overlay.local_forward.is_empty() {
        extend_forwardings_for_pass(
            &mut base.local_forward,
            &mut base.local_forward_args,
            &overlay.local_forward,
            &overlay.local_forward_args,
            overlay.pass,
        );
    }
    if !overlay.remote_forward.is_empty() {
        extend_forwardings_for_pass(
            &mut base.remote_forward,
            &mut base.remote_forward_args,
            &overlay.remote_forward,
            &overlay.remote_forward_args,
            overlay.pass,
        );
    }
    if !overlay.dynamic_forward.is_empty() {
        extend_forwardings_for_pass(
            &mut base.dynamic_forward,
            &mut base.dynamic_forward_args,
            &overlay.dynamic_forward,
            &overlay.dynamic_forward_args,
            overlay.pass,
        );
    }
    if !overlay.forwarding_directives.is_empty() {
        extend_for_pass(
            &mut base.forwarding_directives,
            &overlay.forwarding_directives,
            overlay.pass,
        );
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

        let arguments_are_aligned = base.certificate_file_args.len()
            == base.certificate_files.len()
            && overlay.certificate_file_args.len() == overlay.certificate_files.len();
        if !arguments_are_aligned {
            base.certificate_file_args.clear();
        }
        for (index, cert_file) in overlay.certificate_files.iter().enumerate() {
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
                if arguments_are_aligned {
                    base.certificate_file_args
                        .push(overlay.certificate_file_args[index].clone());
                }
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

fn extend_for_pass<T: Clone + PartialEq>(base: &mut Vec<T>, values: &[T], pass: ConfigPass) {
    if pass == ConfigPass::FinalOnly {
        let new_values = values
            .iter()
            .filter(|value| !base.contains(value))
            .cloned()
            .collect::<Vec<_>>();
        base.extend(new_values);
    } else {
        base.extend(values.iter().cloned());
    }
}

fn extend_paths_for_pass(
    base_paths: &mut Vec<PathBuf>,
    base_arguments: &mut Vec<String>,
    paths: &[PathBuf],
    arguments: &[String],
    pass: ConfigPass,
) {
    if base_arguments.len() != base_paths.len() || arguments.len() != paths.len() {
        extend_for_pass(base_paths, paths, pass);
        base_arguments.clear();
        return;
    }
    if pass == ConfigPass::Any {
        base_paths.extend_from_slice(paths);
        base_arguments.extend_from_slice(arguments);
        return;
    }
    for (path, argument) in paths.iter().zip(arguments) {
        if !base_paths.contains(path) {
            base_paths.push(path.clone());
            base_arguments.push(argument.clone());
        }
    }
}

fn extend_forwardings_for_pass(
    base_values: &mut Vec<String>,
    base_arguments: &mut Vec<Vec<String>>,
    values: &[String],
    arguments: &[Vec<String>],
    pass: ConfigPass,
) {
    if arguments.len() != values.len() || base_arguments.len() != base_values.len() {
        extend_for_pass(base_values, values, pass);
        base_arguments.clear();
        return;
    }
    if pass == ConfigPass::Any {
        base_values.extend_from_slice(values);
        base_arguments.extend_from_slice(arguments);
        return;
    }
    for (value, arguments) in values.iter().zip(arguments) {
        if !base_values.contains(value) {
            base_values.push(value.clone());
            base_arguments.push(arguments.clone());
        }
    }
}

/// Get the effective hostname (resolves HostName directive)
pub(super) fn get_effective_hostname(hosts: &[SshHostConfig], hostname: &str) -> String {
    let config = find_host_config(hosts, hostname);
    effective_hostname(&config, hostname)
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

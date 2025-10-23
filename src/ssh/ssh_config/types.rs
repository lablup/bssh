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

//! Core data structures for SSH configuration

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

/// Configuration block type
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigBlock {
    /// Host block with patterns
    Host(Vec<String>),
    /// Match block with conditions
    Match(Vec<crate::ssh::ssh_config::match_directive::MatchCondition>),
}

/// SSH configuration for a specific host or match block
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SshHostConfig {
    /// Block type (Host patterns or Match conditions)
    pub block_type: Option<ConfigBlock>,
    /// Host patterns (for backward compatibility and Host blocks)
    pub host_patterns: Vec<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<PathBuf>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub strict_host_key_checking: Option<String>,
    pub user_known_hosts_file: Option<PathBuf>,
    pub global_known_hosts_file: Option<PathBuf>,
    pub forward_agent: Option<bool>,
    pub forward_x11: Option<bool>,
    pub server_alive_interval: Option<u32>,
    pub server_alive_count_max: Option<u32>,
    pub connect_timeout: Option<u32>,
    pub connection_attempts: Option<u32>,
    pub batch_mode: Option<bool>,
    pub compression: Option<bool>,
    pub tcp_keep_alive: Option<bool>,
    pub preferred_authentications: Vec<String>,
    pub pubkey_authentication: Option<bool>,
    pub password_authentication: Option<bool>,
    pub keyboard_interactive_authentication: Option<bool>,
    pub gssapi_authentication: Option<bool>,
    pub host_key_algorithms: Vec<String>,
    pub kex_algorithms: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    pub send_env: Vec<String>,
    pub set_env: HashMap<String, String>,
    pub local_forward: Vec<String>,
    pub remote_forward: Vec<String>,
    pub dynamic_forward: Vec<String>,
    pub request_tty: Option<String>,
    pub escape_char: Option<String>,
    pub log_level: Option<String>,
    pub syslog_facility: Option<String>,
    pub protocol: Vec<String>,
    pub address_family: Option<String>,
    pub bind_address: Option<String>,
    pub clear_all_forwardings: Option<bool>,
    pub control_master: Option<String>,
    pub control_path: Option<String>,
    pub control_persist: Option<String>,
    // Phase 2: Certificate authentication and advanced port forwarding
    pub certificate_files: Vec<PathBuf>,
    pub ca_signature_algorithms: Vec<String>,
    pub gateway_ports: Option<String>,
    pub exit_on_forward_failure: Option<bool>,
    pub permit_remote_open: Vec<String>,
    pub hostbased_authentication: Option<bool>,
    pub hostbased_accepted_algorithms: Vec<String>,
    // Phase 3: Command execution and automation options
    pub permit_local_command: Option<bool>,
    pub local_command: Option<String>,
    pub remote_command: Option<String>,
    pub known_hosts_command: Option<String>,
    pub fork_after_authentication: Option<bool>,
    pub session_type: Option<String>,
    pub stdin_null: Option<bool>,
    // Phase 4: Remaining useful SSH config options
    // Host key verification & security
    pub no_host_authentication_for_localhost: Option<bool>,
    pub hash_known_hosts: Option<bool>,
    pub check_host_ip: Option<bool>,
    pub visual_host_key: Option<bool>,
    pub host_key_alias: Option<String>,
    pub verify_host_key_dns: Option<String>,
    pub update_host_keys: Option<String>,
    // Authentication
    pub number_of_password_prompts: Option<u32>,
    pub enable_ssh_keysign: Option<bool>,
    // Network & connection
    pub bind_interface: Option<String>,
    pub ipqos: Option<String>,
    pub rekey_limit: Option<String>,
    // X11 forwarding
    pub forward_x11_timeout: Option<String>,
    pub forward_x11_trusted: Option<bool>,
    // Phase 5: High-priority practical SSH config options
    // Authentication & agent management
    pub identities_only: Option<bool>,
    pub add_keys_to_agent: Option<String>, // yes/no/ask/confirm
    pub identity_agent: Option<String>,    // socket path or "none"
    // Security & algorithm management
    pub pubkey_accepted_algorithms: Vec<String>,
    pub required_rsa_size: Option<u32>,
    pub fingerprint_hash: Option<String>, // md5/sha256
}

impl fmt::Display for SshHostConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Host {}", self.host_patterns.join(" "))?;
        if let Some(ref hostname) = self.hostname {
            write!(f, " ({hostname})")?;
        }
        if let Some(ref user) = self.user {
            write!(f, " user={user}")?;
        }
        if let Some(port) = self.port {
            write!(f, " port={port}")?;
        }
        Ok(())
    }
}

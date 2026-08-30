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

//! SSH connection management and establishment.
//!
//! This module handles the low-level SSH connection establishment,
//! including address resolution, connection attempts, and initial handshake.

use russh::client::{Config, DisconnectReason, Handle, Handler};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use std::{fmt::Debug, io};

use super::address_family::AddressFamily;
use super::auth_policy::SshAuthenticationPolicy;
use super::authentication::{AuthMethod, ServerCheckMethod};
use super::proxy_command::{
    ProxyCommandConfig, ProxyCommandProcess, ProxyMode, spawn_proxy_command,
};
use crate::forwarding::remote::RemoteForwardRegistry;
use crate::forwarding::{ForwardingDirective, ForwardingPlan, ForwardingRuntime};
use crate::ssh::SshConfig;

/// Default keepalive interval in seconds.
///
/// This is intentionally below common 60-second idle reapers so the client
/// sends traffic before the remote side or an intermediate gateway decides the
/// session is idle.
pub const DEFAULT_KEEPALIVE_INTERVAL: u64 = 30;

/// Default maximum keepalive attempts before considering connection dead.
/// With the default interval and max, connection failure is detected within
/// about 120s: three unanswered probes plus the next timer tick that observes
/// they were missed.
pub const DEFAULT_KEEPALIVE_MAX: usize = 3;

/// SSH connection configuration for keepalive and timeout settings.
///
/// This struct provides a centralized way to configure SSH connection
/// parameters, particularly for keepalive functionality which prevents
/// idle connections from being terminated by firewalls or NAT devices.
///
/// # Example
///
/// ```no_run
/// use bssh::ssh::tokio_client::SshConnectionConfig;
///
/// // Use defaults (30s interval, 3 max attempts)
/// let config = SshConnectionConfig::default();
///
/// // Custom configuration
/// let config = SshConnectionConfig::new()
///     .with_keepalive_interval(Some(15))
///     .with_keepalive_max(5);
///
/// // Disable keepalive
/// let config = SshConnectionConfig::new()
///     .with_keepalive_interval(None);
/// ```
#[derive(Debug, Clone)]
pub struct SshConnectionConfig {
    /// Interval in seconds between keepalive packets.
    /// None disables keepalive.
    /// Default: 30 seconds
    pub keepalive_interval: Option<u64>,

    /// Maximum number of keepalive packets to send without response
    /// before considering the connection dead.
    /// Default: 3
    pub keepalive_max: usize,

    /// Whether the ssh_config `Compression` directive resolved to `yes`.
    ///
    /// `false` (the default) matches `Compression no`/unset and advertises
    /// only `none` compression to the server. `true` matches `Compression
    /// yes` and advertises eager `zlib` ahead of `none`. See
    /// [`to_russh_config`](Self::to_russh_config) for why `zlib@openssh.com`
    /// is never advertised regardless of this flag.
    pub compression: bool,

    /// Which IP address family the connection may use.
    ///
    /// [`AddressFamily::Any`] (the default) tries every resolved address in
    /// resolver order, which is the historical behavior. The forced variants
    /// come from `-4`/`-6` or the ssh_config `AddressFamily` keyword and are
    /// applied in [`Client::connect_with_ssh_config`]; see `ARCHITECTURE.md`
    /// ("Address Family Preference") for the scope of that constraint.
    pub address_family: AddressFamily,

    /// Number of complete connection rounds. Each round resolves DNS again,
    /// filters the result by `AddressFamily`, and tries every candidate.
    pub connection_attempts: usize,

    /// Whether kernel TCP keepalive is enabled on a connected direct socket.
    /// This is independent from SSH protocol keepalives.
    pub tcp_keep_alive: bool,

    /// Raw `UserKnownHostsFile` values selected for this host.
    ///
    /// They stay unexpanded until the connection target supplies `%h`, `%p`,
    /// and `%r` values to host-key verification.
    pub user_known_hosts_files: Option<Vec<String>>,

    /// Raw `GlobalKnownHostsFile` values selected for this host.
    pub global_known_hosts_files: Option<Vec<String>>,

    /// Explicit known-hosts identity selected by `HostKeyAlias`.
    pub host_key_alias: Option<String>,
    /// Hash host patterns when writing known_hosts.
    pub hash_known_hosts: bool,
    /// Verify the resolved peer address as an additional known-host identity.
    pub check_host_ip: bool,
    /// Optional external known-host lookup command.
    pub known_hosts_command: Option<String>,
    /// Effective VerifyHostKeyDNS policy (yes, ask, or no).
    pub verify_host_key_dns: String,
    /// Effective UpdateHostKeys policy (yes, ask, or no).
    pub update_host_keys: String,
    /// Effective proxy selection for this target.
    pub proxy_mode: Option<ProxyMode>,
    pub cipher_preferences: Option<Vec<russh::cipher::Name>>,
    pub mac_preferences: Option<Vec<russh::mac::Name>>,
    pub kex_preferences: Option<Vec<russh::kex::Name>>,
    pub host_key_preferences: Option<Vec<ssh_key::Algorithm>>,
    /// Whether known-host key types may reorder the default or modified preference list.
    pub order_host_key_algorithms: bool,
    /// Public-key signature policy for the authentication follow-up.
    pub pubkey_accepted_algorithms: Option<Vec<String>>,
    // Authentication method, identity, certificate, and prompt policy for this host.
    pub auth_policy: SshAuthenticationPolicy,
    /// Forwarding directives resolved for this destination.
    pub forwarding_plan: ForwardingPlan,
}

impl Default for SshConnectionConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: Some(DEFAULT_KEEPALIVE_INTERVAL),
            keepalive_max: DEFAULT_KEEPALIVE_MAX,
            compression: false,
            address_family: AddressFamily::Any,
            connection_attempts: 1,
            tcp_keep_alive: true,
            user_known_hosts_files: None,
            global_known_hosts_files: None,
            host_key_alias: None,
            hash_known_hosts: false,
            check_host_ip: false,
            known_hosts_command: None,
            verify_host_key_dns: "no".to_string(),
            update_host_keys: "no".to_string(),
            proxy_mode: None,
            cipher_preferences: None,
            mac_preferences: None,
            kex_preferences: None,
            host_key_preferences: None,
            order_host_key_algorithms: true,
            pubkey_accepted_algorithms: None,
            auth_policy: SshAuthenticationPolicy::default(),
            forwarding_plan: ForwardingPlan::default(),
        }
    }
}

/// Resolves SSH connection settings for a concrete target host.
///
/// The dispatcher builds this once from the CLI flags, YAML defaults, and the
/// parsed ssh_config. Per-node execution then calls
/// [`resolve_for_host`](Self::resolve_for_host) at the last responsible moment
/// so `Host <name>` blocks apply to the actual destination or jump hop instead
/// of a once-per-dispatch fallback.
#[derive(Debug, Clone, Default)]
pub struct SshConnectionConfigResolver {
    fixed_config: Option<SshConnectionConfig>,
    ssh_config: Option<SshConfig>,
    cli_keepalive_interval: Option<u64>,
    cli_keepalive_max: Option<usize>,
    yaml_keepalive_interval: Option<u64>,
    yaml_keepalive_max: Option<usize>,
    cli_address_family: Option<AddressFamily>,
    cli_host_key_alias: Option<String>,
    cli_proxy_jump: Option<String>,
    yaml_proxy_jump: Option<String>,
    cli_identity_files: Vec<PathBuf>,
    cli_local_forwards: Vec<String>,
    cli_remote_forwards: Vec<String>,
    cli_dynamic_forwards: Vec<String>,
    cli_forwarding_order: Vec<ForwardingDirective>,
}

impl SshConnectionConfigResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fixed(config: SshConnectionConfig) -> Self {
        Self {
            fixed_config: Some(config),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_ssh_config(mut self, ssh_config: Option<SshConfig>) -> Self {
        self.ssh_config = ssh_config;
        self
    }

    #[must_use]
    pub fn with_cli_identity_files(mut self, identity_files: Vec<PathBuf>) -> Self {
        self.cli_identity_files = identity_files;
        self
    }

    #[must_use]
    pub fn with_cli_keepalive_interval(mut self, interval: Option<u64>) -> Self {
        self.cli_keepalive_interval = interval;
        self
    }

    #[must_use]
    pub fn with_cli_keepalive_max(mut self, max: Option<usize>) -> Self {
        self.cli_keepalive_max = max;
        self
    }

    #[must_use]
    pub fn with_yaml_keepalive_interval(mut self, interval: Option<u64>) -> Self {
        self.yaml_keepalive_interval = interval;
        self
    }

    #[must_use]
    pub fn with_yaml_keepalive_max(mut self, max: Option<usize>) -> Self {
        self.yaml_keepalive_max = max;
        self
    }

    #[must_use]
    pub fn with_cli_address_family(mut self, family: Option<AddressFamily>) -> Self {
        if let (Some(config), Some(family)) = (self.fixed_config.as_mut(), family) {
            config.address_family = family;
            return self;
        }
        self.cli_address_family = family;
        self
    }

    #[must_use]
    pub fn with_cli_host_key_alias(mut self, alias: Option<String>) -> Self {
        if let (Some(config), Some(alias)) = (self.fixed_config.as_mut(), alias.as_ref()) {
            config.host_key_alias = Some(alias.clone());
            return self;
        }
        self.cli_host_key_alias = alias;
        self
    }

    #[must_use]
    pub fn with_cli_proxy_jump(mut self, jump: Option<String>) -> Self {
        if let Some(config) = self.fixed_config.as_mut() {
            config.proxy_mode = jump.as_deref().map(proxy_jump_mode);
            return self;
        }
        self.cli_proxy_jump = jump;
        self
    }

    #[must_use]
    pub fn with_yaml_proxy_jump(mut self, jump: Option<String>) -> Self {
        self.yaml_proxy_jump = jump;
        self
    }

    #[must_use]
    pub fn with_cli_forwarding_order(mut self, order: Vec<ForwardingDirective>) -> Self {
        self.cli_forwarding_order = order;
        self
    }

    #[must_use]
    pub fn with_cli_forwardings(
        mut self,
        local: Vec<String>,
        remote: Vec<String>,
        dynamic: Vec<String>,
    ) -> Self {
        self.cli_local_forwards = local;
        self.cli_remote_forwards = remote;
        self.cli_dynamic_forwards = dynamic;
        self
    }

    pub fn resolve_for_host(&self, hostname: &str) -> SshConnectionConfig {
        if let Some(config) = &self.fixed_config {
            return config.clone();
        }

        let keepalive_interval = self
            .cli_keepalive_interval
            .or_else(|| {
                self.ssh_config
                    .as_ref()
                    .and_then(|config| config.get_int_option(Some(hostname), "serveraliveinterval"))
                    .map(|v| v as u64)
            })
            .or(self.yaml_keepalive_interval)
            .unwrap_or(DEFAULT_KEEPALIVE_INTERVAL);

        let keepalive_max = self
            .cli_keepalive_max
            .or_else(|| {
                self.ssh_config
                    .as_ref()
                    .and_then(|config| config.get_int_option(Some(hostname), "serveralivecountmax"))
                    .map(|v| v as usize)
            })
            .or(self.yaml_keepalive_max)
            .unwrap_or(DEFAULT_KEEPALIVE_MAX);

        let compression = self
            .ssh_config
            .as_ref()
            .and_then(|config| config.get_compression(hostname))
            .unwrap_or(false);

        let config_address_family = self
            .ssh_config
            .as_ref()
            .and_then(|config| config.get_address_family(hostname));
        let address_family = self.cli_address_family.unwrap_or_else(|| {
            AddressFamily::resolve(false, false, config_address_family.as_deref())
        });

        let host_config = self
            .ssh_config
            .as_ref()
            .map(|config| config.find_host_config(hostname));
        let connection_attempts = host_config
            .as_ref()
            .and_then(|config| config.connection_attempts)
            .unwrap_or(1) as usize;
        let tcp_keep_alive = host_config
            .as_ref()
            .and_then(|config| config.tcp_keep_alive)
            .unwrap_or(true);
        let user_known_hosts_files = host_config
            .as_ref()
            .and_then(|config| config.user_known_hosts_file.clone());
        let global_known_hosts_files = host_config
            .as_ref()
            .and_then(|config| config.global_known_hosts_file.clone());
        let host_key_alias = self.cli_host_key_alias.clone().or_else(|| {
            host_config
                .as_ref()
                .and_then(|config| config.host_key_alias.clone())
        });
        let hash_known_hosts = host_config
            .as_ref()
            .and_then(|config| config.hash_known_hosts)
            .unwrap_or(false);
        let check_host_ip = host_config
            .as_ref()
            .and_then(|config| config.check_host_ip)
            .unwrap_or(false);
        let known_hosts_command = host_config
            .as_ref()
            .and_then(|config| config.known_hosts_command.clone());
        let verify_host_key_dns = host_config
            .as_ref()
            .and_then(|config| config.verify_host_key_dns.clone())
            .unwrap_or_else(|| "no".to_string());
        let update_host_keys = host_config
            .as_ref()
            .and_then(|config| config.update_host_keys.clone())
            .unwrap_or_else(|| "no".to_string());
        let proxy_mode = self.resolve_proxy_mode(hostname, host_key_alias.clone());
        let cipher_preferences = host_config
            .as_ref()
            .and_then(|config| config.resolved_ciphers.clone());
        let mac_preferences = host_config
            .as_ref()
            .and_then(|config| config.resolved_macs.clone());
        let kex_preferences = host_config
            .as_ref()
            .and_then(|config| config.resolved_kex_algorithms.clone());
        let host_key_preferences = host_config
            .as_ref()
            .and_then(|config| config.resolved_host_key_algorithms.clone());
        let order_host_key_algorithms = host_config.as_ref().is_none_or(|config| {
            config.host_key_algorithms.is_empty()
                || config.host_key_algorithms[0].starts_with('+')
                || config.host_key_algorithms[0].starts_with('-')
        });

        let pubkey_accepted_algorithms = host_config
            .as_ref()
            .and_then(|config| config.resolved_pubkey_accepted_algorithms.clone());
        let mut auth_policy = host_config
            .as_ref()
            .map(|config| {
                let preferred_authentications = if config.preferred_authentications.is_empty() {
                    SshAuthenticationPolicy::default().preferred_authentications
                } else {
                    config.preferred_authentications.clone()
                };
                let identity_file_none = config
                    .identity_files
                    .iter()
                    .any(|path| path.to_string_lossy().eq_ignore_ascii_case("none"));
                let identity_files = config
                    .identity_files
                    .iter()
                    .filter(|path| !path.to_string_lossy().eq_ignore_ascii_case("none"))
                    .cloned()
                    .collect();
                SshAuthenticationPolicy {
                    cli_identity_files: Vec::new(),
                    identity_files,
                    identity_file_none,
                    certificate_files: config.certificate_files.clone(),
                    identities_only: config.identities_only.unwrap_or(false),
                    preferred_authentications,
                    pubkey_authentication: config.pubkey_authentication.unwrap_or(true),
                    password_authentication: config.password_authentication.unwrap_or(true),
                    number_of_password_prompts: config.number_of_password_prompts.unwrap_or(3),
                    batch_mode: config.batch_mode.unwrap_or(false),
                    pubkey_accepted_algorithms: config
                        .resolved_pubkey_accepted_algorithms
                        .clone()
                        .or_else(|| SshAuthenticationPolicy::default().pubkey_accepted_algorithms),
                }
            })
            .unwrap_or_default();
        auth_policy
            .cli_identity_files
            .clone_from(&self.cli_identity_files);
        let mut local_forwards = Vec::new();
        let mut remote_forwards = Vec::new();
        if self.cli_forwarding_order.is_empty() {
            local_forwards.extend(
                self.cli_local_forwards
                    .iter()
                    .cloned()
                    .map(ForwardingDirective::Local),
            );
            local_forwards.extend(
                self.cli_dynamic_forwards
                    .iter()
                    .cloned()
                    .map(ForwardingDirective::Dynamic),
            );
            remote_forwards.extend(
                self.cli_remote_forwards
                    .iter()
                    .cloned()
                    .map(ForwardingDirective::Remote),
            );
        } else {
            for directive in &self.cli_forwarding_order {
                match directive {
                    ForwardingDirective::Remote(_) => remote_forwards.push(directive.clone()),
                    _ => local_forwards.push(directive.clone()),
                }
            }
        }
        if let Some(config) = host_config.as_ref() {
            if config.forwarding_directives.is_empty() {
                local_forwards.extend(
                    config
                        .local_forward
                        .iter()
                        .cloned()
                        .map(ForwardingDirective::Local),
                );
                local_forwards.extend(
                    config
                        .dynamic_forward
                        .iter()
                        .cloned()
                        .map(ForwardingDirective::Dynamic),
                );
                remote_forwards.extend(
                    config
                        .remote_forward
                        .iter()
                        .cloned()
                        .map(ForwardingDirective::Remote),
                );
            } else {
                for directive in &config.forwarding_directives {
                    match directive {
                        ForwardingDirective::Remote(_) => remote_forwards.push(directive.clone()),
                        _ => local_forwards.push(directive.clone()),
                    }
                }
            }
        }
        local_forwards.extend(remote_forwards);
        let forwarding_plan = ForwardingPlan {
            directives: local_forwards,
            clear_all: host_config
                .as_ref()
                .and_then(|config| config.clear_all_forwardings)
                .unwrap_or(false),
            exit_on_failure: host_config
                .as_ref()
                .and_then(|config| config.exit_on_forward_failure)
                .unwrap_or(false),
            address_family,
        };
        SshConnectionConfig::new()
            .with_keepalive_interval(if keepalive_interval == 0 {
                None
            } else {
                Some(keepalive_interval)
            })
            .with_keepalive_max(keepalive_max)
            .with_compression(compression)
            .with_address_family(address_family)
            .with_connection_attempts(connection_attempts)
            .with_tcp_keep_alive(tcp_keep_alive)
            .with_known_hosts_files(user_known_hosts_files, global_known_hosts_files)
            .with_host_key_alias(host_key_alias)
            .with_known_host_policy(
                hash_known_hosts,
                check_host_ip,
                known_hosts_command,
                verify_host_key_dns,
                update_host_keys,
            )
            .with_proxy_mode(proxy_mode)
            .with_algorithm_preferences(
                cipher_preferences,
                mac_preferences,
                kex_preferences,
                host_key_preferences,
            )
            .with_known_host_algorithm_ordering(order_host_key_algorithms)
            .with_pubkey_accepted_algorithms(pubkey_accepted_algorithms)
            .with_auth_policy(auth_policy)
            .with_forwarding_plan(forwarding_plan)
    }

    fn resolve_proxy_mode(
        &self,
        hostname: &str,
        host_key_alias: Option<String>,
    ) -> Option<ProxyMode> {
        if let Some(jump) = self.cli_proxy_jump.as_deref() {
            return Some(proxy_jump_mode(jump));
        }

        if let Some(ssh_config) = self.ssh_config.as_ref() {
            let host_config = ssh_config.find_host_config(hostname);
            if let Some(command) = host_config.proxy_command {
                if command.eq_ignore_ascii_case("none") {
                    return Some(ProxyMode::Direct);
                }
                return Some(ProxyMode::Command(
                    ProxyCommandConfig::new(command, hostname)
                        .with_host_key_alias(host_key_alias)
                        .with_fdpass(host_config.proxy_use_fdpass.unwrap_or(false)),
                ));
            }
            if let Some(jump) = host_config.proxy_jump {
                return Some(proxy_jump_mode(&jump));
            }
        }

        self.yaml_proxy_jump.as_deref().map(proxy_jump_mode)
    }
}

fn proxy_jump_mode(jump: &str) -> ProxyMode {
    if jump.eq_ignore_ascii_case("none") || jump.is_empty() {
        ProxyMode::Direct
    } else {
        ProxyMode::Jump(jump.to_string())
    }
}

fn is_retryable_proxy_carrier_error(error: &super::Error) -> bool {
    matches!(
        error,
        super::Error::ProxyCommandSpawn { .. } | super::Error::ProxyCommandFailed { .. }
    )
}

/// Compression preference advertised when ssh_config resolves `Compression
/// no` (or the directive is unset). This matches the current effective
/// behavior and the server-side fix in #215.
const NONE_ONLY_COMPRESSION: &[russh::compression::Name] = &[russh::compression::NONE];

/// Compression preference advertised when ssh_config resolves `Compression
/// yes`.
///
/// This deliberately omits `russh::compression::ZLIB_LEGACY`
/// (`zlib@openssh.com`). #215 found that russh's delayed-zlib transport
/// desyncs the flate2 stream a few packets after compression activates
/// post-auth, corrupting the next packet's length prefix (reproducible on
/// russh 0.61.1 and 0.62.1). That bug lives in russh's compression codec, not
/// the server role, so a bssh client that advertised `zlib@openssh.com` would
/// be just as exposed when talking to a server that selects it. Eager `zlib`
/// (activated immediately after key exchange, not delayed) does not exhibit
/// the same desync and is offered ahead of `none`.
const COMPRESSED_ORDER: &[russh::compression::Name] =
    &[russh::compression::ZLIB, russh::compression::NONE];

impl SshConnectionConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the raw known-hosts path lists selected from ssh_config.
    #[must_use]
    pub fn with_known_hosts_files(
        mut self,
        user_files: Option<Vec<String>>,
        global_files: Option<Vec<String>>,
    ) -> Self {
        self.user_known_hosts_files = user_files;
        self.global_known_hosts_files = global_files;
        self
    }

    /// Set the explicit identity used for known-hosts lookup and recording.
    #[must_use]
    pub fn with_host_key_alias(mut self, alias: Option<String>) -> Self {
        self.host_key_alias = alias;
        self
    }

    #[must_use]
    pub fn with_known_host_policy(
        mut self,
        hash_known_hosts: bool,
        check_host_ip: bool,
        known_hosts_command: Option<String>,
        verify_host_key_dns: String,
        update_host_keys: String,
    ) -> Self {
        self.hash_known_hosts = hash_known_hosts;
        self.check_host_ip = check_host_ip;
        self.known_hosts_command = known_hosts_command;
        self.verify_host_key_dns = verify_host_key_dns;
        self.update_host_keys = update_host_keys;
        self
    }

    /// Set the keepalive interval in seconds.
    /// Pass None, or Some(0), to disable keepalive.
    #[must_use]
    pub fn with_keepalive_interval(mut self, interval: Option<u64>) -> Self {
        self.keepalive_interval = interval.filter(|seconds| *seconds > 0);
        self
    }

    /// Set the maximum number of keepalive attempts.
    #[must_use]
    pub fn with_keepalive_max(mut self, max: usize) -> Self {
        self.keepalive_max = max;
        self
    }

    /// Set whether SSH transport compression should be advertised, mirroring
    /// the ssh_config `Compression` directive (`yes` -> `true`, `no`/unset ->
    /// `false`).
    #[must_use]
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression = enabled;
        self
    }

    /// Constrain the connection to a single IP address family, mirroring
    /// OpenSSH's `-4` / `-6` flags and the ssh_config `AddressFamily` keyword.
    #[must_use]
    pub fn with_address_family(mut self, family: AddressFamily) -> Self {
        self.address_family = family;
        self
    }

    /// Set the number of DNS-resolution and TCP connection rounds.
    #[must_use]
    pub fn with_connection_attempts(mut self, attempts: usize) -> Self {
        self.connection_attempts = attempts.max(1);
        self
    }

    /// Enable or disable kernel TCP keepalive independently of SSH keepalives.
    #[must_use]
    pub fn with_tcp_keep_alive(mut self, enabled: bool) -> Self {
        self.tcp_keep_alive = enabled;
        self
    }

    #[must_use]
    pub fn with_proxy_mode(mut self, proxy_mode: Option<ProxyMode>) -> Self {
        self.proxy_mode = proxy_mode;
        self
    }

    #[must_use]
    pub fn with_algorithm_preferences(
        mut self,
        ciphers: Option<Vec<russh::cipher::Name>>,
        macs: Option<Vec<russh::mac::Name>>,
        kex: Option<Vec<russh::kex::Name>>,
        host_keys: Option<Vec<ssh_key::Algorithm>>,
    ) -> Self {
        self.cipher_preferences = ciphers;
        self.mac_preferences = macs;
        self.kex_preferences = kex;
        self.host_key_preferences = host_keys;
        self
    }

    #[must_use]
    pub fn with_known_host_algorithm_ordering(mut self, enabled: bool) -> Self {
        self.order_host_key_algorithms = enabled;
        self
    }

    /// Expose the resolved user-authentication signature policy.
    #[must_use]
    pub fn with_pubkey_accepted_algorithms(mut self, algorithms: Option<Vec<String>>) -> Self {
        self.pubkey_accepted_algorithms = algorithms;
        self
    }

    /// Attach the resolved authentication policy for this concrete host.
    #[must_use]
    pub fn with_auth_policy(mut self, policy: SshAuthenticationPolicy) -> Self {
        self.auth_policy = policy;
        self
    }

    #[must_use]
    pub fn with_forwarding_plan(mut self, plan: ForwardingPlan) -> Self {
        self.forwarding_plan = plan;
        self
    }

    /// Strip destination forwarding from a configuration used for a jump hop.
    #[must_use]
    pub fn without_forwarding(mut self) -> Self {
        self.forwarding_plan = ForwardingPlan::default();
        self
    }

    /// Convert this configuration to a russh client Config.
    ///
    /// `inactivity_timeout` stays disabled for client sessions. A healthy
    /// interactive SSH session can legitimately produce no inbound data for a
    /// long time, so inactivity must not be treated as a local reason to close
    /// it. When keepalive is enabled, russh's keepalive counter is the liveness
    /// detector; when it is disabled, the client leaves idle sessions alone.
    ///
    /// `preferred.compression` is derived from `self.compression`: `false`
    /// advertises only `none`; `true` advertises `zlib` ahead of `none`.
    /// `zlib@openssh.com` is never advertised; see [`COMPRESSED_ORDER`] for
    /// why.
    pub fn to_russh_config(&self) -> Config {
        let compression_order = if self.compression {
            COMPRESSED_ORDER
        } else {
            NONE_ONLY_COMPRESSION
        };
        let preferred = russh::Preferred {
            compression: std::borrow::Cow::Borrowed(compression_order),
            ..russh::Preferred::DEFAULT
        };
        let preferred = russh::Preferred {
            cipher: self
                .cipher_preferences
                .clone()
                .map(Cow::Owned)
                .unwrap_or(preferred.cipher),
            mac: self
                .mac_preferences
                .clone()
                .map(Cow::Owned)
                .unwrap_or(preferred.mac),
            kex: self
                .kex_preferences
                .clone()
                .map(Cow::Owned)
                .unwrap_or(preferred.kex),
            key: self
                .host_key_preferences
                .clone()
                .map(Cow::Owned)
                .unwrap_or(preferred.key),
            ..preferred
        };

        Config {
            keepalive_interval: self.keepalive_interval.map(Duration::from_secs),
            keepalive_max: self.keepalive_max,
            inactivity_timeout: None,
            preferred,
            ..Default::default()
        }
    }

    /// Derive the kernel TCP keepalive configuration. Returns `None` only when
    /// ssh_config explicitly disables `TCPKeepAlive`.
    ///
    /// TCP keepalive is a belt-and-suspenders mechanism: it lets the kernel
    /// detect a broken TCP path even when no application data is flowing and
    /// even if SSH-level keepalive replies are dropped by a middlebox.
    pub fn to_tcp_keepalive(&self) -> Option<socket2::TcpKeepalive> {
        if !self.tcp_keep_alive {
            return None;
        }
        let interval = self
            .keepalive_interval
            .unwrap_or(DEFAULT_KEEPALIVE_INTERVAL);
        // Start probing after `interval` seconds of idleness, probe every
        // half-interval, up to keepalive_max retries.
        let probe_interval = (interval / 2).max(1);
        let ka = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(interval))
            .with_interval(Duration::from_secs(probe_interval));
        #[cfg(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "ios",
        ))]
        let ka = ka.with_retries(self.keepalive_max.max(1) as u32);
        Some(ka)
    }
}

pub(super) fn configure_tcp_keepalive(
    stream: &tokio::net::TcpStream,
    address: SocketAddr,
    keepalive: &socket2::TcpKeepalive,
) -> Result<(), super::Error> {
    let sock_ref = socket2::SockRef::from(stream);
    sock_ref
        .set_tcp_keepalive(keepalive)
        .map_err(|source| super::Error::TcpKeepAlive { address, source })?;
    if !sock_ref
        .keepalive()
        .map_err(|source| super::Error::TcpKeepAlive { address, source })?
    {
        return Err(super::Error::TcpKeepAlive {
            address,
            source: io::Error::other("kernel reported TCP keepalive disabled after set"),
        });
    }
    Ok(())
}

use super::ToSocketAddrsWithHostname;

/// A ssh connection to a remote server.
///
/// After creating a `Client` by [`connect`]ing to a remote host,
/// use [`execute`] to send commands and receive results through the connections.
///
/// [`connect`]: Client::connect
/// [`execute`]: Client::execute
///
/// # Examples
///
/// ```no_run
/// use bssh::ssh::tokio_client::{Client, AuthMethod, ServerCheckMethod};
/// #[tokio::main]
/// async fn main() -> Result<(), bssh::ssh::tokio_client::Error> {
///     let mut client = Client::connect(
///         ("10.10.10.2", 22),
///         "root",
///         AuthMethod::with_password("root"),
///         ServerCheckMethod::NoCheck,
///     ).await?;
///
///     let result = client.execute("echo Hello SSH").await?;
///     assert_eq!(result.stdout, "Hello SSH\n");
///     assert_eq!(result.exit_status, 0);
///
///     Ok(())
/// }
#[derive(Clone)]
pub struct Client {
    pub(super) connection_handle: Arc<Handle<ClientHandler>>,
    pub(super) username: String,
    pub(super) address: SocketAddr,
    /// Public access to the SSH session for jump host operations
    #[allow(private_interfaces)]
    pub session: Arc<Handle<ClientHandler>>,
    proxy_process: Option<Arc<ProxyCommandProcess>>,
    fatal_transport: FatalTransportState,
    hostkey_rotation: HostkeyRotationTasks,
    forwarding_runtime: Arc<ForwardingRuntime>,
    remote_forward_registry: RemoteForwardRegistry,
}

#[derive(Debug, Clone)]
pub(crate) struct HostkeyRotationTasks {
    enabled: bool,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    protocol_barrier_complete: Arc<tokio::sync::Mutex<bool>>,
}

impl HostkeyRotationTasks {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            tasks: Arc::new(Mutex::new(Vec::new())),
            protocol_barrier_complete: Arc::new(tokio::sync::Mutex::new(false)),
        }
    }

    fn track(&self, task: tokio::task::JoinHandle<()>) {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(task);
    }

    async fn synchronize_protocol(&self, handle: &Handle<ClientHandler>) {
        if !self.enabled {
            return;
        }
        let mut complete = self.protocol_barrier_complete.lock().await;
        if *complete {
            return;
        }
        let completed = match tokio::time::timeout(Duration::from_secs(5), handle.send_ping()).await
        {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                tracing::warn!("Could not complete UpdateHostKeys protocol barrier: {error}");
                false
            }
            Err(_) => {
                tracing::warn!("UpdateHostKeys protocol barrier timed out after 5 seconds");
                false
            }
        };
        if completed {
            *complete = true;
        }
    }

    async fn wait(&self) {
        if !self.enabled {
            return;
        }
        loop {
            let tasks = {
                let mut tasks = self
                    .tasks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                std::mem::take(&mut *tasks)
            };
            if tasks.is_empty() {
                break;
            }
            for task in tasks {
                if let Err(error) = task.await {
                    tracing::warn!("Host-key rotation task failed to join: {error}");
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FatalTransportState(Arc<Mutex<Option<super::TransportIntegrityCause>>>);

impl FatalTransportState {
    fn record(&self, error: &super::Error) {
        let cause = match error {
            super::Error::SshError(russh::Error::PacketAuth) => {
                super::TransportIntegrityCause::PacketAuthentication
            }
            super::Error::SshError(russh::Error::DecryptionError) => {
                super::TransportIntegrityCause::Decryption
            }
            super::Error::SshError(russh::Error::PacketSize(size)) => {
                super::TransportIntegrityCause::PacketSize(*size)
            }
            // russh emits IndexOutOfBounds only when encrypted packet padding
            // exceeds the authenticated plaintext length.
            super::Error::SshError(russh::Error::IndexOutOfBounds) => {
                super::TransportIntegrityCause::InvalidPadding
            }
            _ => return,
        };
        let mut fatal = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fatal.get_or_insert(cause);
    }

    pub(crate) fn take_error(&self) -> Option<super::Error> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .map(|cause| super::Error::TransportIntegrity { cause })
    }
}

struct DirectCarrierOptions<'a> {
    tcp_keepalive: Option<&'a socket2::TcpKeepalive>,
    address_family: AddressFamily,
    connection_attempts: usize,
}

impl Client {
    /// Open a ssh connection to a remote host with default keepalive settings.
    ///
    /// `addr` is an address of the remote host. Anything which implements
    /// [`ToSocketAddrsWithHostname`] trait can be supplied for the address;
    /// ToSocketAddrsWithHostname reimplements all of [`ToSocketAddrs`];
    /// see this trait's documentation for concrete examples.
    ///
    /// If `addr` yields multiple addresses, `connect` will be attempted with
    /// each of the addresses until a connection is successful.
    /// Authentification is tried on the first successful connection and the whole
    /// process aborted if this fails.
    ///
    /// This method uses default keepalive settings (30s interval, 3 max attempts)
    /// to prevent idle connection timeouts.
    pub async fn connect(
        addr: impl ToSocketAddrsWithHostname,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
    ) -> Result<Self, super::Error> {
        Self::connect_with_ssh_config(
            addr,
            username,
            auth,
            server_check,
            &SshConnectionConfig::default(),
        )
        .await
    }

    /// Connect with custom SSH connection configuration.
    ///
    /// This method allows specifying keepalive settings and other connection
    /// parameters through [`SshConnectionConfig`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bssh::ssh::tokio_client::{Client, AuthMethod, ServerCheckMethod, SshConnectionConfig};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), bssh::ssh::tokio_client::Error> {
    ///     let ssh_config = SshConnectionConfig::new()
    ///         .with_keepalive_interval(Some(15))
    ///         .with_keepalive_max(5);
    ///
    ///     let client = Client::connect_with_ssh_config(
    ///         ("example.com", 22),
    ///         "user",
    ///         AuthMethod::with_key_file("~/.ssh/id_rsa", None),
    ///         ServerCheckMethod::DefaultKnownHostsFile,
    ///         &ssh_config,
    ///     ).await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn connect_with_ssh_config(
        addr: impl ToSocketAddrsWithHostname,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
        ssh_config: &SshConnectionConfig,
    ) -> Result<Self, super::Error> {
        if let Some(ProxyMode::Command(proxy)) = ssh_config.proxy_mode.as_ref() {
            let (host, port) = addr.host_port().map_err(super::Error::AddressInvalid)?;
            let policy = KnownHostRuntimePolicy::from_config(
                ssh_config,
                username,
                &host,
                &proxy.original_host,
                port,
            );
            let mut config = ssh_config.to_russh_config();
            if ssh_config.order_host_key_algorithms {
                apply_known_hosts_command_order(
                    &mut config,
                    &policy,
                    ssh_config.host_key_alias.as_deref(),
                )
                .await?;
            }
            let config = Arc::new(config);
            let attempts = ssh_config.connection_attempts.max(1);
            for round in 0..attempts {
                let result = Self::connect_with_proxy_command(
                    &host,
                    port,
                    username,
                    auth.clone(),
                    server_check.clone(),
                    Arc::clone(&config),
                    policy.clone(),
                    proxy,
                )
                .await;
                match result {
                    Ok(client) => {
                        client
                            .initialize_forwarding(&ssh_config.forwarding_plan)
                            .await?;
                        return Ok(client);
                    }
                    Err(error)
                        if is_retryable_proxy_carrier_error(&error) && round + 1 < attempts =>
                    {
                        tracing::debug!(
                            "ProxyCommand carrier round {} of {} failed for '{}'; retrying in 1 second",
                            round + 1,
                            attempts,
                            host
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
            unreachable!("the final ProxyCommand attempt always returns")
        }
        let (policy_host, policy_port) = addr.host_port().map_err(super::Error::AddressInvalid)?;
        let policy = KnownHostRuntimePolicy::from_config(
            ssh_config,
            username,
            &policy_host,
            &policy_host,
            policy_port,
        );
        let mut config = ssh_config.to_russh_config();
        if ssh_config.order_host_key_algorithms {
            apply_known_hosts_command_order(
                &mut config,
                &policy,
                ssh_config.host_key_alias.as_deref(),
            )
            .await?;
        }
        let tcp_keepalive = ssh_config.to_tcp_keepalive();
        let client = Self::connect_with_config_inner(
            addr,
            username,
            auth,
            server_check,
            config,
            policy,
            DirectCarrierOptions {
                tcp_keepalive: tcp_keepalive.as_ref(),
                address_family: ssh_config.address_family,
                connection_attempts: ssh_config.connection_attempts,
            },
        )
        .await?;
        client
            .initialize_forwarding(&ssh_config.forwarding_plan)
            .await?;
        Ok(client)
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_with_proxy_command(
        host: &str,
        port: u16,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
        config: Arc<Config>,
        policy: KnownHostRuntimePolicy,
        proxy: &ProxyCommandConfig,
    ) -> Result<Self, super::Error> {
        let proxy_session = spawn_proxy_command(proxy, host, port, username)?;
        let process = Arc::clone(&proxy_session.process);
        let address = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port);
        let verification_host = proxy.host_key_alias.as_deref().unwrap_or(host);
        // OpenSSH looks up HostKeyAlias literally, without adding the target
        // port even when it is non-standard.
        let verification_port = if proxy.host_key_alias.is_some() {
            22
        } else {
            port
        };
        let verification_address = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            verification_port,
        );
        let handler = ClientHandler::new_with_policy(
            verification_host.to_string(),
            verification_address,
            server_check,
            policy,
        );
        let fatal_transport = handler.fatal_transport_state();
        let hostkey_rotation = handler.hostkey_rotation_tasks();
        let remote_forward_registry = handler.remote_forward_registry();
        let mut handle = match russh::client::connect_stream(config, proxy_session.stream, handler)
            .await
        {
            Ok(handle) => handle,
            Err(error) => {
                if let Some(failure) = process.wait_for_failure(Duration::from_millis(250)).await {
                    return Err(super::Error::ProxyCommandFailed {
                        command: failure.command,
                        status: failure.status,
                        stderr: failure.stderr,
                    });
                }
                return Err(super::Error::during_protocol_negotiation(
                    host.to_string(),
                    port,
                    error,
                ));
            }
        };

        let username = username.to_string();
        if let Err(error) = super::authentication::authenticate(&mut handle, &username, auth).await
        {
            return Err(fatal_transport.take_error().unwrap_or(error));
        }
        let connection_handle = Arc::new(handle);
        let client = Self {
            connection_handle: Arc::clone(&connection_handle),
            username,
            address,
            session: connection_handle,
            proxy_process: Some(process),
            fatal_transport,
            hostkey_rotation,
            forwarding_runtime: Arc::new(ForwardingRuntime::default()),
            remote_forward_registry,
        };
        client.flush_hostkey_updates().await;
        Ok(client)
    }

    /// Same as `connect`, but with the option to specify a non default
    /// [`russh::client::Config`].
    ///
    /// For most use cases, prefer [`connect_with_ssh_config`] which provides
    /// a higher-level API with sensible defaults.
    pub async fn connect_with_config(
        addr: impl ToSocketAddrsWithHostname,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
        config: Config,
    ) -> Result<Self, super::Error> {
        let (policy_host, policy_port) = addr.host_port().map_err(super::Error::AddressInvalid)?;
        let policy = KnownHostRuntimePolicy::unconfigured(username, &policy_host, policy_port);
        Self::connect_with_config_inner(
            addr,
            username,
            auth,
            server_check,
            config,
            policy,
            DirectCarrierOptions {
                tcp_keepalive: None,
                address_family: AddressFamily::Any,
                connection_attempts: 1,
            },
        )
        .await
    }

    /// Resolve `addr`, apply the address family constraint, and connect to the
    /// first candidate that answers.
    ///
    /// With [`AddressFamily::Any`] the candidate list is the resolver's output
    /// untouched, in resolver order. A forced family filters that list and, if
    /// nothing survives, fails with [`Error::NoAddressForFamily`] instead of
    /// falling back to the other family.
    ///
    /// [`Error::NoAddressForFamily`]: super::Error::NoAddressForFamily
    async fn connect_with_config_inner(
        addr: impl ToSocketAddrsWithHostname,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
        config: Config,
        policy: KnownHostRuntimePolicy,
        carrier: DirectCarrierOptions<'_>,
    ) -> Result<Self, super::Error> {
        // A retry round covers only carrier creation: one DNS resolution and
        // TCP connection attempts for all returned addresses. Once a TCP
        // stream exists, socket configuration, SSH KEX/host verification, and
        // authentication fail immediately and are never retried.
        let DirectCarrierOptions {
            tcp_keepalive,
            address_family,
            connection_attempts,
        } = carrier;
        let connection_attempts = connection_attempts.max(1);
        let target_host = addr.hostname();
        let (_, target_port) = addr.host_port().map_err(super::Error::AddressInvalid)?;
        let mut carrier_res: Result<(SocketAddr, tokio::net::TcpStream), super::Error> =
            Err(super::Error::DnsResolution {
                host: target_host.clone(),
                source: io::Error::new(io::ErrorKind::NotFound, "Name or service not known"),
            });

        'rounds: for round in 0..connection_attempts {
            match addr.to_socket_addrs() {
                Ok(resolved) => {
                    let resolved_count = resolved.len();
                    let socket_addrs = address_family.filter(resolved);

                    if address_family.is_forced() {
                        tracing::debug!(
                            "Address family {} forced for '{}': {} of {} resolved address(es) usable",
                            address_family,
                            addr.hostname(),
                            socket_addrs.len(),
                            resolved_count
                        );
                    }

                    if socket_addrs.is_empty() {
                        carrier_res = if address_family.is_forced() {
                            Err(super::Error::NoAddressForFamily {
                                host: target_host.clone(),
                                family: address_family,
                            })
                        } else {
                            Err(super::Error::DnsResolution {
                                host: target_host.clone(),
                                source: io::Error::new(
                                    io::ErrorKind::NotFound,
                                    "Name or service not known",
                                ),
                            })
                        };
                    } else {
                        for socket_addr in socket_addrs {
                            match tokio::net::TcpStream::connect(socket_addr).await {
                                Ok(stream) => {
                                    carrier_res = Ok((socket_addr, stream));
                                    break 'rounds;
                                }
                                Err(error) => {
                                    carrier_res = Err(super::Error::TcpConnect {
                                        host: target_host.clone(),
                                        port: target_port,
                                        source: error,
                                    });
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    carrier_res = Err(super::Error::DnsResolution {
                        host: target_host.clone(),
                        source: error,
                    });
                }
            }

            if round + 1 < connection_attempts {
                tracing::debug!(
                    "Connection round {} of {} failed for '{}'; retrying in 1 second",
                    round + 1,
                    connection_attempts,
                    target_host
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        let (address, stream) = match carrier_res {
            Ok(carrier) => carrier,
            Err(source) if connection_attempts > 1 => {
                return Err(super::Error::ConnectionAttemptsExhausted {
                    attempts: connection_attempts,
                    source: Box::new(source),
                });
            }
            Err(source) => return Err(source),
        };
        if let Some(ka) = tcp_keepalive {
            configure_tcp_keepalive(&stream, address, ka)?;
        }

        let handler =
            ClientHandler::new_with_policy(target_host.clone(), address, server_check, policy);
        let fatal_transport = handler.fatal_transport_state();
        let hostkey_rotation = handler.hostkey_rotation_tasks();
        let remote_forward_registry = handler.remote_forward_registry();
        let mut handle = russh::client::connect_stream(Arc::new(config), stream, handler)
            .await
            .map_err(|error| {
                super::Error::during_protocol_negotiation(target_host, target_port, error)
            })?;
        let username = username.to_string();

        if let Err(error) = super::authentication::authenticate(&mut handle, &username, auth).await
        {
            return Err(fatal_transport.take_error().unwrap_or(error));
        }

        let connection_handle = Arc::new(handle);
        let client = Self {
            connection_handle: connection_handle.clone(),
            username,
            address,
            session: connection_handle,
            proxy_process: None,
            fatal_transport,
            hostkey_rotation,
            forwarding_runtime: Arc::new(ForwardingRuntime::default()),
            remote_forward_registry,
        };
        client.flush_hostkey_updates().await;
        Ok(client)
    }

    /// Wait for any verified UpdateHostKeys rewrite already announced by the server.
    pub async fn flush_hostkey_updates(&self) {
        self.hostkey_rotation
            .synchronize_protocol(&self.connection_handle)
            .await;
        self.hostkey_rotation.wait().await;
    }

    pub(super) fn session_error_or(&self, fallback: super::Error) -> super::Error {
        self.fatal_transport.take_error().unwrap_or(fallback)
    }

    /// Create a Client from an existing russh handle and address.
    ///
    /// This is used internally for jump host connections where we already have
    /// an authenticated russh handle from connect_stream.
    pub fn from_handle_and_address(
        handle: Arc<Handle<ClientHandler>>,
        username: String,
        address: SocketAddr,
    ) -> Self {
        Self::from_handle_and_address_with_state(
            handle,
            username,
            address,
            FatalTransportState::default(),
            RemoteForwardRegistry::default(),
        )
    }

    pub(crate) fn from_handle_and_address_with_state(
        handle: Arc<Handle<ClientHandler>>,
        username: String,
        address: SocketAddr,
        fatal_transport: FatalTransportState,
        remote_forward_registry: RemoteForwardRegistry,
    ) -> Self {
        Self {
            connection_handle: handle.clone(),
            username,
            address,
            session: handle,
            proxy_process: None,
            fatal_transport,
            hostkey_rotation: HostkeyRotationTasks::new(false),
            forwarding_runtime: Arc::new(ForwardingRuntime::default()),
            remote_forward_registry,
        }
    }

    pub(crate) async fn from_authenticated_handle_with_policy_state(
        handle: Arc<Handle<ClientHandler>>,
        username: String,
        address: SocketAddr,
        fatal_transport: FatalTransportState,
        hostkey_rotation: HostkeyRotationTasks,
        remote_forward_registry: RemoteForwardRegistry,
    ) -> Self {
        let client = Self {
            connection_handle: handle.clone(),
            username,
            address,
            session: handle,
            proxy_process: None,
            fatal_transport,
            hostkey_rotation,
            forwarding_runtime: Arc::new(ForwardingRuntime::default()),
            remote_forward_registry,
        };
        client.flush_hostkey_updates().await;
        client
    }

    pub(crate) fn forwarding_transport_clone(&self) -> Self {
        Self {
            forwarding_runtime: Arc::new(ForwardingRuntime::default()),
            ..self.clone()
        }
    }

    pub(crate) async fn initialize_forwarding(
        &self,
        plan: &ForwardingPlan,
    ) -> Result<(), super::Error> {
        let result = self
            .forwarding_runtime
            .start(self, plan)
            .await
            .map_err(|error| super::Error::PortForwardRequestFailed(format!("{error:#}")));
        if result.is_err()
            && let Err(disconnect_error) = self.disconnect().await
        {
            tracing::warn!(
                "Forwarding setup failed and SSH teardown also failed: {disconnect_error}"
            );
        }
        result
    }

    pub(crate) fn remote_forward_registry(&self) -> RemoteForwardRegistry {
        self.remote_forward_registry.clone()
    }

    /// A debugging function to get the username this client is connected as.
    pub fn get_connection_username(&self) -> &String {
        &self.username
    }

    /// A debugging function to get the address this client is connected to.
    pub fn get_connection_address(&self) -> &SocketAddr {
        &self.address
    }

    /// Disconnect from the remote host.
    pub async fn disconnect(&self) -> Result<(), super::Error> {
        let forwarding_result = self
            .forwarding_runtime
            .shutdown()
            .await
            .map_err(|error| super::Error::PortForwardRequestFailed(format!("{error:#}")));
        self.flush_hostkey_updates().await;
        let disconnect_result = self
            .connection_handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(super::Error::SshError);
        if let Some(process) = &self.proxy_process {
            process.terminate();
        }
        match (forwarding_result, disconnect_result) {
            (Err(forwarding_error), Err(disconnect_error)) => {
                tracing::warn!(
                    "Forwarding shutdown failed and SSH disconnect also failed: {disconnect_error}"
                );
                Err(forwarding_error)
            }
            (Err(forwarding_error), Ok(())) => Err(forwarding_error),
            (Ok(()), disconnect_result) => disconnect_result,
        }
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.connection_handle.is_closed()
    }

    /// Request remote port forwarding with an SSH `tcpip-forward` global request.
    ///
    /// This sends a global request to the SSH server to bind a port on the remote end
    /// and forward connections back to the client. This is used for remote port forwarding (-R).
    ///
    /// # Arguments
    /// * `bind_address` - Address to bind on the remote server (e.g., "localhost", "0.0.0.0")
    /// * `bind_port` - Port to bind on the remote server (0 to let server choose)
    ///
    /// # Returns
    /// The actual port number that was bound by the server (useful when bind_port is 0)
    pub async fn request_port_forward(
        &self,
        bind_address: String,
        bind_port: u32,
    ) -> Result<u32, super::Error> {
        let allocated = self
            .connection_handle
            .tcpip_forward(bind_address.clone(), bind_port)
            .await
            .map_err(|error| {
                super::Error::PortForwardRequestFailed(format!(
                    "{bind_address}:{bind_port}: {error}"
                ))
            })?;
        Ok(if bind_port == 0 { allocated } else { bind_port })
    }

    /// Cancel remote port forwarding with an SSH `cancel-tcpip-forward` global request.
    ///
    /// This sends a global request to cancel a previously established remote port forward.
    ///
    /// # Arguments
    /// * `bind_address` - Address that was bound on the remote server
    /// * `bind_port` - Port that was bound on the remote server
    pub async fn cancel_port_forward(
        &self,
        bind_address: String,
        bind_port: u32,
    ) -> Result<(), super::Error> {
        self.connection_handle
            .cancel_tcpip_forward(bind_address.clone(), bind_port)
            .await
            .map_err(|error| {
                super::Error::PortForwardRequestFailed(format!(
                    "cancel {bind_address}:{bind_port}: {error}"
                ))
            })
    }
}

impl Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("username", &self.username)
            .field("address", &self.address)
            .field("proxy_command", &self.proxy_process.is_some())
            .field("connection_handle", &"Handle<ClientHandler>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateHostKeysPolicy {
    No,
    Ask,
    Yes,
}

impl UpdateHostKeysPolicy {
    fn parse(value: &str) -> Self {
        if value.eq_ignore_ascii_case("yes") {
            Self::Yes
        } else if value.eq_ignore_ascii_case("ask") {
            Self::Ask
        } else {
            Self::No
        }
    }
}

/// Runtime-only policy derived from the effective ssh_config.
#[derive(Debug, Clone)]
pub(crate) struct KnownHostRuntimePolicy {
    hash_known_hosts: bool,
    check_host_ip: bool,
    known_hosts_command: Option<String>,
    verify_host_key_dns: super::sshfp::VerifyHostKeyDnsPolicy,
    update_host_keys: UpdateHostKeysPolicy,
    remote_user: String,
    target_host: String,
    target_port: u16,
    original_host: String,
    proxy_jump: String,
    rotation_paths: Option<Vec<String>>,
    known_hosts_paths: Vec<String>,
    host_key_algorithms: Vec<ssh_key::Algorithm>,
}

impl KnownHostRuntimePolicy {
    fn unconfigured(username: &str, target_host: &str, port: u16) -> Self {
        Self {
            hash_known_hosts: false,
            check_host_ip: false,
            known_hosts_command: None,
            verify_host_key_dns: super::sshfp::VerifyHostKeyDnsPolicy::No,
            update_host_keys: UpdateHostKeysPolicy::No,
            remote_user: username.to_string(),
            target_host: target_host.to_string(),
            target_port: port,
            original_host: target_host.to_string(),
            proxy_jump: String::new(),
            rotation_paths: None,
            known_hosts_paths: Vec::new(),
            host_key_algorithms: Vec::new(),
        }
    }

    pub(crate) fn from_config(
        config: &SshConnectionConfig,
        username: &str,
        target_host: &str,
        original_host: &str,
        port: u16,
    ) -> Self {
        let proxy_jump = match config.proxy_mode.as_ref() {
            Some(ProxyMode::Jump(jump)) => jump.clone(),
            _ => String::new(),
        };
        let rotation_paths =
            crate::ssh::known_hosts::user_known_hosts_paths(config, target_host, port, username);
        let known_hosts_paths =
            crate::ssh::known_hosts::read_known_hosts_paths(config, target_host, port, username);
        Self {
            hash_known_hosts: config.hash_known_hosts,
            check_host_ip: config.check_host_ip,
            known_hosts_command: config.known_hosts_command.clone(),
            verify_host_key_dns: super::sshfp::VerifyHostKeyDnsPolicy::parse(
                &config.verify_host_key_dns,
            ),
            update_host_keys: UpdateHostKeysPolicy::parse(&config.update_host_keys),
            remote_user: username.to_string(),
            target_host: target_host.to_string(),
            target_port: port,
            original_host: original_host.to_string(),
            proxy_jump,
            rotation_paths: Some(rotation_paths),
            known_hosts_paths,
            host_key_algorithms: config
                .host_key_preferences
                .clone()
                .unwrap_or_else(|| russh::Preferred::DEFAULT.key.as_ref().to_vec()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HostVerification {
    accepted: bool,
    eligible_for_rotation: bool,
    skip_address_check: bool,
}

impl HostVerification {
    const fn configured(accepted: bool, method: &ServerCheckMethod) -> Self {
        Self {
            accepted,
            eligible_for_rotation: accepted && !matches!(method, ServerCheckMethod::NoCheck),
            skip_address_check: false,
        }
    }

    const fn command() -> Self {
        Self {
            accepted: true,
            eligible_for_rotation: false,
            skip_address_check: false,
        }
    }

    const fn dns() -> Self {
        Self {
            accepted: true,
            eligible_for_rotation: true,
            skip_address_check: true,
        }
    }
}

/// SSH client handler for managing server key verification.
#[derive(Debug, Clone)]
pub struct ClientHandler {
    hostname: String,
    host: SocketAddr,
    server_check: ServerCheckMethod,
    policy: KnownHostRuntimePolicy,
    verified_server_key: Arc<Mutex<Option<russh::keys::PublicKey>>>,
    verified_server_algorithm: Arc<Mutex<Option<ssh_key::Algorithm>>>,
    rotation_allowed: Arc<AtomicBool>,
    proof_in_flight: Arc<AtomicBool>,
    hostkey_rotation: HostkeyRotationTasks,
    fatal_transport: FatalTransportState,
    remote_forward_registry: RemoteForwardRegistry,
}

impl ClientHandler {
    /// Create a new client handler.
    pub fn new(hostname: String, host: SocketAddr, server_check: ServerCheckMethod) -> Self {
        Self::new_with_policy(
            hostname.clone(),
            host,
            server_check,
            KnownHostRuntimePolicy::unconfigured("", &hostname, host.port()),
        )
    }

    pub(crate) fn new_with_policy(
        hostname: String,
        host: SocketAddr,
        server_check: ServerCheckMethod,
        policy: KnownHostRuntimePolicy,
    ) -> Self {
        let hostkey_rotation =
            HostkeyRotationTasks::new(policy.update_host_keys == UpdateHostKeysPolicy::Yes);
        Self {
            hostname,
            host,
            server_check,
            policy,
            verified_server_key: Arc::new(Mutex::new(None)),
            verified_server_algorithm: Arc::new(Mutex::new(None)),
            rotation_allowed: Arc::new(AtomicBool::new(false)),
            proof_in_flight: Arc::new(AtomicBool::new(false)),
            hostkey_rotation,
            fatal_transport: FatalTransportState::default(),
            remote_forward_registry: RemoteForwardRegistry::default(),
        }
    }

    pub(crate) fn hostkey_rotation_tasks(&self) -> HostkeyRotationTasks {
        self.hostkey_rotation.clone()
    }

    pub(crate) fn fatal_transport_state(&self) -> FatalTransportState {
        self.fatal_transport.clone()
    }

    pub(crate) fn remote_forward_registry(&self) -> RemoteForwardRegistry {
        self.remote_forward_registry.clone()
    }

    async fn run_known_hosts_lookup(
        &self,
        hostname: &str,
        port: u16,
        invocation: &'static str,
        server_key: &russh::keys::PublicKey,
        host_key_alias: Option<&str>,
    ) -> Result<Option<super::host_verification::KnownHostLookup>, super::Error> {
        let Some(command) = self.policy.known_hosts_command.as_deref() else {
            return Ok(None);
        };

        let lookup_host = super::host_verification::known_hosts_entry_name(hostname, port);
        let fingerprint = server_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        let key_blob =
            server_key
                .to_bytes()
                .map_err(|error| super::Error::KnownHostsCommandFailed {
                    reason: format!("could not encode the offered host key: {error}"),
                })?;
        let key_base64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_blob);
        let local_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| whoami::username().unwrap_or_else(|_| "user".to_string()));
        let local_user_id = local_user_id();
        let local_hostname_fqdn = whoami::hostname().unwrap_or_else(|_| "localhost".to_string());
        let local_hostname = local_hostname_fqdn
            .split('.')
            .next()
            .unwrap_or(&local_hostname_fqdn)
            .to_string();
        let home_dir = dirs::home_dir()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let key_type = server_key.algorithm().as_str().to_string();
        let context = super::known_hosts_command::KnownHostsCommandContext {
            lookup_host: &lookup_host,
            target_host: &self.policy.target_host,
            original_host: &self.policy.original_host,
            host_key_alias,
            connection_port: self.policy.target_port,
            remote_user: &self.policy.remote_user,
            local_user: &local_user,
            local_user_id: &local_user_id,
            local_hostname: &local_hostname,
            local_hostname_fqdn: &local_hostname_fqdn,
            home_dir: &home_dir,
            proxy_jump: &self.policy.proxy_jump,
            invocation,
            fingerprint: &fingerprint,
            key_base64: &key_base64,
            key_type: &key_type,
        };
        let output = super::known_hosts_command::run_known_hosts_command(command, &context).await?;
        super::host_verification::lookup_known_host_data(&output, hostname, port, server_key)
            .map(Some)
    }

    fn rotation_paths(&self, method: &ServerCheckMethod) -> Vec<String> {
        if let Some(paths) = self.policy.rotation_paths.as_ref() {
            return paths.clone();
        }
        match method {
            ServerCheckMethod::KnownHostsFile(path)
            | ServerCheckMethod::AcceptNewKnownHostsFile(path) => vec![path.clone()],
            ServerCheckMethod::KnownHostsFiles(paths) => paths.clone(),
            ServerCheckMethod::AcceptNewKnownHostsFiles { files, write_path } => {
                let mut paths = files.clone();
                if let Some(write_path) = write_path
                    && !paths.contains(write_path)
                {
                    paths.insert(0, write_path.clone());
                }
                paths
            }
            ServerCheckMethod::DefaultKnownHostsFile => {
                crate::ssh::known_hosts::get_default_known_hosts_path()
                    .map(|path| vec![path.to_string_lossy().into_owned()])
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        }
    }
}

pub(crate) async fn apply_known_hosts_command_order(
    config: &mut Config,
    policy: &KnownHostRuntimePolicy,
    host_key_alias: Option<&str>,
) -> Result<(), super::Error> {
    let hostname = host_key_alias.unwrap_or(&policy.target_host);
    let lookup_port = if host_key_alias.is_some() {
        22
    } else {
        policy.target_port
    };
    let mut known_algorithms =
        known_host_algorithms_from_paths(&policy.known_hosts_paths, hostname, lookup_port)?;

    if let Some(command) = policy.known_hosts_command.as_deref() {
        let lookup_host = super::host_verification::known_hosts_entry_name(hostname, lookup_port);
        let local_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| whoami::username().unwrap_or_else(|_| "user".to_string()));
        let local_user_id = local_user_id();
        let local_hostname_fqdn = whoami::hostname().unwrap_or_else(|_| "localhost".to_string());
        let local_hostname = local_hostname_fqdn
            .split('.')
            .next()
            .unwrap_or(&local_hostname_fqdn)
            .to_string();
        let home_dir = dirs::home_dir()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let context = super::known_hosts_command::KnownHostsCommandContext {
            lookup_host: &lookup_host,
            target_host: &policy.target_host,
            original_host: &policy.original_host,
            host_key_alias,
            connection_port: policy.target_port,
            remote_user: &policy.remote_user,
            local_user: &local_user,
            local_user_id: &local_user_id,
            local_hostname: &local_hostname,
            local_hostname_fqdn: &local_hostname_fqdn,
            home_dir: &home_dir,
            proxy_jump: &policy.proxy_jump,
            invocation: "ORDER",
            fingerprint: "NONE",
            key_base64: "NONE",
            key_type: "NONE",
        };
        let output = super::known_hosts_command::run_known_hosts_command(command, &context).await?;
        for algorithm in
            super::host_verification::known_host_algorithms_data(&output, hostname, lookup_port)?
        {
            if !known_algorithms.contains(&algorithm) {
                known_algorithms.push(algorithm);
            }
        }
    }

    prefer_known_host_algorithms(config, &known_algorithms);
    Ok(())
}

fn known_host_algorithms_from_paths(
    paths: &[String],
    hostname: &str,
    port: u16,
) -> Result<Vec<ssh_key::Algorithm>, super::Error> {
    let mut algorithms = Vec::new();
    for path in paths {
        let data = match std::fs::read_to_string(path) {
            Ok(data) => data,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                tracing::error!("Could not read known_hosts file '{path}' for ORDER: {error}");
                return Err(super::Error::ServerCheckFailed);
            }
        };
        for algorithm in
            super::host_verification::known_host_algorithms_data(&data, hostname, port)?
        {
            if !algorithms.contains(&algorithm) {
                algorithms.push(algorithm);
            }
        }
    }
    Ok(algorithms)
}

fn prefer_known_host_algorithms(config: &mut Config, known: &[ssh_key::Algorithm]) {
    let matches_known = |candidate: &ssh_key::Algorithm| {
        known.iter().any(|algorithm| {
            (matches!(candidate, ssh_key::Algorithm::Rsa { .. })
                && matches!(algorithm, ssh_key::Algorithm::Rsa { .. }))
                || candidate == algorithm
        })
    };
    if known.is_empty() || config.preferred.key.first().is_some_and(matches_known) {
        return;
    }
    let mut preferred = config.preferred.key.iter().cloned().collect::<Vec<_>>();
    preferred.sort_by_key(|algorithm| !matches_known(algorithm));
    config.preferred.key = Cow::Owned(preferred);
}

#[cfg(unix)]
fn local_user_id() -> String {
    // SAFETY: geteuid takes no pointers and has no preconditions.
    unsafe { libc::geteuid() }.to_string()
}

#[cfg(not(unix))]
fn local_user_id() -> String {
    "NONE".to_string()
}

fn check_host_ip_address(
    policy: &KnownHostRuntimePolicy,
    host: SocketAddr,
    host_key_alias: Option<&str>,
) -> Option<String> {
    let address = host.ip().to_string();
    (policy.check_host_ip
        && host_key_alias.is_none()
        && !host.ip().is_unspecified()
        && address != policy.target_host)
        .then_some(address)
}

fn method_uses_known_hosts(method: &ServerCheckMethod) -> bool {
    matches!(
        method,
        ServerCheckMethod::DefaultKnownHostsFile
            | ServerCheckMethod::KnownHostsFile(_)
            | ServerCheckMethod::KnownHostsFiles(_)
            | ServerCheckMethod::AcceptNewKnownHostsFiles { .. }
            | ServerCheckMethod::AcceptNewKnownHostsFile(_)
            | ServerCheckMethod::AcceptNewInMemory
    )
}

fn method_is_accept_new(method: &ServerCheckMethod) -> bool {
    matches!(
        method,
        ServerCheckMethod::AcceptNewKnownHostsFiles { .. }
            | ServerCheckMethod::AcceptNewKnownHostsFile(_)
            | ServerCheckMethod::AcceptNewInMemory
    )
}

fn accept_new_stores(method: &ServerCheckMethod) -> Option<(Vec<String>, Option<String>)> {
    match method {
        ServerCheckMethod::AcceptNewKnownHostsFile(path) => {
            Some((vec![path.clone()], Some(path.clone())))
        }
        ServerCheckMethod::AcceptNewKnownHostsFiles { files, write_path } => {
            Some((files.clone(), write_path.clone()))
        }
        ServerCheckMethod::AcceptNewInMemory => Some((Vec::new(), None)),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn verify_accept_new_host_and_address(
    method: &ServerCheckMethod,
    hostname: &str,
    hostname_port: u16,
    address: &str,
    address_port: u16,
    server_key: &russh::keys::PublicKey,
    hash_known_hosts: bool,
    hostname_lookup: Option<super::host_verification::KnownHostLookup>,
    address_lookup: Option<super::host_verification::KnownHostLookup>,
) -> Result<HostVerification, super::Error> {
    let (paths, write_path) = accept_new_stores(method)
        .expect("combined accept-new verification requires an accept-new method");
    let identities = [
        (hostname, hostname_port, hostname_lookup),
        (address, address_port, address_lookup),
    ];
    let mut configured_identities = Vec::with_capacity(2);
    let mut primary_from_command = false;

    for (index, (identity, port, lookup)) in identities.iter().enumerate() {
        match lookup {
            Some(super::host_verification::KnownHostLookup::Match) => {
                match verify_configured_stores_without_recording(
                    method, identity, *port, server_key,
                ) {
                    Ok(true) => configured_identities.push((*identity, *port)),
                    Ok(false) | Err(super::Error::HostKeyChanged { .. }) => {
                        primary_from_command |= index == 0;
                    }
                    Err(error) => return Err(error),
                }
            }
            Some(super::host_verification::KnownHostLookup::Conflict { line }) => {
                if verify_configured_stores_without_recording(method, identity, *port, server_key)?
                {
                    configured_identities.push((*identity, *port));
                } else {
                    return Err(command_conflict(identity, *port, server_key, *line));
                }
            }
            Some(super::host_verification::KnownHostLookup::Unknown) | None => {
                configured_identities.push((*identity, *port));
            }
        }
    }

    super::host_verification::verify_accept_new_identities_files_with_hash(
        &configured_identities,
        server_key,
        &paths,
        write_path.as_deref(),
        hash_known_hosts,
    )
    .await?;

    Ok(if primary_from_command {
        HostVerification::command()
    } else {
        HostVerification::configured(true, method)
    })
}

fn verify_configured_stores_without_recording(
    method: &ServerCheckMethod,
    hostname: &str,
    port: u16,
    server_key: &russh::keys::PublicKey,
) -> Result<bool, super::Error> {
    match method {
        ServerCheckMethod::DefaultKnownHostsFile => {
            let path = crate::ssh::known_hosts::get_default_known_hosts_path()
                .ok_or(super::Error::ServerCheckFailed)?;
            super::host_verification::verify_known_hosts_file(
                hostname,
                port,
                server_key,
                &path.to_string_lossy(),
            )
        }
        ServerCheckMethod::KnownHostsFile(path)
        | ServerCheckMethod::AcceptNewKnownHostsFile(path) => {
            super::host_verification::verify_known_hosts_file(hostname, port, server_key, path)
        }
        ServerCheckMethod::KnownHostsFiles(paths)
        | ServerCheckMethod::AcceptNewKnownHostsFiles { files: paths, .. } => {
            super::host_verification::verify_known_hosts_files(hostname, port, server_key, paths)
        }
        ServerCheckMethod::AcceptNewInMemory => Ok(false),
        _ => Ok(false),
    }
}

async fn verify_server_check_method(
    method: &ServerCheckMethod,
    hostname: &str,
    port: u16,
    server_key: &russh::keys::PublicKey,
    hash_known_hosts: bool,
) -> Result<bool, super::Error> {
    match method {
        ServerCheckMethod::NoCheck => Ok(true),
        ServerCheckMethod::PublicKey(key) => {
            let expected = russh::keys::parse_public_key_base64(key)
                .map_err(|_| super::Error::ServerCheckFailed)?;
            Ok(expected == *server_key)
        }
        ServerCheckMethod::PublicKeyFile(path) => {
            let expected =
                russh::keys::load_public_key(path).map_err(|_| super::Error::ServerCheckFailed)?;
            Ok(expected == *server_key)
        }
        ServerCheckMethod::KnownHostsFile(path) => {
            super::host_verification::verify_known_hosts_file(hostname, port, server_key, path)
        }
        ServerCheckMethod::KnownHostsFiles(paths) => {
            super::host_verification::verify_known_hosts_files(hostname, port, server_key, paths)
        }
        ServerCheckMethod::DefaultKnownHostsFile => {
            let Some(path) = crate::ssh::known_hosts::get_default_known_hosts_path() else {
                tracing::error!(
                    "Cannot determine the known_hosts path; rejecting host key for '{}'",
                    hostname
                );
                return Err(super::Error::ServerCheckFailed);
            };
            super::host_verification::verify_known_hosts_file(
                hostname,
                port,
                server_key,
                &path.to_string_lossy(),
            )
        }
        ServerCheckMethod::AcceptNewKnownHostsFile(path) => {
            super::host_verification::verify_accept_new_with_hash(
                hostname,
                port,
                server_key,
                path,
                hash_known_hosts,
            )
            .await
        }
        ServerCheckMethod::AcceptNewKnownHostsFiles { files, write_path } => {
            super::host_verification::verify_accept_new_files_with_hash(
                hostname,
                port,
                server_key,
                files,
                write_path.as_deref(),
                hash_known_hosts,
            )
            .await
        }
        ServerCheckMethod::AcceptNewInMemory => {
            super::host_verification::verify_accept_new_in_memory(hostname, port, server_key).await
        }
        ServerCheckMethod::HostKeyAlias { .. } => {
            unreachable!("aliases are unwrapped by ClientHandler")
        }
    }
}

fn command_conflict(
    hostname: &str,
    port: u16,
    server_key: &russh::keys::PublicKey,
    line: usize,
) -> super::Error {
    super::host_verification::map_known_hosts_error(
        hostname,
        port,
        server_key,
        "KnownHostsCommand",
        russh::keys::Error::KeyChanged { line },
    )
}

async fn verify_with_known_hosts_command(
    method: &ServerCheckMethod,
    hostname: &str,
    port: u16,
    server_key: &russh::keys::PublicKey,
    command_lookup: Option<super::host_verification::KnownHostLookup>,
    hash_known_hosts: bool,
) -> Result<HostVerification, super::Error> {
    if !method_uses_known_hosts(method) {
        let accepted =
            verify_server_check_method(method, hostname, port, server_key, hash_known_hosts)
                .await?;
        return Ok(HostVerification::configured(accepted, method));
    }

    match command_lookup {
        Some(super::host_verification::KnownHostLookup::Match) => {
            match verify_configured_stores_without_recording(method, hostname, port, server_key) {
                Ok(true) => Ok(HostVerification::configured(true, method)),
                Ok(false) | Err(super::Error::HostKeyChanged { .. }) => {
                    Ok(HostVerification::command())
                }
                Err(error) => Err(error),
            }
        }
        Some(super::host_verification::KnownHostLookup::Conflict { line })
            if method_is_accept_new(method) =>
        {
            match verify_configured_stores_without_recording(method, hostname, port, server_key)? {
                true => Ok(HostVerification::configured(true, method)),
                false => Err(command_conflict(hostname, port, server_key, line)),
            }
        }
        Some(super::host_verification::KnownHostLookup::Conflict { line }) => {
            match verify_server_check_method(method, hostname, port, server_key, hash_known_hosts)
                .await?
            {
                true => Ok(HostVerification::configured(true, method)),
                false => Err(command_conflict(hostname, port, server_key, line)),
            }
        }
        Some(super::host_verification::KnownHostLookup::Unknown) | None => {
            let accepted =
                verify_server_check_method(method, hostname, port, server_key, hash_known_hosts)
                    .await?;
            Ok(HostVerification::configured(accepted, method))
        }
    }
}

async fn verify_primary_host_after_sshfp<Lookup, LookupFuture>(
    method: &ServerCheckMethod,
    hostname: &str,
    port: u16,
    server_key: &russh::keys::PublicKey,
    hash_known_hosts: bool,
    sshfp: super::sshfp::SshfpDecision,
    command_lookup: Lookup,
) -> Result<HostVerification, super::Error>
where
    Lookup: FnOnce() -> LookupFuture,
    LookupFuture: std::future::Future<
            Output = Result<Option<super::host_verification::KnownHostLookup>, super::Error>,
        >,
{
    match sshfp {
        super::sshfp::SshfpDecision::Accept => Ok(HostVerification::dns()),
        super::sshfp::SshfpDecision::Continue => {
            let command_lookup = command_lookup().await?;
            verify_with_known_hosts_command(
                method,
                hostname,
                port,
                server_key,
                command_lookup,
                hash_known_hosts,
            )
            .await
        }
    }
}

impl Handler for ClientHandler {
    type Error = super::Error;

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            DisconnectReason::Error(error) => {
                self.fatal_transport.record(&error);
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let registry = self.remote_forward_registry.clone();
        let connected_address = connected_address.to_string();
        async move {
            if registry
                .route(&connected_address, connected_port, channel)
                .await
            {
                reply.accept().await;
            } else {
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
            }
            Ok(())
        }
    }

    async fn check_server_key(
        &mut self,
        server_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let mut method = &self.server_check;
        let mut host_key_alias = None;
        while let ServerCheckMethod::HostKeyAlias {
            alias,
            method: inner,
        } = method
        {
            host_key_alias.get_or_insert(alias.as_str());
            method = inner;
        }
        let hostname = host_key_alias.unwrap_or(&self.hostname);
        let port = if host_key_alias.is_some() {
            22
        } else {
            self.host.port()
        };

        // bssh does not yet validate OpenSSH host certificates. Never compare
        // an unverified certificate's embedded key against ordinary
        // known_hosts entries.
        let server_public_key = match server_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, hash_alg } => {
                let algorithm = match key.algorithm() {
                    ssh_key::Algorithm::Rsa { .. } => ssh_key::Algorithm::Rsa { hash: *hash_alg },
                    algorithm => algorithm,
                };
                *self
                    .verified_server_algorithm
                    .lock()
                    .map_err(|_| super::Error::ServerCheckFailed)? = Some(algorithm);
                key
            }
            russh::keys::PublicKeyOrCertificate::Certificate(cert) => {
                if matches!(method, ServerCheckMethod::NoCheck) {
                    return Ok(true);
                }
                tracing::error!(
                    "Host '{}' presented an unverifiable OpenSSH host certificate (key ID '{}')",
                    hostname,
                    cert.key_id()
                );
                return Err(super::Error::ServerCheckFailed);
            }
        };

        // DNSSEC is evaluated before any KnownHostsCommand lookup or accept-new
        // write. Only a DNSSEC-secure, consistently matching RRset accepts
        // immediately. Every other outcome falls back to known_hosts.
        let sshfp = super::sshfp::verify_sshfp(
            &self.policy.target_host,
            server_public_key,
            self.policy.verify_host_key_dns,
        )
        .await;
        let address = check_host_ip_address(&self.policy, self.host, host_key_alias);
        let (verification, address_preflighted) = if sshfp == super::sshfp::SshfpDecision::Accept {
            (HostVerification::dns(), true)
        } else if let Some(address) = address.as_deref()
            && method_is_accept_new(method)
        {
            // Run both helper invocations before either identity can be
            // persisted. The grouped verifier rechecks both file identities
            // under one lock and atomically appends all unknown rows.
            let hostname_lookup = self
                .run_known_hosts_lookup(
                    hostname,
                    port,
                    "HOSTNAME",
                    server_public_key,
                    host_key_alias,
                )
                .await?;
            let address_lookup = self
                .run_known_hosts_lookup(
                    address,
                    self.host.port(),
                    "ADDRESS",
                    server_public_key,
                    host_key_alias,
                )
                .await?;
            (
                verify_accept_new_host_and_address(
                    method,
                    hostname,
                    port,
                    address,
                    self.host.port(),
                    server_public_key,
                    self.policy.hash_known_hosts,
                    hostname_lookup,
                    address_lookup,
                )
                .await?,
                true,
            )
        } else {
            (
                verify_primary_host_after_sshfp(
                    method,
                    hostname,
                    port,
                    server_public_key,
                    self.policy.hash_known_hosts,
                    sshfp,
                    || {
                        self.run_known_hosts_lookup(
                            hostname,
                            port,
                            "HOSTNAME",
                            server_public_key,
                            host_key_alias,
                        )
                    },
                )
                .await?,
                false,
            )
        };

        if !verification.accepted {
            return Ok(false);
        }

        if !verification.skip_address_check
            && !address_preflighted
            && let Some(address) = address.as_deref()
        {
            let address_lookup = self
                .run_known_hosts_lookup(
                    address,
                    self.host.port(),
                    "ADDRESS",
                    server_public_key,
                    host_key_alias,
                )
                .await?;
            // An unknown address does not invalidate an otherwise trusted
            // hostname in strict mode, but a changed/revoked address does.
            let _ = verify_with_known_hosts_command(
                method,
                address,
                self.host.port(),
                server_public_key,
                address_lookup,
                self.policy.hash_known_hosts,
            )
            .await?;
        }
        if matches!(method, ServerCheckMethod::NoCheck) && !verification.skip_address_check {
            let mut identities = vec![(hostname, port)];
            if let Some(address) = address.as_deref() {
                identities.push((address, self.host.port()));
            }
            let write_path = self
                .policy
                .rotation_paths
                .as_ref()
                .and_then(|paths| paths.first())
                .map(String::as_str);
            super::host_verification::learn_accept_all_identities_files_with_hash(
                &identities,
                server_public_key,
                &self.policy.known_hosts_paths,
                write_path,
                self.policy.hash_known_hosts,
            )
            .await?;
        }

        *self
            .verified_server_key
            .lock()
            .map_err(|_| super::Error::ServerCheckFailed)? = Some(server_public_key.clone());
        self.rotation_allowed
            .store(verification.eligible_for_rotation, Ordering::Release);
        Ok(true)
    }

    fn openssh_ext_host_keys_announced(
        &mut self,
        keys: Vec<russh::keys::PublicKey>,
        session: &mut russh::client::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        match self.policy.update_host_keys {
            UpdateHostKeysPolicy::No => return std::future::ready(Ok(())),
            UpdateHostKeysPolicy::Ask => {
                tracing::warn!(
                    "UpdateHostKeys=ask requires a controlling terminal; bssh is non-interactive at the host-key callback and refuses the update"
                );
                return std::future::ready(Ok(()));
            }
            UpdateHostKeysPolicy::Yes => {}
        }
        let keys = keys
            .into_iter()
            .filter(|key| {
                self.policy.host_key_algorithms.iter().any(|allowed| {
                    match (key.algorithm(), allowed) {
                        (ssh_key::Algorithm::Rsa { .. }, ssh_key::Algorithm::Rsa { .. }) => true,
                        (offered, allowed) => offered == *allowed,
                    }
                })
            })
            .collect::<Vec<_>>();
        if !self.rotation_allowed.load(Ordering::Acquire) || keys.is_empty() {
            return std::future::ready(Ok(()));
        }
        if keys.len() > super::hostkey_rotation::MAX_ANNOUNCED_KEYS {
            tracing::warn!(
                "Ignoring {} announced host keys because the proof request is limited to {} keys",
                keys.len(),
                super::hostkey_rotation::MAX_ANNOUNCED_KEYS
            );
            return std::future::ready(Ok(()));
        }
        if self
            .proof_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            tracing::warn!("Ignoring repeated host-key announcement while proof is pending");
            return std::future::ready(Ok(()));
        }

        let mut method = &self.server_check;
        let mut host_key_alias = None;
        while let ServerCheckMethod::HostKeyAlias {
            alias,
            method: inner,
        } = method
        {
            host_key_alias.get_or_insert(alias.as_str());
            method = inner;
        }
        let hostname = host_key_alias.unwrap_or(&self.hostname).to_string();
        let port = if host_key_alias.is_some() {
            22
        } else {
            self.host.port()
        };
        let paths = self.rotation_paths(method);
        if paths.is_empty() {
            self.proof_in_flight.store(false, Ordering::Release);
            tracing::debug!(
                "UpdateHostKeys is enabled but no writable user known_hosts file is configured"
            );
            return std::future::ready(Ok(()));
        }
        let mut identities = vec![(hostname.clone(), port)];
        if let Some(address) = check_host_ip_address(&self.policy, self.host, host_key_alias) {
            identities.push((address, self.host.port()));
        }
        let current_key = match self.verified_server_key.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                self.proof_in_flight.store(false, Ordering::Release);
                return std::future::ready(Err(super::Error::ServerCheckFailed));
            }
        };
        let negotiated_algorithm = match self.verified_server_algorithm.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                self.proof_in_flight.store(false, Ordering::Release);
                return std::future::ready(Err(super::Error::ServerCheckFailed));
            }
        };
        let Some(current_key) = current_key else {
            self.proof_in_flight.store(false, Ordering::Release);
            return std::future::ready(Ok(()));
        };

        let (sender, receiver) = tokio::sync::oneshot::channel();
        if let Err(error) = session.request_hostkeys_prove(sender, &keys) {
            self.proof_in_flight.store(false, Ordering::Release);
            tracing::warn!("Could not request announced host-key proof: {error}");
            return std::future::ready(Ok(()));
        }

        let hash_known_hosts = self.policy.hash_known_hosts;
        let proof_in_flight = Arc::clone(&self.proof_in_flight);
        let task = tokio::spawn(async move {
            let result = match tokio::time::timeout(Duration::from_secs(5), receiver).await {
                Ok(Ok(Some(proof))) => {
                    let identity_refs = identities
                        .iter()
                        .map(|(hostname, port)| (hostname.as_str(), *port))
                        .collect::<Vec<_>>();
                    super::hostkey_rotation::apply_hostkeys_proof(
                        &paths,
                        &identity_refs,
                        &current_key,
                        &keys,
                        &proof,
                        negotiated_algorithm.as_ref(),
                        hash_known_hosts,
                    )
                    .await
                }
                Ok(Ok(None)) => Err("server rejected or malformed the host-key proof".to_string()),
                Ok(Err(_)) => Err("host-key proof channel closed without a reply".to_string()),
                Err(_) => Err("host-key proof request timed out after 5 seconds".to_string()),
            };
            if let Err(error) = result {
                tracing::warn!(
                    "Ignoring unsafe or unproven host-key announcement for '{}': {}",
                    hostname,
                    error
                );
            }
            proof_in_flight.store(false, Ordering::Release);
        });
        self.hostkey_rotation.track(task);
        std::future::ready(Ok(()))
    }
}

#[cfg(test)]
mod fatal_transport_tests {
    use super::*;
    use crate::ssh::tokio_client::{Error, TransportIntegrityCause};

    #[test]
    fn first_typed_integrity_cause_is_preserved_and_consumed_once() {
        let state = FatalTransportState::default();
        state.record(&Error::SshError(russh::Error::PacketAuth));
        state.record(&Error::SshError(russh::Error::DecryptionError));

        let error = state
            .take_error()
            .expect("typed packet cause must be recorded");
        assert!(matches!(
            error,
            Error::TransportIntegrity {
                cause: TransportIntegrityCause::PacketAuthentication
            }
        ));
        assert_eq!(
            error.to_string(),
            "Corrupted MAC: message authentication code incorrect"
        );
        assert!(
            state.take_error().is_none(),
            "a fatal cause must not leak into a later failure"
        );
    }

    #[test]
    fn ordinary_auth_and_channel_failures_are_not_mislabeled_as_integrity_errors() {
        let state = FatalTransportState::default();
        state.record(&Error::KeyAuthFailed);
        state.record(&Error::SshError(russh::Error::SendError));

        assert!(state.take_error().is_none());
    }

    #[test]
    fn packet_size_and_invalid_padding_remain_distinct_typed_causes() {
        for (source, expected) in [
            (
                russh::Error::PacketSize(262_145),
                TransportIntegrityCause::PacketSize(262_145),
            ),
            (
                russh::Error::IndexOutOfBounds,
                TransportIntegrityCause::InvalidPadding,
            ),
        ] {
            let state = FatalTransportState::default();
            state.record(&Error::SshError(source));
            assert!(matches!(
                state.take_error(),
                Some(Error::TransportIntegrity { cause }) if cause == expected
            ));
        }
    }

    #[test]
    fn handler_state_is_shared_with_clones_but_fresh_for_each_connection() {
        let address = "127.0.0.1:22".parse().unwrap();
        let first = ClientHandler::new(
            "first.example".to_string(),
            address,
            ServerCheckMethod::NoCheck,
        );
        let first_clone = first.clone();
        let second = ClientHandler::new(
            "second.example".to_string(),
            address,
            ServerCheckMethod::NoCheck,
        );

        first
            .fatal_transport_state()
            .record(&Error::SshError(russh::Error::PacketAuth));

        assert!(matches!(
            first_clone.fatal_transport_state().take_error(),
            Some(Error::TransportIntegrity {
                cause: TransportIntegrityCause::PacketAuthentication
            })
        ));
        assert!(
            second.fatal_transport_state().take_error().is_none(),
            "a reconnect must not inherit a previous connection's fatal cause"
        );
        assert!(
            first.fatal_transport_state().take_error().is_none(),
            "a consumed cause must not be reused by another operation"
        );
    }
}

#[cfg(test)]
mod known_host_policy_tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey, PublicKeyOrCertificate};
    use tempfile::tempdir;

    fn key() -> russh::keys::PublicKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    #[tokio::test]
    async fn tracked_rotation_is_complete_before_flush_returns() {
        let tasks = HostkeyRotationTasks::new(true);
        let complete = Arc::new(AtomicBool::new(false));
        let task_complete = Arc::clone(&complete);
        tasks.track(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            task_complete.store(true, Ordering::Release);
        }));
        tasks.wait().await;
        assert!(complete.load(Ordering::Acquire));
    }

    #[test]
    fn update_host_keys_ask_is_preserved_as_fail_closed_policy() {
        assert_eq!(
            UpdateHostKeysPolicy::parse("ask"),
            UpdateHostKeysPolicy::Ask
        );
        assert_eq!(
            UpdateHostKeysPolicy::parse("yes"),
            UpdateHostKeysPolicy::Yes
        );
        assert_eq!(UpdateHostKeysPolicy::parse("no"), UpdateHostKeysPolicy::No);
    }

    #[test]
    fn order_prefers_algorithms_backed_by_command_keys() {
        let mut config = Config::default();
        config.preferred.key = Cow::Owned(vec![
            ssh_key::Algorithm::Ed25519,
            ssh_key::Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha512),
            },
            ssh_key::Algorithm::Dsa,
        ]);
        prefer_known_host_algorithms(&mut config, &[ssh_key::Algorithm::Dsa]);
        assert_eq!(config.preferred.key[0], ssh_key::Algorithm::Dsa);
        assert_eq!(config.preferred.key[1], ssh_key::Algorithm::Ed25519);
    }

    #[tokio::test]
    async fn check_host_ip_rejects_a_conflicting_address_key() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let offered = key();
        let wrong_address_key = key();
        std::fs::write(
            &path,
            format!(
                "node.example {}\n127.0.0.1 {}\n",
                offered.to_openssh().unwrap(),
                wrong_address_key.to_openssh().unwrap()
            ),
        )
        .unwrap();

        let mut policy = KnownHostRuntimePolicy::unconfigured("remote", "node.example", 22);
        policy.check_host_ip = true;
        let mut handler = ClientHandler::new_with_policy(
            "node.example".to_string(),
            "127.0.0.1:22".parse().unwrap(),
            ServerCheckMethod::KnownHostsFile(path.to_string_lossy().into_owned()),
            policy,
        );

        let error = handler
            .check_server_key(&PublicKeyOrCertificate::from(offered))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            super::super::Error::HostKeyChanged {
                ref host,
                port: 22,
                ..
            } if host == "127.0.0.1"
        ));
    }

    #[tokio::test]
    async fn hashed_alias_write_uses_alias_identity_and_selected_path() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("selected-known-hosts");
        let offered = key();
        let mut policy = KnownHostRuntimePolicy::unconfigured("remote", "real.example", 2222);
        policy.hash_known_hosts = true;
        policy.check_host_ip = true;
        let method = ServerCheckMethod::HostKeyAlias {
            alias: "shared-alias".to_string(),
            method: Box::new(ServerCheckMethod::AcceptNewKnownHostsFile(
                path.to_string_lossy().into_owned(),
            )),
        };
        let mut handler = ClientHandler::new_with_policy(
            "real.example".to_string(),
            "192.0.2.5:2222".parse().unwrap(),
            method,
            policy,
        );

        assert!(
            handler
                .check_server_key(&PublicKeyOrCertificate::from(offered.clone()))
                .await
                .unwrap()
        );

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("|1|"));
        assert!(!contents.contains("shared-alias"));
        assert!(!contents.contains("real.example"));
        let alias_keys =
            russh::keys::known_hosts::known_host_keys_path("shared-alias", 22, &path).unwrap();
        assert!(alias_keys.iter().any(|(_, key)| key == &offered));
        assert!(
            russh::keys::known_hosts::known_host_keys_path("real.example", 2222, &path)
                .unwrap()
                .is_empty()
        );
        assert!(
            russh::keys::known_hosts::known_host_keys_path("192.0.2.5", 2222, &path)
                .unwrap()
                .is_empty(),
            "HostKeyAlias must suppress CheckHostIP writes"
        );
    }
    #[test]
    fn order_eligibility_preserves_raw_host_key_algorithm_modifiers() {
        for (directive, expected) in [
            (None, true),
            (Some("+ssh-rsa"), true),
            (Some("-ssh-rsa"), true),
            (Some("ssh-ed25519,rsa-sha2-512"), false),
        ] {
            let body = directive
                .map(|value| format!("Host node\n    HostKeyAlgorithms {value}\n"))
                .unwrap_or_else(|| "Host node\n".to_string());
            let config = SshConfig::parse(&body).unwrap();
            let resolved = SshConnectionConfigResolver::new()
                .with_ssh_config(Some(config))
                .resolve_for_host("node");
            assert_eq!(
                resolved.order_host_key_algorithms, expected,
                "{directive:?}"
            );
            if directive == Some("+ssh-rsa") {
                assert!(
                    resolved
                        .host_key_preferences
                        .as_ref()
                        .expect("modifier must materialize preferences")
                        .contains(&ssh_key::Algorithm::Rsa { hash: None })
                );
            }
        }
    }

    #[test]
    fn order_reads_alias_and_nondefault_port_from_multiple_stores() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("known_hosts");
        let second = directory.path().join("ssh_known_hosts");
        let ed25519 = key();
        let ecdsa = PrivateKey::random(
            &mut rand::rng(),
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .unwrap()
        .public_key()
        .clone();
        std::fs::write(
            &first,
            format!("[node.example]:2222 {}\n", ed25519.to_openssh().unwrap()),
        )
        .unwrap();
        std::fs::write(
            &second,
            format!(
                "[node.example]:2222 {}\nshared-alias {}\n",
                ecdsa.to_openssh().unwrap(),
                ecdsa.to_openssh().unwrap()
            ),
        )
        .unwrap();
        let paths = [
            first.to_string_lossy().into_owned(),
            second.to_string_lossy().into_owned(),
        ];

        let algorithms = known_host_algorithms_from_paths(&paths, "node.example", 2222).unwrap();
        assert!(algorithms.contains(&ssh_key::Algorithm::Ed25519));
        assert!(algorithms.contains(&ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        }));
        assert_eq!(
            known_host_algorithms_from_paths(&paths, "shared-alias", 22).unwrap(),
            vec![ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            }]
        );
    }

    #[test]
    fn ssh_rsa_sha1_is_not_default_but_remains_explicitly_available() {
        let legacy = ssh_key::Algorithm::Rsa { hash: None };
        let defaults = SshConnectionConfig::new().to_russh_config();
        assert!(!defaults.preferred.key.contains(&legacy));

        let opted_in = SshConnectionConfig::new()
            .with_algorithm_preferences(None, None, None, Some(vec![legacy.clone()]))
            .to_russh_config();
        assert_eq!(opted_in.preferred.key.as_ref(), &[legacy]);
    }
    #[test]
    fn host_key_alias_disables_address_verification_and_rotation_identity() {
        let mut policy = KnownHostRuntimePolicy::unconfigured("remote", "real.example", 2222);
        policy.check_host_ip = true;
        let address: SocketAddr = "192.0.2.5:2222".parse().unwrap();
        assert_eq!(
            check_host_ip_address(&policy, address, Some("shared-alias")),
            None
        );
        assert_eq!(
            check_host_ip_address(&policy, address, None).as_deref(),
            Some("192.0.2.5")
        );
    }
    #[tokio::test]
    async fn dns_secure_only_match_skips_lookup_address_and_tofu() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let method =
            ServerCheckMethod::AcceptNewKnownHostsFile(path.to_string_lossy().into_owned());
        let offered = key();
        let lookup_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&lookup_called);

        let accepted = verify_primary_host_after_sshfp(
            &method,
            "node.example",
            22,
            &offered,
            false,
            super::super::sshfp::SshfpDecision::Accept,
            move || async move {
                called.store(true, Ordering::Release);
                Ok(None)
            },
        )
        .await
        .unwrap();
        assert!(accepted.accepted);
        assert!(accepted.skip_address_check);
        assert!(!lookup_called.load(Ordering::Acquire));
        assert!(
            !path.exists(),
            "secure DNS match must not perform a TOFU write"
        );
    }

    #[tokio::test]
    async fn dns_mismatch_bogus_and_insecure_outcomes_fall_back_to_tofu() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let method =
            ServerCheckMethod::AcceptNewKnownHostsFile(path.to_string_lossy().into_owned());
        let offered = key();

        for reason in [
            "match plus mismatch",
            "secure mismatch",
            "bogus",
            "insecure",
        ] {
            let _ = std::fs::remove_file(&path);
            let lookup_called = Arc::new(AtomicBool::new(false));
            let called = Arc::clone(&lookup_called);
            let fallback = verify_primary_host_after_sshfp(
                &method,
                "node.example",
                22,
                &offered,
                false,
                super::super::sshfp::SshfpDecision::Continue,
                move || async move {
                    called.store(true, Ordering::Release);
                    Ok(None)
                },
            )
            .await
            .unwrap();
            assert!(fallback.accepted, "{reason}");
            assert!(!fallback.skip_address_check, "{reason}");
            assert!(lookup_called.load(Ordering::Acquire), "{reason}");
            assert!(path.exists(), "{reason} must fall back to a TOFU write");
        }
    }

    #[tokio::test]
    async fn check_host_ip_conflict_leaves_unknown_hostname_unrecorded() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let offered = key();
        let conflicting = key();
        let original = format!("192.0.2.5 {}\n", conflicting.to_openssh().unwrap());
        std::fs::write(&path, &original).unwrap();
        let method =
            ServerCheckMethod::AcceptNewKnownHostsFile(path.to_string_lossy().into_owned());

        let result = verify_accept_new_host_and_address(
            &method,
            "node.example",
            22,
            "192.0.2.5",
            22,
            &offered,
            false,
            None,
            None,
        )
        .await;
        assert!(matches!(
            result,
            Err(super::super::Error::HostKeyChanged { .. })
        ));
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    }

    #[tokio::test]
    async fn check_host_ip_records_both_unknown_identities_atomically() {
        let directory = tempdir().unwrap();
        let offered = key();
        for hash_known_hosts in [false, true] {
            let path = directory
                .path()
                .join(format!("known_hosts-{hash_known_hosts}"));
            let method =
                ServerCheckMethod::AcceptNewKnownHostsFile(path.to_string_lossy().into_owned());

            let verification = verify_accept_new_host_and_address(
                &method,
                "node.example",
                22,
                "192.0.2.5",
                22,
                &offered,
                hash_known_hosts,
                None,
                None,
            )
            .await
            .unwrap();
            assert!(verification.accepted);
            let contents = std::fs::read_to_string(&path).unwrap();
            assert_eq!(contents.lines().count(), 2);
            if hash_known_hosts {
                assert!(contents.lines().all(|line| line.starts_with("|1|")));
            }
            for identity in ["node.example", "192.0.2.5"] {
                let keys =
                    russh::keys::known_hosts::known_host_keys_path(identity, 22, &path).unwrap();
                assert!(keys.iter().any(|(_, key)| key == &offered));
            }
        }
    }
}

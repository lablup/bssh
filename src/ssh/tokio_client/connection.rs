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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fmt::Debug, io};

use super::address_family::AddressFamily;
use super::authentication::{AuthMethod, ServerCheckMethod};
use super::proxy_command::{
    ProxyCommandConfig, ProxyCommandProcess, ProxyMode, spawn_proxy_command,
};
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
    /// Effective proxy selection for this target.
    pub proxy_mode: Option<ProxyMode>,
    pub cipher_preferences: Option<Vec<russh::cipher::Name>>,
    pub mac_preferences: Option<Vec<russh::mac::Name>>,
    pub kex_preferences: Option<Vec<russh::kex::Name>>,
    pub host_key_preferences: Option<Vec<ssh_key::Algorithm>>,
    /// Public-key signature policy for the authentication follow-up.
    pub pubkey_accepted_algorithms: Option<Vec<String>>,
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
            proxy_mode: None,
            cipher_preferences: None,
            mac_preferences: None,
            kex_preferences: None,
            host_key_preferences: None,
            pubkey_accepted_algorithms: None,
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

        let pubkey_accepted_algorithms = host_config
            .as_ref()
            .and_then(|config| config.resolved_pubkey_accepted_algorithms.clone());
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
            .with_proxy_mode(proxy_mode)
            .with_algorithm_preferences(
                cipher_preferences,
                mac_preferences,
                kex_preferences,
                host_key_preferences,
            )
            .with_pubkey_accepted_algorithms(pubkey_accepted_algorithms)
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

    /// Expose the resolved user-authentication signature policy.
    #[must_use]
    pub fn with_pubkey_accepted_algorithms(mut self, algorithms: Option<Vec<String>>) -> Self {
        self.pubkey_accepted_algorithms = algorithms;
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
            let attempts = ssh_config.connection_attempts.max(1);
            for round in 0..attempts {
                let result = Self::connect_with_proxy_command(
                    &host,
                    port,
                    username,
                    auth.clone(),
                    server_check.clone(),
                    ssh_config.to_russh_config(),
                    proxy,
                )
                .await;
                match result {
                    Ok(client) => return Ok(client),
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
        let config = ssh_config.to_russh_config();
        let tcp_keepalive = ssh_config.to_tcp_keepalive();
        Self::connect_with_config_inner(
            addr,
            username,
            auth,
            server_check,
            config,
            DirectCarrierOptions {
                tcp_keepalive: tcp_keepalive.as_ref(),
                address_family: ssh_config.address_family,
                connection_attempts: ssh_config.connection_attempts,
            },
        )
        .await
    }

    async fn connect_with_proxy_command(
        host: &str,
        port: u16,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
        config: Config,
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
        let handler = ClientHandler::new(
            verification_host.to_string(),
            verification_address,
            server_check,
        );
        let fatal_transport = handler.fatal_transport_state();
        let mut handle =
            match russh::client::connect_stream(Arc::new(config), proxy_session.stream, handler)
                .await
            {
                Ok(handle) => handle,
                Err(error) => {
                    if let Some(failure) =
                        process.wait_for_failure(Duration::from_millis(250)).await
                    {
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
        Ok(Self {
            connection_handle: Arc::clone(&connection_handle),
            username,
            address,
            session: connection_handle,
            proxy_process: Some(process),
            fatal_transport,
        })
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
        Self::connect_with_config_inner(
            addr,
            username,
            auth,
            server_check,
            config,
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

        let handler = ClientHandler::new(target_host.clone(), address, server_check);
        let fatal_transport = handler.fatal_transport_state();
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
        Ok(Self {
            connection_handle: connection_handle.clone(),
            username,
            address,
            session: connection_handle,
            proxy_process: None,
            fatal_transport,
        })
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
        )
    }

    pub(crate) fn from_handle_and_address_with_state(
        handle: Arc<Handle<ClientHandler>>,
        username: String,
        address: SocketAddr,
        fatal_transport: FatalTransportState,
    ) -> Self {
        Self {
            connection_handle: handle.clone(),
            username,
            address,
            session: handle,
            proxy_process: None,
            fatal_transport,
        }
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
        let result = self
            .connection_handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(super::Error::SshError);
        if let Some(process) = &self.proxy_process {
            process.terminate();
        }
        result
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.connection_handle.is_closed()
    }

    /// Request remote port forwarding (tcpip-forward) - Future Implementation Placeholder
    ///
    /// **TODO**: This method needs to be implemented once russh provides
    /// global request functionality or we find the appropriate API.
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
        _bind_address: String,
        _bind_port: u32,
    ) -> Result<u32, super::Error> {
        // **TODO**: Implement actual tcpip-forward global request
        // For now, return an error indicating this is not yet implemented
        tracing::warn!("Remote port forwarding request not yet implemented - TODO");
        Err(super::Error::PortForwardingNotSupported)
    }

    /// Cancel remote port forwarding (cancel-tcpip-forward) - Future Implementation Placeholder
    ///
    /// **TODO**: This method needs to be implemented once russh provides
    /// global request functionality or we find the appropriate API.
    ///
    /// This sends a global request to cancel a previously established remote port forward.
    ///
    /// # Arguments
    /// * `bind_address` - Address that was bound on the remote server
    /// * `bind_port` - Port that was bound on the remote server
    pub async fn cancel_port_forward(
        &self,
        _bind_address: String,
        _bind_port: u32,
    ) -> Result<(), super::Error> {
        // **TODO**: Implement actual cancel-tcpip-forward global request
        // For now, return an error indicating this is not yet implemented
        tracing::warn!("Cancel remote port forwarding not yet implemented - TODO");
        Err(super::Error::PortForwardingNotSupported)
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

/// SSH client handler for managing server key verification.
#[derive(Debug, Clone)]
pub struct ClientHandler {
    hostname: String,
    host: SocketAddr,
    server_check: ServerCheckMethod,
    fatal_transport: FatalTransportState,
}

impl ClientHandler {
    /// Create a new client handler.
    pub fn new(hostname: String, host: SocketAddr, server_check: ServerCheckMethod) -> Self {
        Self {
            hostname,
            host,
            server_check,
            fatal_transport: FatalTransportState::default(),
        }
    }

    pub(crate) fn fatal_transport_state(&self) -> FatalTransportState {
        self.fatal_transport.clone()
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

    async fn check_server_key(
        &mut self,
        server_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let mut server_check = &self.server_check;
        let mut host_key_alias = None;
        while let ServerCheckMethod::HostKeyAlias { alias, method } = server_check {
            if host_key_alias.is_none() {
                host_key_alias = Some(alias.as_str());
            }
            server_check = method;
        }
        let hostname = host_key_alias.unwrap_or(&self.hostname);
        let port = if host_key_alias.is_some() {
            22
        } else {
            self.host.port()
        };

        // russh 0.63 widened this callback to also deliver OpenSSH *host
        // certificates*. bssh never advertises certificate host key algorithms
        // (both `Preferred` overrides only touch compression, and
        // `Preferred::DEFAULT.host_key_certificates` is empty), so a server
        // cannot legitimately negotiate one. Should a peer send one anyway,
        // fail closed: bssh has no CA signature verification, so the key inside
        // the certificate has never been vouched for by anything we trust, and
        // matching it against known_hosts would answer the wrong question.
        // `NoCheck` still wins, because there the user disabled verification.
        let server_public_key = match server_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key,
            russh::keys::PublicKeyOrCertificate::Certificate(cert) => {
                if matches!(server_check, ServerCheckMethod::NoCheck) {
                    return Ok(true);
                }
                tracing::error!(
                    "Host '{}' presented an OpenSSH host certificate (key ID '{}'); \
                     bssh cannot verify certificate signatures, so the host is rejected. \
                     Configure the server to offer a plain host key.",
                    hostname,
                    cert.key_id()
                );
                return Err(super::Error::ServerCheckFailed);
            }
        };

        match server_check {
            ServerCheckMethod::NoCheck => Ok(true),
            ServerCheckMethod::PublicKey(key) => {
                let pk = russh::keys::parse_public_key_base64(key)
                    .map_err(|_| super::Error::ServerCheckFailed)?;

                Ok(pk == *server_public_key)
            }
            ServerCheckMethod::PublicKeyFile(key_file_name) => {
                let pk = russh::keys::load_public_key(key_file_name)
                    .map_err(|_| super::Error::ServerCheckFailed)?;

                Ok(pk == *server_public_key)
            }
            ServerCheckMethod::KnownHostsFile(known_hosts_path) => {
                super::host_verification::verify_known_hosts_file(
                    hostname,
                    port,
                    server_public_key,
                    known_hosts_path,
                )
            }
            ServerCheckMethod::KnownHostsFiles(known_hosts_paths) => {
                super::host_verification::verify_known_hosts_files(
                    hostname,
                    port,
                    server_public_key,
                    known_hosts_paths,
                )
            }
            ServerCheckMethod::DefaultKnownHostsFile => {
                // Resolve the default path here rather than letting russh
                // resolve it internally, so the check and the changed-key
                // banner's `ssh-keygen -f "<file>"` hint agree on one path and
                // both modes share `verify_known_hosts_file`. No home
                // directory means no trust state at all, so fail closed.
                let Some(known_hosts_path) =
                    crate::ssh::known_hosts::get_default_known_hosts_path()
                else {
                    tracing::error!(
                        "Cannot determine the known_hosts path; rejecting host key for '{}'",
                        hostname
                    );
                    return Err(super::Error::ServerCheckFailed);
                };
                super::host_verification::verify_known_hosts_file(
                    hostname,
                    port,
                    server_public_key,
                    &known_hosts_path.to_string_lossy(),
                )
            }
            ServerCheckMethod::AcceptNewKnownHostsFile(known_hosts_path) => {
                super::host_verification::verify_accept_new(
                    hostname,
                    port,
                    server_public_key,
                    known_hosts_path,
                )
                .await
            }
            ServerCheckMethod::AcceptNewKnownHostsFiles { files, write_path } => {
                super::host_verification::verify_accept_new_files(
                    hostname,
                    port,
                    server_public_key,
                    files,
                    write_path.as_deref(),
                )
                .await
            }
            ServerCheckMethod::AcceptNewInMemory => {
                super::host_verification::verify_accept_new_in_memory(
                    hostname,
                    port,
                    server_public_key,
                )
                .await
            }
            ServerCheckMethod::HostKeyAlias { .. } => unreachable!("aliases are unwrapped above"),
        }
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

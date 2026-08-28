use super::AddressFamily;
use std::io;

/// A fatal packet-integrity failure reported by the SSH transport.
///
/// These variants mirror the narrow set of russh errors emitted while
/// authenticating or decoding an encrypted packet. Keeping this typed avoids
/// relabeling ordinary authentication or channel failures as corruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportIntegrityCause {
    PacketAuthentication,
    Decryption,
    PacketSize(usize),
    InvalidPadding,
}

impl std::fmt::Display for TransportIntegrityCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketAuthentication => {
                f.write_str("Corrupted MAC: message authentication code incorrect")
            }
            Self::Decryption => f.write_str(
                "Corrupted MAC: authenticated packet decryption failed \
                 (message authentication code incorrect)",
            ),
            Self::PacketSize(size) => write!(f, "Bad packet size: {size}"),
            Self::InvalidPadding => f.write_str("padding error: invalid packet padding"),
        }
    }
}

/// This is the `thiserror` error for all crate errors.
///
/// Most ssh related error is wrapped in the `SshError` variant,
/// giving access to the underlying [`russh::Error`] type.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Permission denied (keyboard-interactive).")]
    KeyboardInteractiveAuthFailed,
    #[error("No keyboard-interactive response for prompt: {0}")]
    KeyboardInteractiveNoResponseForPrompt(String),
    #[error("Permission denied (publickey).")]
    KeyAuthFailed,
    #[error("Unable to load key, bad format or passphrase: {0}")]
    KeyInvalid(russh::keys::Error),
    #[error("SSH authentication policy rejected the configured credential: {0}")]
    AuthenticationPolicy(String),
    #[error("SSH identity algorithm is excluded by PubkeyAcceptedAlgorithms: {0}")]
    IdentityAlgorithmExcluded(String),
    #[error("Permission denied (password).")]
    PasswordWrong,
    #[error(
        "Permission denied ({methods}).\nbssh: SSH identities: {identity_status}\nbssh: SSH agent: {agent_status}\nbssh: Default SSH keys: not found or not authorized\nbssh: Password authentication: {password_status}\nbssh: use -i/--identity, --password, or ssh-add to configure an authentication method"
    )]
    AuthenticationExhausted {
        methods: String,
        identity_status: String,
        agent_status: String,
        password_status: &'static str,
    },
    #[error("Invalid address was provided: {0}")]
    AddressInvalid(io::Error),
    #[error("ssh: Could not resolve hostname {host}: {source}")]
    DnsResolution {
        host: String,
        #[source]
        source: io::Error,
    },
    #[error("ssh: connect to host {host} port {port}: {source}")]
    TcpConnect {
        host: String,
        port: u16,
        #[source]
        source: io::Error,
    },
    #[error("failed to resolve BindAddress '{bind_address}' for {family}: {source}")]
    BindAddressResolution {
        bind_address: String,
        family: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("BindAddress '{bind_address}' has no {family} address for destination {destination}")]
    BindAddressFamily {
        bind_address: String,
        family: &'static str,
        destination: std::net::SocketAddr,
    },
    #[error("BindInterface '{interface}' cannot select a {family} source address: {source}")]
    BindInterface {
        interface: String,
        family: &'static str,
        #[source]
        source: io::Error,
    },
    #[error(
        "failed to bind source address {source_address} for destination {destination}: {source}"
    )]
    SourceBind {
        source_address: std::net::SocketAddr,
        destination: std::net::SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("failed to apply IPQoS {value:#04x} to {family} destination {destination}: {source}")]
    IpQos {
        value: u8,
        family: &'static str,
        destination: std::net::SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("connection failed after {attempts} carrier attempts: {source}")]
    ConnectionAttemptsExhausted {
        attempts: usize,
        #[source]
        source: Box<Error>,
    },
    #[error(
        "ssh: connect to host {host} port {port}: Connection timed out\nbssh: timed out after {seconds} seconds during {stage}"
    )]
    ConnectionTimeout {
        host: String,
        port: u16,
        seconds: u64,
        stage: &'static str,
    },
    #[error("SSH protocol or version negotiation failed for {host} port {port}: {source}")]
    ProtocolNegotiation {
        host: String,
        port: u16,
        #[source]
        source: russh::Error,
    },
    #[error("BatchMode prohibits passphrase or keychain prompting for key '{path}'")]
    KeyPassphrasePromptDisabled { path: std::path::PathBuf },
    #[error("Authentication {prompt} prompt timed out after {seconds} seconds")]
    AuthenticationPromptTimeout { prompt: &'static str, seconds: u64 },
    #[error("ProxyCommand '{command}' contains unsupported token '{token}'")]
    InvalidProxyCommandToken { command: String, token: String },
    #[error("Failed to start ProxyCommand '{command}': {source}")]
    ProxyCommandSpawn {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to configure TCPKeepAlive on socket {address}: {source}")]
    TcpKeepAlive {
        address: std::net::SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("ProxyCommand '{command}' failed ({status}): {stderr}")]
    ProxyCommandFailed {
        command: String,
        status: String,
        stderr: String,
    },
    #[error(
        "ProxyUseFdpass yes is not supported for ProxyCommand '{command}'; remove ProxyUseFdpass or set it to no"
    )]
    ProxyUseFdpassUnsupported { command: String },
    /// An address family was forced (`-4`/`-6`, or ssh_config `AddressFamily`)
    /// and name resolution produced no address of that family. This is a hard
    /// failure with no fallback to the other family, matching OpenSSH, and it
    /// replaces the generic "could not resolve to any addresses" so the user
    /// can tell a forced-family mismatch from a genuine resolution failure.
    #[error("no {family} address found for {host}")]
    NoAddressForFamily { host: String, family: AddressFamily },
    #[error("Remote command failed: server did not send an exit status")]
    CommandDidntExit,
    #[error("Host key verification failed")]
    ServerCheckFailed,
    #[error("KnownHostsCommand failed: {reason}")]
    KnownHostsCommandFailed { reason: String },
    /// `port` is not interpolated into the `Display` text, but carrying it is
    /// what lets the client-facing messages name the actual known_hosts entry
    /// (`[host]:port` for non-standard ports) in their `ssh-keygen -R`
    /// remediation hint.
    #[error(
        "Host key for '{host}' has changed and no longer matches the known_hosts entry at line {line}"
    )]
    HostKeyChanged {
        host: String,
        port: u16,
        line: usize,
    },
    /// The offered key exactly matches a key an operator explicitly
    /// blocklisted with a known_hosts `@revoked` marker line. `port` is
    /// carried for the same reason `HostKeyChanged` carries it (naming the
    /// actual known_hosts entry in client-facing guidance), but unlike a
    /// changed key there is no `ssh-keygen -R` remediation to suggest: the
    /// marker was placed deliberately, and removing it would silence the
    /// warning rather than fix anything.
    #[error("Host key for '{host}' is explicitly revoked by the known_hosts entry at line {line}")]
    HostKeyRevoked {
        host: String,
        port: u16,
        line: usize,
    },
    #[error("SSH protocol error: {0}")]
    SshError(#[from] russh::Error),
    #[error("SSH channel send failed: {0}")]
    SendError(#[from] russh::SendError),
    #[error("{cause}")]
    TransportIntegrity { cause: TransportIntegrityCause },
    #[error("SSH agent authentication error: {0}")]
    AgentAuthError(#[from] russh::AgentAuthError),
    #[error("Failed to connect to SSH agent")]
    AgentConnectionFailed,
    #[error("Failed to request identities from SSH agent")]
    AgentRequestIdentitiesFailed,
    /// Timed out before russh requested an SSH signature, so another planned
    /// authentication method may safely reuse the transport.
    #[error("SSH agent setup operation '{action}' timed out after {seconds} seconds")]
    AgentOperationTimeout { action: &'static str, seconds: u64 },
    /// Timed out after russh requested a signature. The transport may still
    /// be waiting for `Msg::Signed` and must not be reused.
    #[error("SSH agent signing operation '{action}' timed out after {seconds} seconds")]
    AgentSignerTimeout { action: &'static str, seconds: u64 },
    #[error("SSH agent has no identities")]
    AgentNoIdentities,
    #[error("Permission denied (publickey). SSH agent identities were rejected")]
    AgentAuthenticationFailed,
    /// A local certificate signer failed after russh requested a signature;
    /// unlike key-loading errors, this is fatal to the current transport.
    #[error(
        "Local SSH certificate signing failed after the server requested a signature: {source}"
    )]
    LocalSignerFailed {
        #[source]
        source: russh::keys::Error,
    },
    #[error("SFTP error occurred: {0}")]
    SftpError(#[from] russh_sftp::client::error::Error),
    #[error("I/O operation failed: {0}")]
    IoError(#[from] io::Error),
    #[error("SSH channel open failed: {source}")]
    ChannelOpen {
        #[source]
        source: russh::Error,
    },
    #[error("Remote command execution failed during {action}: {source}")]
    CommandExecution {
        action: &'static str,
        #[source]
        source: russh::Error,
    },
    #[error("Command validation failed: {0}")]
    CommandValidationFailed(String),
    #[error("Port forwarding request failed: {0}")]
    PortForwardRequestFailed(String),
    #[error("Remote port forwarding setup failed: {0}")]
    RemotePortForwardFailed(String),
    #[error("Port forwarding is not supported by the SSH server")]
    PortForwardingNotSupported,
    #[error("Global request failed: {0}")]
    GlobalRequestFailed(String),
    #[error("Task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

impl Error {
    #[must_use]
    pub fn is_ssh_client_failure(&self) -> bool {
        matches!(
            self,
            Self::KeyboardInteractiveAuthFailed
                | Self::KeyboardInteractiveNoResponseForPrompt(_)
                | Self::KeyAuthFailed
                | Self::KeyInvalid(_)
                | Self::AuthenticationPolicy(_)
                | Self::KeyPassphrasePromptDisabled { .. }
                | Self::AuthenticationPromptTimeout { .. }
                | Self::PasswordWrong
                | Self::AuthenticationExhausted { .. }
                | Self::AddressInvalid(_)
                | Self::DnsResolution { .. }
                | Self::TcpConnect { .. }
                | Self::BindAddressResolution { .. }
                | Self::BindAddressFamily { .. }
                | Self::BindInterface { .. }
                | Self::SourceBind { .. }
                | Self::IpQos { .. }
                | Self::ConnectionAttemptsExhausted { .. }
                | Self::ConnectionTimeout { .. }
                | Self::ProtocolNegotiation { .. }
                | Self::InvalidProxyCommandToken { .. }
                | Self::ProxyCommandSpawn { .. }
                | Self::ProxyCommandFailed { .. }
                | Self::ProxyUseFdpassUnsupported { .. }
                | Self::NoAddressForFamily { .. }
                | Self::CommandDidntExit
                | Self::ServerCheckFailed
                | Self::KnownHostsCommandFailed { .. }
                | Self::HostKeyChanged { .. }
                | Self::HostKeyRevoked { .. }
                | Self::SshError(_)
                | Self::SendError(_)
                | Self::TransportIntegrity { .. }
                | Self::AgentAuthError(_)
                | Self::IdentityAlgorithmExcluded(_)
                | Self::AgentConnectionFailed
                | Self::AgentRequestIdentitiesFailed
                | Self::AgentOperationTimeout { .. }
                | Self::AgentSignerTimeout { .. }
                | Self::AgentNoIdentities
                | Self::AgentAuthenticationFailed
                | Self::LocalSignerFailed { .. }
                | Self::SftpError(_)
                | Self::IoError(_)
                | Self::ChannelOpen { .. }
                | Self::CommandExecution { .. }
                | Self::PortForwardRequestFailed(_)
                | Self::RemotePortForwardFailed(_)
                | Self::PortForwardingNotSupported
                | Self::GlobalRequestFailed(_)
        )
    }

    /// Add connection-target context only to transport-level handshake errors.
    /// Typed host-key and other client errors must remain intact for callers.
    pub(super) fn during_protocol_negotiation(host: String, port: u16, source: Self) -> Self {
        match source {
            Self::SshError(source) => Self::ProtocolNegotiation { host, port, source },
            source => source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, TransportIntegrityCause};
    use std::io;

    #[test]
    fn io_backed_errors_name_the_layer_and_preserve_the_os_cause() {
        let refused = Error::TcpConnect {
            host: "127.0.0.1".to_string(),
            port: 22,
            source: io::Error::from_raw_os_error(libc::ECONNREFUSED),
        };
        let unreachable = Error::TcpConnect {
            host: "192.0.2.1".to_string(),
            port: 22,
            source: io::Error::from_raw_os_error(libc::ENETUNREACH),
        };
        let dns = Error::DnsResolution {
            host: "does-not-exist.invalid".to_string(),
            source: io::Error::new(io::ErrorKind::NotFound, "Name or service not known"),
        };

        let refused = refused.to_string();
        let unreachable = unreachable.to_string();
        let dns = dns.to_string();

        assert!(refused.contains("connect to host 127.0.0.1 port 22"));
        assert!(refused.to_ascii_lowercase().contains("refused"));
        assert!(refused.contains("os error"));
        assert!(unreachable.to_ascii_lowercase().contains("unreachable"));
        assert!(unreachable.contains("os error"));
        assert!(dns.contains("Could not resolve hostname does-not-exist.invalid"));
        assert!(dns.contains("Name or service not known"));
    }

    #[test]
    fn connection_timeout_names_target_and_stage() {
        let error = Error::ConnectionTimeout {
            host: "host.example".to_string(),
            port: 2222,
            seconds: 7,
            stage: "protocol negotiation",
        };

        let rendered = error.to_string();
        let mut lines = rendered.lines();
        assert_eq!(
            lines.next(),
            Some("ssh: connect to host host.example port 2222: Connection timed out")
        );
        assert_eq!(
            lines.next(),
            Some("bssh: timed out after 7 seconds during protocol negotiation")
        );
        assert!(error.is_ssh_client_failure());
    }

    #[test]
    fn authentication_errors_name_the_refused_method() {
        assert_eq!(
            Error::KeyAuthFailed.to_string(),
            "Permission denied (publickey)."
        );
        assert_eq!(
            Error::PasswordWrong.to_string(),
            "Permission denied (password)."
        );
        assert_eq!(
            Error::KeyboardInteractiveAuthFailed.to_string(),
            "Permission denied (keyboard-interactive)."
        );
        assert!(
            Error::AgentAuthenticationFailed
                .to_string()
                .starts_with("Permission denied (publickey).")
        );
    }

    #[test]
    fn authentication_exhaustion_lists_attempted_methods_and_remediation() {
        let error = Error::AuthenticationExhausted {
            methods: "publickey".to_string(),
            identity_status: "attempted /tmp/missing-key".to_string(),
            agent_status: "not available".to_string(),
            password_status: "not available in non-interactive mode",
        };

        let rendered = error.to_string();
        assert!(rendered.contains("bssh: SSH identities: attempted /tmp/missing-key"));
        assert!(rendered.starts_with("Permission denied (publickey).\n"));
        assert!(rendered.contains("bssh: SSH agent: not available"));
        assert!(rendered.contains("bssh: Default SSH keys: not found or not authorized"));
        assert!(rendered.contains("bssh: Password authentication: not available"));
        assert!(error.is_ssh_client_failure());
    }

    #[test]
    fn io_backed_error_variants_never_render_as_bare_io_error() {
        let errors = vec![
            Error::AddressInvalid(io::Error::new(io::ErrorKind::InvalidInput, "bad address")),
            Error::DnsResolution {
                host: "host.invalid".to_string(),
                source: io::Error::new(io::ErrorKind::NotFound, "name lookup failed"),
            },
            Error::TcpConnect {
                host: "host".to_string(),
                port: 22,
                source: io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused"),
            },
            Error::ProxyCommandSpawn {
                command: "proxy".to_string(),
                source: io::Error::new(io::ErrorKind::NotFound, "executable not found"),
            },
            Error::SshError(russh::Error::IO(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed",
            ))),
            Error::IoError(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed")),
        ];

        for error in errors {
            let rendered = error.to_string();
            assert_ne!(rendered, "I/O error");
            assert_ne!(rendered, "IO error");
            assert!(rendered.contains(": "), "missing cause in {rendered:?}");
        }
    }

    #[test]
    fn host_key_mismatch_is_distinct_from_other_client_failures() {
        let rendered = Error::HostKeyChanged {
            host: "host.example".to_string(),
            port: 22,
            line: 7,
        }
        .to_string();

        assert!(rendered.contains("host.example"));
        assert!(rendered.contains("has changed"));
        assert!(rendered.contains("known_hosts entry at line 7"));
        assert!(!rendered.contains("Permission denied"));
        assert!(!rendered.contains("Could not resolve hostname"));
    }

    #[test]
    fn retry_exhaustion_preserves_attempt_count_and_typed_source_chain() {
        let error = Error::ConnectionAttemptsExhausted {
            attempts: 3,
            source: Box::new(Error::TcpConnect {
                host: "host.example".to_string(),
                port: 2222,
                source: io::Error::from_raw_os_error(libc::ECONNREFUSED),
            }),
        };

        assert!(error.to_string().contains("after 3 carrier attempts"));
        match error {
            Error::ConnectionAttemptsExhausted { attempts, source } => {
                assert_eq!(attempts, 3);
                assert!(matches!(*source, Error::TcpConnect { port: 2222, .. }));
            }
            other => panic!("unexpected retry error: {other:?}"),
        }
    }

    #[test]
    fn protocol_context_wraps_only_untyped_ssh_errors() {
        let protocol = Error::during_protocol_negotiation(
            "host.example".to_string(),
            2222,
            Error::SshError(russh::Error::IO(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed",
            ))),
        );
        assert!(matches!(
            protocol,
            Error::ProtocolNegotiation { port: 2222, .. }
        ));

        let host_key = Error::during_protocol_negotiation(
            "host.example".to_string(),
            2222,
            Error::HostKeyChanged {
                host: "host.example".to_string(),
                port: 2222,
                line: 7,
            },
        );
        assert!(matches!(host_key, Error::HostKeyChanged { line: 7, .. }));

        let auth = Error::during_protocol_negotiation(
            "host.example".to_string(),
            2222,
            Error::KeyAuthFailed,
        );
        assert!(matches!(auth, Error::KeyAuthFailed));
    }

    #[test]
    fn transport_integrity_display_is_specific_to_each_typed_cause() {
        let packet_auth = Error::TransportIntegrity {
            cause: TransportIntegrityCause::PacketAuthentication,
        }
        .to_string();
        assert_eq!(
            packet_auth,
            "Corrupted MAC: message authentication code incorrect"
        );

        let decryption = Error::TransportIntegrity {
            cause: TransportIntegrityCause::Decryption,
        }
        .to_string();
        assert!(decryption.starts_with("Corrupted MAC: authenticated packet decryption failed"));
        assert!(decryption.contains("message authentication code incorrect"));

        let packet_size = Error::TransportIntegrity {
            cause: TransportIntegrityCause::PacketSize(262_145),
        }
        .to_string();
        assert_eq!(packet_size, "Bad packet size: 262145");
        assert!(!packet_size.contains("message authentication code incorrect"));

        let padding = Error::TransportIntegrity {
            cause: TransportIntegrityCause::InvalidPadding,
        }
        .to_string();
        assert_eq!(padding, "padding error: invalid packet padding");
        assert!(!padding.contains("message authentication code incorrect"));

        assert!(
            !Error::KeyAuthFailed
                .to_string()
                .contains("message authentication code incorrect")
        );
    }
}

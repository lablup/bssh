use super::AddressFamily;
use std::io;

/// This is the `thiserror` error for all crate errors.
///
/// Most ssh related error is wrapped in the `SshError` variant,
/// giving access to the underlying [`russh::Error`] type.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Keyboard-interactive authentication failed")]
    KeyboardInteractiveAuthFailed,
    #[error("No keyboard-interactive response for prompt: {0}")]
    KeyboardInteractiveNoResponseForPrompt(String),
    #[error("Key authentication failed")]
    KeyAuthFailed,
    #[error("Unable to load key, bad format or passphrase: {0}")]
    KeyInvalid(russh::keys::Error),
    #[error("Password authentication failed")]
    PasswordWrong,
    #[error("Invalid address was provided: {0}")]
    AddressInvalid(io::Error),
    /// An address family was forced (`-4`/`-6`, or ssh_config `AddressFamily`)
    /// and name resolution produced no address of that family. This is a hard
    /// failure with no fallback to the other family, matching OpenSSH, and it
    /// replaces the generic "could not resolve to any addresses" so the user
    /// can tell a forced-family mismatch from a genuine resolution failure.
    #[error("no {family} address found for {host}")]
    NoAddressForFamily { host: String, family: AddressFamily },
    #[error("The executed command didn't send an exit code")]
    CommandDidntExit,
    #[error("Server check failed")]
    ServerCheckFailed,
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
    #[error("SSH error occurred: {0}")]
    SshError(#[from] russh::Error),
    #[error("Send error")]
    SendError(#[from] russh::SendError),
    #[error("Agent auth error")]
    AgentAuthError(#[from] russh::AgentAuthError),
    #[error("Failed to connect to SSH agent")]
    AgentConnectionFailed,
    #[error("Failed to request identities from SSH agent")]
    AgentRequestIdentitiesFailed,
    #[error("SSH agent has no identities")]
    AgentNoIdentities,
    #[error("SSH agent authentication failed")]
    AgentAuthenticationFailed,
    #[error("SFTP error occurred: {0}")]
    SftpError(#[from] russh_sftp::client::error::Error),
    #[error("I/O error")]
    IoError(#[from] io::Error),
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

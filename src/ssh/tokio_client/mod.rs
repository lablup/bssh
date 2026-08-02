//! This module is an internalized version of async-ssh2-tokio library.
//! It provides an asynchronous and easy-to-use high level SSH client
//! for rust with the tokio runtime. Powered by the rust ssh implementation
//! russh.
//!
//! The heart of this module is [`Client`]. Use this for connection, authentication and execution.
//!
//! # Features
//! * Connect to a SSH Host via IP
//! * Execute commands on the remote host
//! * Get the stdout and exit code of the command
//! * SFTP file upload/download
//! * SSH agent authentication
//! * Multiple authentication methods

// Module declarations
pub mod address_family;
pub mod authentication;
pub mod channel_manager;
pub mod connection;
#[cfg(test)]
mod connection_tests;
pub mod error;
pub mod file_transfer;
// `pub(crate)` so the client-facing error message builders in `ssh::client` can
// reuse `known_hosts_entry_name` instead of duplicating the `[host]:port` rule.
pub(crate) mod host_verification;
mod to_socket_addrs_with_hostname;

// Re-export public API types for backward compatibility
pub use address_family::AddressFamily;
pub use authentication::{AuthKeyboardInteractive, AuthMethod, ServerCheckMethod};
pub use channel_manager::{CommandExecutedResult, CommandOutput};
pub use connection::{
    Client, ClientHandler, DEFAULT_KEEPALIVE_INTERVAL, DEFAULT_KEEPALIVE_MAX, SshConnectionConfig,
    SshConnectionConfigResolver,
};
pub use error::Error;
pub use to_socket_addrs_with_hostname::ToSocketAddrsWithHostname;

// Re-export russh types commonly used with this module
pub use russh::client::Config;

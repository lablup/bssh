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
pub mod authentication;
pub mod channel_manager;
pub mod connection;
pub mod error;
pub mod file_transfer;
mod to_socket_addrs_with_hostname;

// Re-export public API types for backward compatibility
pub use authentication::{AuthKeyboardInteractive, AuthMethod, ServerCheckMethod};
pub use channel_manager::CommandExecutedResult;
pub use connection::{Client, ClientHandler};
pub use error::Error;
pub use to_socket_addrs_with_hostname::ToSocketAddrsWithHostname;

// Re-export russh types commonly used with this module
pub use russh::client::Config;

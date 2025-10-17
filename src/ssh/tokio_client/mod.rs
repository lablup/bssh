//! This module is an internalized version of async-ssh2-tokio library.
//! It provides an asynchronous and easy-to-use high level SSH client
//! for rust with the tokio runtime. Powered by the rust ssh implementation
//! russh.
//!
//! The heart of this module is [`client::Client`]. Use this for connection, authentication and execution.
//!
//! # Features
//! * Connect to a SSH Host via IP
//! * Execute commands on the remote host
//! * Get the stdout and exit code of the command
//! * SFTP file upload/download
//! * SSH agent authentication
//! * Multiple authentication methods

pub mod client;
pub mod error;
mod to_socket_addrs_with_hostname;

pub use client::{AuthMethod, Client, CommandExecutedResult, ServerCheckMethod};
pub use error::Error;
pub use to_socket_addrs_with_hostname::ToSocketAddrsWithHostname;

pub use russh::client::Config;

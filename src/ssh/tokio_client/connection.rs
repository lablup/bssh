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

use russh::client::{Config, Handle, Handler};
use std::net::SocketAddr;
use std::sync::Arc;
use std::{fmt::Debug, io};

use super::authentication::{AuthMethod, ServerCheckMethod};
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
}

impl Client {
    /// Open a ssh connection to a remote host.
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
    pub async fn connect(
        addr: impl ToSocketAddrsWithHostname,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
    ) -> Result<Self, super::Error> {
        Self::connect_with_config(addr, username, auth, server_check, Config::default()).await
    }

    /// Same as `connect`, but with the option to specify a non default
    /// [`russh::client::Config`].
    pub async fn connect_with_config(
        addr: impl ToSocketAddrsWithHostname,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
        config: Config,
    ) -> Result<Self, super::Error> {
        let config = Arc::new(config);

        // Connection code inspired from std::net::TcpStream::connect and std::net::each_addr
        let socket_addrs = addr
            .to_socket_addrs()
            .map_err(super::Error::AddressInvalid)?;
        let mut connect_res = Err(super::Error::AddressInvalid(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        )));
        for socket_addr in socket_addrs {
            let handler = ClientHandler {
                hostname: addr.hostname(),
                host: socket_addr,
                server_check: server_check.clone(),
            };
            match russh::client::connect(config.clone(), socket_addr, handler).await {
                Ok(h) => {
                    connect_res = Ok((socket_addr, h));
                    break;
                }
                Err(e) => connect_res = Err(e),
            }
        }
        let (address, mut handle) = connect_res?;
        let username = username.to_string();

        super::authentication::authenticate(&mut handle, &username, auth).await?;

        let connection_handle = Arc::new(handle);
        Ok(Self {
            connection_handle: connection_handle.clone(),
            username,
            address,
            session: connection_handle,
        })
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
        Self {
            connection_handle: handle.clone(),
            username,
            address,
            session: handle,
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
        self.connection_handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(super::Error::SshError)
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
}

impl ClientHandler {
    /// Create a new client handler.
    pub fn new(hostname: String, host: SocketAddr, server_check: ServerCheckMethod) -> Self {
        Self {
            hostname,
            host,
            server_check,
        }
    }
}

impl Handler for ClientHandler {
    type Error = super::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.server_check {
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
                let result = russh::keys::check_known_hosts_path(
                    &self.hostname,
                    self.host.port(),
                    server_public_key,
                    known_hosts_path,
                )
                .map_err(|_| super::Error::ServerCheckFailed)?;

                Ok(result)
            }
            ServerCheckMethod::DefaultKnownHostsFile => {
                let result = russh::keys::check_known_hosts(
                    &self.hostname,
                    self.host.port(),
                    server_public_key,
                )
                .map_err(|_| super::Error::ServerCheckFailed)?;

                Ok(result)
            }
        }
    }
}

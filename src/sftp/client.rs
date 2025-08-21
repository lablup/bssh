// Copyright 2025 Lablup Inc.
// Based on async-ssh2-tokio (https://github.com/tyan-boot/async-ssh2-tokio)
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

use russh::client::{Config, Handle, Handler, Msg};
use russh::{Channel, ChannelMsg};
use russh_sftp::{client::SftpSession, protocol::OpenFlags};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::error::{Error, Result};

/// An authentication token.
///
/// Used when creating a [`Client`] for authentication.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    Password(String),
    PrivateKey {
        /// entire contents of private key file
        key_data: String,
        key_pass: Option<String>,
    },
    PrivateKeyFile {
        key_file_path: PathBuf,
        key_pass: Option<String>,
    },
    #[cfg(not(target_os = "windows"))]
    Agent,
}

impl AuthMethod {
    /// Convenience method to create a [`AuthMethod`] from a string literal.
    pub fn with_password(password: &str) -> Self {
        Self::Password(password.to_string())
    }

    pub fn with_key(key: &str, passphrase: Option<&str>) -> Self {
        Self::PrivateKey {
            key_data: key.to_string(),
            key_pass: passphrase.map(str::to_string),
        }
    }

    pub fn with_key_file<T: AsRef<Path>>(key_file_path: T, passphrase: Option<&str>) -> Self {
        Self::PrivateKeyFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            key_pass: passphrase.map(str::to_string),
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn with_agent() -> Self {
        Self::Agent
    }
}

/// Server host key verification method
#[derive(Debug, Clone)]
pub enum ServerCheckMethod {
    NoCheck,
    /// base64 encoded key without the type prefix or hostname suffix
    PublicKey(String),
    PublicKeyFile(String),
    DefaultKnownHostsFile,
    KnownHostsFile(String),
}

impl ServerCheckMethod {
    pub fn with_public_key(key: &str) -> Self {
        Self::PublicKey(key.to_string())
    }

    pub fn with_public_key_file(key_file_name: &str) -> Self {
        Self::PublicKeyFile(key_file_name.to_string())
    }

    pub fn with_known_hosts_file(known_hosts_file: &str) -> Self {
        Self::KnownHostsFile(known_hosts_file.to_string())
    }
}

/// Result of command execution
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// The stdout output of the command.
    pub stdout: String,
    /// The stderr output of the command.
    pub stderr: String,
    /// The unix exit status (`$?` in bash).
    pub exit_status: u32,
}

/// An SSH connection to a remote server.
#[derive(Clone)]
pub struct Client {
    connection_handle: Arc<Handle<ClientHandler>>,
    username: String,
    address: SocketAddr,
}

impl Client {
    /// Open an SSH connection to a remote host.
    pub async fn connect(
        addr: (impl Into<String>, u16),
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
    ) -> Result<Self> {
        Self::connect_with_config(addr, username, auth, server_check, Config::default()).await
    }

    /// Same as `connect`, but with the option to specify a non-default Config.
    pub async fn connect_with_config(
        addr: (impl Into<String>, u16),
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
        config: Config,
    ) -> Result<Self> {
        let hostname = addr.0.into();
        let port = addr.1;
        let socket_addr: SocketAddr = format!("{}:{}", hostname, port)
            .parse()
            .map_err(|e| Error::AddressInvalid(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;

        let config = Arc::new(config);
        let handler = ClientHandler {
            hostname: hostname.clone(),
            host: socket_addr,
            server_check,
        };

        let mut handle = russh::client::connect(config, socket_addr, handler).await?;
        
        Self::authenticate(&mut handle, username, auth).await?;

        Ok(Self {
            connection_handle: Arc::new(handle),
            username: username.to_string(),
            address: socket_addr,
        })
    }

    /// Authenticate with the given method.
    async fn authenticate(
        handle: &mut Handle<ClientHandler>,
        username: &str,
        auth: AuthMethod,
    ) -> Result<()> {
        match auth {
            AuthMethod::Password(password) => {
                let is_authenticated = handle.authenticate_password(username, password).await?;
                if !is_authenticated.success() {
                    return Err(Error::PasswordWrong);
                }
            }
            AuthMethod::PrivateKey { key_data, key_pass } => {
                let cprivk = russh_keys::decode_secret_key(key_data.as_str(), key_pass.as_deref())?;
                let is_authenticated = handle
                    .authenticate_publickey(username, Arc::new(cprivk))
                    .await?;
                if !is_authenticated.success() {
                    return Err(Error::KeyAuthFailed);
                }
            }
            AuthMethod::PrivateKeyFile {
                key_file_path,
                key_pass,
            } => {
                let cprivk = russh_keys::load_secret_key(key_file_path, key_pass.as_deref())?;
                let is_authenticated = handle
                    .authenticate_publickey(username, Arc::new(cprivk))
                    .await?;
                if !is_authenticated.success() {
                    return Err(Error::KeyAuthFailed);
                }
            }
            #[cfg(not(target_os = "windows"))]
            AuthMethod::Agent => {
                let mut agent = russh_keys::agent::client::AgentClient::connect_env()
                    .await
                    .map_err(|_| Error::AuthenticationFailed)?;
                
                let identities = agent.request_identities().await?;
                let mut auth_success = false;
                
                for key in identities {
                    let result = handle
                        .authenticate_publickey(username, Arc::new(key))
                        .await;
                    
                    if let Ok(auth_result) = result {
                        if auth_result.success() {
                            auth_success = true;
                            break;
                        }
                    }
                }
                
                if !auth_success {
                    return Err(Error::AuthenticationFailed);
                }
            }
        };
        Ok(())
    }

    pub async fn get_channel(&self) -> Result<Channel<Msg>> {
        self.connection_handle
            .channel_open_session()
            .await
            .map_err(Error::from)
    }

    /// Execute a remote command via the SSH connection.
    pub async fn execute(&self, command: &str) -> Result<CommandResult> {
        let mut stdout_buffer = vec![];
        let mut stderr_buffer = vec![];
        let mut channel = self.connection_handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut result: Option<u32> = None;

        // While the channel has messages...
        while let Some(msg) = channel.wait().await {
            match msg {
                // If we get data, add it to the buffer
                ChannelMsg::Data { ref data } => {
                    stdout_buffer.write_all(data).await?;
                }
                ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr_buffer.write_all(data).await?;
                    }
                }
                // If we get an exit code report, store it
                ChannelMsg::ExitStatus { exit_status } => result = Some(exit_status),
                _ => {}
            }
        }

        // If we received an exit code, report it back
        if let Some(exit_status) = result {
            Ok(CommandResult {
                stdout: String::from_utf8_lossy(&stdout_buffer).to_string(),
                stderr: String::from_utf8_lossy(&stderr_buffer).to_string(),
                exit_status,
            })
        } else {
            Err(Error::CommandFailed("Command didn't exit".to_string()))
        }
    }

    /// Upload a file with SFTP to the remote server.
    pub async fn upload_file<T: AsRef<Path>, U: Into<String>>(
        &self,
        src_file_path: T,
        dest_file_path: U,
    ) -> Result<()> {
        // Start SFTP session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // Read file contents locally
        let file_contents = tokio::fs::read(src_file_path).await?;

        // Write to remote file
        let mut file = sftp
            .open_with_flags(
                dest_file_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
            )
            .await?;
        file.write_all(&file_contents).await?;
        file.flush().await?;
        file.shutdown().await?;

        Ok(())
    }

    /// Download a file from the remote server using SFTP.
    pub async fn download_file<T: AsRef<Path>, U: Into<String>>(
        &self,
        remote_file_path: U,
        local_file_path: T,
    ) -> Result<()> {
        // Start SFTP session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // Open remote file for reading
        let mut remote_file = sftp
            .open_with_flags(remote_file_path, OpenFlags::READ)
            .await?;

        // Read remote file contents
        let mut contents = Vec::new();
        remote_file.read_to_end(&mut contents).await?;

        // Write contents to local file
        let mut local_file = tokio::fs::File::create(local_file_path.as_ref()).await?;
        local_file.write_all(&contents).await?;
        local_file.flush().await?;

        Ok(())
    }

    /// Upload a directory recursively using SFTP.
    pub async fn upload_dir<T: AsRef<Path>, U: Into<String>>(
        &self,
        local_dir: T,
        remote_dir: U,
    ) -> Result<()> {
        let local_dir = local_dir.as_ref();
        let remote_dir_str = remote_dir.into();

        // Start SFTP session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // Create remote directory
        sftp.create_dir(&remote_dir_str).await.ok(); // Ignore if exists

        // Walk local directory
        self.upload_dir_recursive(&sftp, local_dir, &remote_dir_str).await?;

        Ok(())
    }

    async fn upload_dir_recursive(
        &self,
        sftp: &SftpSession,
        local_dir: &Path,
        remote_dir: &str,
    ) -> Result<()> {
        let mut entries = tokio::fs::read_dir(local_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            let remote_path = format!("{}/{}", remote_dir, file_name_str);

            let metadata = entry.metadata().await?;
            if metadata.is_dir() {
                // Create remote directory and recurse
                sftp.create_dir(&remote_path).await.ok(); // Ignore if exists
                self.upload_dir_recursive(sftp, &path, &remote_path).await?;
            } else if metadata.is_file() {
                // Upload file
                let file_contents = tokio::fs::read(&path).await?;
                let mut file = sftp
                    .open_with_flags(
                        &remote_path,
                        OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                    )
                    .await?;
                file.write_all(&file_contents).await?;
                file.flush().await?;
                file.shutdown().await?;
            }
        }

        Ok(())
    }

    /// Download a directory recursively using SFTP.
    pub async fn download_dir<T: AsRef<Path>, U: Into<String>>(
        &self,
        remote_dir: U,
        local_dir: T,
    ) -> Result<()> {
        let remote_dir_str = remote_dir.into();
        let local_dir = local_dir.as_ref();

        // Create local directory
        tokio::fs::create_dir_all(local_dir).await?;

        // Start SFTP session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // Read remote directory
        self.download_dir_recursive(&sftp, &remote_dir_str, local_dir).await?;

        Ok(())
    }

    async fn download_dir_recursive(
        &self,
        sftp: &SftpSession,
        remote_dir: &str,
        local_dir: &Path,
    ) -> Result<()> {
        let entries = sftp.read_dir(remote_dir).await?;

        for entry in entries {
            let file_name = entry.file_name();
            let remote_path = format!("{}/{}", remote_dir, file_name);
            let local_path = local_dir.join(&file_name);

            let metadata = sftp.metadata(&remote_path).await?;
            if metadata.is_dir() {
                // Create local directory and recurse
                tokio::fs::create_dir_all(&local_path).await?;
                self.download_dir_recursive(sftp, &remote_path, &local_path).await?;
            } else if metadata.is_file() {
                // Download file
                let mut remote_file = sftp
                    .open_with_flags(&remote_path, OpenFlags::READ)
                    .await?;
                let mut contents = Vec::new();
                remote_file.read_to_end(&mut contents).await?;

                let mut local_file = tokio::fs::File::create(&local_path).await?;
                local_file.write_all(&contents).await?;
                local_file.flush().await?;
            }
        }

        Ok(())
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.connection_handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(Error::from)
    }

    pub fn is_closed(&self) -> bool {
        self.connection_handle.is_closed()
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

#[derive(Debug, Clone)]
struct ClientHandler {
    hostname: String,
    host: SocketAddr,
    server_check: ServerCheckMethod,
}

impl Handler for ClientHandler {
    type Error = Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        match &self.server_check {
            ServerCheckMethod::NoCheck => Ok(true),
            ServerCheckMethod::PublicKey(key) => {
                let pk = russh_keys::parse_public_key_base64(key)
                    .map_err(|_| Error::Other("Server check failed".to_string()))?;
                Ok(pk == *server_public_key)
            }
            ServerCheckMethod::PublicKeyFile(key_file_name) => {
                let pk = russh_keys::load_public_key(key_file_name)
                    .map_err(|_| Error::Other("Server check failed".to_string()))?;
                Ok(pk == *server_public_key)
            }
            ServerCheckMethod::KnownHostsFile(known_hosts_path) => {
                let result = russh_keys::check_known_hosts_path(
                    &self.hostname,
                    self.host.port(),
                    server_public_key,
                    known_hosts_path,
                )
                .map_err(|_| Error::Other("Server check failed".to_string()))?;
                Ok(result)
            }
            ServerCheckMethod::DefaultKnownHostsFile => {
                let result = russh_keys::check_known_hosts(
                    &self.hostname,
                    self.host.port(),
                    server_public_key,
                )
                .map_err(|_| Error::Other("Server check failed".to_string()))?;
                Ok(result)
            }
        }
    }
}
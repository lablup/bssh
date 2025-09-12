use russh::client::KeyboardInteractiveAuthResponse;
use russh::{
    client::{Config, Handle, Handler, Msg},
    Channel,
};
use russh_sftp::{client::SftpSession, protocol::OpenFlags};
use std::net::SocketAddr;
use std::sync::Arc;
use std::{fmt::Debug, path::Path};
use std::{io, path::PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use super::ToSocketAddrsWithHostname;
use crate::utils::buffer_pool::global;

// Buffer size constants for SSH operations
/// SSH I/O buffer size constants - optimized for different operation types
///
/// Buffer sizing rationale:
/// - Sizes chosen based on SSH protocol characteristics and network efficiency
/// - Balance between memory usage and I/O performance
/// - Aligned with common SSH implementation patterns
///
/// Buffer size for SSH command I/O operations
/// - 8KB (8192 bytes) optimal for most SSH command operations
/// - Matches typical SSH channel window sizes
/// - Reduces syscall overhead while keeping memory usage reasonable
/// - Handles multi-line command output efficiently
const SSH_CMD_BUFFER_SIZE: usize = 8192;

/// Buffer size for SFTP file transfer operations
/// - 64KB (65536 bytes) for efficient large file transfers
/// - Standard high-performance I/O buffer size
/// - Reduces network round-trips for file operations
/// - Balances memory usage with transfer throughput
#[allow(dead_code)]
const SFTP_BUFFER_SIZE: usize = 65536;

/// Small buffer size for SSH response parsing
/// - 1KB (1024 bytes) for typical command responses and headers
/// - Optimal for status messages and short responses
/// - Minimizes memory allocation for frequent small reads
/// - Matches typical terminal line lengths
const SSH_RESPONSE_BUFFER_SIZE: usize = 1024;

/// An authentification token.
///
/// Used when creating a [`Client`] for authentification.
/// Supports password, private key, public key, SSH agent, and keyboard interactive authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMethod {
    Password(Zeroizing<String>),
    PrivateKey {
        /// entire contents of private key file
        key_data: Zeroizing<String>,
        key_pass: Option<Zeroizing<String>>,
    },
    PrivateKeyFile {
        key_file_path: PathBuf,
        key_pass: Option<Zeroizing<String>>,
    },
    #[cfg(not(target_os = "windows"))]
    PublicKeyFile {
        key_file_path: PathBuf,
    },
    #[cfg(not(target_os = "windows"))]
    Agent,
    KeyboardInteractive(AuthKeyboardInteractive),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PromptResponse {
    exact: bool,
    prompt: String,
    response: Zeroizing<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct AuthKeyboardInteractive {
    /// Hnts to the server the preferred methods to be used for authentication.
    submethods: Option<String>,
    responses: Vec<PromptResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServerCheckMethod {
    NoCheck,
    /// base64 encoded key without the type prefix or hostname suffix (type is already encoded)
    PublicKey(String),
    PublicKeyFile(String),
    DefaultKnownHostsFile,
    KnownHostsFile(String),
}

impl AuthMethod {
    /// Convenience method to create a [`AuthMethod`] from a string literal.
    pub fn with_password(password: &str) -> Self {
        Self::Password(Zeroizing::new(password.to_string()))
    }

    pub fn with_key(key: &str, passphrase: Option<&str>) -> Self {
        Self::PrivateKey {
            key_data: Zeroizing::new(key.to_string()),
            key_pass: passphrase.map(|p| Zeroizing::new(p.to_string())),
        }
    }

    pub fn with_key_file<T: AsRef<Path>>(key_file_path: T, passphrase: Option<&str>) -> Self {
        Self::PrivateKeyFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            key_pass: passphrase.map(|p| Zeroizing::new(p.to_string())),
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn with_public_key_file<T: AsRef<Path>>(key_file_path: T) -> Self {
        Self::PublicKeyFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
        }
    }

    /// Creates a new SSH agent authentication method.
    ///
    /// This will attempt to authenticate using all identities available in the SSH agent.
    /// The SSH agent must be running and the SSH_AUTH_SOCK environment variable must be set.
    ///
    /// # Example
    /// ```no_run
    /// use bssh::ssh::tokio_client::AuthMethod;
    ///
    /// let auth = AuthMethod::with_agent();
    /// ```
    ///
    /// # Platform Support
    /// This method is only available on Unix-like systems (Linux, macOS, etc.).
    /// It is not available on Windows.
    #[cfg(not(target_os = "windows"))]
    pub fn with_agent() -> Self {
        Self::Agent
    }

    pub const fn with_keyboard_interactive(auth: AuthKeyboardInteractive) -> Self {
        Self::KeyboardInteractive(auth)
    }
}

impl AuthKeyboardInteractive {
    pub fn new() -> Self {
        Default::default()
    }

    /// Hnts to the server the preferred methods to be used for authentication.
    pub fn with_submethods(mut self, submethods: impl Into<String>) -> Self {
        self.submethods = Some(submethods.into());
        self
    }

    /// Adds a response to the list of responses for a given prompt.
    ///
    /// The comparison for the prompt is done using a "contains".
    pub fn with_response(mut self, prompt: impl Into<String>, response: impl Into<String>) -> Self {
        self.responses.push(PromptResponse {
            exact: false,
            prompt: prompt.into(),
            response: Zeroizing::new(response.into()),
        });

        self
    }

    /// Adds a response to the list of responses for a given exact prompt.
    pub fn with_response_exact(
        mut self,
        prompt: impl Into<String>,
        response: impl Into<String>,
    ) -> Self {
        self.responses.push(PromptResponse {
            exact: true,
            prompt: prompt.into(),
            response: Zeroizing::new(response.into()),
        });

        self
    }
}

impl PromptResponse {
    fn matches(&self, received_prompt: &str) -> bool {
        if self.exact {
            self.prompt.eq(received_prompt)
        } else {
            received_prompt.contains(&self.prompt)
        }
    }
}

impl From<AuthKeyboardInteractive> for AuthMethod {
    fn from(value: AuthKeyboardInteractive) -> Self {
        Self::with_keyboard_interactive(value)
    }
}

impl ServerCheckMethod {
    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_public_key(key: &str) -> Self {
        Self::PublicKey(key.to_string())
    }

    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_public_key_file(key_file_name: &str) -> Self {
        Self::PublicKeyFile(key_file_name.to_string())
    }

    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_known_hosts_file(known_hosts_file: &str) -> Self {
        Self::KnownHostsFile(known_hosts_file.to_string())
    }
}

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
    connection_handle: Arc<Handle<ClientHandler>>,
    username: String,
    address: SocketAddr,
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

        Self::authenticate(&mut handle, &username, auth).await?;

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

    /// This takes a handle and performs authentification with the given method.
    async fn authenticate(
        handle: &mut Handle<ClientHandler>,
        username: &String,
        auth: AuthMethod,
    ) -> Result<(), super::Error> {
        match auth {
            AuthMethod::Password(password) => {
                let is_authentificated =
                    handle.authenticate_password(username, &**password).await?;
                if !is_authentificated.success() {
                    return Err(super::Error::PasswordWrong);
                }
            }
            AuthMethod::PrivateKey { key_data, key_pass } => {
                let cprivk =
                    russh::keys::decode_secret_key(&key_data, key_pass.as_ref().map(|p| &***p))
                        .map_err(super::Error::KeyInvalid)?;
                let is_authentificated = handle
                    .authenticate_publickey(
                        username,
                        russh::keys::PrivateKeyWithHashAlg::new(
                            Arc::new(cprivk),
                            handle.best_supported_rsa_hash().await?.flatten(),
                        ),
                    )
                    .await?;
                if !is_authentificated.success() {
                    return Err(super::Error::KeyAuthFailed);
                }
            }
            AuthMethod::PrivateKeyFile {
                key_file_path,
                key_pass,
            } => {
                let cprivk =
                    russh::keys::load_secret_key(key_file_path, key_pass.as_ref().map(|p| &***p))
                        .map_err(super::Error::KeyInvalid)?;
                let is_authentificated = handle
                    .authenticate_publickey(
                        username,
                        russh::keys::PrivateKeyWithHashAlg::new(
                            Arc::new(cprivk),
                            handle.best_supported_rsa_hash().await?.flatten(),
                        ),
                    )
                    .await?;
                if !is_authentificated.success() {
                    return Err(super::Error::KeyAuthFailed);
                }
            }
            #[cfg(not(target_os = "windows"))]
            AuthMethod::PublicKeyFile { key_file_path } => {
                let cpubk = russh::keys::load_public_key(key_file_path)
                    .map_err(super::Error::KeyInvalid)?;
                let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                    .await
                    .unwrap();
                let mut auth_identity: Option<russh::keys::PublicKey> = None;
                for identity in agent
                    .request_identities()
                    .await
                    .map_err(super::Error::KeyInvalid)?
                {
                    if identity == cpubk {
                        auth_identity = Some(identity.clone());
                        break;
                    }
                }

                if auth_identity.is_none() {
                    return Err(super::Error::KeyAuthFailed);
                }

                let is_authentificated = handle
                    .authenticate_publickey_with(
                        username,
                        cpubk,
                        handle.best_supported_rsa_hash().await?.flatten(),
                        &mut agent,
                    )
                    .await?;
                if !is_authentificated.success() {
                    return Err(super::Error::KeyAuthFailed);
                }
            }
            #[cfg(not(target_os = "windows"))]
            AuthMethod::Agent => {
                let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                    .await
                    .map_err(|_| super::Error::AgentConnectionFailed)?;

                let identities = agent
                    .request_identities()
                    .await
                    .map_err(|_| super::Error::AgentRequestIdentitiesFailed)?;

                if identities.is_empty() {
                    return Err(super::Error::AgentNoIdentities);
                }

                let mut auth_success = false;
                for identity in identities {
                    let result = handle
                        .authenticate_publickey_with(
                            username,
                            identity.clone(),
                            handle.best_supported_rsa_hash().await?.flatten(),
                            &mut agent,
                        )
                        .await;

                    if let Ok(auth_result) = result {
                        if auth_result.success() {
                            auth_success = true;
                            break;
                        }
                    }
                }

                if !auth_success {
                    return Err(super::Error::AgentAuthenticationFailed);
                }
            }
            AuthMethod::KeyboardInteractive(mut kbd) => {
                let mut res = handle
                    .authenticate_keyboard_interactive_start(username, kbd.submethods)
                    .await?;
                loop {
                    let prompts = match res {
                        KeyboardInteractiveAuthResponse::Success => break,
                        KeyboardInteractiveAuthResponse::Failure { .. } => {
                            return Err(super::Error::KeyboardInteractiveAuthFailed);
                        }
                        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => prompts,
                    };

                    let mut responses = vec![];
                    for prompt in prompts {
                        let Some(pos) = kbd
                            .responses
                            .iter()
                            .position(|pr| pr.matches(&prompt.prompt))
                        else {
                            return Err(super::Error::KeyboardInteractiveNoResponseForPrompt(
                                prompt.prompt,
                            ));
                        };
                        let pr = kbd.responses.remove(pos);
                        responses.push(pr.response.to_string());
                    }

                    res = handle
                        .authenticate_keyboard_interactive_respond(responses)
                        .await?;
                }
            }
        };
        Ok(())
    }

    pub async fn get_channel(&self) -> Result<Channel<Msg>, super::Error> {
        self.connection_handle
            .channel_open_session()
            .await
            .map_err(super::Error::SshError)
    }

    /// Open a TCP/IP forwarding channel.
    ///
    /// This opens a `direct-tcpip` channel to the given target.
    pub async fn open_direct_tcpip_channel<
        T: ToSocketAddrsWithHostname,
        S: Into<Option<SocketAddr>>,
    >(
        &self,
        target: T,
        src: S,
    ) -> Result<Channel<Msg>, super::Error> {
        let targets = target
            .to_socket_addrs()
            .map_err(super::Error::AddressInvalid)?;
        let src = src
            .into()
            .map(|src| (src.ip().to_string(), src.port().into()))
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 22));

        let mut connect_err = super::Error::AddressInvalid(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        ));
        for target in targets {
            match self
                .connection_handle
                .channel_open_direct_tcpip(
                    target.ip().to_string(),
                    target.port().into(),
                    src.0.clone(),
                    src.1,
                )
                .await
            {
                Ok(channel) => return Ok(channel),
                Err(err) => connect_err = super::Error::SshError(err),
            }
        }

        Err(connect_err)
    }

    /// Upload a file with sftp to the remote server.
    ///
    /// `src_file_path` is the path to the file on the local machine.
    /// `dest_file_path` is the path to the file on the remote machine.
    /// Some sshd_config does not enable sftp by default, so make sure it is enabled.
    /// A config line like a `Subsystem sftp internal-sftp` or
    /// `Subsystem sftp /usr/lib/openssh/sftp-server` is needed in the sshd_config in remote machine.
    pub async fn upload_file<T: AsRef<Path>, U: Into<String>>(
        &self,
        src_file_path: T,
        //fa993: This cannot be AsRef<Path> because of underlying lib constraints as described here
        //https://github.com/AspectUnk/russh-sftp/issues/7#issuecomment-1738355245
        dest_file_path: U,
    ) -> Result<(), super::Error> {
        // start sftp session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // read file contents locally
        let file_contents = tokio::fs::read(src_file_path)
            .await
            .map_err(super::Error::IoError)?;

        // interaction with i/o
        let mut file = sftp
            .open_with_flags(
                dest_file_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
            )
            .await?;
        file.write_all(&file_contents)
            .await
            .map_err(super::Error::IoError)?;
        file.flush().await.map_err(super::Error::IoError)?;
        file.shutdown().await.map_err(super::Error::IoError)?;

        Ok(())
    }

    /// Download a file from the remote server using sftp.
    ///
    /// `remote_file_path` is the path to the file on the remote machine.
    /// `local_file_path` is the path to the file on the local machine.
    /// Some sshd_config does not enable sftp by default, so make sure it is enabled.
    /// A config line like a `Subsystem sftp internal-sftp` or
    /// `Subsystem sftp /usr/lib/openssh/sftp-server` is needed in the sshd_config in remote machine.
    pub async fn download_file<T: AsRef<Path>, U: Into<String>>(
        &self,
        remote_file_path: U,
        local_file_path: T,
    ) -> Result<(), super::Error> {
        // start sftp session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // open remote file for reading
        let mut remote_file = sftp
            .open_with_flags(remote_file_path, OpenFlags::READ)
            .await?;

        // Use pooled buffer for reading file contents to reduce allocations
        let mut pooled_buffer = global::get_large_buffer();
        remote_file.read_to_end(pooled_buffer.as_mut_vec()).await?;
        let contents = pooled_buffer.as_vec().clone(); // Clone to owned Vec for writing

        // write contents to local file
        let mut local_file = tokio::fs::File::create(local_file_path.as_ref())
            .await
            .map_err(super::Error::IoError)?;

        local_file
            .write_all(&contents)
            .await
            .map_err(super::Error::IoError)?;
        local_file.flush().await.map_err(super::Error::IoError)?;

        Ok(())
    }

    /// Upload a directory to the remote server using sftp recursively.
    ///
    /// `local_dir_path` is the path to the directory on the local machine.
    /// `remote_dir_path` is the path to the directory on the remote machine.
    /// All files and subdirectories will be uploaded recursively.
    pub async fn upload_dir<T: AsRef<Path>, U: Into<String>>(
        &self,
        local_dir_path: T,
        remote_dir_path: U,
    ) -> Result<(), super::Error> {
        let local_dir = local_dir_path.as_ref();
        let remote_dir = remote_dir_path.into();

        // Verify local directory exists
        if !local_dir.is_dir() {
            return Err(super::Error::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Local directory does not exist: {local_dir:?}"),
            )));
        }

        // Start SFTP session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // Create remote directory if it doesn't exist
        let _ = sftp.create_dir(&remote_dir).await; // Ignore error if already exists

        // Process directory recursively
        self.upload_dir_recursive(&sftp, local_dir, &remote_dir)
            .await?;

        Ok(())
    }

    /// Helper function to recursively upload directory contents
    #[allow(clippy::only_used_in_recursion)]
    fn upload_dir_recursive<'a>(
        &'a self,
        sftp: &'a SftpSession,
        local_dir: &'a Path,
        remote_dir: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), super::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            // Read local directory contents
            let entries = tokio::fs::read_dir(local_dir)
                .await
                .map_err(super::Error::IoError)?;

            let mut entries = entries;
            while let Some(entry) = entries.next_entry().await.map_err(super::Error::IoError)? {
                let path = entry.path();
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();
                let remote_path = format!("{remote_dir}/{file_name_str}");

                let metadata = entry.metadata().await.map_err(super::Error::IoError)?;

                if metadata.is_dir() {
                    // Create remote directory and recurse
                    let _ = sftp.create_dir(&remote_path).await; // Ignore error if already exists
                    self.upload_dir_recursive(sftp, &path, &remote_path).await?;
                } else if metadata.is_file() {
                    // Upload file
                    let file_contents = tokio::fs::read(&path)
                        .await
                        .map_err(super::Error::IoError)?;

                    let mut remote_file = sftp
                        .open_with_flags(
                            &remote_path,
                            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                        )
                        .await?;

                    remote_file
                        .write_all(&file_contents)
                        .await
                        .map_err(super::Error::IoError)?;
                    remote_file.flush().await.map_err(super::Error::IoError)?;
                    remote_file
                        .shutdown()
                        .await
                        .map_err(super::Error::IoError)?;
                }
            }

            Ok(())
        })
    }

    /// Download a directory from the remote server using sftp recursively.
    ///
    /// `remote_dir_path` is the path to the directory on the remote machine.
    /// `local_dir_path` is the path to the directory on the local machine.
    /// All files and subdirectories will be downloaded recursively.
    pub async fn download_dir<T: AsRef<Path>, U: Into<String>>(
        &self,
        remote_dir_path: U,
        local_dir_path: T,
    ) -> Result<(), super::Error> {
        let local_dir = local_dir_path.as_ref();
        let remote_dir = remote_dir_path.into();

        // Start SFTP session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // Create local directory if it doesn't exist
        tokio::fs::create_dir_all(local_dir)
            .await
            .map_err(super::Error::IoError)?;

        // Process directory recursively
        self.download_dir_recursive(&sftp, &remote_dir, local_dir)
            .await?;

        Ok(())
    }

    /// Helper function to recursively download directory contents
    #[allow(clippy::only_used_in_recursion)]
    fn download_dir_recursive<'a>(
        &'a self,
        sftp: &'a SftpSession,
        remote_dir: &'a str,
        local_dir: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), super::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            // Read remote directory contents
            let entries = sftp.read_dir(remote_dir).await?;

            for entry in entries {
                let name = entry.file_name();
                let metadata = entry.metadata();

                // Skip . and .. (already handled by iterator)
                if name == "." || name == ".." {
                    continue;
                }

                let remote_path = format!("{remote_dir}/{name}");
                let local_path = local_dir.join(&name);

                if metadata.file_type().is_dir() {
                    // Create local directory and recurse
                    tokio::fs::create_dir_all(&local_path)
                        .await
                        .map_err(super::Error::IoError)?;

                    self.download_dir_recursive(sftp, &remote_path, &local_path)
                        .await?;
                } else if metadata.file_type().is_file() {
                    // Download file using pooled buffer
                    let mut remote_file =
                        sftp.open_with_flags(&remote_path, OpenFlags::READ).await?;

                    let mut pooled_buffer = global::get_large_buffer();
                    remote_file.read_to_end(pooled_buffer.as_mut_vec()).await?;
                    let contents = pooled_buffer.as_vec().clone();

                    tokio::fs::write(&local_path, contents)
                        .await
                        .map_err(super::Error::IoError)?;
                }
            }

            Ok(())
        })
    }

    /// Execute a remote command via the ssh connection.
    ///
    /// Returns stdout, stderr and the exit code of the command,
    /// packaged in a [`CommandExecutedResult`] struct.
    /// If you need the stderr output interleaved within stdout, you should postfix the command with a redirection,
    /// e.g. `echo foo 2>&1`.
    /// If you dont want any output at all, use something like `echo foo >/dev/null 2>&1`.
    ///
    /// Make sure your commands don't read from stdin and exit after bounded time.
    ///
    /// Can be called multiple times, but every invocation is a new shell context.
    /// Thus `cd`, setting variables and alike have no effect on future invocations.
    pub async fn execute(&self, command: &str) -> Result<CommandExecutedResult, super::Error> {
        // Sanitize command to prevent injection attacks
        let sanitized_command = crate::utils::sanitize_command(command)
            .map_err(|e| super::Error::CommandValidationFailed(e.to_string()))?;

        // Pre-allocate buffers with capacity to avoid frequent reallocations
        let mut stdout_buffer = Vec::with_capacity(SSH_CMD_BUFFER_SIZE);
        let mut stderr_buffer = Vec::with_capacity(SSH_RESPONSE_BUFFER_SIZE);
        let mut channel = self.connection_handle.channel_open_session().await?;
        channel.exec(true, sanitized_command.as_str()).await?;

        let mut result: Option<u32> = None;

        // While the channel has messages...
        while let Some(msg) = channel.wait().await {
            //dbg!(&msg);
            match msg {
                // If we get data, add it to the buffer
                russh::ChannelMsg::Data { ref data } => {
                    stdout_buffer.write_all(data).await.unwrap()
                }
                russh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr_buffer.write_all(data).await.unwrap()
                    }
                }

                // If we get an exit code report, store it, but crucially don't
                // assume this message means end of communications. The data might
                // not be finished yet!
                russh::ChannelMsg::ExitStatus { exit_status } => result = Some(exit_status),

                // We SHOULD get this EOF messagge, but 4254 sec 5.3 also permits
                // the channel to close without it being sent. And sometimes this
                // message can even precede the Data message, so don't handle it
                // russh::ChannelMsg::Eof => break,
                _ => {}
            }
        }

        // If we received an exit code, report it back
        if let Some(result) = result {
            Ok(CommandExecutedResult {
                stdout: String::from_utf8_lossy(&stdout_buffer).to_string(),
                stderr: String::from_utf8_lossy(&stderr_buffer).to_string(),
                exit_status: result,
            })

        // Otherwise, report an error
        } else {
            Err(super::Error::CommandDidntExit)
        }
    }

    /// Request an interactive shell with PTY support.
    ///
    /// This method opens a new SSH channel with PTY (pseudo-terminal) support,
    /// suitable for interactive shell sessions.
    ///
    /// # Arguments
    /// * `term_type` - Terminal type (e.g., "xterm", "xterm-256color", "vt100")
    /// * `width` - Terminal width in columns
    /// * `height` - Terminal height in rows
    ///
    /// # Returns
    /// A `Channel` that can be used for bidirectional communication with the remote shell.
    pub async fn request_interactive_shell(
        &self,
        term_type: &str,
        width: u32,
        height: u32,
    ) -> Result<Channel<Msg>, super::Error> {
        let channel = self.connection_handle.channel_open_session().await?;

        // Request PTY with the specified terminal type and dimensions
        channel
            .request_pty(
                false,
                term_type,
                width,
                height,
                0,   // pixel width (0 means undefined)
                0,   // pixel height (0 means undefined)
                &[], // terminal modes (empty means use defaults)
            )
            .await?;

        // Request shell
        channel.request_shell(false).await?;

        Ok(channel)
    }

    /// Request window size change for an existing PTY channel.
    ///
    /// This should be called when the local terminal is resized to update
    /// the remote PTY dimensions.
    pub async fn resize_pty(
        &self,
        channel: &mut Channel<Msg>,
        width: u32,
        height: u32,
    ) -> Result<(), super::Error> {
        channel
            .window_change(width, height, 0, 0)
            .await
            .map_err(super::Error::SshError)
    }

    /// A debugging function to get the username this client is connected as.
    pub fn get_connection_username(&self) -> &String {
        &self.username
    }

    /// A debugging function to get the address this client is connected to.
    pub fn get_connection_address(&self) -> &SocketAddr {
        &self.address
    }

    pub async fn disconnect(&self) -> Result<(), super::Error> {
        self.connection_handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(super::Error::SshError)
    }

    pub fn is_closed(&self) -> bool {
        self.connection_handle.is_closed()
    }

    /// Request remote port forwarding (tcpip-forward) - Phase 2 Implementation Placeholder
    ///
    /// **Phase 2 TODO**: This method needs to be implemented once russh provides
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
        // **Phase 2 TODO**: Implement actual tcpip-forward global request
        // For now, return an error indicating this is not yet implemented
        tracing::warn!("Remote port forwarding request not yet implemented - Phase 2 TODO");
        Err(super::Error::PortForwardingNotSupported)
    }

    /// Cancel remote port forwarding (cancel-tcpip-forward) - Phase 2 Implementation Placeholder
    ///
    /// **Phase 2 TODO**: This method needs to be implemented once russh provides
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
        // **Phase 2 TODO**: Implement actual cancel-tcpip-forward global request
        // For now, return an error indicating this is not yet implemented
        tracing::warn!("Cancel remote port forwarding not yet implemented - Phase 2 TODO");
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandExecutedResult {
    /// The stdout output of the command.
    pub stdout: String,
    /// The stderr output of the command.
    pub stderr: String,
    /// The unix exit status (`$?` in bash).
    pub exit_status: u32,
}

#[derive(Debug, Clone)]
pub struct ClientHandler {
    hostname: String,
    host: SocketAddr,
    server_check: ServerCheckMethod,
}

impl ClientHandler {
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

// Tests removed as they depend on external test infrastructure
// Original tests are available in references/async-ssh2-tokio/src/client.rs

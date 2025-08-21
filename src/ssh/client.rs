use anyhow::{Context, Result};
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::Arc;
use thrussh::client;

use super::handler::BsshHandler;

pub struct SshClient {
    host: String,
    port: u16,
    username: String,
    handler: BsshHandler,
}

impl SshClient {
    pub fn new(host: String, port: u16, username: String) -> Self {
        let handler = BsshHandler::new(format!("{}:{}", host, port));
        Self {
            host,
            port,
            username,
            handler,
        }
    }

    pub async fn connect_and_execute(
        &mut self,
        command: &str,
        key_path: Option<&Path>,
    ) -> Result<CommandResult> {
        let addr = format!("{}:{}", self.host, self.port);
        tracing::debug!("Connecting to {}", addr);

        // Parse socket address
        let socket_addr = addr
            .to_socket_addrs()
            .context("Failed to resolve host")?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Could not resolve {}", addr))?;

        // Create SSH config
        let config = client::Config::default();
        
        // Connect to the SSH server
        let mut session = client::connect(Arc::new(config), socket_addr, self.handler.clone())
            .await
            .context("Failed to connect to SSH server")?;

        // Authenticate
        let auth_res = if let Some(key_path) = key_path {
            self.authenticate_with_key(&mut session, key_path).await
        } else {
            // Try SSH agent first
            match thrussh_keys::agent::client::AgentClient::connect_env().await {
                Ok(agent) => {
                    self.authenticate_with_agent(&mut session, agent).await
                }
                Err(_) => {
                    // Fall back to trying default key locations
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                    let default_key = Path::new(&home).join(".ssh").join("id_rsa");
                    if default_key.exists() {
                        self.authenticate_with_key(&mut session, &default_key).await
                    } else {
                        anyhow::bail!("No SSH key specified and no default key found")
                    }
                }
            }
        };
        
        auth_res?;

        // Open a channel and execute command
        let mut channel = session
            .channel_open_session()
            .await
            .context("Failed to open SSH channel")?;

        channel
            .exec(true, command)
            .await
            .context("Failed to execute command")?;

        // Wait for command to complete
        let mut output = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        
        while let Some(msg) = channel.wait().await {
            match msg {
                thrussh::ChannelMsg::Data { ref data } => {
                    output.extend_from_slice(data);
                }
                thrussh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr.extend_from_slice(data);
                    }
                }
                thrussh::ChannelMsg::ExitStatus { exit_status: status } => {
                    exit_status = Some(status);
                }
                thrussh::ChannelMsg::Eof => break,
                _ => {}
            }
        }

        // Close the session
        session
            .disconnect(thrussh::Disconnect::ByApplication, "", "")
            .await
            .ok();

        // Use the collected output
        let exit_status = exit_status.unwrap_or(255);

        Ok(CommandResult {
            host: self.host.clone(),
            output,
            stderr,
            exit_status,
        })
    }

    async fn authenticate_with_key(
        &self,
        session: &mut client::Handle<BsshHandler>,
        key_path: &Path,
    ) -> Result<()> {
        tracing::debug!("Authenticating with key: {:?}", key_path);
        
        let key = thrussh_keys::load_secret_key(key_path, None)
            .context("Failed to load SSH key")?;

        let auth_result = session
            .authenticate_publickey(&self.username, Arc::new(key))
            .await
            .context("Failed to authenticate with public key")?;

        if !auth_result {
            anyhow::bail!("Authentication failed for user {}", self.username);
        }

        Ok(())
    }

    async fn authenticate_with_agent<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        _session: &mut client::Handle<BsshHandler>,
        mut agent: thrussh_keys::agent::client::AgentClient<S>,
    ) -> Result<()> {
        tracing::debug!("Authenticating with SSH agent");
        
        let identities = agent.request_identities().await
            .context("Failed to get identities from SSH agent")?;
        
        for _pubkey in identities {
            // With SSH agent, we need to use the agent for signing
            // This is a simplified version - proper implementation would use agent signing
            tracing::debug!("Trying SSH agent key");
            
            // For now, skip agent auth - it requires more complex signing flow
            // In production, you'd implement proper agent signing
            tracing::warn!("SSH agent authentication not fully implemented");
            let auth_result = false;
            
            if auth_result {
                return Ok(());
            }
            break; // Try only once with agent auth
        }
        
        anyhow::bail!("SSH agent authentication failed for user {}", self.username);
    }
}

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub host: String,
    pub output: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: u32,
}

impl CommandResult {
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.output).to_string()
    }

    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }

    pub fn is_success(&self) -> bool {
        self.exit_status == 0
    }
}
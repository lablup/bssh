use anyhow::{Context, Result};
use async_ssh2_tokio::{AuthMethod, Client, ServerCheckMethod};
use std::path::Path;

pub struct SshClient {
    host: String,
    port: u16,
    username: String,
}

impl SshClient {
    pub fn new(host: String, port: u16, username: String) -> Self {
        Self {
            host,
            port,
            username,
        }
    }

    pub async fn connect_and_execute(
        &mut self,
        command: &str,
        key_path: Option<&Path>,
    ) -> Result<CommandResult> {
        let addr = (self.host.as_str(), self.port);
        tracing::debug!("Connecting to {}:{}", self.host, self.port);

        // Determine authentication method
        let auth_method = if let Some(key_path) = key_path {
            tracing::debug!("Authenticating with key: {:?}", key_path);
            AuthMethod::with_key_file(key_path, None)
        } else {
            // Try default key location
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let default_key = Path::new(&home).join(".ssh").join("id_rsa");

            if default_key.exists() {
                tracing::debug!("Using default key: {:?}", default_key);
                AuthMethod::with_key_file(default_key, None)
            } else {
                anyhow::bail!("No SSH key specified and no default key found");
            }
        };

        // Connect and authenticate
        let client = Client::connect(
            addr,
            &self.username,
            auth_method,
            ServerCheckMethod::NoCheck, // TODO: Implement proper host key verification
        )
        .await
        .context("Failed to connect to SSH server")?;

        tracing::debug!("Connected and authenticated successfully");
        tracing::debug!("Executing command: {}", command);

        // Execute command
        let result = client
            .execute(command)
            .await
            .context("Failed to execute command")?;

        tracing::debug!(
            "Command execution completed with status: {}",
            result.exit_status
        );

        // Convert result to our format
        Ok(CommandResult {
            host: self.host.clone(),
            output: result.stdout.into_bytes(),
            stderr: result.stderr.into_bytes(),
            exit_status: result.exit_status,
        })
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

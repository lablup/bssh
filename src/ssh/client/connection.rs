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

use super::core::SshClient;
use crate::jump::{parse_jump_hosts, JumpHostChain};
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::{AuthMethod, Client};
use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;

// SSH connection timeout design:
// - 30 seconds accommodates slow networks and SSH negotiation
// - Industry standard for SSH client connections
// - Balances user patience with reliability on poor networks
const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;

impl SshClient {
    /// Determine the authentication method based on provided parameters
    pub(super) async fn determine_auth_method(
        &self,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
        #[cfg(target_os = "macos")] use_keychain: bool,
    ) -> Result<AuthMethod> {
        // Use centralized authentication logic from auth module
        let mut auth_ctx =
            crate::ssh::auth::AuthContext::new(self.username.clone(), self.host.clone())
                .with_context(|| {
                    format!("Invalid credentials for {}@{}", self.username, self.host)
                })?;

        // Set key path if provided
        if let Some(path) = key_path {
            auth_ctx = auth_ctx
                .with_key_path(Some(path.to_path_buf()))
                .with_context(|| format!("Invalid SSH key path: {path:?}"))?;
        }

        auth_ctx = auth_ctx.with_agent(use_agent).with_password(use_password);

        #[cfg(target_os = "macos")]
        {
            auth_ctx = auth_ctx.with_keychain(use_keychain);
        }

        auth_ctx.determine_method().await
    }

    /// Create a direct SSH connection (no jump hosts)
    pub(super) async fn connect_direct(
        &self,
        auth_method: &AuthMethod,
        strict_mode: StrictHostKeyChecking,
    ) -> Result<Client> {
        let addr = (self.host.as_str(), self.port);
        let check_method = crate::ssh::known_hosts::get_check_method(strict_mode);

        let connect_timeout = Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS);

        match tokio::time::timeout(
            connect_timeout,
            Client::connect(addr, &self.username, auth_method.clone(), check_method),
        )
        .await
        {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(e)) => {
                // Specific error from the SSH connection attempt
                let error_msg = match &e {
                    crate::ssh::tokio_client::Error::KeyAuthFailed => {
                        "Authentication failed. The private key was rejected by the server.".to_string()
                    }
                    crate::ssh::tokio_client::Error::PasswordWrong => {
                        "Password authentication failed.".to_string()
                    }
                    crate::ssh::tokio_client::Error::ServerCheckFailed => {
                        "Host key verification failed. The server's host key was not recognized or has changed.".to_string()
                    }
                    crate::ssh::tokio_client::Error::KeyInvalid(key_err) => {
                        format!("Failed to load SSH key: {key_err}. Please check the key file format and passphrase.")
                    }
                    crate::ssh::tokio_client::Error::AgentConnectionFailed => {
                        "Failed to connect to SSH agent. Please ensure SSH_AUTH_SOCK is set and the agent is running.".to_string()
                    }
                    crate::ssh::tokio_client::Error::AgentNoIdentities => {
                        "SSH agent has no identities. Please add your key to the agent using 'ssh-add'.".to_string()
                    }
                    crate::ssh::tokio_client::Error::AgentAuthenticationFailed => {
                        "SSH agent authentication failed.".to_string()
                    }
                    crate::ssh::tokio_client::Error::SshError(ssh_err) => {
                        format!("SSH connection error: {ssh_err}")
                    }
                    _ => {
                        format!("Failed to connect: {e}")
                    }
                };
                Err(anyhow::anyhow!(error_msg).context(e))
            }
            Err(_) => Err(anyhow::anyhow!(
                "Connection timeout after {SSH_CONNECT_TIMEOUT_SECS} seconds. \
                     Please check if the host is reachable and SSH service is running."
            )),
        }
    }

    /// Create an SSH connection through jump hosts
    pub(super) async fn connect_via_jump_hosts(
        &self,
        jump_hosts: &[crate::jump::parser::JumpHost],
        auth_method: &AuthMethod,
        strict_mode: StrictHostKeyChecking,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<Client> {
        // Create jump host chain
        let chain = JumpHostChain::new(jump_hosts.to_vec())
            .with_connect_timeout(Duration::from_secs(30))
            .with_command_timeout(Duration::from_secs(300));

        // Connect through the chain
        let connection = chain
            .connect(
                &self.host,
                self.port,
                &self.username,
                auth_method.clone(),
                key_path,
                Some(strict_mode),
                use_agent,
                use_password,
            )
            .await
            .with_context(|| {
                format!(
                    "Failed to establish jump host connection to {}:{}",
                    self.host, self.port
                )
            })?;

        tracing::info!(
            "Jump host connection established: {}",
            connection.jump_info.path_description()
        );

        Ok(connection.client)
    }

    /// Establish a connection based on configuration (direct or via jump hosts)
    pub(super) async fn establish_connection(
        &self,
        auth_method: &AuthMethod,
        strict_mode: StrictHostKeyChecking,
        jump_hosts_spec: Option<&str>,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
    ) -> Result<Client> {
        if let Some(jump_spec) = jump_hosts_spec {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection");
                self.connect_direct(auth_method, strict_mode).await
            } else {
                tracing::info!(
                    "Connecting to {}:{} via {} jump host(s): {}",
                    self.host,
                    self.port,
                    jump_hosts.len(),
                    jump_hosts
                        .iter()
                        .map(|j| j.to_string())
                        .collect::<Vec<_>>()
                        .join(" -> ")
                );

                self.connect_via_jump_hosts(
                    &jump_hosts,
                    auth_method,
                    strict_mode,
                    key_path,
                    use_agent,
                    use_password,
                )
                .await
            }
        } else {
            // Direct connection
            tracing::debug!("Using direct connection (no jump hosts)");
            self.connect_direct(auth_method, strict_mode).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_determine_auth_method_with_key() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key");
        std::fs::write(&key_path, "fake key content").unwrap();

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client
            .determine_auth_method(
                Some(&key_path),
                false,
                false,
                #[cfg(target_os = "macos")]
                false,
            )
            .await
            .unwrap();

        match auth {
            AuthMethod::PrivateKeyFile { key_file_path, .. } => {
                // Path should be canonicalized now
                assert!(key_file_path.is_absolute());
            }
            _ => panic!("Expected PrivateKeyFile auth method"),
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_determine_auth_method_with_agent() {
        // Create a temporary socket file to simulate agent
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh-agent.sock");
        // Create an empty file to simulate socket existence
        std::fs::write(&socket_path, "").unwrap();

        std::env::set_var("SSH_AUTH_SOCK", socket_path.to_str().unwrap());

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client
            .determine_auth_method(
                None,
                true,
                false,
                #[cfg(target_os = "macos")]
                false,
            )
            .await
            .unwrap();

        match auth {
            AuthMethod::Agent => {}
            _ => panic!("Expected Agent auth method"),
        }

        std::env::remove_var("SSH_AUTH_SOCK");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_determine_auth_method_with_agent() {
        use std::os::unix::net::UnixListener;

        // Create a temporary directory for the socket
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh-agent.sock");

        // Create a real Unix domain socket (required on Linux)
        let _listener = UnixListener::bind(&socket_path).unwrap();

        std::env::set_var("SSH_AUTH_SOCK", socket_path.to_str().unwrap());

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client
            .determine_auth_method(None, true, false)
            .await
            .unwrap();

        match auth {
            AuthMethod::Agent => {}
            _ => panic!("Expected Agent auth method"),
        }

        std::env::remove_var("SSH_AUTH_SOCK");
    }

    #[test]
    fn test_determine_auth_method_with_password() {
        let _client = SshClient::new("test.com".to_string(), 22, "user".to_string());

        // Note: We can't actually test password prompt in unit tests
        // as it requires terminal input. This would need integration testing.
        // For now, we just verify the function compiles with the new parameter.
    }

    #[tokio::test]
    async fn test_determine_auth_method_fallback_to_default() {
        // Save original environment variables
        let original_home = std::env::var("HOME").ok();
        let original_ssh_auth_sock = std::env::var("SSH_AUTH_SOCK").ok();

        // Create a fake home directory with default key
        let temp_dir = TempDir::new().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let default_key = ssh_dir.join("id_rsa");
        std::fs::write(&default_key, "fake key").unwrap();

        // Set test environment
        std::env::set_var("HOME", temp_dir.path().to_str().unwrap());
        std::env::remove_var("SSH_AUTH_SOCK");

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client
            .determine_auth_method(
                None,
                false,
                false,
                #[cfg(target_os = "macos")]
                false,
            )
            .await
            .unwrap();

        // Restore original environment variables
        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        } else {
            std::env::remove_var("HOME");
        }
        if let Some(sock) = original_ssh_auth_sock {
            std::env::set_var("SSH_AUTH_SOCK", sock);
        }

        match auth {
            AuthMethod::PrivateKeyFile { key_file_path, .. } => {
                // Path should be canonicalized now
                assert!(key_file_path.is_absolute());
            }
            _ => panic!("Expected PrivateKeyFile auth method"),
        }
    }
}

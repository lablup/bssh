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

use russh_keys::{key, load_secret_key};
use std::path::Path;
use std::sync::Arc;

use super::error::{SftpError, SftpResult};

/// Authentication method for SSH connections
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// Authenticate using SSH agent
    Agent,
    /// Authenticate using a private key file
    PrivateKey {
        key: Arc<key::KeyPair>,
    },
    /// Authenticate using password (not implemented for security)
    #[allow(dead_code)]
    Password {
        password: String,
    },
}

impl AuthMethod {
    /// Create authentication method from a private key file
    pub async fn from_key_file<P: AsRef<Path>>(
        key_path: P,
        passphrase: Option<&str>,
    ) -> SftpResult<Self> {
        let key_path = key_path.as_ref();
        
        tracing::debug!("Loading private key from: {:?}", key_path);

        let key_data = tokio::fs::read(key_path)
            .await
            .map_err(|e| SftpError::generic(format!("Failed to read key file {:?}: {}", key_path, e)))?;

        let key = load_secret_key(&key_data, passphrase)
            .map_err(|e| SftpError::key(e))?;

        Ok(Self::PrivateKey {
            key: Arc::new(key),
        })
    }

    /// Create authentication method using SSH agent
    pub fn agent() -> Self {
        Self::Agent
    }

    /// Check if SSH agent is available
    pub async fn is_agent_available() -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            std::env::var("SSH_AUTH_SOCK").is_ok()
        }
        #[cfg(target_os = "windows")]
        {
            false // SSH agent not supported on Windows
        }
    }

    /// Auto-detect the best authentication method
    pub async fn auto_detect(
        key_path: Option<&Path>,
        use_agent: bool,
    ) -> SftpResult<Self> {
        // If SSH agent is explicitly requested, try that first
        if use_agent {
            #[cfg(not(target_os = "windows"))]
            {
                if Self::is_agent_available().await {
                    tracing::debug!("Using SSH agent for authentication");
                    return Ok(Self::Agent);
                } else {
                    tracing::warn!("SSH agent requested but SSH_AUTH_SOCK environment variable not set");
                }
            }
            #[cfg(target_os = "windows")]
            {
                return Err(SftpError::authentication(
                    "SSH agent authentication is not supported on Windows"
                ));
            }
        }

        // Try key file authentication
        if let Some(key_path) = key_path {
            return Self::from_key_file(key_path, None).await;
        }

        // If no explicit key path, try SSH agent if available (auto-detect)
        #[cfg(not(target_os = "windows"))]
        if !use_agent && Self::is_agent_available().await {
            tracing::debug!("SSH agent detected, attempting agent authentication");
            return Ok(Self::Agent);
        }

        // Fallback to default key locations
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let default_keys = [
            "id_rsa",
            "id_ed25519", 
            "id_ecdsa",
            "id_dsa",
        ];

        for key_name in &default_keys {
            let key_path = Path::new(&home).join(".ssh").join(key_name);
            if key_path.exists() {
                tracing::debug!("Using default key: {:?}", key_path);
                return Self::from_key_file(&key_path, None).await;
            }
        }

        Err(SftpError::authentication(
            "SSH authentication failed: No authentication method available.\n\
             Tried:\n\
             - SSH agent (SSH_AUTH_SOCK not set or agent not available)\n\
             - Default key files (~/.ssh/id_rsa, ~/.ssh/id_ed25519, etc. not found)\n\
             \n\
             Solutions:\n\
             - Start SSH agent and add keys with 'ssh-add'\n\
             - Specify a key file with -i/--identity\n\
             - Create a default key at ~/.ssh/id_rsa or ~/.ssh/id_ed25519"
        ))
    }
}

/// Authenticate with SSH server using the specified method
pub async fn authenticate_with_server(
    session: &mut russh::client::Handle<super::session::BsshClientHandler>,
    username: &str,
    auth_method: &AuthMethod,
) -> SftpResult<bool> {
    match auth_method {
        AuthMethod::Agent => {
            tracing::debug!("Authenticating with SSH agent");
            authenticate_with_agent(session, username).await
        }
        AuthMethod::PrivateKey { key } => {
            tracing::debug!("Authenticating with private key");
            authenticate_with_key(session, username, key.clone()).await
        }
        AuthMethod::Password { .. } => {
            Err(SftpError::authentication(
                "Password authentication is not implemented for security reasons"
            ))
        }
    }
}

async fn authenticate_with_agent(
    _session: &mut russh::client::Handle<super::session::BsshClientHandler>,
    _username: &str,
) -> SftpResult<bool> {
    // SSH agent authentication is not supported in russh-keys 0.45
    // This would require a more recent version of russh-keys
    Err(SftpError::authentication(
        "SSH agent authentication is not supported in this version of russh-keys. Please use private key authentication instead."
    ))
}

async fn authenticate_with_key(
    session: &mut russh::client::Handle<super::session::BsshClientHandler>,
    username: &str,
    key: Arc<key::KeyPair>,
) -> SftpResult<bool> {
    tracing::debug!("Trying private key authentication");

    let auth_result = session
        .authenticate_publickey(username, key)
        .await
        .map_err(|e| SftpError::authentication(format!("Private key authentication failed: {}", e)))?;

    if auth_result {
        tracing::debug!("Private key authentication successful");
        Ok(true)
    } else {
        Err(SftpError::authentication("Private key was rejected by the server"))
    }
}
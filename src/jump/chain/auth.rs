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

use crate::jump::parser::JumpHost;
use crate::ssh::tokio_client::{AuthMethod, ClientHandler};
use anyhow::{Context, Result};
use std::path::Path;
use tokio::sync::Mutex;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Check if the SSH agent has any loaded identities.
///
/// This function queries the SSH agent to determine if it has any keys loaded.
/// Returns `true` if the agent has at least one identity, `false` otherwise.
/// If communication with the agent fails, returns `false` to allow fallback to key files.
#[cfg(not(target_os = "windows"))]
async fn agent_has_identities() -> bool {
    use russh::keys::agent::client::AgentClient;

    match AgentClient::connect_env().await {
        Ok(mut agent) => match agent.request_identities().await {
            Ok(identities) => {
                let has_keys = !identities.is_empty();
                if has_keys {
                    debug!("SSH agent has {} loaded identities", identities.len());
                } else {
                    debug!("SSH agent is running but has no loaded identities");
                }
                has_keys
            }
            Err(e) => {
                warn!("Failed to request identities from SSH agent: {e}");
                false
            }
        },
        Err(e) => {
            warn!("Failed to connect to SSH agent: {e}");
            false
        }
    }
}

/// Determine authentication method for a jump host
///
/// For now, uses the same authentication method as the destination.
/// In the future, this could be enhanced to support per-host authentication.
pub(super) async fn determine_auth_method(
    jump_host: &JumpHost,
    key_path: Option<&Path>,
    use_agent: bool,
    use_password: bool,
    auth_mutex: &Mutex<()>,
) -> Result<AuthMethod> {
    // For now, use the same auth method determination logic as the main SSH client
    // This could be enhanced to support per-jump-host authentication in the future

    if use_password {
        // SECURITY: Acquire mutex to serialize password prompts
        // This prevents multiple simultaneous prompts that could confuse users
        let _guard = auth_mutex.lock().await;

        // Display which jump host we're authenticating to
        let prompt = format!(
            "Enter password for jump host {} ({}@{}): ",
            jump_host.to_connection_string(),
            jump_host.effective_user(),
            jump_host.host
        );

        let password = Zeroizing::new(
            rpassword::prompt_password(prompt).with_context(|| "Failed to read password")?,
        );
        return Ok(AuthMethod::with_password(&password));
    }

    if use_agent {
        #[cfg(not(target_os = "windows"))]
        {
            if std::env::var("SSH_AUTH_SOCK").is_ok() && agent_has_identities().await {
                return Ok(AuthMethod::Agent);
            }
            // If agent is running but has no identities, fall through to try key files
        }
    }

    if let Some(key_path) = key_path {
        // SECURITY: Use Zeroizing to ensure key contents are cleared from memory
        let key_contents = Zeroizing::new(
            std::fs::read_to_string(key_path)
                .with_context(|| format!("Failed to read SSH key file: {key_path:?}"))?,
        );

        let passphrase = if key_contents.contains("ENCRYPTED")
            || key_contents.contains("Proc-Type: 4,ENCRYPTED")
        {
            // SECURITY: Acquire mutex to serialize passphrase prompts
            let _guard = auth_mutex.lock().await;

            let prompt = format!(
                "Enter passphrase for key {key_path:?} (jump host {}): ",
                jump_host.to_connection_string()
            );

            let pass = Zeroizing::new(
                rpassword::prompt_password(prompt).with_context(|| "Failed to read passphrase")?,
            );
            Some(pass)
        } else {
            None
        };

        return Ok(AuthMethod::with_key_file(
            key_path,
            passphrase.as_ref().map(|p| p.as_str()),
        ));
    }

    // Fallback to SSH agent if available and has identities
    #[cfg(not(target_os = "windows"))]
    if std::env::var("SSH_AUTH_SOCK").is_ok() && agent_has_identities().await {
        return Ok(AuthMethod::Agent);
    }
    // If agent is running but has no identities, fall through to try default key files

    // Try default key files
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let home_path = Path::new(&home).join(".ssh");
    let default_keys = [
        home_path.join("id_ed25519"),
        home_path.join("id_rsa"),
        home_path.join("id_ecdsa"),
        home_path.join("id_dsa"),
    ];

    for default_key in &default_keys {
        if default_key.exists() {
            // SECURITY: Use Zeroizing to ensure key contents are cleared from memory
            let key_contents = Zeroizing::new(
                std::fs::read_to_string(default_key)
                    .with_context(|| format!("Failed to read SSH key file: {default_key:?}"))?,
            );

            let passphrase = if key_contents.contains("ENCRYPTED")
                || key_contents.contains("Proc-Type: 4,ENCRYPTED")
            {
                // SECURITY: Acquire mutex to serialize passphrase prompts
                let _guard = auth_mutex.lock().await;

                let prompt = format!(
                    "Enter passphrase for key {default_key:?} (jump host {}): ",
                    jump_host.to_connection_string()
                );

                let pass = Zeroizing::new(
                    rpassword::prompt_password(prompt)
                        .with_context(|| "Failed to read passphrase")?,
                );
                Some(pass)
            } else {
                None
            };

            return Ok(AuthMethod::with_key_file(
                default_key,
                passphrase.as_ref().map(|p| p.as_str()),
            ));
        }
    }

    anyhow::bail!("No authentication method available for jump host")
}

/// Authenticate to a jump host or destination
pub(super) async fn authenticate_connection(
    handle: &mut russh::client::Handle<ClientHandler>,
    username: &str,
    auth_method: AuthMethod,
) -> Result<()> {
    use crate::ssh::tokio_client::AuthMethod;

    match auth_method {
        AuthMethod::Password(password) => {
            let auth_result = handle
                .authenticate_password(username, &**password)
                .await
                .map_err(|e| anyhow::anyhow!("Password authentication failed: {e}"))?;

            if !auth_result.success() {
                anyhow::bail!("Password authentication rejected by server");
            }
        }

        AuthMethod::PrivateKey { key_data, key_pass } => {
            let private_key =
                russh::keys::decode_secret_key(&key_data, key_pass.as_ref().map(|p| &***p))
                    .map_err(|e| anyhow::anyhow!("Failed to decode private key: {e}"))?;

            let auth_result = handle
                .authenticate_publickey(
                    username,
                    russh::keys::PrivateKeyWithHashAlg::new(
                        std::sync::Arc::new(private_key),
                        handle.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await
                .map_err(|e| anyhow::anyhow!("Private key authentication failed: {e}"))?;

            if !auth_result.success() {
                anyhow::bail!("Private key authentication rejected by server");
            }
        }

        AuthMethod::PrivateKeyFile {
            key_file_path,
            key_pass,
        } => {
            let private_key =
                russh::keys::load_secret_key(key_file_path, key_pass.as_ref().map(|p| &***p))
                    .map_err(|e| anyhow::anyhow!("Failed to load private key from file: {e}"))?;

            let auth_result = handle
                .authenticate_publickey(
                    username,
                    russh::keys::PrivateKeyWithHashAlg::new(
                        std::sync::Arc::new(private_key),
                        handle.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await
                .map_err(|e| anyhow::anyhow!("Private key file authentication failed: {e}"))?;

            if !auth_result.success() {
                anyhow::bail!("Private key file authentication rejected by server");
            }
        }

        #[cfg(not(target_os = "windows"))]
        AuthMethod::Agent => {
            let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|_| anyhow::anyhow!("Failed to connect to SSH agent"))?;

            let identities = agent
                .request_identities()
                .await
                .map_err(|_| anyhow::anyhow!("Failed to request identities from SSH agent"))?;

            if identities.is_empty() {
                anyhow::bail!("No identities available in SSH agent");
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
                anyhow::bail!("SSH agent authentication rejected by server");
            }
        }

        _ => {
            anyhow::bail!("Unsupported authentication method");
        }
    }

    Ok(())
}

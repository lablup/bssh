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

//! SSH authentication methods and server verification.
//!
//! This module provides authentication mechanisms including:
//! - Password authentication
//! - Private key authentication (file or in-memory)
//! - Public key authentication
//! - SSH agent authentication
//! - Keyboard-interactive authentication
//!
//! It also provides server verification methods via `ServerCheckMethod`.

use russh::client::{Handle, Handler};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

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

    pub fn with_key_file<T: AsRef<std::path::Path>>(
        key_file_path: T,
        passphrase: Option<&str>,
    ) -> Self {
        Self::PrivateKeyFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            key_pass: passphrase.map(|p| Zeroizing::new(p.to_string())),
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn with_public_key_file<T: AsRef<std::path::Path>>(key_file_path: T) -> Self {
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

/// Server host key verification methods.
///
/// These methods control how the client verifies the server's host key during connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServerCheckMethod {
    /// No verification - accept any host key (insecure, for testing only)
    NoCheck,
    /// Verify against a specific base64 encoded public key
    PublicKey(String),
    /// Verify against a public key file
    PublicKeyFile(String),
    /// Use default known_hosts file (~/.ssh/known_hosts)
    DefaultKnownHostsFile,
    /// Use a specific known_hosts file path
    KnownHostsFile(String),
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

/// This takes a handle and performs authentification with the given method.
pub(super) async fn authenticate<H: Handler>(
    handle: &mut Handle<H>,
    username: &String,
    auth: AuthMethod,
) -> Result<(), super::Error> {
    use russh::client::KeyboardInteractiveAuthResponse;

    match auth {
        AuthMethod::Password(password) => {
            let is_authentificated = handle.authenticate_password(username, &**password).await?;
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
            let cpubk =
                russh::keys::load_public_key(key_file_path).map_err(super::Error::KeyInvalid)?;
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

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
use crate::jump::{JumpHostChain, parse_jump_hosts};
use crate::security::Password;
use crate::ssh::SessionPurpose;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::{
    AuthMethod, Client, ProxyMode, SshConnectionConfig, SshConnectionConfigResolver,
};
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

// SSH connection timeout design:
// - 30 seconds accommodates slow networks and SSH negotiation
// - Industry standard for SSH client connections
// - Balances user patience with reliability on poor networks
const SSH_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Build the friendly, outer-context message for a failed direct SSH
/// connection attempt.
///
/// The result is meant to be used as `anyhow::Error::new(e).context(message)`
/// so the message renders as the outer layer and `e` renders as the cause.
/// Because anyhow's `{:#}` form joins layers with `": "`, a context message
/// that restates the variant's own `Display` text would make the same wording
/// appear twice in one line. So this returns `None` for variants whose
/// `Display` already says everything the context layer would, and the
/// messages it does return add remediation guidance without echoing the
/// cause and carry no trailing period (which would render as `".: "`).
/// See issue #238.
fn connect_error_message(e: &crate::ssh::tokio_client::Error) -> Option<String> {
    match e {
        crate::ssh::tokio_client::Error::KeyAuthFailed => {
            Some("The private key was rejected by the server".to_string())
        }
        crate::ssh::tokio_client::Error::ServerCheckFailed => Some(
            "Host key verification failed: the server's host key was not recognized or has changed"
                .to_string(),
        ),
        crate::ssh::tokio_client::Error::HostKeyChanged { host, port, .. } => {
            // Name the entry as known_hosts records it, so the command also
            // works for non-standard ports, and double quote it so zsh does not
            // reject the unmatched `[...]` glob. No `-f` here: this path has no
            // known_hosts path to hand, and production always uses the default
            // file, which `ssh-keygen` picks itself.
            let entry = crate::ssh::tokio_client::host_verification::known_hosts_entry_name(
                host, *port,
            );
            Some(format!(
                "Possible man-in-the-middle attack: verify the server's new key out of band, or remove the old entry with 'ssh-keygen -R \"{entry}\"' if the change is expected"
            ))
        }
        // Unlike `HostKeyChanged`, there is no `ssh-keygen -R` remediation to
        // offer: the marker was placed deliberately to blocklist this exact
        // key, and the entry it points at is the `@revoked` line itself, not
        // a stale pin to remove.
        crate::ssh::tokio_client::Error::HostKeyRevoked { .. } => Some(
            "The offered host key matches a key explicitly revoked in known_hosts; do not connect unless you can independently verify the server's identity out of band"
                .to_string(),
        ),
        crate::ssh::tokio_client::Error::SshError(russh::Error::UnknownKey) => Some(
            "The host is not in known_hosts and strict host key checking is enabled; connect once with '--strict-host-key-checking accept-new' or add the key manually"
                .to_string(),
        ),
        crate::ssh::tokio_client::Error::KeyInvalid(_) => {
            Some("Check the key file format and passphrase".to_string())
        }
        crate::ssh::tokio_client::Error::AgentConnectionFailed => {
            Some("Ensure SSH_AUTH_SOCK is set and the agent is running".to_string())
        }
        crate::ssh::tokio_client::Error::AgentNoIdentities => {
            Some("Add your key to the agent using 'ssh-add'".to_string())
        }
        // `PasswordWrong`, `AgentAuthenticationFailed` and `SshError` already
        // render the full story through their own `Display`, and any context
        // here would only repeat it.
        _ => None,
    }
}

impl SshClient {
    /// Determine the authentication method based on provided parameters.
    ///
    /// The `pre_collected_password` argument carries the password the dispatcher
    /// collected once up-front (via `--password`). When `use_password` is `true`
    /// and a pre-collected value is provided, `AuthContext::password_auth()`
    /// consumes it directly instead of prompting in the per-node task.
    pub(super) async fn determine_auth_method(
        &self,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
        #[cfg(target_os = "macos")] use_keychain: bool,
        pre_collected_password: Option<Arc<Password>>,
        ssh_connection_config: Option<&SshConnectionConfig>,
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

        auth_ctx = auth_ctx
            .with_agent(use_agent)
            .with_password(use_password)
            .with_pre_collected_password(pre_collected_password);
        auth_ctx = auth_ctx.with_policy(
            ssh_connection_config
                .map(|config| config.auth_policy.clone())
                .unwrap_or_default(),
        );

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
        connect_timeout_seconds: Option<u64>,
        ssh_connection_config: Option<&SshConnectionConfig>,
    ) -> Result<Client> {
        // SECURITY: Add rate limiting before connection attempts
        const RATE_LIMIT_DELAY: Duration = Duration::from_millis(100);
        tokio::time::sleep(RATE_LIMIT_DELAY).await;

        // SECURITY: Capture start time for timing attack mitigation
        let start_time = std::time::Instant::now();

        let addr = (self.host.as_str(), self.port);

        let connect_timeout =
            Duration::from_secs(connect_timeout_seconds.unwrap_or(SSH_CONNECT_TIMEOUT_SECS));

        let default_conn_cfg;
        let conn_cfg = match ssh_connection_config {
            Some(c) => c,
            None => {
                default_conn_cfg = SshConnectionConfig::default();
                &default_conn_cfg
            }
        };
        let check_method = crate::ssh::known_hosts::get_check_method_for_target(
            strict_mode,
            conn_cfg,
            &self.host,
            self.port,
            &self.username,
        );

        let result = match tokio::time::timeout(
            connect_timeout,
            Client::connect_with_ssh_config(
                addr,
                &self.username,
                auth_method.clone(),
                check_method,
                conn_cfg,
            ),
        )
        .await
        {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(e)) => {
                // Specific error from the SSH connection attempt.
                // The friendly message is the outer context and `e` is the
                // cause, so `{:#}` renders "<friendly message>: <cause>"
                // instead of the reverse. Variants whose own `Display` is
                // already sufficient get no extra layer, so the same wording
                // is not printed twice; see issue #238.
                match connect_error_message(&e) {
                    Some(error_msg) => Err(anyhow::Error::new(e).context(error_msg)),
                    None => Err(anyhow::Error::new(e)),
                }
            }
            Err(_) => Err(anyhow::Error::new(
                crate::ssh::tokio_client::Error::ConnectionTimeout {
                    host: self.host.clone(),
                    port: self.port,
                    seconds: connect_timeout.as_secs(),
                    stage: "connection setup or authentication",
                },
            )),
        };

        // SECURITY: Normalize timing to prevent timing attacks
        // Ensure all authentication attempts take at least 500ms to complete
        const MIN_AUTH_DURATION: Duration = Duration::from_millis(500);
        let elapsed = start_time.elapsed();
        if elapsed < MIN_AUTH_DURATION {
            tokio::time::sleep(MIN_AUTH_DURATION - elapsed).await;
        }

        result
    }

    /// Create an SSH connection through jump hosts
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn connect_via_jump_hosts(
        &self,
        jump_hosts: &[crate::jump::parser::JumpHost],
        auth_method: &AuthMethod,
        strict_mode: StrictHostKeyChecking,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
        connect_timeout_seconds: Option<u64>,
        ssh_connection_config: Option<&SshConnectionConfig>,
        ssh_connection_config_resolver: Option<&SshConnectionConfigResolver>,
        pre_collected_password: Option<Arc<Password>>,
        session_purpose: SessionPurpose,
    ) -> Result<Client> {
        // Create jump host chain with user-specified or default connect timeout
        let connect_timeout =
            Duration::from_secs(connect_timeout_seconds.unwrap_or(SSH_CONNECT_TIMEOUT_SECS));
        let mut chain = JumpHostChain::new(jump_hosts.to_vec())
            .with_connect_timeout(connect_timeout)
            .with_command_timeout(Duration::from_secs(300))
            .with_ssh_password(pre_collected_password);
        if let Some(cfg) = ssh_connection_config {
            chain = chain.with_ssh_connection_config(cfg.clone());
        }
        if let Some(resolver) = ssh_connection_config_resolver {
            chain = chain.with_ssh_connection_config_resolver(resolver.clone());
        }
        chain = chain.with_session_purpose(session_purpose);

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
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn establish_connection(
        &self,
        auth_method: &AuthMethod,
        strict_mode: StrictHostKeyChecking,
        jump_hosts_spec: Option<&str>,
        key_path: Option<&Path>,
        use_agent: bool,
        use_password: bool,
        connect_timeout_seconds: Option<u64>,
        ssh_connection_config: Option<&SshConnectionConfig>,
        ssh_connection_config_resolver: Option<&SshConnectionConfigResolver>,
        pre_collected_password: Option<Arc<Password>>,
        session_purpose: SessionPurpose,
    ) -> Result<Client> {
        let selected_config = ssh_connection_config
            .cloned()
            .unwrap_or_default()
            .with_session_purpose(session_purpose);
        let ssh_connection_config = Some(&selected_config);
        let jump_hosts_spec =
            match ssh_connection_config.and_then(|config| config.proxy_mode.as_ref()) {
                Some(ProxyMode::Jump(jump)) => Some(jump.as_str()),
                Some(ProxyMode::Command(_) | ProxyMode::Direct) => None,
                None => jump_hosts_spec,
            };

        if let Some(jump_spec) = jump_hosts_spec {
            // Parse jump hosts
            let jump_hosts = parse_jump_hosts(jump_spec).with_context(|| {
                format!("Failed to parse jump host specification: '{jump_spec}'")
            })?;

            if jump_hosts.is_empty() {
                tracing::debug!("No valid jump hosts found, using direct connection");
                self.connect_direct(
                    auth_method,
                    strict_mode,
                    connect_timeout_seconds,
                    ssh_connection_config,
                )
                .await
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
                    connect_timeout_seconds,
                    ssh_connection_config,
                    ssh_connection_config_resolver,
                    pre_collected_password,
                    session_purpose,
                )
                .await
            }
        } else {
            // Direct connection
            tracing::debug!("Using direct connection (no jump hosts)");
            self.connect_direct(
                auth_method,
                strict_mode,
                connect_timeout_seconds,
                ssh_connection_config,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::EnvGuard;
    use serial_test::serial;
    use tempfile::TempDir;

    fn write_test_key(path: &Path) {
        use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};

        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        std::fs::write(path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn test_determine_auth_method_with_key() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key");
        write_test_key(&key_path);

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let mut config = SshConnectionConfig::default();
        config.auth_policy.identities_only = true;
        let auth = client
            .determine_auth_method(
                Some(&key_path),
                false,
                false,
                #[cfg(target_os = "macos")]
                false,
                None,
                Some(&config),
            )
            .await
            .unwrap();

        match auth {
            AuthMethod::PrivateKeyFileWithPolicy { key_file_path, .. } => {
                // Path should be canonicalized now
                assert!(key_file_path.is_absolute());
            }
            _ => panic!("Expected policy-aware private-key auth method"),
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[serial]
    async fn test_determine_auth_method_with_agent() {
        use std::os::unix::net::UnixListener;

        // Create a temporary directory for the socket and SSH keys
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh-agent.sock");

        // Create a real Unix domain socket (required on macOS)
        // Note: This is a fake socket that doesn't implement SSH agent protocol
        let _listener = UnixListener::bind(&socket_path).unwrap();

        // Create a fake SSH key for fallback (since our fake agent has no identities)
        let ssh_dir = temp_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        write_test_key(&ssh_dir.join("id_ed25519"));

        // Guards restore prior values on drop.
        let _sock = EnvGuard::set("SSH_AUTH_SOCK", socket_path.to_str().unwrap());
        let _home = EnvGuard::set("HOME", temp_dir.path());

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client
            .determine_auth_method(
                None,
                true,
                false,
                #[cfg(target_os = "macos")]
                false,
                None,
                None,
            )
            .await
            .unwrap();

        let AuthMethod::Methods(methods) = auth else {
            panic!("expected ordered agent and default-key methods");
        };
        assert!(matches!(
            methods.first(),
            Some(AuthMethod::AgentWithPolicy { .. })
        ));
        assert!(matches!(
            methods.get(1),
            Some(AuthMethod::PrivateKeyFileWithPolicy { key_file_path, .. })
                if key_file_path.ends_with("id_ed25519")
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[serial]
    async fn test_determine_auth_method_with_agent() {
        use std::os::unix::net::UnixListener;

        // Create a temporary directory for the socket and SSH keys
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh-agent.sock");

        // Create a real Unix domain socket (required on Linux)
        // Note: This is a fake socket that doesn't implement SSH agent protocol
        let _listener = UnixListener::bind(&socket_path).unwrap();

        // Create a fake SSH key for fallback (since our fake agent has no identities)
        let ssh_dir = temp_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        write_test_key(&ssh_dir.join("id_ed25519"));

        // Guards restore prior values on drop.
        let _sock = EnvGuard::set("SSH_AUTH_SOCK", socket_path.to_str().unwrap());
        let _home = EnvGuard::set("HOME", temp_dir.path());

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client
            .determine_auth_method(None, true, false, None, None)
            .await
            .unwrap();

        let AuthMethod::Methods(methods) = auth else {
            panic!("expected ordered agent and default-key methods");
        };
        assert!(matches!(
            methods.first(),
            Some(AuthMethod::AgentWithPolicy { .. })
        ));
        assert!(matches!(
            methods.get(1),
            Some(AuthMethod::PrivateKeyFileWithPolicy { key_file_path, .. })
                if key_file_path.ends_with("id_ed25519")
        ));
    }

    #[test]
    fn test_determine_auth_method_with_password() {
        let _client = SshClient::new("test.com".to_string(), 22, "user".to_string());

        // Note: We can't actually test password prompt in unit tests
        // as it requires terminal input. This would need integration testing.
        // For now, we just verify the function compiles with the new parameter.
    }

    #[tokio::test]
    #[serial]
    async fn test_determine_auth_method_fallback_to_default() {
        // Create a fake home directory with default key
        let temp_dir = TempDir::new().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let default_key = ssh_dir.join("id_ed25519");
        write_test_key(&default_key);

        // Guards restore prior values on drop.
        let _home = EnvGuard::set("HOME", temp_dir.path().to_str().unwrap());
        let _sock = EnvGuard::remove("SSH_AUTH_SOCK");

        let client = SshClient::new("test.com".to_string(), 22, "user".to_string());
        let auth = client
            .determine_auth_method(
                None,
                false,
                false,
                #[cfg(target_os = "macos")]
                false,
                None,
                None,
            )
            .await
            .unwrap();

        match auth {
            AuthMethod::PrivateKeyFileWithPolicy { key_file_path, .. } => {
                // Path should be canonicalized now
                assert!(key_file_path.is_absolute());
            }
            _ => panic!("Expected policy-aware private-key auth method"),
        }
    }

    #[test]
    fn test_connect_error_ordering_puts_friendly_message_first() {
        // Regression test for issue #238's readability defect: the friendly
        // message must be the OUTER context so `{:#}` renders it first,
        // followed by the underlying cause, instead of the reverse.
        let e = crate::ssh::tokio_client::Error::KeyAuthFailed;
        let cause_text = e.to_string();
        let error_msg = connect_error_message(&e).expect("KeyAuthFailed adds guidance");
        let err = anyhow::Error::new(e).context(error_msg);

        let rendered = format!("{err:#}");
        assert_eq!(
            rendered, "The private key was rejected by the server: Permission denied (publickey).",
            "expected friendly message first, then the cause"
        );
        // The underlying cause must appear after the friendly message, not
        // before it, and must not be swallowed.
        let friendly_end = rendered
            .find("The private key was rejected by the server")
            .unwrap()
            + "The private key was rejected by the server".len();
        assert!(
            rendered[friendly_end..].contains(&cause_text),
            "expected the cause to appear after the friendly message, got: {rendered}"
        );
    }

    #[test]
    fn test_connect_error_message_omits_context_that_would_repeat_cause() {
        // Variants whose own `Display` already says everything get no extra
        // context layer, so the same wording is not printed twice. Before this
        // fix, `PasswordWrong` rendered as
        // "Permission denied (password).: Permission denied (password).".
        for e in [
            crate::ssh::tokio_client::Error::PasswordWrong,
            crate::ssh::tokio_client::Error::AgentAuthenticationFailed,
            crate::ssh::tokio_client::Error::CommandDidntExit,
        ] {
            let cause_text = e.to_string();
            assert!(
                connect_error_message(&e).is_none(),
                "{cause_text} should not get a context layer"
            );

            let rendered = format!("{:#}", anyhow::Error::new(e));
            assert_eq!(rendered, cause_text);
            assert_eq!(
                rendered.matches(cause_text.as_str()).count(),
                1,
                "cause text should appear exactly once, got: {rendered}"
            );
        }
    }

    #[test]
    fn test_connect_error_message_does_not_duplicate_inner_key_error() {
        // `KeyInvalid`'s own `Display` already interpolates the underlying
        // key error, so the context layer must not interpolate it again.
        let key_err = russh::keys::Error::KeyIsCorrupt;
        let inner_text = key_err.to_string();
        let e = crate::ssh::tokio_client::Error::KeyInvalid(key_err);

        let error_msg = connect_error_message(&e).expect("KeyInvalid adds guidance");
        assert!(
            !error_msg.contains(&inner_text),
            "context must not echo the inner key error, got: {error_msg}"
        );

        let rendered = format!("{:#}", anyhow::Error::new(e).context(error_msg));
        assert_eq!(
            rendered.matches(inner_text.as_str()).count(),
            1,
            "inner key error should appear exactly once, got: {rendered}"
        );
    }

    #[test]
    fn test_connect_error_messages_have_no_trailing_period() {
        // `{:#}` joins layers with ": ", so a trailing period would render as
        // the awkward sequence ".: " in the middle of a line.
        for e in [
            crate::ssh::tokio_client::Error::KeyAuthFailed,
            crate::ssh::tokio_client::Error::ServerCheckFailed,
            crate::ssh::tokio_client::Error::AgentConnectionFailed,
            crate::ssh::tokio_client::Error::AgentNoIdentities,
            crate::ssh::tokio_client::Error::HostKeyChanged {
                host: "node1.example.com".to_string(),
                port: 22,
                line: 3,
            },
            crate::ssh::tokio_client::Error::HostKeyChanged {
                host: "node1.example.com".to_string(),
                port: 2222,
                line: 3,
            },
            crate::ssh::tokio_client::Error::HostKeyRevoked {
                host: "node1.example.com".to_string(),
                port: 22,
                line: 3,
            },
            crate::ssh::tokio_client::Error::SshError(russh::Error::UnknownKey),
        ] {
            let message = connect_error_message(&e).expect("variant adds guidance");
            assert!(
                !message.ends_with('.'),
                "context message must not end with a period, got: {message}"
            );
        }
    }

    #[test]
    fn test_connect_error_message_host_key_changed_adds_guidance_without_echo() {
        // The changed-key context layer must add remediation guidance (which
        // host entry to remove) without restating the cause's own wording,
        // which would render twice through anyhow's `{:#}` form (#239, #238).
        let e = crate::ssh::tokio_client::Error::HostKeyChanged {
            host: "node1.example.com".to_string(),
            port: 22,
            line: 7,
        };
        let cause_text = e.to_string();
        let message = connect_error_message(&e).expect("HostKeyChanged adds guidance");
        assert!(
            message.contains("ssh-keygen -R \"node1.example.com\""),
            "guidance must include the removal command, got: {message}"
        );
        assert!(
            !message.contains("has changed and no longer matches"),
            "context must not restate the cause, got: {message}"
        );

        let rendered = format!("{:#}", anyhow::Error::new(e).context(message));
        assert_eq!(
            rendered.matches(cause_text.as_str()).count(),
            1,
            "cause text should appear exactly once, got: {rendered}"
        );
        assert!(
            rendered.contains("line 7"),
            "the conflicting line number must survive into the chain, got: {rendered}"
        );
    }

    #[test]
    fn test_connect_error_message_host_key_changed_names_port_qualified_entry() {
        // known_hosts records a non-standard port as `[host]:port`, so
        // `ssh-keygen -R host` would remove nothing and leave the user stuck.
        // The guidance must name the entry that actually exists, quoted so the
        // unmatched `[...]` glob does not make zsh reject the command.
        let e = crate::ssh::tokio_client::Error::HostKeyChanged {
            host: "node1.example.com".to_string(),
            port: 2222,
            line: 7,
        };
        let message = connect_error_message(&e).expect("HostKeyChanged adds guidance");
        assert!(
            message.contains("ssh-keygen -R \"[node1.example.com]:2222\""),
            "guidance must name the port-qualified entry, got: {message}"
        );
        assert!(
            !message.contains("has changed and no longer matches"),
            "context must not restate the cause, got: {message}"
        );
    }

    #[test]
    fn test_connect_error_message_host_key_revoked_adds_guidance_without_echo() {
        // Same invariant as HostKeyChanged: the context layer adds guidance
        // without restating the cause's own wording, which would otherwise
        // render twice through anyhow's `{:#}` form (#239, #238).
        let e = crate::ssh::tokio_client::Error::HostKeyRevoked {
            host: "node1.example.com".to_string(),
            port: 22,
            line: 7,
        };
        let cause_text = e.to_string();
        let message = connect_error_message(&e).expect("HostKeyRevoked adds guidance");
        assert!(
            message.contains("explicitly revoked"),
            "guidance must warn about revocation, got: {message}"
        );
        assert!(
            !message.contains("is explicitly revoked by the known_hosts entry at line"),
            "context must not restate the cause, got: {message}"
        );

        let rendered = format!("{:#}", anyhow::Error::new(e).context(message));
        assert_eq!(
            rendered.matches(cause_text.as_str()).count(),
            1,
            "cause text should appear exactly once, got: {rendered}"
        );
    }
}

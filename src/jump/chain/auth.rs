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
use crate::security::Password;
use crate::ssh::tokio_client::{AuthMethod, ClientHandler};
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;

/// Determine authentication method for a jump host
///
/// Priority order for SSH key selection:
/// 1. Jump host's own `ssh_key` field (from structured config)
/// 2. Cluster/defaults `key_path` (fallback, passed as parameter)
/// 3. SSH agent (if use_agent=true and agent has keys)
/// 4. Default key files (~/.ssh/id_*)
///
/// When `use_password` is `true`, the `pre_collected_password` argument MUST
/// carry the password the dispatcher collected once up-front via
/// `prompt_password()`. Per-call password prompts here would race
/// across parallel jump-host auth tasks and produce N prompts for N nodes —
/// the very bug `--password` was supposed to fix.
pub(super) async fn determine_auth_method(
    jump_host: &JumpHost,
    key_path: Option<&Path>,
    use_agent: bool,
    use_password: bool,
    pre_collected_password: Option<Arc<Password>>,
    ssh_connection_config: &crate::ssh::tokio_client::SshConnectionConfig,
) -> Result<AuthMethod> {
    let effective_key_path = if let Some(ref jump_key) = jump_host.ssh_key {
        use crate::config::{expand_env_vars, expand_tilde};
        let expanded_path = expand_env_vars(jump_key);
        let path = Path::new(&expanded_path);
        Some(if expanded_path.starts_with('~') {
            expand_tilde(path)
        } else {
            path.to_path_buf()
        })
    } else {
        key_path.map(Path::to_path_buf)
    };

    let mut context =
        crate::ssh::AuthContext::new(jump_host.effective_user(), jump_host.host.clone())?
            .with_agent(use_agent)
            .with_password(use_password)
            .with_pre_collected_password(pre_collected_password)
            .with_policy(ssh_connection_config.auth_policy.clone());
    if let Some(path) = effective_key_path {
        context = context.with_key_path(Some(path))?;
    }
    context.determine_method().await
}

/// Authenticate to a jump host or destination
///
/// # Arguments
/// * `handle` - The SSH client handle to authenticate
/// * `username` - The username to authenticate as
/// * `auth_method` - The authentication method to use
/// * `host_description` - A description of the host (e.g., "jump host 'bastion.example.com:22'")
pub(super) async fn authenticate_connection(
    handle: &mut russh::client::Handle<ClientHandler>,
    username: &str,
    auth_method: AuthMethod,
    host_description: &str,
) -> Result<()> {
    crate::ssh::tokio_client::authentication::authenticate(
        handle,
        &username.to_string(),
        auth_method,
    )
    .await
    .with_context(|| format!("Authentication failed for {host_description} (user: {username})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::EnvGuard;
    use russh::keys::ssh_key::LineEnding;
    use tempfile::TempDir;

    /// Helper to create a test JumpHost
    fn create_test_jump_host() -> JumpHost {
        JumpHost::new(
            "test.example.com".to_string(),
            Some("testuser".to_string()),
            Some(22),
        )
    }

    /// Helper to create a valid unencrypted test SSH key
    fn create_test_ssh_key(dir: &TempDir, name: &str) -> std::path::PathBuf {
        let key_path = dir.path().join(name);
        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .expect("generate test key");
        std::fs::write(
            &key_path,
            key.to_openssh(LineEnding::LF)
                .expect("encode test key")
                .as_bytes(),
        )
        .expect("write test key");
        key_path
    }

    /// Test: determine_auth_method falls back to key file when agent is unavailable
    #[tokio::test]
    #[serial_test::serial]
    async fn test_determine_auth_method_fallback_to_key_file() {
        // Clear SSH_AUTH_SOCK to ensure agent is "unavailable"; guard restores on drop.
        let _sock = EnvGuard::remove("SSH_AUTH_SOCK");

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let key_path = create_test_ssh_key(&temp_dir, "id_test");
        let jump_host = create_test_jump_host();

        // With use_agent=true but no agent available, should fall back to key file
        let result = determine_auth_method(
            &jump_host,
            Some(key_path.as_path()),
            true,  // use_agent
            false, // use_password
            None,  // pre_collected_password
            &crate::ssh::tokio_client::SshConnectionConfig::default(),
        )
        .await;

        assert!(result.is_ok(), "Should succeed with key file fallback");
        let auth_method = result.unwrap();

        match auth_method {
            AuthMethod::Methods(methods) => {
                assert!(matches!(
                    methods.first(),
                    Some(AuthMethod::PrivateKeyFileWithPolicy { .. })
                ));
                assert!(matches!(
                    methods.get(1),
                    Some(AuthMethod::AgentWithPolicy { .. })
                ));
            }
            other => panic!("Expected ordered key and agent plan, got {other:?}"),
        }
    }

    /// Test: determine_auth_method falls back to default keys when no key_path provided
    #[tokio::test]
    #[serial_test::serial]
    async fn test_determine_auth_method_tries_default_keys() {
        // Clear SSH_AUTH_SOCK; guard restores on drop.
        let _sock = EnvGuard::remove("SSH_AUTH_SOCK");

        // Create a temporary HOME directory with an SSH key
        let temp_home = TempDir::new().expect("Failed to create temp home");
        let ssh_dir = temp_home.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).expect("Failed to create .ssh dir");

        create_test_ssh_key(&temp_home, ".ssh/id_ed25519");

        // Set HOME; guard restores on drop.
        let _home = EnvGuard::set("HOME", temp_home.path());

        let jump_host = create_test_jump_host();

        // No key_path provided, should try default keys
        let result = determine_auth_method(
            &jump_host,
            None,  // No key_path
            false, // use_agent
            false, // use_password
            None,  // pre_collected_password
            &crate::ssh::tokio_client::SshConnectionConfig::default(),
        )
        .await;

        assert!(
            result.is_ok(),
            "Should find default key at ~/.ssh/id_ed25519"
        );
        let auth_method = result.unwrap();

        match auth_method {
            AuthMethod::PrivateKeyFileWithPolicy { key_file_path, .. } => {
                let path_str = key_file_path.to_string_lossy();
                assert!(
                    path_str.ends_with("id_ed25519") || path_str.contains("id_ed25519"),
                    "Should use id_ed25519 from default location, got: {path_str}"
                );
            }
            other => {
                panic!("Expected PrivateKeyFile, got {:?}", other);
            }
        }
    }

    /// Test: determine_auth_method fails when no authentication method is available
    /// Note: This test verifies the error case when no auth methods work
    #[tokio::test]
    #[serial_test::serial]
    async fn test_determine_auth_method_fails_when_no_method_available() {
        // This serial test removes SSH_AUTH_SOCK so the lazy planner has no
        // ambient agent candidate. The guard restores the original value.
        let _sock = EnvGuard::remove("SSH_AUTH_SOCK");

        // Create a temporary HOME directory without any SSH keys
        let temp_home = TempDir::new().expect("Failed to create temp home");
        let ssh_dir = temp_home.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).expect("Failed to create .ssh dir");
        // Don't create any keys - the .ssh dir is empty

        let _home = EnvGuard::set("HOME", temp_home.path());

        let jump_host = create_test_jump_host();

        // No working agent, no key_path, no default keys - should fail
        let result = determine_auth_method(
            &jump_host,
            None,  // No key_path
            false, // use_agent=false means don't try agent first
            false, // use_password
            None,  // pre_collected_password
            &crate::ssh::tokio_client::SshConnectionConfig::default(),
        )
        .await;

        let error = result.expect_err("isolated HOME and invalid agent must have no method");
        assert!(error.to_string().contains("Permission denied"));
    }

    /// Test: Jump host's own ssh_key takes priority over cluster key_path
    #[tokio::test]
    #[serial_test::serial]
    async fn test_jump_host_ssh_key_priority() {
        // Clear SSH_AUTH_SOCK; guard restores on drop.
        let _sock = EnvGuard::remove("SSH_AUTH_SOCK");

        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create jump host's own key
        let jump_key_path = create_test_ssh_key(&temp_dir, "jump_host_key");
        let jump_key_str = jump_key_path.to_string_lossy().to_string();

        // Create cluster's key
        let cluster_key_path = create_test_ssh_key(&temp_dir, "cluster_key");

        // Create jump host with its own ssh_key
        let jump_host = JumpHost::with_ssh_key(
            "test.example.com".to_string(),
            Some("testuser".to_string()),
            Some(22),
            Some(jump_key_str.clone()),
        );

        // Call determine_auth_method with both jump host key and cluster key
        let result = determine_auth_method(
            &jump_host,
            Some(cluster_key_path.as_path()), // Cluster key
            false,                            // use_agent
            false,                            // use_password
            None,                             // pre_collected_password
            &crate::ssh::tokio_client::SshConnectionConfig::default(),
        )
        .await;

        assert!(result.is_ok(), "Should succeed with jump host's key");
        let auth_method = result.unwrap();

        // Verify it used the jump host's key, not the cluster key
        match auth_method {
            AuthMethod::PrivateKeyFileWithPolicy { key_file_path, .. } => {
                let path_str = key_file_path.to_string_lossy();
                assert!(
                    path_str.contains("jump_host_key"),
                    "Should use jump host's key (jump_host_key), got: {path_str}"
                );
                assert!(
                    !path_str.contains("cluster_key"),
                    "Should NOT use cluster key, got: {path_str}"
                );
            }
            other => {
                panic!("Expected PrivateKeyFile, got {:?}", other);
            }
        }
    }

    /// Test: Falls back to cluster key when jump host has no ssh_key
    #[tokio::test]
    #[serial_test::serial]
    async fn test_fallback_to_cluster_key() {
        // Clear SSH_AUTH_SOCK; guard restores on drop.
        let _sock = EnvGuard::remove("SSH_AUTH_SOCK");

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cluster_key_path = create_test_ssh_key(&temp_dir, "cluster_key");

        // Create jump host WITHOUT its own ssh_key
        let jump_host = JumpHost::new(
            "test.example.com".to_string(),
            Some("testuser".to_string()),
            Some(22),
        );

        let result = determine_auth_method(
            &jump_host,
            Some(cluster_key_path.as_path()),
            false,
            false,
            None, // pre_collected_password
            &crate::ssh::tokio_client::SshConnectionConfig::default(),
        )
        .await;

        assert!(result.is_ok(), "Should succeed with cluster key");
        let auth_method = result.unwrap();

        // Verify it used the cluster key
        match auth_method {
            AuthMethod::PrivateKeyFileWithPolicy { key_file_path, .. } => {
                let path_str = key_file_path.to_string_lossy();
                assert!(
                    path_str.contains("cluster_key"),
                    "Should use cluster key, got: {path_str}"
                );
            }
            other => {
                panic!("Expected PrivateKeyFile, got {:?}", other);
            }
        }
    }
}

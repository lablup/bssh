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

//! SSH connection management and node operations.

use anyhow::Result;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::node::Node;
use crate::security::{Password, SudoPassword};
use crate::ssh::{
    CliTtyMode, SessionPolicy, SshClient, SshConfig,
    client::{CommandResult, ConnectionConfig},
    known_hosts::StrictHostKeyChecking,
    tokio_client::{SshConnectionConfig, SshConnectionConfigResolver, is_direct_proxy_jump},
};

/// Configuration for node execution.
#[derive(Clone)]
pub(crate) struct ExecutionConfig<'a> {
    pub key_path: Option<&'a str>,
    pub strict_mode: StrictHostKeyChecking,
    pub use_agent: bool,
    pub use_password: bool,
    #[cfg(target_os = "macos")]
    pub use_keychain: bool,
    pub timeout: Option<u64>,
    pub connect_timeout: Option<u64>,
    pub jump_hosts: Option<&'a str>,
    pub sudo_password: Option<Arc<SudoPassword>>,
    /// Pre-collected SSH password (collected once by the dispatcher and shared
    /// across every per-node task). When `use_password` is true, this MUST be
    /// `Some(_)`; auth.rs consumes it instead of prompting per node.
    pub ssh_password: Option<Arc<Password>>,
    pub ssh_config: Option<&'a SshConfig>,
    pub tty_mode: CliTtyMode,
    /// SSH connection configuration (keepalive settings).
    /// Threaded through to `Client::connect_with_ssh_config` so user-configured
    /// `server_alive_interval` / `server_alive_count_max` apply to exec mode.
    pub ssh_connection_config: Option<&'a SshConnectionConfig>,
    /// Per-host resolver used by jump chains so each hop consults its own
    /// ssh_config Host block instead of inheriting the destination's settings.
    pub ssh_connection_config_resolver: Option<&'a SshConnectionConfigResolver>,
}

/// Execute a command on a node with jump host support.
pub(crate) async fn execute_on_node_with_jump_hosts(
    node: Node,
    command: &str,
    config: &ExecutionConfig<'_>,
) -> Result<CommandResult> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = config.key_path.map(Path::new);

    // Resolve ProxyJump against the original ssh_config alias, before HostName
    // expansion. CLI remains authoritative.
    let effective_jump_hosts =
        resolve_effective_jump_hosts(config.jump_hosts, config.ssh_config, node.config_host());

    let session_policy = config
        .ssh_config
        .map(|ssh_config| {
            let effective = ssh_config.find_host_config(node.config_host());
            SessionPolicy::resolve_with_jump_spec(
                &effective,
                &node,
                (!command.is_empty()).then_some(command),
                config.tty_mode,
                std::io::stdin().is_terminal(),
                effective_jump_hosts.as_deref(),
            )
        })
        .transpose()?;

    let connection_config = ConnectionConfig {
        key_path,
        strict_mode: Some(config.strict_mode),
        use_agent: config.use_agent,
        use_password: config.use_password,
        #[cfg(target_os = "macos")]
        use_keychain: config.use_keychain,
        timeout_seconds: config.timeout,
        connect_timeout_seconds: config.connect_timeout,
        jump_hosts_spec: effective_jump_hosts.as_deref(),
        ssh_connection_config: config.ssh_connection_config,
        ssh_connection_config_resolver: config.ssh_connection_config_resolver,
        session_policy: session_policy.as_ref(),
        ssh_password: config.ssh_password.clone(),
    };

    // If sudo password is provided, use streaming execution to handle prompts
    if let Some(ref sudo_password) = config.sudo_password {
        use crate::ssh::tokio_client::CommandOutput;
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel(1000);
        let exit_status = client
            .connect_and_execute_with_sudo(command, &connection_config, tx, sudo_password)
            .await?;

        // Collect output from channel
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        while let Some(output) = rx.recv().await {
            match output {
                CommandOutput::StdOut(data) => stdout.extend_from_slice(&data),
                CommandOutput::StdErr(data) => stderr.extend_from_slice(&data),
                CommandOutput::ExitCode(_) => {
                    // Exit code is already captured from the function return value
                }
            }
        }

        Ok(CommandResult {
            host: node.host.clone(),
            output: stdout,
            stderr,
            exit_status,
        })
    } else {
        client
            .connect_and_execute_with_jump_hosts(command, &connection_config)
            .await
    }
}

/// Upload a file or directory to a node with jump host support.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_to_node(
    node: Node,
    local_path: &Path,
    remote_path: &str,
    key_path: Option<&str>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    jump_hosts: Option<&str>,
    connect_timeout_seconds: Option<u64>,
    ssh_config: Option<&SshConfig>,
    pre_collected_password: Option<Arc<Password>>,
    ssh_connection_config: &SshConnectionConfig,
    ssh_connection_config_resolver: &SshConnectionConfigResolver,
) -> Result<()> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    let effective_jump_hosts =
        resolve_effective_jump_hosts(jump_hosts, ssh_config, node.config_host());

    // Check if the local path is a directory
    if local_path.is_dir() {
        client
            .upload_dir_with_jump_hosts(
                local_path,
                remote_path,
                key_path,
                Some(strict_mode),
                use_agent,
                use_password,
                effective_jump_hosts.as_deref(),
                connect_timeout_seconds,
                pre_collected_password,
                ssh_connection_config,
                Some(ssh_connection_config_resolver),
            )
            .await
    } else {
        client
            .upload_file_with_jump_hosts(
                local_path,
                remote_path,
                key_path,
                Some(strict_mode),
                use_agent,
                use_password,
                effective_jump_hosts.as_deref(),
                connect_timeout_seconds,
                pre_collected_password,
                ssh_connection_config,
                Some(ssh_connection_config_resolver),
            )
            .await
    }
}

/// Download a file from a node with jump host support.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_from_node(
    node: Node,
    remote_path: &str,
    local_path: &Path,
    key_path: Option<&str>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    jump_hosts: Option<&str>,
    connect_timeout_seconds: Option<u64>,
    ssh_config: Option<&SshConfig>,
    pre_collected_password: Option<Arc<Password>>,
    ssh_connection_config: &SshConnectionConfig,
    ssh_connection_config_resolver: &SshConnectionConfigResolver,
) -> Result<PathBuf> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    let effective_jump_hosts =
        resolve_effective_jump_hosts(jump_hosts, ssh_config, node.config_host());

    // This function handles both files and directories
    // The caller should check if it's a directory and use the appropriate method
    client
        .download_file_with_jump_hosts(
            remote_path,
            local_path,
            key_path,
            Some(strict_mode),
            use_agent,
            use_password,
            effective_jump_hosts.as_deref(),
            connect_timeout_seconds,
            pre_collected_password,
            ssh_connection_config,
            Some(ssh_connection_config_resolver),
        )
        .await?;

    Ok(local_path.to_path_buf())
}

/// Download a directory from a node with jump host support.
#[allow(clippy::too_many_arguments)]
pub async fn download_dir_from_node(
    node: Node,
    remote_path: &str,
    local_path: &Path,
    key_path: Option<&str>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    jump_hosts: Option<&str>,
    connect_timeout_seconds: Option<u64>,
    ssh_config: Option<&SshConfig>,
    pre_collected_password: Option<Arc<Password>>,
    ssh_connection_config: &SshConnectionConfig,
    ssh_connection_config_resolver: &SshConnectionConfigResolver,
) -> Result<PathBuf> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    let effective_jump_hosts =
        resolve_effective_jump_hosts(jump_hosts, ssh_config, node.config_host());

    client
        .download_dir_with_jump_hosts(
            remote_path,
            local_path,
            key_path,
            Some(strict_mode),
            use_agent,
            use_password,
            effective_jump_hosts.as_deref(),
            connect_timeout_seconds,
            pre_collected_password,
            ssh_connection_config,
            Some(ssh_connection_config_resolver),
        )
        .await?;

    Ok(local_path.to_path_buf())
}

/// Helper function to resolve effective jump hosts with priority:
/// 1. CLI jump hosts (highest priority)
/// 2. SSH config ProxyJump for the specific host
/// 3. None (direct connection)
///
#[inline]
fn resolve_effective_jump_hosts(
    cli_jump_hosts: Option<&str>,
    ssh_config: Option<&SshConfig>,
    config_host: &str,
) -> Option<String> {
    if let Some(jump_hosts) = cli_jump_hosts {
        return Some(normalize_jump_hosts(jump_hosts));
    }
    ssh_config
        .and_then(|config| config.get_proxy_jump(config_host))
        .map(|jump_hosts| normalize_jump_hosts(&jump_hosts))
}

/// Preserve an explicit direct decision as an empty jump specification.
///
/// `Some("")` remains authoritative over lower-priority ssh_config values,
/// while both the session-policy and SSH client layers interpret it as no hop.
fn normalize_jump_hosts(jump_hosts: &str) -> String {
    if is_direct_proxy_jump(jump_hosts) {
        String::new()
    } else {
        jump_hosts.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_and_transfer_proxy_jump_uses_original_host_alias() {
        let ssh_config = SshConfig::parse(
            r#"
Host target-alias
    HostName effective-target
    ProxyJump alias-bastion

Host effective-target
    ProxyJump wrong-bastion
"#,
        )
        .expect("valid ssh_config");
        let node = Node::new("effective-target".to_string(), 22, "user".to_string())
            .with_original_host("target-alias".to_string());

        assert_eq!(
            resolve_effective_jump_hosts(None, Some(&ssh_config), node.config_host()),
            Some("alias-bastion".to_string())
        );
    }

    /// Test that CLI jump hosts take precedence over SSH config
    #[test]
    fn test_resolve_effective_jump_hosts_cli_precedence() {
        let ssh_config_content = r#"
Host example.com
    ProxyJump bastion.example.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        // CLI should override SSH config
        let result = resolve_effective_jump_hosts(
            Some("cli-bastion.example.com"),
            Some(&ssh_config),
            "example.com",
        );
        assert_eq!(result, Some("cli-bastion.example.com".to_string()));

        // CLI can explicitly disable a configured jump without allowing the
        // ssh_config fallback to become active again.
        for direct in ["none", "direct", " NONE "] {
            assert_eq!(
                resolve_effective_jump_hosts(Some(direct), Some(&ssh_config), "example.com"),
                Some(String::new())
            );
        }
    }

    /// Test that SSH config ProxyJump is used when no CLI jump hosts
    #[test]
    fn test_resolve_effective_jump_hosts_ssh_config_fallback() {
        let ssh_config_content = r#"
Host example.com
    ProxyJump bastion.example.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        let result = resolve_effective_jump_hosts(None, Some(&ssh_config), "example.com");
        assert_eq!(result, Some("bastion.example.com".to_string()));
    }

    /// Test that no jump hosts is returned when neither CLI nor SSH config specifies one
    #[test]
    fn test_resolve_effective_jump_hosts_none() {
        let ssh_config = SshConfig::new();

        let result = resolve_effective_jump_hosts(None, Some(&ssh_config), "example.com");
        assert_eq!(result, None);
    }

    /// Test that no jump hosts is returned when SSH config is not provided
    #[test]
    fn test_resolve_effective_jump_hosts_no_ssh_config() {
        let result = resolve_effective_jump_hosts(None, None, "example.com");
        assert_eq!(result, None);
    }

    /// Test multi-hop ProxyJump chain from SSH config
    #[test]
    fn test_resolve_effective_jump_hosts_multi_hop() {
        let ssh_config_content = r#"
Host internal.example.com
    ProxyJump jump1.example.com,jump2.example.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        let result = resolve_effective_jump_hosts(None, Some(&ssh_config), "internal.example.com");
        assert_eq!(
            result,
            Some("jump1.example.com,jump2.example.com".to_string())
        );
    }

    /// Test ProxyJump with port specification
    #[test]
    fn test_resolve_effective_jump_hosts_with_port() {
        let ssh_config_content = r#"
Host internal.example.com
    ProxyJump bastion.example.com:2222
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        let result = resolve_effective_jump_hosts(None, Some(&ssh_config), "internal.example.com");
        assert_eq!(result, Some("bastion.example.com:2222".to_string()));
    }

    /// Test ProxyJump with user@host:port format
    #[test]
    fn test_resolve_effective_jump_hosts_with_user_and_port() {
        let ssh_config_content = r#"
Host internal.example.com
    ProxyJump admin@bastion.example.com:2222
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        let result = resolve_effective_jump_hosts(None, Some(&ssh_config), "internal.example.com");
        assert_eq!(result, Some("admin@bastion.example.com:2222".to_string()));
    }

    /// Test wildcard pattern matching for ProxyJump
    #[test]
    fn test_resolve_effective_jump_hosts_wildcard() {
        let ssh_config_content = r#"
Host db.internal.example.com
    ProxyJump db-gateway.example.com

Host *.internal.example.com
    ProxyJump gateway.example.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        // OpenSSH uses the first value obtained, so put the exact host first.
        let result =
            resolve_effective_jump_hosts(None, Some(&ssh_config), "db.internal.example.com");
        assert_eq!(result, Some("db-gateway.example.com".to_string()));

        // Should match wildcard pattern
        let result =
            resolve_effective_jump_hosts(None, Some(&ssh_config), "web.internal.example.com");
        assert_eq!(result, Some("gateway.example.com".to_string()));
    }

    /// Test that unmatched hosts get no ProxyJump
    #[test]
    fn test_resolve_effective_jump_hosts_no_match() {
        let ssh_config_content = r#"
Host *.internal.example.com
    ProxyJump gateway.example.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        // Should not match - different domain
        let result = resolve_effective_jump_hosts(None, Some(&ssh_config), "external.example.com");
        assert_eq!(result, None);
    }

    #[test]
    fn direct_proxy_jump_values_normalize_to_an_empty_chain() {
        for directive in ["none", "direct", "NONE", "DIRECT"] {
            let ssh_config_content = format!(
                r#"
Host direct.example.com
    ProxyJump {directive}

Host *.example.com
    ProxyJump gateway.example.com
"#
            );
            let ssh_config = SshConfig::parse(&ssh_config_content).unwrap();

            let result =
                resolve_effective_jump_hosts(None, Some(&ssh_config), "direct.example.com");
            assert_eq!(result.as_deref(), Some(""), "value={directive}");
            assert!(
                crate::jump::parse_jump_hosts(result.as_deref().unwrap())
                    .unwrap()
                    .is_empty(),
                "value={directive}"
            );
        }
    }

    #[tokio::test]
    async fn command_and_all_transfer_paths_never_dial_proxy_jump_none() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let ssh_config = SshConfig::parse(
            r#"
Host direct-target
    HostName 127.0.0.1
    ProxyJump none
"#,
        )
        .unwrap();
        let resolver = SshConnectionConfigResolver::new().with_ssh_config(Some(ssh_config.clone()));
        let target_config = resolver.resolve_for_host("direct-target");
        let node = Node::new("127.0.0.1".to_string(), port, "user".to_string())
            .with_original_host("direct-target".to_string());
        let password = Arc::new(Password::new("test-password".to_string()).unwrap());
        let temp_dir = tempfile::TempDir::new().unwrap();
        let upload_file = temp_dir.path().join("upload.txt");
        std::fs::write(&upload_file, b"test").unwrap();

        let assert_direct_target = |path: &str, error: anyhow::Error| {
            let message = format!("{error:#}");
            assert!(message.contains("127.0.0.1"), "path={path}: {message}");
            assert!(!message.contains("none:22"), "path={path}: {message}");
            assert!(
                !message.contains("jump host none"),
                "path={path}: {message}"
            );
        };

        let execution_config = ExecutionConfig {
            key_path: None,
            strict_mode: StrictHostKeyChecking::AcceptNew,
            use_agent: false,
            use_password: true,
            #[cfg(target_os = "macos")]
            use_keychain: false,
            timeout: Some(1),
            connect_timeout: Some(1),
            jump_hosts: None,
            sudo_password: None,
            ssh_password: Some(password.clone()),
            ssh_config: Some(&ssh_config),
            tty_mode: CliTtyMode::Disable,
            ssh_connection_config: Some(&target_config),
            ssh_connection_config_resolver: Some(&resolver),
        };
        let error = execute_on_node_with_jump_hosts(node.clone(), "true", &execution_config)
            .await
            .unwrap_err();
        assert_direct_target("command", error);

        for (path, local_path) in [
            ("upload-file", upload_file.as_path()),
            ("upload-directory", temp_dir.path()),
        ] {
            let error = upload_to_node(
                node.clone(),
                local_path,
                "/tmp/remote",
                None,
                StrictHostKeyChecking::AcceptNew,
                false,
                true,
                None,
                Some(1),
                Some(&ssh_config),
                Some(password.clone()),
                &target_config,
                &resolver,
            )
            .await
            .unwrap_err();
            assert_direct_target(path, error);
        }

        let error = download_from_node(
            node.clone(),
            "/tmp/remote-file",
            &temp_dir.path().join("download.txt"),
            None,
            StrictHostKeyChecking::AcceptNew,
            false,
            true,
            None,
            Some(1),
            Some(&ssh_config),
            Some(password.clone()),
            &target_config,
            &resolver,
        )
        .await
        .unwrap_err();
        assert_direct_target("download-file", error);

        let error = download_dir_from_node(
            node,
            "/tmp/remote-dir",
            &temp_dir.path().join("download-dir"),
            None,
            StrictHostKeyChecking::AcceptNew,
            false,
            true,
            None,
            Some(1),
            Some(&ssh_config),
            Some(password),
            &target_config,
            &resolver,
        )
        .await
        .unwrap_err();
        assert_direct_target("download-directory", error);
    }

    /// Test complex multi-hop chain with user and ports
    #[test]
    fn test_resolve_effective_jump_hosts_complex_chain() {
        let ssh_config_content = r#"
Host production.internal
    ProxyJump user1@jump1.example.com:22,user2@jump2.example.com:2222,jump3.example.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        let result = resolve_effective_jump_hosts(None, Some(&ssh_config), "production.internal");
        assert_eq!(
            result,
            Some(
                "user1@jump1.example.com:22,user2@jump2.example.com:2222,jump3.example.com"
                    .to_string()
            )
        );
    }
}

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
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::node::Node;
use crate::security::SudoPassword;
use crate::ssh::{
    client::{CommandResult, ConnectionConfig},
    known_hosts::StrictHostKeyChecking,
    SshClient, SshConfig,
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
    pub ssh_config: Option<&'a SshConfig>,
}

/// Execute a command on a node with jump host support.
pub(crate) async fn execute_on_node_with_jump_hosts(
    node: Node,
    command: &str,
    config: &ExecutionConfig<'_>,
) -> Result<CommandResult> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = config.key_path.map(Path::new);

    // Determine effective jump hosts: CLI takes precedence, then SSH config
    // Store the SSH config jump hosts String to extend its lifetime
    let ssh_config_jump_hosts = config
        .ssh_config
        .and_then(|ssh_config| ssh_config.get_proxy_jump(&node.host));

    let effective_jump_hosts = if config.jump_hosts.is_some() {
        // CLI jump hosts specified
        config.jump_hosts
    } else {
        // Fall back to SSH config ProxyJump for this specific host
        ssh_config_jump_hosts.as_deref()
    };

    let connection_config = ConnectionConfig {
        key_path,
        strict_mode: Some(config.strict_mode),
        use_agent: config.use_agent,
        use_password: config.use_password,
        #[cfg(target_os = "macos")]
        use_keychain: config.use_keychain,
        timeout_seconds: config.timeout,
        connect_timeout_seconds: config.connect_timeout,
        jump_hosts_spec: effective_jump_hosts,
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
) -> Result<()> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    // Determine effective jump hosts: CLI takes precedence, then SSH config
    let ssh_config_jump_hosts =
        ssh_config.and_then(|ssh_config| ssh_config.get_proxy_jump(&node.host));

    let effective_jump_hosts = if jump_hosts.is_some() {
        jump_hosts
    } else {
        ssh_config_jump_hosts.as_deref()
    };

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
                effective_jump_hosts,
                connect_timeout_seconds,
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
                effective_jump_hosts,
                connect_timeout_seconds,
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
) -> Result<PathBuf> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    // Determine effective jump hosts: CLI takes precedence, then SSH config
    let ssh_config_jump_hosts =
        ssh_config.and_then(|ssh_config| ssh_config.get_proxy_jump(&node.host));

    let effective_jump_hosts = if jump_hosts.is_some() {
        jump_hosts
    } else {
        ssh_config_jump_hosts.as_deref()
    };

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
            effective_jump_hosts,
            connect_timeout_seconds,
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
) -> Result<PathBuf> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    // Determine effective jump hosts: CLI takes precedence, then SSH config
    let ssh_config_jump_hosts =
        ssh_config.and_then(|ssh_config| ssh_config.get_proxy_jump(&node.host));

    let effective_jump_hosts = if jump_hosts.is_some() {
        jump_hosts
    } else {
        ssh_config_jump_hosts.as_deref()
    };

    client
        .download_dir_with_jump_hosts(
            remote_path,
            local_path,
            key_path,
            Some(strict_mode),
            use_agent,
            use_password,
            effective_jump_hosts,
            connect_timeout_seconds,
        )
        .await?;

    Ok(local_path.to_path_buf())
}

/// Helper function to resolve effective jump hosts with priority:
/// 1. CLI jump hosts (highest priority)
/// 2. SSH config ProxyJump for the specific host
/// 3. None (direct connection)
///
/// This is extracted for testing purposes and used internally by all connection functions.
#[allow(dead_code)] // Used for testing
#[inline]
fn resolve_effective_jump_hosts(
    cli_jump_hosts: Option<&str>,
    ssh_config: Option<&SshConfig>,
    hostname: &str,
) -> Option<String> {
    if cli_jump_hosts.is_some() {
        return cli_jump_hosts.map(String::from);
    }
    ssh_config.and_then(|config| config.get_proxy_jump(hostname))
}

#[cfg(test)]
mod tests {
    use super::*;

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
Host *.internal.example.com
    ProxyJump gateway.example.com

Host db.internal.example.com
    ProxyJump db-gateway.example.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        // Should match db.internal.example.com specifically
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

    /// Test ProxyJump none value (disables jump)
    #[test]
    fn test_resolve_effective_jump_hosts_none_value() {
        let ssh_config_content = r#"
Host *.example.com
    ProxyJump gateway.example.com

Host direct.example.com
    ProxyJump none
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        // direct.example.com should have ProxyJump explicitly set to "none"
        // Note: The actual handling of "none" as special value would be
        // done by the connection layer, but the config should return it
        let result = resolve_effective_jump_hosts(None, Some(&ssh_config), "direct.example.com");
        assert_eq!(result, Some("none".to_string()));
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

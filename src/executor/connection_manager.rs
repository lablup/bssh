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
    SshClient,
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
    pub jump_hosts: Option<&'a str>,
    pub sudo_password: Option<Arc<SudoPassword>>,
}

/// Execute a command on a node with jump host support.
pub(crate) async fn execute_on_node_with_jump_hosts(
    node: Node,
    command: &str,
    config: &ExecutionConfig<'_>,
) -> Result<CommandResult> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = config.key_path.map(Path::new);

    let connection_config = ConnectionConfig {
        key_path,
        strict_mode: Some(config.strict_mode),
        use_agent: config.use_agent,
        use_password: config.use_password,
        #[cfg(target_os = "macos")]
        use_keychain: config.use_keychain,
        timeout_seconds: config.timeout,
        jump_hosts_spec: config.jump_hosts,
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
) -> Result<()> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

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
                jump_hosts,
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
                jump_hosts,
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
) -> Result<PathBuf> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

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
            jump_hosts,
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
) -> Result<PathBuf> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    client
        .download_dir_with_jump_hosts(
            remote_path,
            local_path,
            key_path,
            Some(strict_mode),
            use_agent,
            use_password,
            jump_hosts,
        )
        .await?;

    Ok(local_path.to_path_buf())
}

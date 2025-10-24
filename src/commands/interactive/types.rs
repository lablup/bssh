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

//! Core types and structures for interactive mode

use anyhow::Result;
use russh::client::Msg;
use russh::Channel;
use std::path::PathBuf;
use tokio::time::Duration;

use crate::config::{Config, InteractiveConfig};
use crate::node::Node;
use crate::pty::PtyConfig;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::Client;

/// SSH output polling interval for responsive display
/// - 10ms provides very responsive output display
/// - Short enough to appear instantaneous to users
/// - Balances CPU usage with terminal responsiveness
pub const SSH_OUTPUT_POLL_INTERVAL_MS: u64 = 10;

/// Number of nodes to show in compact display format
/// - 3 nodes provides enough context without overwhelming output
/// - Shows first three nodes with ellipsis for remainder
/// - Keeps command prompts readable in multi-node mode
pub const NODES_TO_SHOW_IN_COMPACT: usize = 3;

/// Interactive mode command configuration
pub struct InteractiveCommand {
    pub single_node: bool,
    pub multiplex: bool,
    pub prompt_format: String,
    pub history_file: PathBuf,
    pub work_dir: Option<String>,
    pub nodes: Vec<Node>,
    pub config: Config,
    pub interactive_config: InteractiveConfig,
    pub cluster_name: Option<String>,
    // Authentication parameters (consistent with exec mode)
    pub key_path: Option<PathBuf>,
    pub use_agent: bool,
    pub use_password: bool,
    #[cfg(target_os = "macos")]
    pub use_keychain: bool,
    pub strict_mode: StrictHostKeyChecking,
    // Jump hosts
    pub jump_hosts: Option<String>,
    // PTY configuration
    pub pty_config: PtyConfig,
    pub use_pty: Option<bool>, // None = auto-detect, Some(true) = force, Some(false) = disable
}

/// Result of an interactive session
#[derive(Debug)]
pub struct InteractiveResult {
    pub duration: Duration,
    pub commands_executed: usize,
    pub nodes_connected: usize,
}

/// Represents the state of a connected node in interactive mode
pub(super) struct NodeSession {
    pub node: Node,
    #[allow(dead_code)]
    pub client: Client,
    pub channel: Channel<Msg>,
    pub working_dir: String,
    pub is_connected: bool,
    pub is_active: bool, // Whether this node is currently active for commands
}

impl NodeSession {
    /// Create a new NodeSession
    pub fn new(node: Node, client: Client, channel: Channel<Msg>, working_dir: String) -> Self {
        Self {
            node,
            client,
            channel,
            working_dir,
            is_connected: true,
            is_active: true,
        }
    }

    /// Send a command to this node's shell
    pub async fn send_command(&mut self, command: &str) -> Result<()> {
        let data = format!("{command}\n");
        self.channel.data(data.as_bytes()).await?;
        Ok(())
    }

    /// Read available output from this node
    pub async fn read_output(&mut self) -> Result<Option<String>> {
        // SSH channel read timeout design:
        // - 100ms prevents blocking while waiting for output
        // - Short enough to maintain interactive responsiveness
        // - Allows polling loop to check for other events (shutdown, input)
        const SSH_OUTPUT_READ_TIMEOUT_MS: u64 = 100;
        match tokio::time::timeout(
            Duration::from_millis(SSH_OUTPUT_READ_TIMEOUT_MS),
            self.channel.wait(),
        )
        .await
        {
            Ok(Some(msg)) => match msg {
                russh::ChannelMsg::Data { ref data } => {
                    Ok(Some(String::from_utf8_lossy(data).to_string()))
                }
                russh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        // stderr
                        Ok(Some(String::from_utf8_lossy(data).to_string()))
                    } else {
                        Ok(None)
                    }
                }
                russh::ChannelMsg::Eof => {
                    self.is_connected = false;
                    Ok(None)
                }
                russh::ChannelMsg::Close => {
                    self.is_connected = false;
                    Ok(None)
                }
                _ => Ok(None),
            },
            Ok(None) => Ok(None),
            Err(_) => Ok(None), // Timeout, no data available
        }
    }
}

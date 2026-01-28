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

//! Configuration type definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main configuration structure.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,

    #[serde(default)]
    pub clusters: HashMap<String, Cluster>,

    #[serde(default)]
    pub interactive: InteractiveConfig,
}

/// Jump host configuration format.
///
/// Supports multiple formats:
/// - Legacy string format: `"[user@]hostname[:port]"`
/// - SSH config reference: `"@alias"` (references ~/.ssh/config Host alias)
/// - Structured format with optional ssh_key
/// - Structured SSH config reference with ssh_config_host field
///
/// Uses `#[serde(untagged)]` to allow seamless deserialization of all formats.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum JumpHostConfig {
    /// Structured SSH config reference format with ssh_config_host field
    /// Must be listed first for serde to try matching object format before string
    SshConfigHostRef {
        /// SSH config Host alias to reference (from ~/.ssh/config)
        ssh_config_host: String,
    },
    /// Structured format with optional ssh_key field
    Detailed {
        host: String,
        #[serde(default)]
        user: Option<String>,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        ssh_key: Option<String>,
    },
    /// Legacy string format: "[user@]hostname[:port]"
    /// Also supports SSH config reference with "@" prefix: "@alias"
    Simple(String),
}

/// Global default settings.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Defaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub ssh_key: Option<String>,
    pub parallel: Option<usize>,
    pub timeout: Option<u64>,
    /// Jump host specification for all connections.
    /// Supports both string format and structured format with optional ssh_key.
    /// Empty string explicitly disables jump host inheritance.
    pub jump_host: Option<JumpHostConfig>,
    /// SSH keepalive interval in seconds.
    /// Sends keepalive packets to prevent idle connection timeouts.
    /// Default: 60 seconds. Set to 0 to disable.
    pub server_alive_interval: Option<u64>,
    /// Maximum keepalive messages without response before disconnect.
    /// Default: 3
    pub server_alive_count_max: Option<usize>,
}

/// Interactive mode configuration.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct InteractiveConfig {
    #[serde(default = "default_interactive_mode")]
    pub default_mode: InteractiveMode,

    #[serde(default = "default_prompt_format")]
    pub prompt_format: String,

    #[serde(default)]
    pub history_file: Option<String>,

    #[serde(default)]
    pub colors: HashMap<String, String>,

    #[serde(default)]
    pub keybindings: KeyBindings,

    #[serde(default)]
    pub broadcast_prefix: Option<String>,

    #[serde(default)]
    pub node_switch_prefix: Option<String>,

    #[serde(default)]
    pub show_timestamps: bool,

    #[serde(default)]
    pub work_dir: Option<String>,
}

/// Interactive mode type.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum InteractiveMode {
    #[default]
    SingleNode,
    Multiplex,
}

/// Keyboard bindings configuration.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct KeyBindings {
    #[serde(default = "default_switch_node")]
    pub switch_node: String,

    #[serde(default = "default_broadcast_toggle")]
    pub broadcast_toggle: String,

    #[serde(default = "default_quit")]
    pub quit: String,

    #[serde(default)]
    pub clear_screen: Option<String>,
}

/// Cluster configuration.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Cluster {
    pub nodes: Vec<NodeConfig>,

    #[serde(flatten)]
    pub defaults: ClusterDefaults,

    #[serde(default)]
    pub interactive: Option<InteractiveConfig>,
}

/// Cluster-specific default settings.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ClusterDefaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub ssh_key: Option<String>,
    pub parallel: Option<usize>,
    pub timeout: Option<u64>,
    /// Jump host specification for this cluster.
    /// Supports both string format and structured format with optional ssh_key.
    /// Empty string explicitly disables jump host inheritance.
    pub jump_host: Option<JumpHostConfig>,
    /// SSH keepalive interval in seconds.
    /// Sends keepalive packets to prevent idle connection timeouts.
    /// Default: 60 seconds. Set to 0 to disable.
    pub server_alive_interval: Option<u64>,
    /// Maximum keepalive messages without response before disconnect.
    /// Default: 3
    pub server_alive_count_max: Option<usize>,
}

/// Node configuration within a cluster.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum NodeConfig {
    Simple(String),
    Detailed {
        host: String,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        user: Option<String>,
        /// Jump host specification for this node.
        /// Supports both string format and structured format with optional ssh_key.
        /// Empty string explicitly disables jump host inheritance.
        #[serde(default)]
        jump_host: Option<JumpHostConfig>,
    },
}

/// Structure for updating interactive configuration preferences.
#[derive(Debug, Default)]
pub struct InteractiveConfigUpdate {
    pub default_mode: Option<InteractiveMode>,
    pub prompt_format: Option<String>,
    pub history_file: Option<String>,
    pub work_dir: Option<String>,
    pub show_timestamps: Option<bool>,
    pub colors: Option<HashMap<String, String>>,
}

// Default value functions for serde
pub(super) fn default_interactive_mode() -> InteractiveMode {
    InteractiveMode::SingleNode
}

pub(super) fn default_prompt_format() -> String {
    "[{node}:{user}@{host}:{pwd}]$ ".to_string()
}

pub(super) fn default_switch_node() -> String {
    "Ctrl+N".to_string()
}

pub(super) fn default_broadcast_toggle() -> String {
    "Ctrl+B".to_string()
}

pub(super) fn default_quit() -> String {
    "Ctrl+Q".to_string()
}

impl JumpHostConfig {
    /// Convert to a connection string for resolution.
    ///
    /// Note: For SSH config references (`@alias` or `ssh_config_host`), this returns
    /// the alias name with "@" prefix. The actual resolution to hostname/user/port
    /// must be done by the caller using SSH config parsing.
    pub fn to_connection_string(&self) -> String {
        match self {
            JumpHostConfig::Simple(s) => s.clone(),
            JumpHostConfig::Detailed {
                host,
                user,
                port,
                ssh_key: _,
            } => {
                let mut result = String::new();
                if let Some(u) = user {
                    result.push_str(u);
                    result.push('@');
                }
                result.push_str(host);
                if let Some(p) = port {
                    result.push(':');
                    result.push_str(&p.to_string());
                }
                result
            }
            JumpHostConfig::SshConfigHostRef { ssh_config_host } => {
                format!("@{}", ssh_config_host)
            }
        }
    }

    /// Get the SSH key path if specified
    pub fn ssh_key(&self) -> Option<&str> {
        match self {
            JumpHostConfig::Simple(_) => None,
            JumpHostConfig::Detailed { ssh_key, .. } => ssh_key.as_deref(),
            JumpHostConfig::SshConfigHostRef { .. } => None,
        }
    }

    /// Check if this is an SSH config reference (either `@alias` string or `ssh_config_host` field)
    pub fn is_ssh_config_ref(&self) -> bool {
        match self {
            JumpHostConfig::Simple(s) => s.starts_with('@'),
            JumpHostConfig::SshConfigHostRef { .. } => true,
            JumpHostConfig::Detailed { .. } => false,
        }
    }

    /// Get the SSH config host alias if this is an SSH config reference.
    ///
    /// Returns the alias name (without "@" prefix) for:
    /// - `JumpHostConfig::Simple("@alias")` -> Some("alias")
    /// - `JumpHostConfig::SshConfigHostRef { ssh_config_host: "alias" }` -> Some("alias")
    /// - Other variants -> None
    pub fn ssh_config_host(&self) -> Option<&str> {
        match self {
            JumpHostConfig::Simple(s) if s.starts_with('@') => Some(&s[1..]),
            JumpHostConfig::SshConfigHostRef { ssh_config_host } => Some(ssh_config_host),
            _ => None,
        }
    }
}

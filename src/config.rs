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

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::node::Node;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,

    #[serde(default)]
    pub clusters: HashMap<String, Cluster>,

    #[serde(default)]
    pub interactive: InteractiveConfig,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Defaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub ssh_key: Option<String>,
    pub parallel: Option<usize>,
    pub timeout: Option<u64>,
}

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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum InteractiveMode {
    #[default]
    SingleNode,
    Multiplex,
}

fn default_interactive_mode() -> InteractiveMode {
    InteractiveMode::SingleNode
}

fn default_prompt_format() -> String {
    "[{node}:{user}@{host}:{pwd}]$ ".to_string()
}

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

fn default_switch_node() -> String {
    "Ctrl+N".to_string()
}

fn default_broadcast_toggle() -> String {
    "Ctrl+B".to_string()
}

fn default_quit() -> String {
    "Ctrl+Q".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Cluster {
    pub nodes: Vec<NodeConfig>,

    #[serde(flatten)]
    pub defaults: ClusterDefaults,

    #[serde(default)]
    pub interactive: Option<InteractiveConfig>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ClusterDefaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub ssh_key: Option<String>,
    pub parallel: Option<usize>,
    pub timeout: Option<u64>,
}

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
    },
}

impl Config {
    pub async fn load(path: &Path) -> Result<Self> {
        // Expand tilde in path
        let expanded_path = expand_tilde(path);

        if !expanded_path.exists() {
            tracing::debug!(
                "Config file not found at {:?}, using defaults",
                expanded_path
            );
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&expanded_path)
            .await
            .with_context(|| format!("Failed to read configuration file at {}. Please check file permissions and ensure the file is accessible.", expanded_path.display()))?;

        let config: Config =
            serde_yaml::from_str(&content).with_context(|| format!("Failed to parse YAML configuration file at {}. Please check the YAML syntax is valid.\nCommon issues:\n  - Incorrect indentation (use spaces, not tabs)\n  - Missing colons after keys\n  - Unquoted special characters", expanded_path.display()))?;

        Ok(config)
    }

    /// Create a cluster configuration from Backend.AI environment variables
    pub fn from_backendai_env() -> Option<Cluster> {
        let cluster_hosts = env::var("BACKENDAI_CLUSTER_HOSTS").ok()?;
        let _current_host = env::var("BACKENDAI_CLUSTER_HOST").ok()?;
        let cluster_role = env::var("BACKENDAI_CLUSTER_ROLE").ok();

        // Parse the hosts into nodes
        let mut nodes = Vec::new();
        for host in cluster_hosts.split(',') {
            let host = host.trim();
            if !host.is_empty() {
                // Get current user as default
                let default_user = env::var("USER")
                    .or_else(|_| env::var("USERNAME"))
                    .or_else(|_| env::var("LOGNAME"))
                    .unwrap_or_else(|_| {
                        // Try to get current user from system
                        #[cfg(unix)]
                        {
                            whoami::username()
                        }
                        #[cfg(not(unix))]
                        {
                            "user".to_string()
                        }
                    });

                // Backend.AI multi-node clusters use port 2200 by default
                nodes.push(NodeConfig::Simple(format!("{default_user}@{host}:2200")));
            }
        }

        if nodes.is_empty() {
            return None;
        }

        // Check if we should filter nodes based on role
        let filtered_nodes = if let Some(role) = &cluster_role {
            if role == "main" {
                // If current node is main, execute on all nodes
                nodes
            } else {
                // If current node is sub, only execute on sub nodes
                // We need to identify which nodes are sub nodes
                // For now, we'll execute on all nodes except the main (first) node
                nodes.into_iter().skip(1).collect()
            }
        } else {
            nodes
        };

        Some(Cluster {
            nodes: filtered_nodes,
            defaults: ClusterDefaults {
                ssh_key: Some("/home/config/ssh/id_cluster".to_string()),
                ..ClusterDefaults::default()
            },
            interactive: None,
        })
    }

    /// Load configuration with priority order:
    /// 1. Explicit --config path (if exists and different from default)
    /// 2. Backend.AI environment variables
    /// 3. Current directory config.yaml
    /// 4. XDG config directory ($XDG_CONFIG_HOME/bssh/config.yaml or ~/.config/bssh/config.yaml)
    /// 5. Default path (~/.config/bssh/config.yaml)
    pub async fn load_with_priority(cli_config_path: &Path) -> Result<Self> {
        let default_config_path = PathBuf::from("~/.config/bssh/config.yaml");
        let expanded_cli_path = expand_tilde(cli_config_path);
        let expanded_default_path = expand_tilde(&default_config_path);

        // Check if user explicitly specified a config file (different from default)
        let is_custom_config = expanded_cli_path != expanded_default_path;

        if is_custom_config && expanded_cli_path.exists() {
            // User explicitly specified a config file and it exists - use it with highest priority
            tracing::debug!(
                "Using explicitly specified config file: {:?}",
                expanded_cli_path
            );
            return Self::load(&expanded_cli_path).await;
        } else if is_custom_config {
            // Custom config specified but doesn't exist - log and continue
            tracing::debug!(
                "Custom config file not found, continuing with other sources: {:?}",
                expanded_cli_path
            );
        }

        // Check for Backend.AI environment first
        if let Some(backendai_cluster) = Self::from_backendai_env() {
            tracing::debug!("Using Backend.AI cluster configuration from environment");
            let mut config = Self::default();
            config
                .clusters
                .insert("bai_auto".to_string(), backendai_cluster);
            return Ok(config);
        }

        // Load configuration from standard locations
        Self::load_from_standard_locations().await.or_else(|_| {
            tracing::debug!("No config file found, using default empty configuration");
            Ok(Self::default())
        })
    }

    /// Load configuration from standard locations (helper method)
    async fn load_from_standard_locations() -> Result<Self> {
        // Try current directory config.yaml
        let current_dir_config = PathBuf::from("config.yaml");
        if current_dir_config.exists() {
            tracing::debug!("Found config.yaml in current directory");
            if let Ok(config) = Self::load(&current_dir_config).await {
                return Ok(config);
            }
        }

        // Try XDG config directory
        if let Ok(xdg_config_home) = env::var("XDG_CONFIG_HOME") {
            // Use XDG_CONFIG_HOME if set
            let xdg_config = PathBuf::from(xdg_config_home)
                .join("bssh")
                .join("config.yaml");
            tracing::debug!("Checking XDG_CONFIG_HOME path: {:?}", xdg_config);
            if xdg_config.exists() {
                tracing::debug!("Found config at XDG_CONFIG_HOME: {:?}", xdg_config);
                if let Ok(config) = Self::load(&xdg_config).await {
                    return Ok(config);
                }
            }
        } else {
            // Fallback to ~/.config/bssh/config.yaml if XDG_CONFIG_HOME is not set
            if let Ok(home) = env::var("HOME") {
                let xdg_config = PathBuf::from(home)
                    .join(".config")
                    .join("bssh")
                    .join("config.yaml");
                tracing::debug!("Checking ~/.config/bssh path: {:?}", xdg_config);
                if xdg_config.exists() {
                    tracing::debug!("Found config at ~/.config/bssh: {:?}", xdg_config);
                    if let Ok(config) = Self::load(&xdg_config).await {
                        return Ok(config);
                    }
                }
            }
        }

        // No config file found
        anyhow::bail!("No configuration file found")
    }

    pub fn get_cluster(&self, name: &str) -> Option<&Cluster> {
        self.clusters.get(name)
    }

    pub fn resolve_nodes(&self, cluster_name: &str) -> Result<Vec<Node>> {
        let cluster = self
            .get_cluster(cluster_name)
            .ok_or_else(|| anyhow::anyhow!("Cluster '{}' not found in configuration.\nAvailable clusters: {}\nPlease check your configuration file or use 'bssh list' to see available clusters.", cluster_name, self.clusters.keys().cloned().collect::<Vec<_>>().join(", ")))?;

        let mut nodes = Vec::new();

        for node_config in &cluster.nodes {
            let node = match node_config {
                NodeConfig::Simple(host) => {
                    // Expand environment variables in host
                    let expanded_host = expand_env_vars(host);

                    let default_user = cluster
                        .defaults
                        .user
                        .as_ref()
                        .or(self.defaults.user.as_ref())
                        .map(|u| expand_env_vars(u));

                    let default_port = cluster.defaults.port.or(self.defaults.port).unwrap_or(22);

                    Node::parse(&expanded_host, default_user.as_deref()).map(|mut n| {
                        if !expanded_host.contains(':') {
                            n.port = default_port;
                        }
                        n
                    })?
                }
                NodeConfig::Detailed { host, port, user } => {
                    // Expand environment variables
                    let expanded_host = expand_env_vars(host);

                    let username = user
                        .as_ref()
                        .map(|u| expand_env_vars(u))
                        .or_else(|| cluster.defaults.user.as_ref().map(|u| expand_env_vars(u)))
                        .or_else(|| self.defaults.user.as_ref().map(|u| expand_env_vars(u)))
                        .unwrap_or_else(|| {
                            std::env::var("USER")
                                .or_else(|_| std::env::var("USERNAME"))
                                .or_else(|_| std::env::var("LOGNAME"))
                                .unwrap_or_else(|_| {
                                    // Try to get current user from system
                                    #[cfg(unix)]
                                    {
                                        whoami::username()
                                    }
                                    #[cfg(not(unix))]
                                    {
                                        "user".to_string()
                                    }
                                })
                        });

                    let port = port
                        .or(cluster.defaults.port)
                        .or(self.defaults.port)
                        .unwrap_or(22);

                    Node::new(expanded_host, port, username)
                }
            };

            nodes.push(node);
        }

        Ok(nodes)
    }

    pub fn get_ssh_key(&self, cluster_name: Option<&str>) -> Option<String> {
        if let Some(cluster_name) = cluster_name {
            if let Some(cluster) = self.get_cluster(cluster_name) {
                if let Some(key) = &cluster.defaults.ssh_key {
                    return Some(key.clone());
                }
            }
        }

        self.defaults.ssh_key.clone()
    }

    pub fn get_timeout(&self, cluster_name: Option<&str>) -> Option<u64> {
        if let Some(cluster_name) = cluster_name {
            if let Some(cluster) = self.get_cluster(cluster_name) {
                if let Some(timeout) = cluster.defaults.timeout {
                    return Some(timeout);
                }
            }
        }

        self.defaults.timeout
    }

    pub fn get_parallel(&self, cluster_name: Option<&str>) -> Option<usize> {
        if let Some(cluster_name) = cluster_name {
            if let Some(cluster) = self.get_cluster(cluster_name) {
                if let Some(parallel) = cluster.defaults.parallel {
                    return Some(parallel);
                }
            }
        }

        self.defaults.parallel
    }

    /// Get interactive configuration for a cluster (with fallback to global)
    pub fn get_interactive_config(&self, cluster_name: Option<&str>) -> InteractiveConfig {
        let mut config = self.interactive.clone();

        if let Some(cluster_name) = cluster_name {
            if let Some(cluster) = self.get_cluster(cluster_name) {
                if let Some(ref cluster_interactive) = cluster.interactive {
                    // Merge cluster-specific overrides with global config
                    // Cluster settings take precedence where specified
                    config.default_mode = cluster_interactive.default_mode.clone();

                    if !cluster_interactive.prompt_format.is_empty() {
                        config.prompt_format = cluster_interactive.prompt_format.clone();
                    }

                    if cluster_interactive.history_file.is_some() {
                        config.history_file = cluster_interactive.history_file.clone();
                    }

                    if cluster_interactive.work_dir.is_some() {
                        config.work_dir = cluster_interactive.work_dir.clone();
                    }

                    if cluster_interactive.broadcast_prefix.is_some() {
                        config.broadcast_prefix = cluster_interactive.broadcast_prefix.clone();
                    }

                    if cluster_interactive.node_switch_prefix.is_some() {
                        config.node_switch_prefix = cluster_interactive.node_switch_prefix.clone();
                    }

                    // Note: For booleans, we always use the cluster value since there's no "unset" state
                    config.show_timestamps = cluster_interactive.show_timestamps;

                    // Merge colors (cluster colors override global ones)
                    for (k, v) in &cluster_interactive.colors {
                        config.colors.insert(k.clone(), v.clone());
                    }

                    // Merge keybindings
                    if !cluster_interactive.keybindings.switch_node.is_empty() {
                        config.keybindings.switch_node =
                            cluster_interactive.keybindings.switch_node.clone();
                    }
                    if !cluster_interactive.keybindings.broadcast_toggle.is_empty() {
                        config.keybindings.broadcast_toggle =
                            cluster_interactive.keybindings.broadcast_toggle.clone();
                    }
                    if !cluster_interactive.keybindings.quit.is_empty() {
                        config.keybindings.quit = cluster_interactive.keybindings.quit.clone();
                    }
                    if cluster_interactive.keybindings.clear_screen.is_some() {
                        config.keybindings.clear_screen =
                            cluster_interactive.keybindings.clear_screen.clone();
                    }
                }
            }
        }

        config
    }

    /// Save the configuration to a file
    pub async fn save(&self, path: &Path) -> Result<()> {
        let expanded_path = expand_tilde(path);

        // Ensure parent directory exists
        if let Some(parent) = expanded_path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create directory {parent:?}"))?;
        }

        let yaml =
            serde_yaml::to_string(self).context("Failed to serialize configuration to YAML")?;

        fs::write(&expanded_path, yaml)
            .await
            .with_context(|| format!("Failed to write configuration to {expanded_path:?}"))?;

        Ok(())
    }

    /// Update interactive preferences and save to the default config file
    pub async fn update_interactive_preferences(
        &mut self,
        cluster_name: Option<&str>,
        updates: InteractiveConfigUpdate,
    ) -> Result<()> {
        let target_config = if let Some(cluster_name) = cluster_name {
            if let Some(cluster) = self.clusters.get_mut(cluster_name) {
                // Update cluster-specific config
                if cluster.interactive.is_none() {
                    cluster.interactive = Some(InteractiveConfig::default());
                }
                cluster.interactive.as_mut().unwrap()
            } else {
                // Update global config
                &mut self.interactive
            }
        } else {
            // Update global config
            &mut self.interactive
        };

        // Apply updates
        if let Some(mode) = updates.default_mode {
            target_config.default_mode = mode;
        }
        if let Some(prompt) = updates.prompt_format {
            target_config.prompt_format = prompt;
        }
        if let Some(history) = updates.history_file {
            target_config.history_file = Some(history);
        }
        if let Some(work_dir) = updates.work_dir {
            target_config.work_dir = Some(work_dir);
        }
        if let Some(timestamps) = updates.show_timestamps {
            target_config.show_timestamps = timestamps;
        }
        if let Some(colors) = updates.colors {
            target_config.colors.extend(colors);
        }

        // Save to the appropriate config file
        let config_path = self.get_config_path()?;
        self.save(&config_path).await?;

        Ok(())
    }

    /// Get the path to the configuration file (for saving)
    fn get_config_path(&self) -> Result<PathBuf> {
        // Priority order for determining config file path:
        // 1. Current directory config.yaml (if it exists)
        // 2. XDG config directory
        // 3. Default ~/.bssh/config.yaml

        let current_dir_config = PathBuf::from("config.yaml");
        if current_dir_config.exists() {
            return Ok(current_dir_config);
        }

        // Try XDG config directory
        if let Ok(xdg_config_home) = env::var("XDG_CONFIG_HOME") {
            let xdg_config = PathBuf::from(xdg_config_home)
                .join("bssh")
                .join("config.yaml");
            return Ok(xdg_config);
        } else if let Some(proj_dirs) = ProjectDirs::from("", "", "bssh") {
            let xdg_config = proj_dirs.config_dir().join("config.yaml");
            return Ok(xdg_config);
        }

        // Default to ~/.bssh/config.yaml
        let home = env::var("HOME")
            .or_else(|_| env::var("USERPROFILE"))
            .context("Unable to determine home directory")?;
        Ok(PathBuf::from(home).join(".bssh").join("config.yaml"))
    }
}

/// Structure for updating interactive configuration preferences
#[derive(Debug, Default)]
pub struct InteractiveConfigUpdate {
    pub default_mode: Option<InteractiveMode>,
    pub prompt_format: Option<String>,
    pub history_file: Option<String>,
    pub work_dir: Option<String>,
    pub show_timestamps: Option<bool>,
    pub colors: Option<HashMap<String, String>>,
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    if let Some(path_str) = path.to_str() {
        if path_str.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(path_str.replacen("~", &home, 1));
            }
        }
    }
    path.to_path_buf()
}

/// Expand environment variables in a string
/// Supports ${VAR} and $VAR syntax
fn expand_env_vars(input: &str) -> String {
    let mut result = input.to_string();
    let mut processed = 0;

    // Handle ${VAR} syntax
    while processed < result.len() {
        if let Some(start) = result[processed..].find("${") {
            let abs_start = processed + start;
            if let Some(end) = result[abs_start..].find('}') {
                let var_name = &result[abs_start + 2..abs_start + end];
                if !var_name.is_empty() && var_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    let replacement = std::env::var(var_name).unwrap_or_else(|_| {
                        tracing::debug!("Environment variable {} not found", var_name);
                        format!("${{{var_name}}}")
                    });
                    result.replace_range(abs_start..abs_start + end + 1, &replacement);
                    processed = abs_start + replacement.len();
                } else {
                    processed = abs_start + end + 1;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    // Handle $VAR syntax (but be careful not to expand ${} again)
    let mut i = 0;
    let bytes = result.as_bytes();
    let mut new_result = String::new();

    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] != b'{' {
            let start = i;
            i += 1;

            // Find the end of the variable name
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }

            if i > start + 1 {
                let var_name = std::str::from_utf8(&bytes[start + 1..i]).unwrap();
                let replacement = std::env::var(var_name).unwrap_or_else(|_| {
                    tracing::debug!("Environment variable {} not found", var_name);
                    String::from_utf8(bytes[start..i].to_vec()).unwrap()
                });
                new_result.push_str(&replacement);
            } else {
                new_result.push('$');
            }
        } else {
            new_result.push(bytes[i] as char);
            i += 1;
        }
    }

    new_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_env_vars() {
        unsafe {
            std::env::set_var("TEST_VAR", "test_value");
            std::env::set_var("TEST_USER", "testuser");
        }

        // Test ${VAR} syntax
        assert_eq!(expand_env_vars("Hello ${TEST_VAR}!"), "Hello test_value!");
        assert_eq!(expand_env_vars("${TEST_USER}@host"), "testuser@host");

        // Test $VAR syntax
        assert_eq!(expand_env_vars("Hello $TEST_VAR!"), "Hello test_value!");
        assert_eq!(expand_env_vars("$TEST_USER@host"), "testuser@host");

        // Test mixed
        assert_eq!(
            expand_env_vars("${TEST_USER}:$TEST_VAR"),
            "testuser:test_value"
        );

        // Test non-existent variable (should leave as-is)
        assert_eq!(expand_env_vars("${NONEXISTENT}"), "${NONEXISTENT}");
        assert_eq!(expand_env_vars("$NONEXISTENT"), "$NONEXISTENT");

        // Test no variables
        assert_eq!(expand_env_vars("no variables here"), "no variables here");
    }

    #[test]
    fn test_expand_tilde() {
        // Save original HOME value
        let original_home = std::env::var("HOME").ok();

        // Set test HOME value
        std::env::set_var("HOME", "/home/user");

        let path = Path::new("~/.ssh/config");
        let expanded = expand_tilde(path);

        // Restore original HOME value
        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        } else {
            std::env::remove_var("HOME");
        }

        assert_eq!(expanded, PathBuf::from("/home/user/.ssh/config"));
    }

    #[test]
    fn test_config_parsing() {
        let yaml = r#"
defaults:
  user: admin
  port: 22
  ssh_key: ~/.ssh/id_rsa

interactive:
  default_mode: multiplex
  prompt_format: "[{node}] $ "
  history_file: ~/.bssh_history
  show_timestamps: true
  colors:
    node1: red
    node2: blue
  keybindings:
    switch_node: "Ctrl+T"
    broadcast_toggle: "Ctrl+A"

clusters:
  production:
    nodes:
      - web1.example.com
      - web2.example.com:2222
      - user@web3.example.com
    ssh_key: ~/.ssh/prod_key
    interactive:
      default_mode: single_node
      prompt_format: "prod> "
  
  staging:
    nodes:
      - host: staging1.example.com
        port: 2200
        user: deploy
      - staging2.example.com
    user: staging_user
"#;

        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.defaults.user, Some("admin".to_string()));
        assert_eq!(config.clusters.len(), 2);

        // Test global interactive config
        assert!(matches!(
            config.interactive.default_mode,
            InteractiveMode::Multiplex
        ));
        assert_eq!(config.interactive.prompt_format, "[{node}] $ ");
        assert_eq!(
            config.interactive.history_file,
            Some("~/.bssh_history".to_string())
        );
        assert!(config.interactive.show_timestamps);
        assert_eq!(
            config.interactive.colors.get("node1"),
            Some(&"red".to_string())
        );
        assert_eq!(config.interactive.keybindings.switch_node, "Ctrl+T");

        let prod_cluster = config.get_cluster("production").unwrap();
        assert_eq!(prod_cluster.nodes.len(), 3);
        assert_eq!(
            prod_cluster.defaults.ssh_key,
            Some("~/.ssh/prod_key".to_string())
        );

        // Test cluster-specific interactive config
        let prod_interactive = prod_cluster.interactive.as_ref().unwrap();
        assert!(matches!(
            prod_interactive.default_mode,
            InteractiveMode::SingleNode
        ));
        assert_eq!(prod_interactive.prompt_format, "prod> ");
    }

    #[test]
    fn test_interactive_config_fallback() {
        let yaml = r#"
interactive:
  default_mode: multiplex
  prompt_format: "global> "
  show_timestamps: true

clusters:
  with_override:
    nodes:
      - host1
    interactive:
      default_mode: multiplex
      prompt_format: "override> "
  
  without_override:
    nodes:
      - host2
"#;

        let config: Config = serde_yaml::from_str(yaml).unwrap();

        // Test cluster with override - merged config
        let with_override = config.get_interactive_config(Some("with_override"));
        assert_eq!(with_override.prompt_format, "override> ");
        assert!(matches!(
            with_override.default_mode,
            InteractiveMode::Multiplex
        ));
        // Note: show_timestamps uses cluster value (default false) since we can't tell if it was explicitly set

        // Test cluster without override (falls back to global)
        let without_override = config.get_interactive_config(Some("without_override"));
        assert_eq!(without_override.prompt_format, "global> ");
        assert!(matches!(
            without_override.default_mode,
            InteractiveMode::Multiplex
        ));
        assert!(without_override.show_timestamps);

        // Test global config when no cluster specified
        let global = config.get_interactive_config(None);
        assert_eq!(global.prompt_format, "global> ");
        assert!(matches!(global.default_mode, InteractiveMode::Multiplex));
    }

    #[test]
    fn test_backendai_env_parsing() {
        // Set up Backend.AI environment variables
        unsafe {
            std::env::set_var("BACKENDAI_CLUSTER_HOSTS", "sub1,main1");
            std::env::set_var("BACKENDAI_CLUSTER_HOST", "main1");
            std::env::set_var("BACKENDAI_CLUSTER_ROLE", "main");
            std::env::set_var("USER", "testuser");
        }

        let cluster = Config::from_backendai_env().unwrap();

        // Should have 2 nodes when role is "main"
        assert_eq!(cluster.nodes.len(), 2);

        // Check first node (should include port 2200)
        match &cluster.nodes[0] {
            NodeConfig::Simple(host) => {
                assert_eq!(host, "testuser@sub1:2200");
            }
            _ => panic!("Expected Simple node config"),
        }

        // Test with sub role - should skip the first (main) node
        unsafe {
            std::env::set_var("BACKENDAI_CLUSTER_ROLE", "sub");
        }
        let cluster = Config::from_backendai_env().unwrap();
        assert_eq!(cluster.nodes.len(), 1);

        match &cluster.nodes[0] {
            NodeConfig::Simple(host) => {
                assert_eq!(host, "testuser@main1:2200");
            }
            _ => panic!("Expected Simple node config"),
        }

        // Clean up
        unsafe {
            std::env::remove_var("BACKENDAI_CLUSTER_HOSTS");
            std::env::remove_var("BACKENDAI_CLUSTER_HOST");
            std::env::remove_var("BACKENDAI_CLUSTER_ROLE");
        }
    }
}

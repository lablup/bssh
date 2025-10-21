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

//! Configuration loading and priority management.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::env;
use std::path::{Path, PathBuf};
use tokio::fs;

use super::types::{Cluster, ClusterDefaults, Config, NodeConfig};
use super::utils::{expand_tilde, get_current_username};

impl Config {
    /// Load configuration from a file.
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

    /// Create a cluster configuration from Backend.AI environment variables.
    pub fn from_backendai_env() -> Option<Cluster> {
        let cluster_hosts = env::var("BACKENDAI_CLUSTER_HOSTS").ok()?;
        let _current_host = env::var("BACKENDAI_CLUSTER_HOST").ok()?;
        let cluster_role = env::var("BACKENDAI_CLUSTER_ROLE").ok();

        // Parse the hosts into nodes
        let mut nodes = Vec::new();
        for host in cluster_hosts.split(',') {
            let host = host.trim();
            if !host.is_empty() {
                let default_user = get_current_username();
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

    /// Load configuration from standard locations (helper method).
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

    /// Save the configuration to a file.
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

    /// Get the path to the configuration file (for saving).
    pub(crate) fn get_config_path(&self) -> Result<PathBuf> {
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

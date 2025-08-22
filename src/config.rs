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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::node::Node;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,

    #[serde(default)]
    pub clusters: HashMap<String, Cluster>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Defaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub ssh_key: Option<String>,
    pub parallel: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Cluster {
    pub nodes: Vec<NodeConfig>,

    #[serde(flatten)]
    pub defaults: ClusterDefaults,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ClusterDefaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub ssh_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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
            .with_context(|| format!("Failed to read configuration file at {expanded_path:?}. Please check file permissions and ensure the file is accessible."))?;

        let config: Config =
            serde_yaml::from_str(&content).with_context(|| format!("Failed to parse YAML configuration file at {expanded_path:?}. Please check the YAML syntax is valid.\nCommon issues:\n  - Incorrect indentation (use spaces, not tabs)\n  - Missing colons after keys\n  - Unquoted special characters"))?;

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
                    .unwrap_or_else(|_| "root".to_string());

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
            defaults: ClusterDefaults::default(),
        })
    }

    /// Load configuration with priority order:
    /// 1. Backend.AI environment variables
    /// 2. Current directory config.yaml
    /// 3. User home directory ~/.config/bssh/config.yaml
    /// 4. Default path (usually ~/.bssh/config.yaml)
    pub async fn load_with_priority(default_path: &Path) -> Result<Self> {
        // Try Backend.AI environment first
        if let Some(backendai_cluster) = Self::from_backendai_env() {
            let mut config = Self::default();
            config
                .clusters
                .insert("backendai".to_string(), backendai_cluster);
            return Ok(config);
        }

        // Try current directory config.yaml
        let current_dir_config = PathBuf::from("config.yaml");
        if current_dir_config.exists()
            && let Ok(config) = Self::load(&current_dir_config).await
        {
            return Ok(config);
        }

        // Try ~/.config/bssh/config.yaml
        if let Some(home_dir) = dirs::home_dir() {
            let home_config = home_dir.join(".config").join("bssh").join("config.yaml");
            if home_config.exists()
                && let Ok(config) = Self::load(&home_config).await
            {
                return Ok(config);
            }
        }

        // Finally, try the default path
        Self::load(default_path).await
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
                            std::env::var("USER").unwrap_or_else(|_| "root".to_string())
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
        if let Some(cluster_name) = cluster_name
            && let Some(cluster) = self.get_cluster(cluster_name)
            && let Some(key) = &cluster.defaults.ssh_key
        {
            return Some(key.clone());
        }

        self.defaults.ssh_key.clone()
    }
}

fn expand_tilde(path: &Path) -> PathBuf {
    if let Some(path_str) = path.to_str()
        && path_str.starts_with("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(path_str.replacen("~", &home, 1));
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
        unsafe {
            std::env::set_var("HOME", "/home/user");
        }
        let path = Path::new("~/.ssh/config");
        let expanded = expand_tilde(path);
        assert_eq!(expanded, PathBuf::from("/home/user/.ssh/config"));
    }

    #[test]
    fn test_config_parsing() {
        let yaml = r#"
defaults:
  user: admin
  port: 22
  ssh_key: ~/.ssh/id_rsa

clusters:
  production:
    nodes:
      - web1.example.com
      - web2.example.com:2222
      - user@web3.example.com
    ssh_key: ~/.ssh/prod_key
  
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

        let prod_cluster = config.get_cluster("production").unwrap();
        assert_eq!(prod_cluster.nodes.len(), 3);
        assert_eq!(
            prod_cluster.defaults.ssh_key,
            Some("~/.ssh/prod_key".to_string())
        );
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

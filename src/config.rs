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
        if let Some(cluster_name) = cluster_name {
            if let Some(cluster) = self.get_cluster(cluster_name) {
                if let Some(key) = &cluster.defaults.ssh_key {
                    return Some(key.clone());
                }
            }
        }

        self.defaults.ssh_key.clone()
    }
}

fn expand_tilde(path: &Path) -> PathBuf {
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
        std::env::set_var("TEST_VAR", "test_value");
        std::env::set_var("TEST_USER", "testuser");

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
        std::env::set_var("HOME", "/home/user");
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
}

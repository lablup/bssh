use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::node::Node;

#[derive(Debug, Serialize, Deserialize)]
#[derive(Default)]
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
            .context("Failed to read config file")?;

        let config: Config =
            serde_yaml::from_str(&content).context("Failed to parse config file")?;

        Ok(config)
    }

    pub fn get_cluster(&self, name: &str) -> Option<&Cluster> {
        self.clusters.get(name)
    }

    pub fn resolve_nodes(&self, cluster_name: &str) -> Result<Vec<Node>> {
        let cluster = self
            .get_cluster(cluster_name)
            .ok_or_else(|| anyhow::anyhow!("Cluster '{}' not found", cluster_name))?;

        let mut nodes = Vec::new();

        for node_config in &cluster.nodes {
            let node = match node_config {
                NodeConfig::Simple(host) => {
                    let default_user = cluster
                        .defaults
                        .user
                        .as_deref()
                        .or(self.defaults.user.as_deref());

                    let default_port = cluster.defaults.port.or(self.defaults.port).unwrap_or(22);

                    Node::parse(host, default_user).map(|mut n| {
                        if !host.contains(':') {
                            n.port = default_port;
                        }
                        n
                    })?
                }
                NodeConfig::Detailed { host, port, user } => {
                    let username = user
                        .as_deref()
                        .or(cluster.defaults.user.as_deref())
                        .or(self.defaults.user.as_deref())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| {
                            std::env::var("USER").unwrap_or_else(|_| "root".to_string())
                        });

                    let port = port
                        .or(cluster.defaults.port)
                        .or(self.defaults.port)
                        .unwrap_or(22);

                    Node::new(host.clone(), port, username)
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

#[cfg(test)]
mod tests {
    use super::*;

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

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

//! Node resolution and cluster management.

use anyhow::Result;

use crate::node::Node;

use super::types::{Cluster, Config, NodeConfig};
use super::utils::{expand_env_vars, get_current_username};

impl Config {
    /// Get a cluster by name.
    pub fn get_cluster(&self, name: &str) -> Option<&Cluster> {
        self.clusters.get(name)
    }

    /// Resolve nodes for a cluster.
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
                NodeConfig::Detailed {
                    host, port, user, ..
                } => {
                    // Expand environment variables
                    let expanded_host = expand_env_vars(host);

                    let username = user
                        .as_ref()
                        .map(|u| expand_env_vars(u))
                        .or_else(|| cluster.defaults.user.as_ref().map(|u| expand_env_vars(u)))
                        .or_else(|| self.defaults.user.as_ref().map(|u| expand_env_vars(u)))
                        .unwrap_or_else(get_current_username);

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

    /// Get SSH key for a cluster.
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

    /// Get timeout for a cluster.
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

    /// Get parallelism level for a cluster.
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

    /// Get jump host for a specific node in a cluster.
    ///
    /// Resolution priority (highest to lowest):
    /// 1. Node-level `jump_host` (in `NodeConfig::Detailed`)
    /// 2. Cluster-level `jump_host` (in `ClusterDefaults`)
    /// 3. Global default `jump_host` (in `Defaults`)
    ///
    /// Empty string (`""`) explicitly disables jump host inheritance.
    pub fn get_jump_host(&self, cluster_name: &str, node_index: usize) -> Option<String> {
        if let Some(cluster) = self.get_cluster(cluster_name) {
            // Check node-level first
            if let Some(NodeConfig::Detailed {
                jump_host: Some(jh),
                ..
            }) = cluster.nodes.get(node_index)
            {
                if jh.is_empty() {
                    return None; // Explicitly disabled
                }
                return Some(jh.clone());
            }
            // Check cluster-level
            if let Some(jh) = &cluster.defaults.jump_host {
                if jh.is_empty() {
                    return None; // Explicitly disabled
                }
                return Some(jh.clone());
            }
        }
        // Fall back to global default
        self.defaults.jump_host.clone().filter(|s| !s.is_empty())
    }

    /// Get jump host for a cluster (cluster-level default).
    ///
    /// Resolution priority (highest to lowest):
    /// 1. Cluster-level `jump_host` (in `ClusterDefaults`)
    /// 2. Global default `jump_host` (in `Defaults`)
    ///
    /// Empty string (`""`) explicitly disables jump host inheritance.
    pub fn get_cluster_jump_host(&self, cluster_name: Option<&str>) -> Option<String> {
        if let Some(cluster_name) = cluster_name {
            if let Some(cluster) = self.get_cluster(cluster_name) {
                if let Some(jh) = &cluster.defaults.jump_host {
                    if jh.is_empty() {
                        return None; // Explicitly disabled
                    }
                    return Some(jh.clone());
                }
            }
        }
        // Fall back to global default
        self.defaults.jump_host.clone().filter(|s| !s.is_empty())
    }
}

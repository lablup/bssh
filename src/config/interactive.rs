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

//! Interactive configuration management.

use anyhow::Result;

use super::types::{Config, InteractiveConfig, InteractiveConfigUpdate};

impl Config {
    /// Get interactive configuration for a cluster (with fallback to global).
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

    /// Update interactive preferences and save to the default config file.
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
                cluster
                    .interactive
                    .as_mut()
                    .expect("interactive config should exist after initialization")
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
}

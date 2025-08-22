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

use owo_colors::OwoColorize;

use crate::config::{Config, NodeConfig};

pub fn list_clusters(config: &Config) {
    if config.clusters.is_empty() {
        println!("{}", "No clusters configured".dimmed());
        return;
    }

    println!("\n{} {}\n", "▶".cyan(), "Available clusters".bold());
    for (name, cluster) in &config.clusters {
        println!(
            "  {} {} ({} {})",
            "●".blue(),
            name.bold(),
            cluster.nodes.len().to_string().yellow(),
            if cluster.nodes.len() == 1 {
                "node"
            } else {
                "nodes"
            }
        );
        for node_config in &cluster.nodes {
            let node_str = match node_config {
                NodeConfig::Simple(s) => s.clone(),
                NodeConfig::Detailed { host, .. } => host.clone(),
            };
            println!("    {} {}", "•".dimmed(), node_str.dimmed());
        }
    }
    println!();
}

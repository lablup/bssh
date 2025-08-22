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

use bssh::config::Config;
use std::env;

#[tokio::test]
async fn test_backendai_env_auto_detection() {
    // Save original env vars
    let orig_hosts = env::var("BACKENDAI_CLUSTER_HOSTS").ok();
    let orig_host = env::var("BACKENDAI_CLUSTER_HOST").ok();
    let orig_role = env::var("BACKENDAI_CLUSTER_ROLE").ok();

    // Set Backend.AI environment variables
    unsafe {
        env::set_var("BACKENDAI_CLUSTER_HOSTS", "node1.ai,node2.ai,node3.ai");
        env::set_var("BACKENDAI_CLUSTER_HOST", "node1.ai");
        env::set_var("BACKENDAI_CLUSTER_ROLE", "main");
    }

    // Load config with priority (should detect Backend.AI env)
    let config = Config::load_with_priority(&std::path::PathBuf::from("nonexistent.yaml"))
        .await
        .expect("Config should load with Backend.AI env");

    // Check that backendai cluster was created
    assert!(config.clusters.contains_key("backendai"));

    // Get the backendai cluster
    let cluster = config.clusters.get("backendai").unwrap();

    // Verify nodes were parsed correctly
    assert_eq!(cluster.nodes.len(), 3);

    // Resolve nodes for the backendai cluster
    let nodes = config
        .resolve_nodes("backendai")
        .expect("Should resolve backendai nodes");
    assert_eq!(nodes.len(), 3);

    // Check node details
    assert_eq!(nodes[0].host, "node1.ai");
    assert_eq!(nodes[0].port, 2200); // Backend.AI default port
    assert_eq!(nodes[1].host, "node2.ai");
    assert_eq!(nodes[2].host, "node3.ai");

    // Restore original env vars
    unsafe {
        if let Some(val) = orig_hosts {
            env::set_var("BACKENDAI_CLUSTER_HOSTS", val);
        } else {
            env::remove_var("BACKENDAI_CLUSTER_HOSTS");
        }

        if let Some(val) = orig_host {
            env::set_var("BACKENDAI_CLUSTER_HOST", val);
        } else {
            env::remove_var("BACKENDAI_CLUSTER_HOST");
        }

        if let Some(val) = orig_role {
            env::set_var("BACKENDAI_CLUSTER_ROLE", val);
        } else {
            env::remove_var("BACKENDAI_CLUSTER_ROLE");
        }
    }
}

#[tokio::test]
async fn test_backendai_env_with_single_host() {
    // Save original env vars
    let orig_hosts = env::var("BACKENDAI_CLUSTER_HOSTS").ok();
    let orig_host = env::var("BACKENDAI_CLUSTER_HOST").ok();

    // Set Backend.AI environment variables with single host
    unsafe {
        env::set_var("BACKENDAI_CLUSTER_HOSTS", "single-node.ai");
        env::set_var("BACKENDAI_CLUSTER_HOST", "single-node.ai");
    }

    // Load config
    let config = Config::load_with_priority(&std::path::PathBuf::from("nonexistent.yaml"))
        .await
        .expect("Config should load");

    // Verify backendai cluster exists
    assert!(config.clusters.contains_key("backendai"));

    let nodes = config
        .resolve_nodes("backendai")
        .expect("Should resolve nodes");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].host, "single-node.ai");
    assert_eq!(nodes[0].port, 2200);

    // Restore
    unsafe {
        if let Some(val) = orig_hosts {
            env::set_var("BACKENDAI_CLUSTER_HOSTS", val);
        } else {
            env::remove_var("BACKENDAI_CLUSTER_HOSTS");
        }

        if let Some(val) = orig_host {
            env::set_var("BACKENDAI_CLUSTER_HOST", val);
        } else {
            env::remove_var("BACKENDAI_CLUSTER_HOST");
        }
    }
}

#[tokio::test]
async fn test_no_backendai_env() {
    // Save and clear Backend.AI env vars
    let orig_hosts = env::var("BACKENDAI_CLUSTER_HOSTS").ok();
    let orig_host = env::var("BACKENDAI_CLUSTER_HOST").ok();

    unsafe {
        env::remove_var("BACKENDAI_CLUSTER_HOSTS");
        env::remove_var("BACKENDAI_CLUSTER_HOST");
        env::remove_var("BACKENDAI_CLUSTER_ROLE");
    }

    // Load config without Backend.AI env
    let config = Config::load_with_priority(&std::path::PathBuf::from("nonexistent.yaml"))
        .await
        .expect("Config should load");

    // Verify no backendai cluster was created
    assert!(!config.clusters.contains_key("backendai"));

    // Restore if needed
    unsafe {
        if let Some(val) = orig_hosts {
            env::set_var("BACKENDAI_CLUSTER_HOSTS", val);
        }
        if let Some(val) = orig_host {
            env::set_var("BACKENDAI_CLUSTER_HOST", val);
        }
    }
}

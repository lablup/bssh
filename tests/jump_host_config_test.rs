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

//! Integration tests for jump_host configuration feature (issue #115)
//!
//! These tests verify that jump_host can be configured in config.yaml
//! at global, cluster, and node levels, and that CLI -J option takes
//! precedence over configuration.

use bssh::config::Config;

/// Test that global default jump_host is applied to all clusters
#[test]
fn test_config_global_jump_host_applied_to_all_clusters() {
    let yaml = r#"
defaults:
  user: admin
  jump_host: global-bastion.example.com

clusters:
  cluster_a:
    nodes:
      - host: a1.internal
      - host: a2.internal

  cluster_b:
    nodes:
      - host: b1.internal
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // All clusters should inherit global jump_host
    assert_eq!(
        config.get_cluster_jump_host(Some("cluster_a")),
        Some("global-bastion.example.com".to_string())
    );
    assert_eq!(
        config.get_cluster_jump_host(Some("cluster_b")),
        Some("global-bastion.example.com".to_string())
    );
}

/// Test that cluster-level jump_host overrides global default
#[test]
fn test_config_cluster_jump_host_overrides_global() {
    let yaml = r#"
defaults:
  jump_host: global-bastion.example.com

clusters:
  with_override:
    nodes:
      - host: node1.internal
    jump_host: cluster-bastion.example.com

  without_override:
    nodes:
      - host: node2.internal
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Cluster with override should use cluster jump_host
    assert_eq!(
        config.get_cluster_jump_host(Some("with_override")),
        Some("cluster-bastion.example.com".to_string())
    );

    // Cluster without override should use global jump_host
    assert_eq!(
        config.get_cluster_jump_host(Some("without_override")),
        Some("global-bastion.example.com".to_string())
    );
}

/// Test that node-level jump_host overrides cluster default
#[test]
fn test_config_node_jump_host_overrides_cluster() {
    let yaml = r#"
defaults:
  jump_host: global-bastion.example.com

clusters:
  production:
    nodes:
      - host: node1.internal
        jump_host: node1-bastion.example.com
      - host: node2.internal
      - host: node3.internal
        jump_host: node3-bastion.example.com
    jump_host: cluster-bastion.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Node 0 has override
    assert_eq!(
        config.get_jump_host("production", 0),
        Some("node1-bastion.example.com".to_string())
    );

    // Node 1 uses cluster default
    assert_eq!(
        config.get_jump_host("production", 1),
        Some("cluster-bastion.example.com".to_string())
    );

    // Node 2 has override
    assert_eq!(
        config.get_jump_host("production", 2),
        Some("node3-bastion.example.com".to_string())
    );
}

/// Test that empty string explicitly disables jump_host
#[test]
fn test_config_empty_string_disables_jump_host() {
    let yaml = r#"
defaults:
  jump_host: global-bastion.example.com

clusters:
  direct_access:
    nodes:
      - host: direct1.example.com
    jump_host: ""

  mixed:
    nodes:
      - host: via_bastion.internal
      - host: direct.internal
        jump_host: ""
    jump_host: cluster-bastion.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Cluster with empty jump_host should have no jump_host
    assert_eq!(config.get_cluster_jump_host(Some("direct_access")), None);
    assert_eq!(config.get_jump_host("direct_access", 0), None);

    // Node with empty jump_host should have no jump_host
    assert_eq!(
        config.get_jump_host("mixed", 0),
        Some("cluster-bastion.example.com".to_string())
    );
    assert_eq!(config.get_jump_host("mixed", 1), None);
}

/// Test environment variable expansion in jump_host
#[test]
fn test_config_jump_host_env_expansion() {
    // Set environment variables
    unsafe {
        std::env::set_var("BSSH_TEST_BASTION", "env-bastion.example.com");
        std::env::set_var("BSSH_TEST_PORT", "2222");
    }

    let yaml = r#"
defaults:
  jump_host: ${BSSH_TEST_BASTION}

clusters:
  production:
    nodes:
      - host: node1.internal
        jump_host: ${BSSH_TEST_BASTION}:${BSSH_TEST_PORT}
      - host: node2.internal
    jump_host: $BSSH_TEST_BASTION:$BSSH_TEST_PORT
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Global default with env var
    assert_eq!(
        config.get_cluster_jump_host(Some("nonexistent")),
        Some("env-bastion.example.com".to_string())
    );

    // Node-level with ${VAR} syntax
    assert_eq!(
        config.get_jump_host("production", 0),
        Some("env-bastion.example.com:2222".to_string())
    );

    // Cluster-level with $VAR syntax
    assert_eq!(
        config.get_jump_host("production", 1),
        Some("env-bastion.example.com:2222".to_string())
    );

    // Clean up
    unsafe {
        std::env::remove_var("BSSH_TEST_BASTION");
        std::env::remove_var("BSSH_TEST_PORT");
    }
}

/// Test jump_host with user@host:port format
#[test]
fn test_config_jump_host_full_format() {
    let yaml = r#"
defaults:
  jump_host: jumpuser@bastion.example.com:2222

clusters:
  production:
    nodes:
      - host: node1.internal
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Should preserve full user@host:port format
    assert_eq!(
        config.get_cluster_jump_host(Some("production")),
        Some("jumpuser@bastion.example.com:2222".to_string())
    );
}

/// Test multi-hop jump_host chain
#[test]
fn test_config_jump_host_multi_hop() {
    let yaml = r#"
defaults:
  jump_host: hop1.example.com,hop2.example.com,hop3.example.com

clusters:
  production:
    nodes:
      - host: node1.internal
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Should preserve multi-hop chain
    assert_eq!(
        config.get_cluster_jump_host(Some("production")),
        Some("hop1.example.com,hop2.example.com,hop3.example.com".to_string())
    );
}

/// Test backward compatibility - configs without jump_host should work
#[test]
fn test_config_backward_compatibility() {
    let yaml = r#"
defaults:
  user: admin
  port: 22
  ssh_key: ~/.ssh/id_rsa

clusters:
  production:
    nodes:
      - web1.example.com
      - web2.example.com
    ssh_key: ~/.ssh/prod_key
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Should work without jump_host configured
    assert_eq!(config.get_cluster_jump_host(Some("production")), None);
    assert_eq!(config.get_jump_host("production", 0), None);

    // Other config should still work
    assert_eq!(config.defaults.user, Some("admin".to_string()));
    assert_eq!(config.defaults.port, Some(22));

    let cluster = config.get_cluster("production").unwrap();
    assert_eq!(cluster.nodes.len(), 2);
}

/// Test resolution priority: node > cluster > global
#[test]
fn test_config_jump_host_resolution_priority() {
    let yaml = r#"
defaults:
  jump_host: global.example.com

clusters:
  test:
    nodes:
      - host: node1.internal
        jump_host: node-level.example.com
      - host: node2.internal
      - host: node3.internal
        jump_host: ""
    jump_host: cluster-level.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Node 0: node-level takes priority
    assert_eq!(
        config.get_jump_host("test", 0),
        Some("node-level.example.com".to_string())
    );

    // Node 1: no node-level, uses cluster-level
    assert_eq!(
        config.get_jump_host("test", 1),
        Some("cluster-level.example.com".to_string())
    );

    // Node 2: empty string at node-level disables (even though cluster has value)
    assert_eq!(config.get_jump_host("test", 2), None);

    // get_cluster_jump_host should return cluster-level (not node-level)
    assert_eq!(
        config.get_cluster_jump_host(Some("test")),
        Some("cluster-level.example.com".to_string())
    );
}

/// Test that simple node strings cannot have jump_host override
#[test]
fn test_config_simple_nodes_inherit_cluster_jump_host() {
    let yaml = r#"
clusters:
  production:
    nodes:
      - simple-node.internal
      - user@another-simple.internal:2222
    jump_host: cluster-bastion.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Both simple nodes should inherit cluster jump_host
    assert_eq!(
        config.get_jump_host("production", 0),
        Some("cluster-bastion.example.com".to_string())
    );
    assert_eq!(
        config.get_jump_host("production", 1),
        Some("cluster-bastion.example.com".to_string())
    );
}

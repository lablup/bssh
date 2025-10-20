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

//! Configuration tests.

use std::path::{Path, PathBuf};

use super::types::{Config, InteractiveMode, NodeConfig};
use super::utils::{expand_env_vars, expand_tilde};

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

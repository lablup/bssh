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

//! Integration tests for jump_host configuration feature (issue #115, #167, and #170)
//!
//! These tests verify that jump_host can be configured in config.yaml
//! at global, cluster, and node levels, and that CLI -J option takes
//! precedence over configuration.
//!
//! Tests for issue #167 verify per-jump-host SSH key configuration.
//! Tests for issue #170 verify SSH config Host alias reference support.

use bssh::config::{Config, JumpHostConfig};
use bssh::ssh::ssh_config::SshConfig;

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

// ===== Tests for issue #167: Per-jump-host SSH key configuration =====

/// Test JumpHostConfig simple format deserialization
#[test]
fn test_jump_host_config_simple_format_parsing() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host: bastion.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");
    let cluster = config.get_cluster("test").expect("Cluster not found");

    match &cluster.defaults.jump_host {
        Some(JumpHostConfig::Simple(s)) => {
            assert_eq!(s, "bastion.example.com");
        }
        other => panic!("Expected Simple variant, got {:?}", other),
    }
}

/// Test JumpHostConfig detailed format with all fields
#[test]
fn test_jump_host_config_detailed_format_full() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host:
      host: bastion.example.com
      user: jumpuser
      port: 2222
      ssh_key: ~/.ssh/bastion_key
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");
    let cluster = config.get_cluster("test").expect("Cluster not found");

    match &cluster.defaults.jump_host {
        Some(JumpHostConfig::Detailed {
            host,
            user,
            port,
            ssh_key,
        }) => {
            assert_eq!(host, "bastion.example.com");
            assert_eq!(user.as_deref(), Some("jumpuser"));
            assert_eq!(*port, Some(2222));
            assert_eq!(ssh_key.as_deref(), Some("~/.ssh/bastion_key"));
        }
        other => panic!("Expected Detailed variant, got {:?}", other),
    }
}

/// Test JumpHostConfig detailed format with minimal fields
#[test]
fn test_jump_host_config_detailed_minimal_host_only() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host:
      host: bastion.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");
    let cluster = config.get_cluster("test").expect("Cluster not found");

    match &cluster.defaults.jump_host {
        Some(JumpHostConfig::Detailed {
            host,
            user,
            port,
            ssh_key,
        }) => {
            assert_eq!(host, "bastion.example.com");
            assert!(user.is_none());
            assert!(port.is_none());
            assert!(ssh_key.is_none());
        }
        other => panic!("Expected Detailed variant, got {:?}", other),
    }
}

/// Test get_jump_host_with_key resolution with structured format
#[test]
fn test_get_cluster_jump_host_with_key_structured() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host:
      host: bastion.example.com
      user: jumpuser
      ssh_key: ~/.ssh/jump_key
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");
    let (conn_str, ssh_key) = config
        .get_cluster_jump_host_with_key(Some("test"))
        .expect("Jump host not found");

    assert_eq!(conn_str, "jumpuser@bastion.example.com");
    assert!(ssh_key.is_some());
    assert!(ssh_key.as_ref().unwrap().contains("jump_key"));
}

/// Test get_jump_host_with_key returns None for simple format ssh_key
#[test]
fn test_get_cluster_jump_host_with_key_simple_no_key() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host: bastion.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");
    let (conn_str, ssh_key) = config
        .get_cluster_jump_host_with_key(Some("test"))
        .expect("Jump host not found");

    assert_eq!(conn_str, "bastion.example.com");
    assert!(ssh_key.is_none());
}

/// Test node-level jump host override with per-jump-host key
#[test]
fn test_node_override_jump_host_with_key() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
        jump_host:
          host: special-bastion.example.com
          ssh_key: ~/.ssh/special_key
    jump_host: default-bastion.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");
    let (conn_str, ssh_key) = config
        .get_jump_host_with_key("test", 0)
        .expect("Jump host not found");

    assert_eq!(conn_str, "special-bastion.example.com");
    assert!(ssh_key.is_some());
    assert!(ssh_key.as_ref().unwrap().contains("special_key"));
}

/// Test environment variable expansion in jump_host ssh_key field
#[test]
fn test_jump_host_ssh_key_env_expansion() {
    std::env::set_var("TEST_JUMP_HOST", "env-bastion.example.com");
    std::env::set_var("TEST_JUMP_KEY", "/keys/env_key");

    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host:
      host: ${TEST_JUMP_HOST}
      ssh_key: ${TEST_JUMP_KEY}
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");
    let (conn_str, ssh_key) = config
        .get_cluster_jump_host_with_key(Some("test"))
        .expect("Jump host not found");

    assert_eq!(conn_str, "env-bastion.example.com");
    assert_eq!(ssh_key.as_deref(), Some("/keys/env_key"));

    std::env::remove_var("TEST_JUMP_HOST");
    std::env::remove_var("TEST_JUMP_KEY");
}

/// Test backward compatibility: both simple and structured formats work
#[test]
fn test_backward_compatibility_mixed_formats() {
    let yaml = r#"
clusters:
  legacy:
    nodes:
      - host: node1
    jump_host: user@bastion1.example.com:2222

  modern:
    nodes:
      - host: node2
    jump_host:
      host: bastion2.example.com
      user: admin
      port: 22
      ssh_key: ~/.ssh/bastion2_key
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");

    // Test legacy format
    let (conn_str1, ssh_key1) = config
        .get_cluster_jump_host_with_key(Some("legacy"))
        .expect("Jump host not found");
    assert_eq!(conn_str1, "user@bastion1.example.com:2222");
    assert!(ssh_key1.is_none());

    // Test modern format
    let (conn_str2, ssh_key2) = config
        .get_cluster_jump_host_with_key(Some("modern"))
        .expect("Jump host not found");
    assert_eq!(conn_str2, "admin@bastion2.example.com:22");
    assert!(ssh_key2.is_some());
    assert!(ssh_key2.as_ref().unwrap().contains("bastion2_key"));
}

/// Test JumpHostConfig to_connection_string method
#[test]
fn test_jump_host_config_to_connection_string() {
    // Simple format
    let config1 = JumpHostConfig::Simple("bastion.example.com".to_string());
    assert_eq!(config1.to_connection_string(), "bastion.example.com");

    // Detailed format with all fields
    let config2 = JumpHostConfig::Detailed {
        host: "bastion.example.com".to_string(),
        user: Some("admin".to_string()),
        port: Some(2222),
        ssh_key: Some("~/.ssh/key".to_string()),
    };
    assert_eq!(
        config2.to_connection_string(),
        "admin@bastion.example.com:2222"
    );

    // Detailed format with only host
    let config3 = JumpHostConfig::Detailed {
        host: "bastion.example.com".to_string(),
        user: None,
        port: None,
        ssh_key: Some("~/.ssh/key".to_string()),
    };
    assert_eq!(config3.to_connection_string(), "bastion.example.com");

    // Detailed format with user but no port
    let config4 = JumpHostConfig::Detailed {
        host: "bastion.example.com".to_string(),
        user: Some("admin".to_string()),
        port: None,
        ssh_key: None,
    };
    assert_eq!(config4.to_connection_string(), "admin@bastion.example.com");
}

/// Test JumpHostConfig ssh_key accessor method
#[test]
fn test_jump_host_config_ssh_key_accessor() {
    // Simple format has no ssh_key
    let config1 = JumpHostConfig::Simple("bastion.example.com".to_string());
    assert!(config1.ssh_key().is_none());

    // Detailed format without ssh_key
    let config2 = JumpHostConfig::Detailed {
        host: "bastion.example.com".to_string(),
        user: None,
        port: None,
        ssh_key: None,
    };
    assert!(config2.ssh_key().is_none());

    // Detailed format with ssh_key
    let config3 = JumpHostConfig::Detailed {
        host: "bastion.example.com".to_string(),
        user: None,
        port: None,
        ssh_key: Some("~/.ssh/key".to_string()),
    };
    assert_eq!(config3.ssh_key(), Some("~/.ssh/key"));
}

// ===== Tests for issue #170: SSH config Host alias reference support =====

/// Test JumpHostConfig SshConfigHostRef parsing
#[test]
fn test_jump_host_config_ssh_config_host_ref_parsing() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host:
      ssh_config_host: bastion
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");
    let cluster = config.get_cluster("test").expect("Cluster not found");

    match &cluster.defaults.jump_host {
        Some(JumpHostConfig::SshConfigHostRef { ssh_config_host }) => {
            assert_eq!(ssh_config_host, "bastion");
        }
        other => panic!("Expected SshConfigHostRef variant, got {:?}", other),
    }
}

/// Test JumpHostConfig Simple format with @ prefix (SSH config reference)
#[test]
fn test_jump_host_config_at_prefix_parsing() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host: "@bastion"
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");
    let cluster = config.get_cluster("test").expect("Cluster not found");

    match &cluster.defaults.jump_host {
        Some(JumpHostConfig::Simple(s)) => {
            assert_eq!(s, "@bastion");
            assert!(cluster
                .defaults
                .jump_host
                .as_ref()
                .unwrap()
                .is_ssh_config_ref());
            assert_eq!(
                cluster
                    .defaults
                    .jump_host
                    .as_ref()
                    .unwrap()
                    .ssh_config_host(),
                Some("bastion")
            );
        }
        other => panic!("Expected Simple variant with @ prefix, got {:?}", other),
    }
}

/// Test JumpHostConfig is_ssh_config_ref method
#[test]
fn test_jump_host_config_is_ssh_config_ref() {
    // Simple format without @ prefix is not SSH config ref
    let config1 = JumpHostConfig::Simple("bastion.example.com".to_string());
    assert!(!config1.is_ssh_config_ref());

    // Simple format with @ prefix is SSH config ref
    let config2 = JumpHostConfig::Simple("@bastion".to_string());
    assert!(config2.is_ssh_config_ref());

    // SshConfigHostRef is always SSH config ref
    let config3 = JumpHostConfig::SshConfigHostRef {
        ssh_config_host: "bastion".to_string(),
    };
    assert!(config3.is_ssh_config_ref());

    // Detailed format is not SSH config ref
    let config4 = JumpHostConfig::Detailed {
        host: "bastion.example.com".to_string(),
        user: None,
        port: None,
        ssh_key: None,
    };
    assert!(!config4.is_ssh_config_ref());
}

/// Test JumpHostConfig ssh_config_host method
#[test]
fn test_jump_host_config_ssh_config_host() {
    // Simple format without @ prefix has no ssh_config_host
    let config1 = JumpHostConfig::Simple("bastion.example.com".to_string());
    assert!(config1.ssh_config_host().is_none());

    // Simple format with @ prefix returns alias (without @)
    let config2 = JumpHostConfig::Simple("@bastion".to_string());
    assert_eq!(config2.ssh_config_host(), Some("bastion"));

    // SshConfigHostRef returns the alias
    let config3 = JumpHostConfig::SshConfigHostRef {
        ssh_config_host: "mybastion".to_string(),
    };
    assert_eq!(config3.ssh_config_host(), Some("mybastion"));

    // Detailed format has no ssh_config_host
    let config4 = JumpHostConfig::Detailed {
        host: "bastion.example.com".to_string(),
        user: None,
        port: None,
        ssh_key: None,
    };
    assert!(config4.ssh_config_host().is_none());
}

/// Test JumpHostConfig to_connection_string for SSH config references
#[test]
fn test_jump_host_config_ssh_config_ref_to_connection_string() {
    // Simple format with @ prefix returns full @alias string
    let config1 = JumpHostConfig::Simple("@bastion".to_string());
    assert_eq!(config1.to_connection_string(), "@bastion");

    // SshConfigHostRef returns @alias format
    let config2 = JumpHostConfig::SshConfigHostRef {
        ssh_config_host: "mybastion".to_string(),
    };
    assert_eq!(config2.to_connection_string(), "@mybastion");
}

/// Test SSH config jump host resolution
#[test]
fn test_ssh_config_resolve_jump_host() {
    let ssh_config_content = r#"
Host bastion
    HostName bastion.example.com
    User jumpuser
    Port 2222
    IdentityFile ~/.ssh/bastion_key

Host gateway
    HostName gateway.example.com
    User admin

Host simple
    HostName simple.example.com
"#;

    let ssh_config = SshConfig::parse(ssh_config_content).expect("Failed to parse SSH config");

    // Test full configuration
    let result = ssh_config.resolve_jump_host("bastion");
    assert!(result.is_some());
    let (hostname, user, port, identity_file) = result.unwrap();
    assert_eq!(hostname, "bastion.example.com");
    assert_eq!(user.as_deref(), Some("jumpuser"));
    assert_eq!(port, Some(2222));
    assert!(identity_file.is_some());
    assert!(identity_file.as_ref().unwrap().contains("bastion_key"));

    // Test partial configuration
    let result2 = ssh_config.resolve_jump_host("gateway");
    assert!(result2.is_some());
    let (hostname2, user2, port2, identity_file2) = result2.unwrap();
    assert_eq!(hostname2, "gateway.example.com");
    assert_eq!(user2.as_deref(), Some("admin"));
    assert!(port2.is_none());
    assert!(identity_file2.is_none());

    // Test minimal configuration
    let result3 = ssh_config.resolve_jump_host("simple");
    assert!(result3.is_some());
    let (hostname3, user3, port3, identity_file3) = result3.unwrap();
    assert_eq!(hostname3, "simple.example.com");
    assert!(user3.is_none());
    assert!(port3.is_none());
    assert!(identity_file3.is_none());
}

/// Test SSH config resolve_jump_host_connection
#[test]
fn test_ssh_config_resolve_jump_host_connection() {
    let ssh_config_content = r#"
Host bastion
    HostName bastion.example.com
    User jumpuser
    Port 2222
    IdentityFile ~/.ssh/bastion_key

Host gateway
    HostName gateway.example.com

Host nohost
    User someuser
"#;

    let ssh_config = SshConfig::parse(ssh_config_content).expect("Failed to parse SSH config");

    // Test full connection string
    let result = ssh_config.resolve_jump_host_connection("bastion");
    assert!(result.is_some());
    let (conn_str, identity_file) = result.unwrap();
    assert_eq!(conn_str, "jumpuser@bastion.example.com:2222");
    assert!(identity_file.is_some());

    // Test without user or port
    let result2 = ssh_config.resolve_jump_host_connection("gateway");
    assert!(result2.is_some());
    let (conn_str2, identity_file2) = result2.unwrap();
    assert_eq!(conn_str2, "gateway.example.com");
    assert!(identity_file2.is_none());

    // Test with user but no HostName (uses alias as hostname)
    let result3 = ssh_config.resolve_jump_host_connection("nohost");
    assert!(result3.is_some());
    let (conn_str3, _) = result3.unwrap();
    assert_eq!(conn_str3, "someuser@nohost");
}

/// Test config resolution with SSH config reference
#[test]
fn test_config_jump_host_ssh_config_resolution() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host: "@bastion"
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");

    let ssh_config_content = r#"
Host bastion
    HostName bastion.example.com
    User jumpuser
    Port 2222
    IdentityFile ~/.ssh/bastion_key
"#;
    let ssh_config = SshConfig::parse(ssh_config_content).expect("Failed to parse SSH config");

    // Without SSH config, resolution returns alias as hostname
    let (conn_str, ssh_key) = config
        .get_jump_host_with_key("test", 0)
        .expect("Jump host not found");
    assert_eq!(conn_str, "bastion");
    assert!(ssh_key.is_none());

    // With SSH config, full resolution works
    let (conn_str2, ssh_key2) = config
        .get_jump_host_with_key_and_ssh_config("test", 0, Some(&ssh_config))
        .expect("Jump host not found");
    assert_eq!(conn_str2, "jumpuser@bastion.example.com:2222");
    assert!(ssh_key2.is_some());
    assert!(ssh_key2.as_ref().unwrap().contains("bastion_key"));
}

/// Test config resolution with SshConfigHostRef variant
#[test]
fn test_config_jump_host_ssh_config_host_ref_resolution() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host:
      ssh_config_host: gateway
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");

    let ssh_config_content = r#"
Host gateway
    HostName gateway.internal.com
    User admin
    IdentityFile ~/.ssh/gateway_key
"#;
    let ssh_config = SshConfig::parse(ssh_config_content).expect("Failed to parse SSH config");

    let (conn_str, ssh_key) = config
        .get_jump_host_with_key_and_ssh_config("test", 0, Some(&ssh_config))
        .expect("Jump host not found");

    assert_eq!(conn_str, "admin@gateway.internal.com");
    assert!(ssh_key.is_some());
    assert!(ssh_key.as_ref().unwrap().contains("gateway_key"));
}

/// Test node-level SSH config reference override
#[test]
fn test_node_level_ssh_config_ref_override() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: special-node
        jump_host: "@special-bastion"
      - host: normal-node
    jump_host: "@default-bastion"
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");

    let ssh_config_content = r#"
Host default-bastion
    HostName default.example.com
    User defaultuser

Host special-bastion
    HostName special.example.com
    User specialuser
    Port 3333
"#;
    let ssh_config = SshConfig::parse(ssh_config_content).expect("Failed to parse SSH config");

    // Node 0 uses special-bastion
    let (conn_str0, _) = config
        .get_jump_host_with_key_and_ssh_config("test", 0, Some(&ssh_config))
        .expect("Jump host not found");
    assert_eq!(conn_str0, "specialuser@special.example.com:3333");

    // Node 1 uses default-bastion
    let (conn_str1, _) = config
        .get_jump_host_with_key_and_ssh_config("test", 1, Some(&ssh_config))
        .expect("Jump host not found");
    assert_eq!(conn_str1, "defaultuser@default.example.com");
}

/// Test global default SSH config reference
#[test]
fn test_global_default_ssh_config_ref() {
    let yaml = r#"
defaults:
  jump_host:
    ssh_config_host: global-bastion

clusters:
  cluster_a:
    nodes:
      - host: a1.internal

  cluster_b:
    nodes:
      - host: b1.internal
    jump_host: direct-bastion.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");

    let ssh_config_content = r#"
Host global-bastion
    HostName global.example.com
    User globaluser
"#;
    let ssh_config = SshConfig::parse(ssh_config_content).expect("Failed to parse SSH config");

    // Cluster A should use global SSH config reference
    let (conn_str_a, _) = config
        .get_cluster_jump_host_with_key_and_ssh_config(Some("cluster_a"), Some(&ssh_config))
        .expect("Jump host not found");
    assert_eq!(conn_str_a, "globaluser@global.example.com");

    // Cluster B has its own explicit jump_host, not SSH config ref
    let (conn_str_b, _) = config
        .get_cluster_jump_host_with_key_and_ssh_config(Some("cluster_b"), Some(&ssh_config))
        .expect("Jump host not found");
    assert_eq!(conn_str_b, "direct-bastion.example.com");
}

/// Test fallback when SSH config alias doesn't exist
#[test]
fn test_ssh_config_ref_nonexistent_fallback() {
    let yaml = r#"
clusters:
  test:
    nodes:
      - host: node1
    jump_host: "@nonexistent-bastion"
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");

    let ssh_config_content = r#"
Host some-other-host
    HostName other.example.com
"#;
    let ssh_config = SshConfig::parse(ssh_config_content).expect("Failed to parse SSH config");

    // Should fallback to using alias as hostname when not found
    let (conn_str, ssh_key) = config
        .get_jump_host_with_key_and_ssh_config("test", 0, Some(&ssh_config))
        .expect("Jump host not found");
    assert_eq!(conn_str, "nonexistent-bastion");
    assert!(ssh_key.is_none());
}

/// Test backward compatibility: all formats work together
#[test]
fn test_all_jump_host_formats_together() {
    let yaml = r#"
clusters:
  legacy:
    nodes:
      - host: node1
    jump_host: user@direct.example.com:2222

  structured:
    nodes:
      - host: node2
    jump_host:
      host: structured.example.com
      user: admin
      ssh_key: ~/.ssh/structured_key

  ssh_config_simple:
    nodes:
      - host: node3
    jump_host: "@bastion"

  ssh_config_structured:
    nodes:
      - host: node4
    jump_host:
      ssh_config_host: gateway
"#;

    let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config");

    let ssh_config_content = r#"
Host bastion
    HostName bastion.resolved.com
    User bastionuser

Host gateway
    HostName gateway.resolved.com
    User gatewayuser
    IdentityFile ~/.ssh/gateway_key
"#;
    let ssh_config = SshConfig::parse(ssh_config_content).expect("Failed to parse SSH config");

    // Legacy format
    let (conn_str1, _) = config
        .get_cluster_jump_host_with_key_and_ssh_config(Some("legacy"), Some(&ssh_config))
        .expect("Jump host not found");
    assert_eq!(conn_str1, "user@direct.example.com:2222");

    // Structured format
    let (conn_str2, key2) = config
        .get_cluster_jump_host_with_key_and_ssh_config(Some("structured"), Some(&ssh_config))
        .expect("Jump host not found");
    assert_eq!(conn_str2, "admin@structured.example.com");
    assert!(key2.is_some());

    // SSH config simple (@alias)
    let (conn_str3, _) = config
        .get_cluster_jump_host_with_key_and_ssh_config(Some("ssh_config_simple"), Some(&ssh_config))
        .expect("Jump host not found");
    assert_eq!(conn_str3, "bastionuser@bastion.resolved.com");

    // SSH config structured (ssh_config_host)
    let (conn_str4, key4) = config
        .get_cluster_jump_host_with_key_and_ssh_config(
            Some("ssh_config_structured"),
            Some(&ssh_config),
        )
        .expect("Jump host not found");
    assert_eq!(conn_str4, "gatewayuser@gateway.resolved.com");
    assert!(key4.is_some());
}

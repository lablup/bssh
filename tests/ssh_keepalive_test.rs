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

//! Tests for SSH keepalive functionality (ServerAliveInterval/ServerAliveCountMax).
//!
//! This module tests:
//! - SshConnectionConfig struct construction and defaults
//! - CLI option parsing for keepalive settings
//! - SSH config file parsing for keepalive options
//! - Config resolution for keepalive settings
//! - Integration with ParallelExecutor

use bssh::ssh::ssh_config::SshConfig;
use bssh::ssh::tokio_client::{
    SshConnectionConfig, DEFAULT_KEEPALIVE_INTERVAL, DEFAULT_KEEPALIVE_MAX,
};

// =============================================================================
// SshConnectionConfig Tests
// =============================================================================

#[test]
fn test_ssh_connection_config_default_values() {
    let config = SshConnectionConfig::default();

    assert_eq!(
        config.keepalive_interval,
        Some(DEFAULT_KEEPALIVE_INTERVAL),
        "Default keepalive interval should be {DEFAULT_KEEPALIVE_INTERVAL}"
    );
    assert_eq!(
        config.keepalive_max, DEFAULT_KEEPALIVE_MAX,
        "Default keepalive max should be {DEFAULT_KEEPALIVE_MAX}"
    );
}

#[test]
fn test_ssh_connection_config_new_equals_default() {
    let new_config = SshConnectionConfig::new();
    let default_config = SshConnectionConfig::default();

    assert_eq!(
        new_config.keepalive_interval, default_config.keepalive_interval,
        "new() and default() should produce same keepalive_interval"
    );
    assert_eq!(
        new_config.keepalive_max, default_config.keepalive_max,
        "new() and default() should produce same keepalive_max"
    );
}

#[test]
fn test_ssh_connection_config_with_custom_interval() {
    let config = SshConnectionConfig::new().with_keepalive_interval(Some(30));

    assert_eq!(
        config.keepalive_interval,
        Some(30),
        "Custom keepalive interval should be 30"
    );
    assert_eq!(
        config.keepalive_max, DEFAULT_KEEPALIVE_MAX,
        "Keepalive max should remain default"
    );
}

#[test]
fn test_ssh_connection_config_with_custom_max() {
    let config = SshConnectionConfig::new().with_keepalive_max(5);

    assert_eq!(
        config.keepalive_interval,
        Some(DEFAULT_KEEPALIVE_INTERVAL),
        "Keepalive interval should remain default"
    );
    assert_eq!(config.keepalive_max, 5, "Custom keepalive max should be 5");
}

#[test]
fn test_ssh_connection_config_disable_keepalive() {
    let config = SshConnectionConfig::new().with_keepalive_interval(None);

    assert_eq!(
        config.keepalive_interval, None,
        "Keepalive interval should be disabled (None)"
    );
}

#[test]
fn test_ssh_connection_config_chain_builders() {
    let config = SshConnectionConfig::new()
        .with_keepalive_interval(Some(120))
        .with_keepalive_max(10);

    assert_eq!(
        config.keepalive_interval,
        Some(120),
        "Chained keepalive interval should be 120"
    );
    assert_eq!(
        config.keepalive_max, 10,
        "Chained keepalive max should be 10"
    );
}

#[test]
fn test_ssh_connection_config_to_russh_config() {
    let config = SshConnectionConfig::new()
        .with_keepalive_interval(Some(45))
        .with_keepalive_max(7);

    let russh_config = config.to_russh_config();

    assert_eq!(
        russh_config.keepalive_interval,
        Some(std::time::Duration::from_secs(45)),
        "russh config should have 45s keepalive interval"
    );
    assert_eq!(
        russh_config.keepalive_max, 7,
        "russh config should have keepalive max of 7"
    );
}

#[test]
fn test_ssh_connection_config_to_russh_config_disabled() {
    let config = SshConnectionConfig::new().with_keepalive_interval(None);

    let russh_config = config.to_russh_config();

    assert_eq!(
        russh_config.keepalive_interval, None,
        "russh config should have disabled keepalive"
    );
}

#[test]
fn test_ssh_connection_config_zero_interval() {
    // Zero interval should be interpreted as "disable keepalive"
    let config = SshConnectionConfig::new().with_keepalive_interval(Some(0));

    let russh_config = config.to_russh_config();

    // russh will interpret Duration::from_secs(0) as disabled
    assert_eq!(
        russh_config.keepalive_interval,
        Some(std::time::Duration::from_secs(0)),
        "Zero interval should be passed through (russh interprets as disabled)"
    );
}

// =============================================================================
// SSH Config File Parsing Tests
// =============================================================================

#[test]
fn test_parse_server_alive_interval() {
    let config = r#"
Host test-server
    ServerAliveInterval 30

Host long-running
    ServerAliveInterval 120

Host disabled
    ServerAliveInterval 0
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = &config_parsed.hosts;
    assert_eq!(hosts.len(), 3);

    assert_eq!(
        hosts[0].server_alive_interval,
        Some(30),
        "test-server should have 30s interval"
    );
    assert_eq!(
        hosts[1].server_alive_interval,
        Some(120),
        "long-running should have 120s interval"
    );
    assert_eq!(
        hosts[2].server_alive_interval,
        Some(0),
        "disabled should have 0s interval"
    );
}

#[test]
fn test_parse_server_alive_count_max() {
    let config = r#"
Host test-server
    ServerAliveCountMax 3

Host patient
    ServerAliveCountMax 10

Host impatient
    ServerAliveCountMax 1
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = &config_parsed.hosts;
    assert_eq!(hosts.len(), 3);

    assert_eq!(
        hosts[0].server_alive_count_max,
        Some(3),
        "test-server should have count max 3"
    );
    assert_eq!(
        hosts[1].server_alive_count_max,
        Some(10),
        "patient should have count max 10"
    );
    assert_eq!(
        hosts[2].server_alive_count_max,
        Some(1),
        "impatient should have count max 1"
    );
}

#[test]
fn test_parse_server_alive_combined() {
    let config = r#"
Host production
    ServerAliveInterval 60
    ServerAliveCountMax 3

Host development
    ServerAliveInterval 30
    ServerAliveCountMax 5
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = &config_parsed.hosts;
    assert_eq!(hosts.len(), 2);

    // Production
    assert_eq!(hosts[0].server_alive_interval, Some(60));
    assert_eq!(hosts[0].server_alive_count_max, Some(3));

    // Development
    assert_eq!(hosts[1].server_alive_interval, Some(30));
    assert_eq!(hosts[1].server_alive_count_max, Some(5));
}

#[test]
fn test_parse_server_alive_equals_syntax() {
    let config = r#"
Host test
    ServerAliveInterval=45
    ServerAliveCountMax=7
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = &config_parsed.hosts;
    assert_eq!(hosts.len(), 1);

    assert_eq!(hosts[0].server_alive_interval, Some(45));
    assert_eq!(hosts[0].server_alive_count_max, Some(7));
}

#[test]
fn test_parse_server_alive_case_insensitive() {
    let config = r#"
Host test1
    serveraliveinterval 15
    serveralivecountmax 2

Host test2
    SERVERALIVEINTERVAL 25
    SERVERALIVECOUNTMAX 4

Host test3
    ServerALIVEInterval 35
    serverALIVECountMax 6
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = &config_parsed.hosts;
    assert_eq!(hosts.len(), 3);

    assert_eq!(hosts[0].server_alive_interval, Some(15));
    assert_eq!(hosts[0].server_alive_count_max, Some(2));

    assert_eq!(hosts[1].server_alive_interval, Some(25));
    assert_eq!(hosts[1].server_alive_count_max, Some(4));

    assert_eq!(hosts[2].server_alive_interval, Some(35));
    assert_eq!(hosts[2].server_alive_count_max, Some(6));
}

#[test]
fn test_parse_server_alive_invalid_non_numeric() {
    let config = r#"
Host test
    ServerAliveInterval abc
"#;

    let result = SshConfig::parse(config);
    assert!(
        result.is_err(),
        "Should reject non-numeric ServerAliveInterval"
    );
}

#[test]
fn test_parse_server_alive_count_max_invalid_non_numeric() {
    let config = r#"
Host test
    ServerAliveCountMax xyz
"#;

    let result = SshConfig::parse(config);
    assert!(
        result.is_err(),
        "Should reject non-numeric ServerAliveCountMax"
    );
}

#[test]
fn test_parse_server_alive_negative_value() {
    let config = r#"
Host test
    ServerAliveInterval -10
"#;

    let result = SshConfig::parse(config);
    assert!(
        result.is_err(),
        "Should reject negative ServerAliveInterval"
    );
}

// =============================================================================
// Config Resolution Tests
// =============================================================================

#[test]
fn test_find_host_config_merges_keepalive() {
    let config = r#"
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3

Host *.example.com
    ServerAliveCountMax 5

Host web.example.com
    ServerAliveInterval 30
"#;

    let config_parsed = SshConfig::parse(config).unwrap();

    // web.example.com should inherit from * and *.example.com with most specific winning
    let host_config = config_parsed.find_host_config("web.example.com");
    assert_eq!(
        host_config.server_alive_interval,
        Some(30),
        "Should use most specific interval (30 from web.example.com)"
    );
    assert_eq!(
        host_config.server_alive_count_max,
        Some(5),
        "Should use *.example.com count max (5)"
    );

    // db.example.com should inherit from * and *.example.com
    let host_config = config_parsed.find_host_config("db.example.com");
    assert_eq!(
        host_config.server_alive_interval,
        Some(60),
        "Should inherit interval (60 from *)"
    );
    assert_eq!(
        host_config.server_alive_count_max,
        Some(5),
        "Should use *.example.com count max (5)"
    );

    // other.net should only match *
    let host_config = config_parsed.find_host_config("other.net");
    assert_eq!(
        host_config.server_alive_interval,
        Some(60),
        "Should inherit interval (60 from *)"
    );
    assert_eq!(
        host_config.server_alive_count_max,
        Some(3),
        "Should inherit count max (3 from *)"
    );
}

#[test]
fn test_get_int_option_server_alive_interval() {
    // SSH config applies matches in order, with later matches overriding earlier ones.
    // So put specific hosts after wildcards if you want specific values to take precedence.
    let config = r#"
Host *
    ServerAliveInterval 60

Host test.example.com
    ServerAliveInterval 45
"#;

    let config_parsed = SshConfig::parse(config).unwrap();

    // Test specific host - specific config (45) overrides wildcard (60)
    let interval = config_parsed.get_int_option(Some("test.example.com"), "serveraliveinterval");
    assert_eq!(interval, Some(45), "Should return 45 for test.example.com");

    // Test fallback - only wildcard matches
    let interval = config_parsed.get_int_option(Some("other.com"), "serveraliveinterval");
    assert_eq!(interval, Some(60), "Should return 60 for other.com");

    // Test with wildcard hostname
    let interval = config_parsed.get_int_option(None, "serveraliveinterval");
    assert_eq!(interval, Some(60), "Should return 60 for * pattern");
}

#[test]
fn test_get_int_option_server_alive_count_max() {
    // SSH config applies matches in order, with later matches overriding earlier ones.
    let config = r#"
Host *
    ServerAliveCountMax 3

Host test.example.com
    ServerAliveCountMax 7
"#;

    let config_parsed = SshConfig::parse(config).unwrap();

    // Test specific host - specific config (7) overrides wildcard (3)
    let count = config_parsed.get_int_option(Some("test.example.com"), "serveralivecountmax");
    assert_eq!(count, Some(7), "Should return 7 for test.example.com");

    // Test fallback - only wildcard matches
    let count = config_parsed.get_int_option(Some("other.com"), "serveralivecountmax");
    assert_eq!(count, Some(3), "Should return 3 for other.com");
}

#[test]
fn test_get_int_option_unknown_option() {
    let config = r#"
Host test
    ServerAliveInterval 30
"#;

    let config_parsed = SshConfig::parse(config).unwrap();

    let result = config_parsed.get_int_option(Some("test"), "unknownoption");
    assert_eq!(result, None, "Should return None for unknown option");
}

// =============================================================================
// bssh Config Resolution Tests
// =============================================================================

#[test]
fn test_bssh_config_get_server_alive_interval() {
    use bssh::config::Config;

    // Note: ClusterDefaults are flattened into Cluster, not nested under "defaults:"
    let yaml = r#"
defaults:
  server_alive_interval: 90

clusters:
  production:
    nodes:
      - host: node1.example.com
    server_alive_interval: 60

  development:
    nodes:
      - host: dev1.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Production cluster has override (flattened into cluster level)
    let interval = config.get_server_alive_interval(Some("production"));
    assert_eq!(
        interval,
        Some(60),
        "Production should use cluster-level interval"
    );

    // Development cluster falls back to global
    let interval = config.get_server_alive_interval(Some("development"));
    assert_eq!(
        interval,
        Some(90),
        "Development should use global default interval"
    );

    // No cluster specified falls back to global
    let interval = config.get_server_alive_interval(None);
    assert_eq!(
        interval,
        Some(90),
        "None should use global default interval"
    );
}

#[test]
fn test_bssh_config_get_server_alive_count_max() {
    use bssh::config::Config;

    // Note: ClusterDefaults are flattened into Cluster, not nested under "defaults:"
    let yaml = r#"
defaults:
  server_alive_count_max: 5

clusters:
  production:
    nodes:
      - host: node1.example.com
    server_alive_count_max: 3

  development:
    nodes:
      - host: dev1.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Production cluster has override (flattened into cluster level)
    let count = config.get_server_alive_count_max(Some("production"));
    assert_eq!(
        count,
        Some(3),
        "Production should use cluster-level count max"
    );

    // Development cluster falls back to global
    let count = config.get_server_alive_count_max(Some("development"));
    assert_eq!(
        count,
        Some(5),
        "Development should use global default count max"
    );

    // No cluster specified falls back to global
    let count = config.get_server_alive_count_max(None);
    assert_eq!(count, Some(5), "None should use global default count max");
}

#[test]
fn test_bssh_config_no_keepalive_settings() {
    use bssh::config::Config;

    let yaml = r#"
clusters:
  minimal:
    nodes:
      - host: node1.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    let interval = config.get_server_alive_interval(Some("minimal"));
    assert_eq!(interval, None, "Should return None when not configured");

    let count = config.get_server_alive_count_max(Some("minimal"));
    assert_eq!(count, None, "Should return None when not configured");
}

// =============================================================================
// ParallelExecutor Integration Tests
// =============================================================================

#[test]
fn test_parallel_executor_with_ssh_connection_config() {
    use bssh::executor::ParallelExecutor;
    use bssh::node::Node;

    let nodes = vec![Node::new("example.com".to_string(), 22, "user".to_string())];

    let ssh_config = SshConnectionConfig::new()
        .with_keepalive_interval(Some(30))
        .with_keepalive_max(5);

    // This just verifies the builder pattern works correctly
    // The executor stores the config internally - we verify it compiles and doesn't panic
    let _executor = ParallelExecutor::new(nodes, 10, None).with_ssh_connection_config(ssh_config);

    // If we got here without panicking, the config was set correctly
}

#[test]
fn test_parallel_executor_default_ssh_connection_config() {
    use bssh::executor::ParallelExecutor;
    use bssh::node::Node;

    let nodes = vec![Node::new("example.com".to_string(), 22, "user".to_string())];

    // Create executor with default settings
    let _executor = ParallelExecutor::new(nodes, 10, None);

    // The executor should use default SshConnectionConfig internally
    // We can't access the private field, but we verify the constructor works
}

#[test]
fn test_parallel_executor_chain_multiple_configs() {
    use bssh::executor::ParallelExecutor;
    use bssh::node::Node;
    use bssh::ssh::known_hosts::StrictHostKeyChecking;

    let nodes = vec![Node::new("example.com".to_string(), 22, "user".to_string())];

    let ssh_config = SshConnectionConfig::new()
        .with_keepalive_interval(Some(45))
        .with_keepalive_max(8);

    // Verify chaining multiple builder methods works
    let _executor =
        ParallelExecutor::new_with_strict_mode(nodes, 10, None, StrictHostKeyChecking::AcceptNew)
            .with_timeout(Some(300))
            .with_connect_timeout(Some(30))
            .with_ssh_connection_config(ssh_config)
            .with_batch_mode(true);

    // If we got here without panicking, all configs were set correctly
}

// =============================================================================
// Interactive Mode Keepalive Tests
// =============================================================================

#[test]
fn test_interactive_mode_ssh_connection_config_default() {
    // Test that InteractiveCommand can be created with default SshConnectionConfig
    // This verifies the field was added correctly
    use bssh::commands::interactive::InteractiveCommand;
    use bssh::config::{Config, InteractiveConfig};
    use bssh::pty::PtyConfig;
    use bssh::ssh::known_hosts::StrictHostKeyChecking;
    use std::path::PathBuf;

    let cmd = InteractiveCommand {
        single_node: true,
        multiplex: false,
        prompt_format: "[{user}@{host}]$ ".to_string(),
        history_file: PathBuf::from("~/.bssh_history"),
        work_dir: None,
        nodes: vec![],
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        #[cfg(target_os = "macos")]
        use_keychain: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        jump_hosts: None,
        pty_config: PtyConfig::default(),
        use_pty: None,
        ssh_connection_config: SshConnectionConfig::default(),
    };

    // Verify default values are applied
    assert_eq!(
        cmd.ssh_connection_config.keepalive_interval,
        Some(DEFAULT_KEEPALIVE_INTERVAL),
        "InteractiveCommand should have default keepalive interval"
    );
    assert_eq!(
        cmd.ssh_connection_config.keepalive_max, DEFAULT_KEEPALIVE_MAX,
        "InteractiveCommand should have default keepalive max"
    );
}

#[test]
fn test_interactive_mode_ssh_connection_config_custom() {
    // Test that InteractiveCommand can be created with custom SshConnectionConfig
    use bssh::commands::interactive::InteractiveCommand;
    use bssh::config::{Config, InteractiveConfig};
    use bssh::pty::PtyConfig;
    use bssh::ssh::known_hosts::StrictHostKeyChecking;
    use std::path::PathBuf;

    let custom_config = SshConnectionConfig::new()
        .with_keepalive_interval(Some(120))
        .with_keepalive_max(10);

    let cmd = InteractiveCommand {
        single_node: true,
        multiplex: false,
        prompt_format: "[{user}@{host}]$ ".to_string(),
        history_file: PathBuf::from("~/.bssh_history"),
        work_dir: None,
        nodes: vec![],
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        #[cfg(target_os = "macos")]
        use_keychain: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        jump_hosts: None,
        pty_config: PtyConfig::default(),
        use_pty: None,
        ssh_connection_config: custom_config,
    };

    // Verify custom values are applied
    assert_eq!(
        cmd.ssh_connection_config.keepalive_interval,
        Some(120),
        "InteractiveCommand should have custom keepalive interval"
    );
    assert_eq!(
        cmd.ssh_connection_config.keepalive_max, 10,
        "InteractiveCommand should have custom keepalive max"
    );
}

#[test]
fn test_interactive_mode_ssh_connection_config_disabled_keepalive() {
    // Test that InteractiveCommand can be created with disabled keepalive
    use bssh::commands::interactive::InteractiveCommand;
    use bssh::config::{Config, InteractiveConfig};
    use bssh::pty::PtyConfig;
    use bssh::ssh::known_hosts::StrictHostKeyChecking;
    use std::path::PathBuf;

    let disabled_config = SshConnectionConfig::new().with_keepalive_interval(None);

    let cmd = InteractiveCommand {
        single_node: true,
        multiplex: false,
        prompt_format: "[{user}@{host}]$ ".to_string(),
        history_file: PathBuf::from("~/.bssh_history"),
        work_dir: None,
        nodes: vec![],
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        #[cfg(target_os = "macos")]
        use_keychain: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        jump_hosts: None,
        pty_config: PtyConfig::default(),
        use_pty: None,
        ssh_connection_config: disabled_config,
    };

    // Verify keepalive is disabled
    assert_eq!(
        cmd.ssh_connection_config.keepalive_interval, None,
        "InteractiveCommand should have disabled keepalive"
    );
}

#[test]
fn test_ssh_connection_config_clone() {
    // Test that SshConnectionConfig implements Clone correctly
    // This is important for passing config to JumpHostChain
    let original = SshConnectionConfig::new()
        .with_keepalive_interval(Some(90))
        .with_keepalive_max(6);

    let cloned = original.clone();

    assert_eq!(
        original.keepalive_interval, cloned.keepalive_interval,
        "Cloned config should have same keepalive_interval"
    );
    assert_eq!(
        original.keepalive_max, cloned.keepalive_max,
        "Cloned config should have same keepalive_max"
    );
}

#[test]
fn test_jump_host_chain_with_ssh_connection_config() {
    // Test that JumpHostChain accepts and stores SshConnectionConfig
    use bssh::jump::JumpHostChain;

    let ssh_config = SshConnectionConfig::new()
        .with_keepalive_interval(Some(45))
        .with_keepalive_max(5);

    // JumpHostChain should accept the config via builder pattern
    let _chain = JumpHostChain::direct().with_ssh_connection_config(ssh_config);

    // If we got here without panicking, the config was accepted correctly
}

#[test]
fn test_jump_host_chain_with_custom_keepalive_for_long_running_sessions() {
    // Test real-world use case: long-running sessions need longer keepalive
    use bssh::jump::parser::JumpHost;
    use bssh::jump::JumpHostChain;
    use std::time::Duration;

    // For long-running interactive sessions, use longer keepalive intervals
    // to reduce network traffic while still detecting dead connections
    let long_session_config = SshConnectionConfig::new()
        .with_keepalive_interval(Some(120)) // 2 minutes
        .with_keepalive_max(5); // 5 attempts = 10 minutes to detect dead connection

    let jump_hosts = vec![JumpHost::new(
        "bastion.example.com".to_string(),
        Some("admin".to_string()),
        Some(22),
    )];

    let _chain = JumpHostChain::new(jump_hosts)
        .with_connect_timeout(Duration::from_secs(60))
        .with_command_timeout(Duration::from_secs(600))
        .with_ssh_connection_config(long_session_config);

    // This verifies the chain can be configured for long-running interactive sessions
}

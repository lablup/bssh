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

//! Integration tests for interactive mode

use bssh::commands::interactive::InteractiveCommand;
use bssh::config::{Config, InteractiveConfig};
use bssh::node::Node;
use bssh::pty::PtyConfig;
use bssh::ssh::known_hosts::StrictHostKeyChecking;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

/// Test interactive command configuration
#[test]
fn test_interactive_command_builder() {
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user1".to_string()),
        Node::new("host2".to_string(), 2222, "user2".to_string()),
    ];

    let cmd = InteractiveCommand {
        single_node: false,
        multiplex: true,
        prompt_format: "[{user}@{host}]$ ".to_string(),
        history_file: PathBuf::from("~/.test_history"),
        work_dir: Some("/tmp".to_string()),
        nodes,
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
        jump_hosts: None,
    };

    assert!(!cmd.single_node);
    assert!(cmd.multiplex);
    assert_eq!(cmd.prompt_format, "[{user}@{host}]$ ");
    assert_eq!(cmd.work_dir, Some("/tmp".to_string()));
    assert_eq!(cmd.nodes.len(), 2);
}

/// Test history file path expansion
#[test]
fn test_history_file_handling() {
    let temp_dir = tempdir().unwrap();
    let history_path = temp_dir.path().join("test_history");

    let cmd = InteractiveCommand {
        single_node: true,
        multiplex: false,
        prompt_format: String::new(),
        history_file: history_path.clone(),
        work_dir: None,
        nodes: vec![],
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
        jump_hosts: None,
    };

    assert_eq!(cmd.history_file, history_path);
}

/// Mock SSH server for testing
struct MockSshServer {
    _port: u16,
    running: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
}

impl MockSshServer {
    fn new(port: u16) -> Self {
        Self {
            _port: port,
            running: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn start(&self) -> Result<(), anyhow::Error> {
        self.running.store(true, Ordering::Relaxed);

        // In a real implementation, this would start an actual SSH server
        // For testing, we just simulate it
        tokio::spawn({
            let running = Arc::clone(&self.running);
            let connections = Arc::clone(&self.connections);
            async move {
                while running.load(Ordering::Relaxed) {
                    // Simulate accepting connections
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    connections.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }
}

#[tokio::test]
async fn test_mock_ssh_server() {
    let server = MockSshServer::new(2222);

    // Start the mock server
    server.start().await.unwrap();
    assert!(server.running.load(Ordering::Relaxed));

    // Wait a bit for "connections"
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Check that we got some "connections"
    assert!(server.connection_count() > 0);

    // Stop the server
    server.stop();
    assert!(!server.running.load(Ordering::Relaxed));
}

/// Test interactive mode with invalid nodes
#[tokio::test]
async fn test_interactive_with_unreachable_nodes() {
    let nodes = vec![Node::new(
        "nonexistent.invalid".to_string(),
        22222,
        "user".to_string(),
    )];

    let cmd = InteractiveCommand {
        single_node: true,
        multiplex: false,
        prompt_format: String::new(),
        history_file: PathBuf::from("/tmp/test_history"),
        work_dir: None,
        nodes,
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
        jump_hosts: None,
    };

    // This should fail to connect
    let result = tokio::time::timeout(Duration::from_secs(5), cmd.execute()).await;

    assert!(result.is_ok(), "Should not timeout");
    assert!(
        result.unwrap().is_err(),
        "Should fail to connect to invalid host"
    );
}

/// Test interactive mode with empty nodes
#[tokio::test]
async fn test_interactive_with_no_nodes() {
    let cmd = InteractiveCommand {
        single_node: false,
        multiplex: true,
        prompt_format: String::new(),
        history_file: PathBuf::from("/tmp/test_history"),
        work_dir: None,
        nodes: vec![],
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
        jump_hosts: None,
    };

    let result = cmd.execute().await;
    assert!(result.is_err(), "Should fail with no nodes");

    if let Err(e) = result {
        let error_msg = e.to_string();
        assert!(
            error_msg.contains("Failed to connect")
                || error_msg.contains("No nodes")
                || error_msg.contains("no nodes"),
            "Error should mention connection failure or no nodes, got: {error_msg}"
        );
    }
}

/// Test single-node vs multiplex mode configuration
#[test]
fn test_mode_configuration() {
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
    ];

    // Single-node mode
    let single_cmd = InteractiveCommand {
        single_node: true,
        multiplex: false,
        prompt_format: String::new(),
        history_file: PathBuf::from("/tmp/history"),
        work_dir: None,
        nodes: nodes.clone(),
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
        jump_hosts: None,
    };

    assert!(single_cmd.single_node);
    assert!(!single_cmd.multiplex);

    // Multiplex mode
    let multi_cmd = InteractiveCommand {
        single_node: false,
        multiplex: true,
        prompt_format: String::new(),
        history_file: PathBuf::from("/tmp/history"),
        work_dir: None,
        nodes,
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
        jump_hosts: None,
    };

    assert!(!multi_cmd.single_node);
    assert!(multi_cmd.multiplex);
}

/// Test working directory configuration
#[test]
fn test_working_directory_config() {
    let cmd_with_dir = InteractiveCommand {
        single_node: true,
        multiplex: false,
        prompt_format: String::new(),
        history_file: PathBuf::from("/tmp/history"),
        work_dir: Some("/var/www".to_string()),
        nodes: vec![],
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
        jump_hosts: None,
    };

    assert_eq!(cmd_with_dir.work_dir, Some("/var/www".to_string()));

    let cmd_without_dir = InteractiveCommand {
        single_node: true,
        multiplex: false,
        prompt_format: String::new(),
        history_file: PathBuf::from("/tmp/history"),
        work_dir: None,
        nodes: vec![],
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
        jump_hosts: None,
    };

    assert_eq!(cmd_without_dir.work_dir, None);
}

/// Test prompt format customization
#[test]
fn test_prompt_format() {
    let formats = vec![
        "[{user}@{host}:{pwd}]$ ",
        "{user}@{host}> ",
        "({node}) $ ",
        "bssh [{host}]> ",
    ];

    for format in formats {
        let cmd = InteractiveCommand {
            single_node: true,
            multiplex: false,
            prompt_format: format.to_string(),
            history_file: PathBuf::from("/tmp/history"),
            work_dir: None,
            nodes: vec![],
            config: Config::default(),
            interactive_config: InteractiveConfig::default(),
            cluster_name: None,
            key_path: None,
            use_agent: false,
            use_password: false,
            strict_mode: StrictHostKeyChecking::AcceptNew,
            pty_config: PtyConfig::default(),
            use_pty: None,
            jump_hosts: None,
        };

        assert_eq!(cmd.prompt_format, format);
    }
}

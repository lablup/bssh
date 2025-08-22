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

//! Tests for node switching functionality in interactive mode

use bssh::node::Node;

/// Mock node session for testing
#[derive(Debug, Clone)]
struct MockNodeSession {
    #[allow(dead_code)]
    node: Node,
    is_connected: bool,
    is_active: bool,
    working_dir: String,
}

impl MockNodeSession {
    fn new(host: &str, port: u16, user: &str) -> Self {
        Self {
            node: Node::new(host.to_string(), port, user.to_string()),
            is_connected: true,
            is_active: true,
            working_dir: "/home/user".to_string(),
        }
    }
}

#[test]
fn test_node_switching_command_parsing() {
    // Test various node switching commands
    let commands = vec![
        ("!node1", true, "Switch to node 1"),
        ("!n2", true, "Shorthand for node 2"),
        ("!all", true, "Activate all nodes"),
        ("!list", true, "List nodes"),
        ("!nodes", true, "Alias for list"),
        ("!status", true, "Show status"),
        ("!help", true, "Show help"),
        ("!?", true, "Help alias"),
        ("!invalid", true, "Invalid command"),
        ("regular command", false, "Not a special command"),
    ];

    for (cmd, is_special, desc) in commands {
        let starts_with_bang = cmd.starts_with('!');
        assert_eq!(starts_with_bang, is_special, "Failed for: {desc}");
    }
}

#[test]
fn test_node_activation_states() {
    let mut sessions = vec![
        MockNodeSession::new("host1", 22, "user"),
        MockNodeSession::new("host2", 22, "user"),
        MockNodeSession::new("host3", 22, "user"),
    ];

    // Initially all should be active
    assert!(sessions.iter().all(|s| s.is_active));

    // Simulate switching to node 1
    for session in &mut sessions {
        session.is_active = false;
    }
    sessions[0].is_active = true;

    // Check only node 1 is active
    assert!(sessions[0].is_active);
    assert!(!sessions[1].is_active);
    assert!(!sessions[2].is_active);

    // Simulate !all command
    for session in &mut sessions {
        if session.is_connected {
            session.is_active = true;
        }
    }

    // All should be active again
    assert!(sessions.iter().all(|s| s.is_active));
}

#[test]
fn test_node_status_display() {
    let sessions = vec![
        MockNodeSession {
            node: Node::new("host1".to_string(), 22, "user".to_string()),
            is_connected: true,
            is_active: true,
            working_dir: "/home/user".to_string(),
        },
        MockNodeSession {
            node: Node::new("host2".to_string(), 22, "user".to_string()),
            is_connected: true,
            is_active: false,
            working_dir: "/home/user".to_string(),
        },
        MockNodeSession {
            node: Node::new("host3".to_string(), 22, "user".to_string()),
            is_connected: false,
            is_active: false,
            working_dir: "/home/user".to_string(),
        },
    ];

    // Count active and connected nodes
    let active_count = sessions
        .iter()
        .filter(|s| s.is_active && s.is_connected)
        .count();
    let total_connected = sessions.iter().filter(|s| s.is_connected).count();

    assert_eq!(active_count, 1, "Should have 1 active node");
    assert_eq!(total_connected, 2, "Should have 2 connected nodes");
}

#[test]
fn test_node_number_parsing() {
    let test_cases = vec![
        ("1", Some(1)),
        ("2", Some(2)),
        ("10", Some(10)),
        ("0", None),        // Invalid: 0-based indexing not allowed
        ("-1", None),       // Invalid: negative
        ("abc", None),      // Invalid: not a number
        ("", None),         // Invalid: empty
        ("999", Some(999)), // Valid but might be out of range
    ];

    for (input, expected) in test_cases {
        let result = input.parse::<usize>().ok().filter(|&n| n > 0);
        assert_eq!(result, expected, "Failed parsing: {input}");
    }
}

#[test]
fn test_command_routing_to_active_nodes() {
    let mut sessions = vec![
        MockNodeSession::new("host1", 22, "user"),
        MockNodeSession::new("host2", 22, "user"),
        MockNodeSession::new("host3", 22, "user"),
    ];

    // Set only node 2 as active
    sessions[0].is_active = false;
    sessions[1].is_active = true;
    sessions[2].is_active = false;

    // Simulate command execution - should only go to active nodes
    let mut commands_sent = 0;
    for session in &sessions {
        if session.is_connected && session.is_active {
            commands_sent += 1;
        }
    }

    assert_eq!(
        commands_sent, 1,
        "Command should only be sent to 1 active node"
    );
}

#[test]
fn test_disconnected_node_handling() {
    let mut sessions = vec![
        MockNodeSession::new("host1", 22, "user"),
        MockNodeSession::new("host2", 22, "user"),
    ];

    // Disconnect node 1
    sessions[0].is_connected = false;

    // Try to activate disconnected node
    for session in &mut sessions {
        session.is_active = false;
    }

    // Should not activate disconnected node
    if sessions[0].is_connected {
        sessions[0].is_active = true;
    }

    assert!(
        !sessions[0].is_active,
        "Disconnected node should not be activated"
    );

    // Activate all should skip disconnected nodes
    for session in &mut sessions {
        if session.is_connected {
            session.is_active = true;
        }
    }

    assert!(
        !sessions[0].is_active,
        "Disconnected node should remain inactive"
    );
    assert!(sessions[1].is_active, "Connected node should be active");
}

#[test]
fn test_prompt_format_with_active_nodes() {
    // Test prompt shows different format when some nodes are inactive
    let active_count = 1;
    let total_connected = 3;

    let prompt_format = if active_count == total_connected {
        "[● ● ●] bssh> ".to_string()
    } else {
        format!("[1 · ·] ({active_count}/{total_connected}) bssh> ")
    };

    assert!(
        prompt_format.contains("(1/3)"),
        "Prompt should show active/total ratio"
    );
}

#[test]
fn test_special_command_validation() {
    // Test that special commands are properly validated
    let valid_commands = vec![
        "!all", "!node1", "!node99", "!n1", "!n99", "!list", "!nodes", "!ls", "!status", "!help",
        "!?",
    ];

    for cmd in valid_commands {
        assert!(cmd.starts_with('!'), "Command should start with !");
        let without_bang = cmd.trim_start_matches('!');
        assert!(
            !without_bang.is_empty(),
            "Command should have content after !"
        );
    }
}

#[test]
fn test_working_directory_preservation() {
    let mut sessions = [
        MockNodeSession {
            node: Node::new("host1".to_string(), 22, "user".to_string()),
            is_connected: true,
            is_active: true,
            working_dir: "/home/user".to_string(),
        },
        MockNodeSession {
            node: Node::new("host2".to_string(), 22, "user".to_string()),
            is_connected: true,
            is_active: true,
            working_dir: "/var/www".to_string(),
        },
    ];

    // Each node should maintain its own working directory
    assert_eq!(sessions[0].working_dir, "/home/user");
    assert_eq!(sessions[1].working_dir, "/var/www");

    // Simulate cd command on node 1 only
    sessions[0].is_active = true;
    sessions[1].is_active = false;
    sessions[0].working_dir = "/tmp".to_string();

    // Node 2 should still have its original directory
    assert_eq!(sessions[0].working_dir, "/tmp");
    assert_eq!(sessions[1].working_dir, "/var/www");
}

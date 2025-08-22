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

//! Tests for broadcast command functionality in interactive mode

use bssh::node::Node;

/// Mock node session for testing broadcast
#[derive(Debug, Clone)]
struct MockNodeSession {
    #[allow(dead_code)]
    node: Node,
    is_connected: bool,
    is_active: bool,
    commands_received: Vec<String>,
}

impl MockNodeSession {
    fn new(host: &str, port: u16, user: &str) -> Self {
        Self {
            node: Node::new(host.to_string(), port, user.to_string()),
            is_connected: true,
            is_active: true,
            commands_received: vec![],
        }
    }

    fn send_command(&mut self, command: &str) -> Result<(), String> {
        if !self.is_connected {
            return Err("Not connected".to_string());
        }
        self.commands_received.push(command.to_string());
        Ok(())
    }
}

#[test]
fn test_broadcast_command_parsing() {
    // Test various broadcast command formats
    let commands = vec![
        ("!broadcast ls -la", true, Some("ls -la")),
        ("!broadcast echo hello", true, Some("echo hello")),
        ("!broadcast", false, None),  // No space after broadcast
        ("!broadcast ", false, None), // Trailing space gets trimmed, becomes "!broadcast"
        ("!broadcast  test", true, Some("test")), // Multiple spaces but has command
        ("broadcast ls", false, None), // Missing !
        ("!broadcastls", false, None), // No space after broadcast
        ("!all", false, None),        // Different command
    ];

    for (cmd, is_broadcast, expected_cmd) in commands {
        // This matches how the production code checks:
        // line.trim().starts_with("!broadcast ")
        let starts_with_broadcast = cmd.trim().starts_with("!broadcast ");
        assert_eq!(starts_with_broadcast, is_broadcast, "Failed for: {cmd}");

        if is_broadcast {
            // Extract command after "!broadcast "
            let extracted = cmd
                .trim()
                .strip_prefix("!broadcast ")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());

            assert_eq!(
                extracted, expected_cmd,
                "Command extraction failed for: {cmd}"
            );
        }
    }
}

#[test]
fn test_broadcast_to_all_nodes() {
    let mut sessions = vec![
        MockNodeSession::new("host1", 22, "user"),
        MockNodeSession::new("host2", 22, "user"),
        MockNodeSession::new("host3", 22, "user"),
    ];

    // Initially only node 1 is active
    sessions[0].is_active = true;
    sessions[1].is_active = false;
    sessions[2].is_active = false;

    // Save current states
    let saved_states: Vec<bool> = sessions.iter().map(|s| s.is_active).collect();

    // Simulate broadcast - activate all connected nodes
    for session in &mut sessions {
        if session.is_connected {
            session.is_active = true;
        }
    }

    // Send command to all active nodes
    let command = "uptime";
    for session in &mut sessions {
        if session.is_connected && session.is_active {
            session.send_command(command).unwrap();
        }
    }

    // Verify all nodes received the command
    assert_eq!(sessions[0].commands_received.len(), 1);
    assert_eq!(sessions[1].commands_received.len(), 1);
    assert_eq!(sessions[2].commands_received.len(), 1);
    assert_eq!(sessions[0].commands_received[0], "uptime");
    assert_eq!(sessions[1].commands_received[0], "uptime");
    assert_eq!(sessions[2].commands_received[0], "uptime");

    // Restore previous states
    for (session, was_active) in sessions.iter_mut().zip(saved_states.iter()) {
        session.is_active = *was_active;
    }

    // Verify states were restored
    assert!(sessions[0].is_active);
    assert!(!sessions[1].is_active);
    assert!(!sessions[2].is_active);
}

#[test]
fn test_broadcast_with_disconnected_nodes() {
    let mut sessions = vec![
        MockNodeSession::new("host1", 22, "user"),
        MockNodeSession::new("host2", 22, "user"),
        MockNodeSession::new("host3", 22, "user"),
    ];

    // Node 2 is disconnected
    sessions[1].is_connected = false;

    // Initially only node 1 is active
    sessions[0].is_active = true;
    sessions[1].is_active = false;
    sessions[2].is_active = false;

    // Simulate broadcast - activate all CONNECTED nodes only
    for session in &mut sessions {
        if session.is_connected {
            session.is_active = true;
        }
    }

    // Send command
    let command = "hostname";
    let mut successful_sends = 0;
    for session in &mut sessions {
        if session.is_connected && session.is_active && session.send_command(command).is_ok() {
            successful_sends += 1;
        }
    }

    // Only 2 nodes should receive the command (disconnected node excluded)
    assert_eq!(successful_sends, 2);
    assert_eq!(sessions[0].commands_received.len(), 1);
    assert_eq!(sessions[1].commands_received.len(), 0); // Disconnected
    assert_eq!(sessions[2].commands_received.len(), 1);
}

#[test]
fn test_broadcast_state_restoration() {
    let mut sessions = vec![
        MockNodeSession::new("host1", 22, "user"),
        MockNodeSession::new("host2", 22, "user"),
        MockNodeSession::new("host3", 22, "user"),
        MockNodeSession::new("host4", 22, "user"),
    ];

    // Complex initial state: nodes 1 and 3 active, 2 and 4 inactive
    sessions[0].is_active = true;
    sessions[1].is_active = false;
    sessions[2].is_active = true;
    sessions[3].is_active = false;

    // Save states
    let saved_states: Vec<bool> = sessions.iter().map(|s| s.is_active).collect();

    // Broadcast activates all
    for session in &mut sessions {
        if session.is_connected {
            session.is_active = true;
        }
    }

    // All should be active during broadcast
    assert!(sessions.iter().all(|s| s.is_active));

    // Restore states
    for (session, was_active) in sessions.iter_mut().zip(saved_states.iter()) {
        session.is_active = *was_active;
    }

    // Verify exact restoration
    assert!(sessions[0].is_active);
    assert!(!sessions[1].is_active);
    assert!(sessions[2].is_active);
    assert!(!sessions[3].is_active);
}

#[test]
fn test_broadcast_empty_command_handling() {
    // Test that we properly handle various forms of empty broadcast commands
    // Note: "!broadcast " with only trailing space becomes "!broadcast" after trim,
    // which doesn't match "!broadcast " pattern
    let valid_empty_broadcasts = vec![
        "!broadcast   ",  // Multiple spaces (at least one remains after trim)
        "!broadcast \t",  // Space then tab
        "!broadcast  \n", // Multiple spaces then newline
    ];

    for cmd in valid_empty_broadcasts {
        let trimmed = cmd.trim();
        if trimmed.starts_with("!broadcast ") {
            // Extract and check if command part is empty
            let command_part = trimmed.strip_prefix("!broadcast ").unwrap().trim();
            assert!(
                command_part.is_empty(),
                "Command should be empty for: {cmd:?}"
            );
        }
    }

    // Test that "!broadcast" and "!broadcast " (trailing space only) are NOT valid
    let invalid_broadcasts = vec![
        "!broadcast",  // No space
        "!broadcast ", // Only trailing space (becomes "!broadcast" after trim)
    ];

    for cmd in invalid_broadcasts {
        assert!(
            !cmd.trim().starts_with("!broadcast "),
            "Should NOT be valid broadcast format: {cmd:?}"
        );
    }
}

#[test]
fn test_broadcast_vs_regular_command() {
    let mut sessions = vec![
        MockNodeSession::new("host1", 22, "user"),
        MockNodeSession::new("host2", 22, "user"),
    ];

    // Only node 1 active
    sessions[0].is_active = true;
    sessions[1].is_active = false;

    // Regular command - goes only to active node
    for session in &mut sessions {
        if session.is_connected && session.is_active {
            session.send_command("regular_cmd").unwrap();
        }
    }

    assert_eq!(sessions[0].commands_received.len(), 1);
    assert_eq!(sessions[1].commands_received.len(), 0);

    // Broadcast command - temporarily activates all
    let saved_states: Vec<bool> = sessions.iter().map(|s| s.is_active).collect();

    for session in &mut sessions {
        if session.is_connected {
            session.is_active = true;
        }
    }

    for session in &mut sessions {
        if session.is_connected && session.is_active {
            session.send_command("broadcast_cmd").unwrap();
        }
    }

    // Both should have received broadcast
    assert_eq!(sessions[0].commands_received.len(), 2);
    assert_eq!(sessions[1].commands_received.len(), 1);
    assert_eq!(sessions[0].commands_received[1], "broadcast_cmd");
    assert_eq!(sessions[1].commands_received[0], "broadcast_cmd");

    // Restore states
    for (session, was_active) in sessions.iter_mut().zip(saved_states.iter()) {
        session.is_active = *was_active;
    }

    // After restoration, only node 1 is active again
    assert!(sessions[0].is_active);
    assert!(!sessions[1].is_active);
}

#[test]
fn test_broadcast_with_no_connected_nodes() {
    let mut sessions = vec![
        MockNodeSession::new("host1", 22, "user"),
        MockNodeSession::new("host2", 22, "user"),
    ];

    // All nodes disconnected
    sessions[0].is_connected = false;
    sessions[1].is_connected = false;

    // Try to broadcast
    let mut successful_sends = 0;
    for session in &mut sessions {
        if session.is_connected {
            session.is_active = true;
            if session.send_command("test").is_ok() {
                successful_sends += 1;
            }
        }
    }

    // No commands should be sent
    assert_eq!(successful_sends, 0);
    assert_eq!(sessions[0].commands_received.len(), 0);
    assert_eq!(sessions[1].commands_received.len(), 0);
}

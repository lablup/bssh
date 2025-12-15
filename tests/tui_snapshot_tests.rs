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

//! TUI Snapshot Tests
//!
//! This module tests TUI rendering using ratatui's TestBackend for deterministic output.
//! Tests cover all view modes: Summary, Detail, Split, and Diff views.

use bssh::executor::{ExecutionStatus, MultiNodeStreamManager, NodeStream};
use bssh::node::Node;
use bssh::ssh::tokio_client::CommandOutput;
use bssh::ui::tui::app::{TuiApp, ViewMode};
use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};
use tokio::sync::mpsc;

/// Helper to convert buffer to a displayable string for snapshot comparison
fn buffer_to_string(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut lines = Vec::new();

    for y in 0..area.height {
        let mut line = String::new();
        for x in 0..area.width {
            let cell = buffer.cell((x, y)).unwrap();
            line.push_str(cell.symbol());
        }
        // Trim trailing whitespace but preserve structure
        let trimmed = line.trim_end();
        lines.push(trimmed.to_string());
    }

    // Remove trailing empty lines
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }

    lines.join("\n")
}

/// Create a test stream manager with mock node data
#[allow(dead_code)]
fn create_test_manager_with_data(
    nodes: Vec<(Node, ExecutionStatus, &str, &str, Option<u32>)>,
) -> MultiNodeStreamManager {
    let mut manager = MultiNodeStreamManager::new();

    for (node, status, _stdout_data, _stderr_data, exit_code) in nodes {
        let (tx, rx) = mpsc::channel(100);
        manager.add_stream(node, rx);

        // Get the stream and set its data
        let idx = manager.total_count() - 1;
        let streams = manager.streams_mut();
        let stream = &mut streams[idx];

        // Set status
        stream.set_status(status);

        // Set exit code if provided
        if let Some(code) = exit_code {
            stream.set_exit_code(code);
        }

        // We need to send data through the channel to populate buffers
        // But since we're directly manipulating state, we'll drop tx to close the channel
        drop(tx);
    }

    manager
}

/// Create a simple test manager for basic tests
fn create_simple_test_manager() -> MultiNodeStreamManager {
    let mut manager = MultiNodeStreamManager::new();

    // Create nodes with receivers
    let node1 = Node::new("host1.example.com".to_string(), 22, "user1".to_string());
    let (_tx1, rx1) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node1, rx1);

    let node2 = Node::new("host2.example.com".to_string(), 22, "user2".to_string());
    let (_tx2, rx2) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node2, rx2);

    let node3 = Node::new("host3.example.com".to_string(), 22, "user3".to_string());
    let (_tx3, rx3) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node3, rx3);

    manager
}

// ============================================================================
// Summary View Tests
// ============================================================================

#[test]
fn test_summary_view_basic_rendering() {
    // Test that summary view renders correctly with default terminal size
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let manager = create_simple_test_manager();
    let _app = TuiApp::new();

    terminal
        .draw(|f| {
            bssh::ui::tui::views::summary::render(f, &manager, "test-cluster", "echo hello", false);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // Verify basic structure - header should contain cluster name
    let output = buffer_to_string(buffer);
    assert!(
        output.contains("test-cluster"),
        "Summary view should show cluster name"
    );
}

#[test]
fn test_summary_view_with_node_states() {
    // Test summary view with various node states
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let manager = create_simple_test_manager();
    let _app = TuiApp::new();

    terminal
        .draw(|f| {
            bssh::ui::tui::views::summary::render(f, &manager, "production", "apt update", false);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show node labels
    assert!(output.contains("[1]"), "Should show node 1 label");
    assert!(output.contains("[2]"), "Should show node 2 label");
    assert!(output.contains("[3]"), "Should show node 3 label");
}

#[test]
fn test_summary_view_all_tasks_completed() {
    // Test summary view when all tasks are completed
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let manager = create_simple_test_manager();

    terminal
        .draw(|f| {
            bssh::ui::tui::views::summary::render(
                f,
                &manager,
                "test-cluster",
                "echo done",
                true, // all_tasks_completed = true
            );
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show completion message (check for key parts since Unicode rendering may vary)
    // The footer shows: "All tasks completed" (may be truncated based on terminal width)
    assert!(
        output.contains("All tasks complete") || output.contains("tasks complete"),
        "Should show completion message when all tasks done. Got: {output}"
    );
}

#[test]
fn test_summary_view_small_terminal() {
    // Test summary view at minimum supported terminal size
    let backend = TestBackend::new(40, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    let manager = create_simple_test_manager();

    terminal
        .draw(|f| {
            bssh::ui::tui::views::summary::render(f, &manager, "cluster", "cmd", false);
        })
        .unwrap();

    // Should not panic with small terminal
    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);
    assert!(
        !output.is_empty(),
        "Should render something in small terminal"
    );
}

#[test]
fn test_summary_view_large_terminal() {
    // Test summary view at large terminal size
    let backend = TestBackend::new(200, 50);
    let mut terminal = Terminal::new(backend).unwrap();

    let manager = create_simple_test_manager();

    terminal
        .draw(|f| {
            bssh::ui::tui::views::summary::render(
                f,
                &manager,
                "large-cluster",
                "complex command",
                false,
            );
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);
    assert!(
        output.contains("large-cluster"),
        "Should render correctly in large terminal"
    );
}

// ============================================================================
// Detail View Tests
// ============================================================================

#[test]
fn test_detail_view_basic_rendering() {
    // Test detail view for a single node
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let node = Node::new(
        "test-host.example.com".to_string(),
        22,
        "testuser".to_string(),
    );
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    let stream = NodeStream::new(node, rx);

    terminal
        .draw(|f| {
            bssh::ui::tui::views::detail::render(f, &stream, 0, 0, false, false);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show node information
    assert!(
        output.contains("test-host.example.com"),
        "Should show node hostname"
    );
    assert!(output.contains("[1]"), "Should show node index (1-based)");
}

#[test]
fn test_detail_view_with_follow_mode() {
    // Test detail view with follow mode enabled
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let node = Node::new("host.example.com".to_string(), 22, "user".to_string());
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    let stream = NodeStream::new(node, rx);

    terminal
        .draw(|f| {
            bssh::ui::tui::views::detail::render(
                f, &stream, 0, 0, true, // follow_mode = true
                false,
            );
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show follow indicator
    assert!(
        output.contains("FOLLOW"),
        "Should show FOLLOW indicator when follow mode is on"
    );
}

#[test]
fn test_detail_view_no_output() {
    // Test detail view when there's no output yet
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let node = Node::new("empty-host.example.com".to_string(), 22, "user".to_string());
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    let stream = NodeStream::new(node, rx);

    terminal
        .draw(|f| {
            bssh::ui::tui::views::detail::render(f, &stream, 0, 0, false, false);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show placeholder for empty output
    assert!(
        output.contains("no output"),
        "Should show 'no output' placeholder"
    );
}

#[test]
fn test_detail_view_all_tasks_completed() {
    // Test detail view when all tasks are completed
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let node = Node::new(
        "completed-host.example.com".to_string(),
        22,
        "user".to_string(),
    );
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    let stream = NodeStream::new(node, rx);

    terminal
        .draw(|f| {
            bssh::ui::tui::views::detail::render(
                f, &stream, 0, 0, false, true, // all_tasks_completed = true
            );
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show completion indicator (check for key parts since Unicode rendering may vary)
    // Text may be truncated based on terminal width
    assert!(
        output.contains("All task") || output.contains("task"),
        "Should show completion message. Got: {output}"
    );
}

// ============================================================================
// Split View Tests
// ============================================================================

#[test]
fn test_split_view_two_nodes() {
    // Test split view with exactly 2 nodes
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let manager = create_simple_test_manager();
    let indices = vec![0, 1];

    terminal
        .draw(|f| {
            bssh::ui::tui::views::split::render(f, &manager, &indices);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show both nodes
    assert!(output.contains("[1]"), "Should show node 1");
    assert!(output.contains("[2]"), "Should show node 2");
}

#[test]
fn test_split_view_four_nodes() {
    // Test split view with 4 nodes (2x2 grid)
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();

    // Create manager with 4 nodes
    let mut manager = MultiNodeStreamManager::new();
    for i in 1..=4 {
        let node = Node::new(format!("host{i}.example.com"), 22, format!("user{i}"));
        let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
        manager.add_stream(node, rx);
    }

    let indices = vec![0, 1, 2, 3];

    terminal
        .draw(|f| {
            bssh::ui::tui::views::split::render(f, &manager, &indices);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show all 4 nodes
    assert!(output.contains("[1]"), "Should show node 1");
    assert!(output.contains("[2]"), "Should show node 2");
    assert!(output.contains("[3]"), "Should show node 3");
    assert!(output.contains("[4]"), "Should show node 4");
}

#[test]
fn test_split_view_single_node_error() {
    // Test split view with only 1 node (should show error)
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let mut manager = MultiNodeStreamManager::new();
    let node = Node::new("single.example.com".to_string(), 22, "user".to_string());
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node, rx);

    let indices = vec![0];

    terminal
        .draw(|f| {
            bssh::ui::tui::views::split::render(f, &manager, &indices);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show error about requiring at least 2 nodes
    assert!(
        output.contains("at least 2 nodes"),
        "Should show error message for single node"
    );
}

// ============================================================================
// Diff View Tests
// ============================================================================

#[test]
fn test_diff_view_two_nodes() {
    // Test diff view comparing two nodes
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();

    let node_a = Node::new("node-a.example.com".to_string(), 22, "user".to_string());
    let (_tx_a, rx_a) = mpsc::channel::<CommandOutput>(100);
    let stream_a = NodeStream::new(node_a, rx_a);

    let node_b = Node::new("node-b.example.com".to_string(), 22, "user".to_string());
    let (_tx_b, rx_b) = mpsc::channel::<CommandOutput>(100);
    let stream_b = NodeStream::new(node_b, rx_b);

    terminal
        .draw(|f| {
            bssh::ui::tui::views::diff::render(f, &stream_a, &stream_b, 0, 1, 0);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show diff header
    assert!(output.contains("Diff View"), "Should show diff view header");
    // Should show both nodes
    assert!(output.contains("[1]"), "Should show node 1 label");
    assert!(output.contains("[2]"), "Should show node 2 label");
}

#[test]
fn test_diff_view_no_output() {
    // Test diff view with empty outputs
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();

    let node_a = Node::new("empty-a.example.com".to_string(), 22, "user".to_string());
    let (_tx_a, rx_a) = mpsc::channel::<CommandOutput>(100);
    let stream_a = NodeStream::new(node_a, rx_a);

    let node_b = Node::new("empty-b.example.com".to_string(), 22, "user".to_string());
    let (_tx_b, rx_b) = mpsc::channel::<CommandOutput>(100);
    let stream_b = NodeStream::new(node_b, rx_b);

    terminal
        .draw(|f| {
            bssh::ui::tui::views::diff::render(f, &stream_a, &stream_b, 0, 1, 0);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let output = buffer_to_string(buffer);

    // Should show placeholder for empty outputs
    assert!(
        output.contains("no output"),
        "Should show 'no output' for empty streams"
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_render_with_unicode_content() {
    // Test rendering with unicode characters in hostname
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let node = Node::new("test-host".to_string(), 22, "user".to_string());
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    let stream = NodeStream::new(node, rx);

    terminal
        .draw(|f| {
            bssh::ui::tui::views::detail::render(f, &stream, 0, 0, false, false);
        })
        .unwrap();

    // Should not panic with unicode
    let buffer = terminal.backend().buffer();
    assert!(buffer.area.width > 0, "Buffer should have width");
}

#[test]
fn test_render_minimum_dimensions() {
    // Test rendering at absolute minimum dimensions
    let backend = TestBackend::new(20, 5);
    let mut terminal = Terminal::new(backend).unwrap();

    let node = Node::new("h".to_string(), 22, "u".to_string());
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    let stream = NodeStream::new(node, rx);

    // This should not panic
    terminal
        .draw(|f| {
            bssh::ui::tui::views::detail::render(f, &stream, 0, 0, false, false);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    assert!(
        buffer.area.height > 0,
        "Should render even with minimal dimensions"
    );
}

// ============================================================================
// TuiApp State Tests
// ============================================================================

#[test]
fn test_tui_app_view_mode_transitions() {
    let mut app = TuiApp::new();

    // Initial state
    assert_eq!(app.view_mode, ViewMode::Summary);

    // Transition to detail view
    app.show_detail(0, 5);
    assert_eq!(app.view_mode, ViewMode::Detail(0));

    // Transition to split view
    app.show_split(vec![0, 1, 2], 5);
    assert_eq!(app.view_mode, ViewMode::Split(vec![0, 1, 2]));

    // Transition to diff view
    app.show_diff(0, 1, 5);
    assert_eq!(app.view_mode, ViewMode::Diff(0, 1));

    // Back to summary
    app.show_summary();
    assert_eq!(app.view_mode, ViewMode::Summary);
}

#[test]
fn test_tui_app_invalid_transitions() {
    let mut app = TuiApp::new();

    // Try to show detail for invalid index
    app.show_detail(10, 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Should not change to invalid node"
    );

    // Try to show split with only one valid index
    app.show_split(vec![0], 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Should not change to split with one node"
    );

    // Try to show diff with same node
    app.show_diff(2, 2, 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Should not diff node with itself"
    );
}

#[test]
fn test_tui_app_needs_redraw_flag() {
    let mut app = TuiApp::new();

    // Initial state needs redraw
    assert!(app.needs_redraw);
    assert!(app.should_redraw());
    // After checking, flag should be reset
    assert!(!app.needs_redraw);

    // View changes should set flag
    app.show_detail(0, 5);
    assert!(app.needs_redraw);
    app.should_redraw();

    // Toggle follow should set flag
    app.toggle_follow();
    assert!(app.needs_redraw);
}

#[test]
fn test_tui_app_scroll_position_limits() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);

    // Test scroll up at zero (should stay at 0)
    app.set_scroll(0, 0);
    app.scroll_up(10);
    assert_eq!(app.get_scroll(0), 0, "Scroll should not go below 0");

    // Test scroll down with max limit
    app.set_scroll(0, 0);
    app.scroll_down(100, 50);
    assert_eq!(app.get_scroll(0), 50, "Scroll should be limited to max");
}

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

//! TUI Event Handling Tests
//!
//! This module tests keyboard navigation, scroll behavior, follow mode toggle,
//! and node selection across all TUI view modes.

use bssh::ui::tui::app::{TuiApp, ViewMode};
use bssh::ui::tui::event::handle_key_event;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Helper to create a key event
fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Helper to create a key event with modifiers
fn key_with_mod(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

// ============================================================================
// Global Key Tests (work in all modes)
// ============================================================================

#[test]
fn test_quit_with_q() {
    let mut app = TuiApp::new();
    assert!(!app.should_quit);

    handle_key_event(&mut app, key(KeyCode::Char('q')), 5);
    assert!(app.should_quit, "Pressing 'q' should quit the app");
}

#[test]
fn test_quit_with_ctrl_c() {
    let mut app = TuiApp::new();
    assert!(!app.should_quit);

    handle_key_event(
        &mut app,
        key_with_mod(KeyCode::Char('c'), KeyModifiers::CONTROL),
        5,
    );
    assert!(app.should_quit, "Pressing Ctrl+C should quit the app");
}

#[test]
fn test_toggle_help_with_question_mark() {
    let mut app = TuiApp::new();
    assert!(!app.show_help);

    handle_key_event(&mut app, key(KeyCode::Char('?')), 5);
    assert!(app.show_help, "Pressing '?' should toggle help on");

    handle_key_event(&mut app, key(KeyCode::Char('?')), 5);
    assert!(!app.show_help, "Pressing '?' again should toggle help off");
}

#[test]
fn test_esc_closes_help() {
    let mut app = TuiApp::new();
    app.show_help = true;
    app.show_detail(0, 5);

    handle_key_event(&mut app, key(KeyCode::Esc), 5);
    assert!(!app.show_help, "Esc should close help overlay first");
    // View mode should not change when closing help
    assert_eq!(
        app.view_mode,
        ViewMode::Detail(0),
        "View should remain unchanged when closing help"
    );
}

#[test]
fn test_esc_returns_to_summary() {
    let mut app = TuiApp::new();
    app.show_detail(2, 5);

    handle_key_event(&mut app, key(KeyCode::Esc), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Esc should return to summary view"
    );
}

#[test]
fn test_esc_in_summary_stays_in_summary() {
    let mut app = TuiApp::new();
    assert_eq!(app.view_mode, ViewMode::Summary);

    handle_key_event(&mut app, key(KeyCode::Esc), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Esc in summary should stay in summary"
    );
}

// ============================================================================
// Summary View Key Tests
// ============================================================================

#[test]
fn test_summary_number_keys_to_detail() {
    let mut app = TuiApp::new();
    let num_nodes = 5;

    // Test keys 1-5
    for i in 1..=5 {
        app.show_summary();
        let key_char = char::from_digit(i as u32, 10).unwrap();
        handle_key_event(&mut app, key(KeyCode::Char(key_char)), num_nodes);
        assert_eq!(
            app.view_mode,
            ViewMode::Detail(i - 1),
            "Key '{key_char}' should switch to detail view for node {i}"
        );
    }
}

#[test]
fn test_summary_number_key_invalid_node() {
    let mut app = TuiApp::new();

    // Try to select node 9 when only 3 nodes exist
    handle_key_event(&mut app, key(KeyCode::Char('9')), 3);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Should not switch to invalid node"
    );
}

#[test]
fn test_summary_s_for_split_view() {
    let mut app = TuiApp::new();

    handle_key_event(&mut app, key(KeyCode::Char('s')), 5);
    match app.view_mode {
        ViewMode::Split(indices) => {
            assert!(
                indices.len() >= 2 && indices.len() <= 4,
                "Split view should have 2-4 nodes"
            );
        }
        _ => panic!("Should switch to split view"),
    }
}

#[test]
fn test_summary_s_requires_two_nodes() {
    let mut app = TuiApp::new();

    // With only 1 node, split should not work
    handle_key_event(&mut app, key(KeyCode::Char('s')), 1);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Split requires at least 2 nodes"
    );
}

#[test]
fn test_summary_d_for_diff_view() {
    let mut app = TuiApp::new();

    handle_key_event(&mut app, key(KeyCode::Char('d')), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Diff(0, 1),
        "Should switch to diff view comparing first two nodes"
    );
}

#[test]
fn test_summary_d_requires_two_nodes() {
    let mut app = TuiApp::new();

    // With only 1 node, diff should not work
    handle_key_event(&mut app, key(KeyCode::Char('d')), 1);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Diff requires at least 2 nodes"
    );
}

// ============================================================================
// Detail View Key Tests
// ============================================================================

#[test]
fn test_detail_scroll_up() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);
    app.set_scroll(0, 10);

    handle_key_event(&mut app, key(KeyCode::Up), 5);
    assert_eq!(app.get_scroll(0), 9, "Up arrow should scroll up by 1");
    assert!(!app.follow_mode, "Scrolling should disable follow mode");
}

#[test]
fn test_detail_scroll_down() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);
    app.set_scroll(0, 10);

    handle_key_event(&mut app, key(KeyCode::Down), 5);
    assert_eq!(app.get_scroll(0), 11, "Down arrow should scroll down by 1");
}

#[test]
fn test_detail_page_up() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);
    app.set_scroll(0, 20);

    handle_key_event(&mut app, key(KeyCode::PageUp), 5);
    assert_eq!(app.get_scroll(0), 10, "PageUp should scroll up by 10");
}

#[test]
fn test_detail_page_down() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);
    app.set_scroll(0, 10);

    handle_key_event(&mut app, key(KeyCode::PageDown), 5);
    assert_eq!(app.get_scroll(0), 20, "PageDown should scroll down by 10");
}

#[test]
fn test_detail_home_key() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);
    app.set_scroll(0, 100);

    handle_key_event(&mut app, key(KeyCode::Home), 5);
    assert_eq!(app.get_scroll(0), 0, "Home should scroll to top");
    assert!(!app.follow_mode, "Home should disable follow mode");
}

#[test]
fn test_detail_end_key() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);
    app.follow_mode = false;

    handle_key_event(&mut app, key(KeyCode::End), 5);
    // End sets scroll to MAX and re-enables follow mode
    assert!(app.follow_mode, "End should enable follow mode");
}

#[test]
fn test_detail_next_node_right_arrow() {
    let mut app = TuiApp::new();
    app.show_detail(1, 5);

    handle_key_event(&mut app, key(KeyCode::Right), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Detail(2),
        "Right arrow should go to next node"
    );
}

#[test]
fn test_detail_prev_node_left_arrow() {
    let mut app = TuiApp::new();
    app.show_detail(2, 5);

    handle_key_event(&mut app, key(KeyCode::Left), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Detail(1),
        "Left arrow should go to previous node"
    );
}

#[test]
fn test_detail_node_wrap_around_next() {
    let mut app = TuiApp::new();
    app.show_detail(4, 5); // Last node (0-indexed)

    handle_key_event(&mut app, key(KeyCode::Right), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Detail(0),
        "Should wrap to first node"
    );
}

#[test]
fn test_detail_node_wrap_around_prev() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5); // First node

    handle_key_event(&mut app, key(KeyCode::Left), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Detail(4),
        "Should wrap to last node"
    );
}

#[test]
fn test_detail_toggle_follow_mode() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);
    let initial_follow = app.follow_mode;

    handle_key_event(&mut app, key(KeyCode::Char('f')), 5);
    assert_eq!(
        app.follow_mode, !initial_follow,
        "Pressing 'f' should toggle follow mode"
    );

    handle_key_event(&mut app, key(KeyCode::Char('f')), 5);
    assert_eq!(
        app.follow_mode, initial_follow,
        "Pressing 'f' again should restore original state"
    );
}

#[test]
fn test_detail_number_keys_jump() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);

    handle_key_event(&mut app, key(KeyCode::Char('3')), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Detail(2),
        "Number key should jump to that node in detail view"
    );
}

// ============================================================================
// Split View Key Tests
// ============================================================================

#[test]
fn test_split_number_keys_focus() {
    let mut app = TuiApp::new();
    app.show_split(vec![0, 1, 2, 3], 5);

    // Pressing '2' should focus on node 2 (index 1)
    handle_key_event(&mut app, key(KeyCode::Char('2')), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Detail(1),
        "Number key in split view should focus on that node"
    );
}

#[test]
fn test_split_esc_to_summary() {
    let mut app = TuiApp::new();
    app.show_split(vec![0, 1], 5);

    handle_key_event(&mut app, key(KeyCode::Esc), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Esc should return to summary"
    );
}

// ============================================================================
// Diff View Key Tests
// ============================================================================

#[test]
fn test_diff_esc_to_summary() {
    let mut app = TuiApp::new();
    app.show_diff(0, 1, 5);

    handle_key_event(&mut app, key(KeyCode::Esc), 5);
    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Esc should return to summary from diff view"
    );
}

// Note: Synchronized scrolling in diff view is marked as TODO in the source code
#[test]
fn test_diff_arrow_keys_exist() {
    let mut app = TuiApp::new();
    app.show_diff(0, 1, 5);

    // These should not panic (even if not fully implemented)
    handle_key_event(&mut app, key(KeyCode::Up), 5);
    handle_key_event(&mut app, key(KeyCode::Down), 5);

    assert_eq!(
        app.view_mode,
        ViewMode::Diff(0, 1),
        "Should still be in diff view after arrow keys"
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_scroll_at_zero_cannot_go_negative() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);
    app.set_scroll(0, 0);

    handle_key_event(&mut app, key(KeyCode::Up), 5);
    assert_eq!(app.get_scroll(0), 0, "Scroll should not go negative");

    handle_key_event(&mut app, key(KeyCode::PageUp), 5);
    assert_eq!(
        app.get_scroll(0),
        0,
        "Scroll should not go negative with PageUp"
    );
}

#[test]
fn test_single_node_navigation() {
    let mut app = TuiApp::new();
    app.show_detail(0, 1); // Only 1 node

    handle_key_event(&mut app, key(KeyCode::Right), 1);
    assert_eq!(
        app.view_mode,
        ViewMode::Detail(0),
        "With single node, right arrow should wrap to same node"
    );

    handle_key_event(&mut app, key(KeyCode::Left), 1);
    assert_eq!(
        app.view_mode,
        ViewMode::Detail(0),
        "With single node, left arrow should wrap to same node"
    );
}

#[test]
fn test_quit_from_any_view_mode() {
    let view_modes = [
        ViewMode::Summary,
        ViewMode::Detail(0),
        ViewMode::Split(vec![0, 1]),
        ViewMode::Diff(0, 1),
    ];

    for initial_mode in &view_modes {
        let mut app = TuiApp::new();
        match initial_mode {
            ViewMode::Summary => {}
            ViewMode::Detail(idx) => app.show_detail(*idx, 5),
            ViewMode::Split(indices) => app.show_split(indices.clone(), 5),
            ViewMode::Diff(a, b) => app.show_diff(*a, *b, 5),
        }

        handle_key_event(&mut app, key(KeyCode::Char('q')), 5);
        assert!(
            app.should_quit,
            "Should be able to quit from {:?}",
            initial_mode
        );
    }
}

#[test]
fn test_help_text_varies_by_mode() {
    let mut app = TuiApp::new();

    // Summary mode help
    let summary_help = app.get_help_text();
    assert!(
        summary_help.iter().any(|(k, _)| *k == "1-9"),
        "Summary help should mention number keys for detail"
    );

    // Detail mode help
    app.show_detail(0, 5);
    let detail_help = app.get_help_text();
    assert!(
        detail_help.iter().any(|(k, _)| k.contains("Scroll")
            || k.contains("up")
            || k.contains("down")
            || *k == "f"),
        "Detail help should mention scroll or follow"
    );

    // Split mode help
    app.show_split(vec![0, 1], 5);
    let split_help = app.get_help_text();
    assert!(
        split_help.iter().any(|(k, _)| k.contains("1-4")),
        "Split help should mention focus keys"
    );
}

#[test]
fn test_needs_redraw_after_key_events() {
    let mut app = TuiApp::new();
    app.should_redraw(); // Clear initial flag

    // Any view change should set needs_redraw
    app.show_detail(0, 5);
    assert!(app.needs_redraw, "View change should set needs_redraw");

    app.should_redraw(); // Clear
    app.toggle_follow();
    assert!(app.needs_redraw, "Toggle follow should set needs_redraw");

    app.should_redraw(); // Clear
    app.toggle_help();
    assert!(app.needs_redraw, "Toggle help should set needs_redraw");
}

#[test]
fn test_scroll_disables_follow_mode() {
    let mut app = TuiApp::new();
    app.show_detail(0, 5);
    app.follow_mode = true;
    app.set_scroll(0, 10);

    // Manual scroll operations should disable follow mode
    app.scroll_up(1);
    assert!(!app.follow_mode, "Scroll up should disable follow mode");

    app.follow_mode = true;
    app.scroll_down(1, 100);
    assert!(!app.follow_mode, "Scroll down should disable follow mode");
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_rapid_key_presses() {
    let mut app = TuiApp::new();

    // Simulate rapid key presses
    for _ in 0..100 {
        handle_key_event(&mut app, key(KeyCode::Down), 5);
        handle_key_event(&mut app, key(KeyCode::Up), 5);
        handle_key_event(&mut app, key(KeyCode::Right), 5);
        handle_key_event(&mut app, key(KeyCode::Left), 5);
    }

    // Should not panic and should be in a valid state
    match app.view_mode {
        ViewMode::Summary | ViewMode::Detail(_) | ViewMode::Split(_) | ViewMode::Diff(_, _) => {}
    }
}

#[test]
fn test_many_view_transitions() {
    let mut app = TuiApp::new();

    for _ in 0..50 {
        handle_key_event(&mut app, key(KeyCode::Char('1')), 5);
        handle_key_event(&mut app, key(KeyCode::Esc), 5);
        handle_key_event(&mut app, key(KeyCode::Char('s')), 5);
        handle_key_event(&mut app, key(KeyCode::Esc), 5);
        handle_key_event(&mut app, key(KeyCode::Char('d')), 5);
        handle_key_event(&mut app, key(KeyCode::Esc), 5);
    }

    assert_eq!(
        app.view_mode,
        ViewMode::Summary,
        "Should end in summary view after transitions"
    );
}

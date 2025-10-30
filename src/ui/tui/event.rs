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

//! Event handling for TUI keyboard input

use super::app::{TuiApp, ViewMode};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;

/// Poll for keyboard events with a timeout
///
/// Returns Some(KeyEvent) if a key was pressed, None if timeout occurred
pub fn poll_event(timeout: Duration) -> anyhow::Result<Option<KeyEvent>> {
    if event::poll(timeout)? {
        if let Event::Key(key) = event::read()? {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// Handle a keyboard event and update app state
pub fn handle_key_event(app: &mut TuiApp, key: KeyEvent, num_nodes: usize) {
    // Global keys that work in any mode
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.quit();
            return;
        }
        KeyCode::Char('q') => {
            app.quit();
            return;
        }
        KeyCode::Char('?') => {
            app.toggle_help();
            return;
        }
        KeyCode::Esc => {
            if app.show_help {
                app.show_help = false;
            } else {
                app.show_summary();
            }
            return;
        }
        _ => {}
    }

    // Mode-specific keys
    match &app.view_mode {
        ViewMode::Summary => handle_summary_keys(app, key, num_nodes),
        ViewMode::Detail(_) => handle_detail_keys(app, key, num_nodes),
        ViewMode::Split(_) => handle_split_keys(app, key, num_nodes),
        ViewMode::Diff(_, _) => handle_diff_keys(app, key),
    }
}

/// Handle keys in summary view
fn handle_summary_keys(app: &mut TuiApp, key: KeyEvent, num_nodes: usize) {
    match key.code {
        // Number keys 1-9 for detail view
        KeyCode::Char(c @ '1'..='9') => {
            let idx = (c as u8 - b'1') as usize;
            if idx < num_nodes {
                app.show_detail(idx, num_nodes);
            }
        }
        // 's' for split view
        KeyCode::Char('s') => {
            if num_nodes >= 2 {
                // Default to first 4 nodes
                let indices: Vec<usize> = (0..num_nodes.min(4)).collect();
                app.show_split(indices, num_nodes);
            }
        }
        // 'd' for diff view
        KeyCode::Char('d') => {
            if num_nodes >= 2 {
                // Default to first 2 nodes
                app.show_diff(0, 1, num_nodes);
            }
        }
        _ => {}
    }
}

/// Handle keys in detail view
fn handle_detail_keys(app: &mut TuiApp, key: KeyEvent, num_nodes: usize) {
    match key.code {
        // Arrow keys for scrolling
        KeyCode::Up => {
            app.scroll_up(1);
        }
        KeyCode::Down => {
            app.scroll_down(1, usize::MAX); // Max will be clamped in scroll_down
        }
        // Page up/down for faster scrolling
        KeyCode::PageUp => {
            app.scroll_up(10);
        }
        KeyCode::PageDown => {
            app.scroll_down(10, usize::MAX);
        }
        // Home/End for jumping to top/bottom
        KeyCode::Home => {
            if let ViewMode::Detail(idx) = app.view_mode {
                app.set_scroll(idx, 0);
                app.follow_mode = false;
            }
        }
        KeyCode::End => {
            if let ViewMode::Detail(idx) = app.view_mode {
                app.set_scroll(idx, usize::MAX);
                app.follow_mode = true; // Re-enable follow mode
            }
        }
        // Left/Right arrows for node switching
        KeyCode::Left => {
            app.prev_node(num_nodes);
        }
        KeyCode::Right => {
            app.next_node(num_nodes);
        }
        // 'f' to toggle follow mode
        KeyCode::Char('f') => {
            app.toggle_follow();
        }
        // Number keys for jumping to specific nodes
        KeyCode::Char(c @ '1'..='9') => {
            let idx = (c as u8 - b'1') as usize;
            if idx < num_nodes {
                app.show_detail(idx, num_nodes);
            }
        }
        _ => {}
    }
}

/// Handle keys in split view
fn handle_split_keys(app: &mut TuiApp, key: KeyEvent, num_nodes: usize) {
    // Number keys to focus on specific nodes
    if let KeyCode::Char(c @ '1'..='9') = key.code {
        let idx = (c as u8 - b'1') as usize;
        if idx < num_nodes {
            app.show_detail(idx, num_nodes);
        }
    }
}

/// Handle keys in diff view
fn handle_diff_keys(_app: &mut TuiApp, key: KeyEvent) {
    match key.code {
        // Arrow keys for synchronized scrolling
        KeyCode::Up => {
            // TODO: Implement synchronized scrolling for diff view
            // For now, we don't support scrolling in diff view
        }
        KeyCode::Down => {
            // TODO: Implement synchronized scrolling for diff view
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quit_keys() {
        let mut app = TuiApp::new();

        // 'q' should quit
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        handle_key_event(&mut app, key, 5);
        assert!(app.should_quit);

        // Reset
        app.should_quit = false;

        // Ctrl+C should quit
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        handle_key_event(&mut app, key, 5);
        assert!(app.should_quit);
    }

    #[test]
    fn test_summary_navigation() {
        let mut app = TuiApp::new();

        // Press '2' to view node 1 (0-indexed)
        let key = KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE);
        handle_key_event(&mut app, key, 5);
        assert_eq!(app.view_mode, ViewMode::Detail(1));

        // Press 's' for split view
        app.show_summary();
        let key = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE);
        handle_key_event(&mut app, key, 5);
        assert!(matches!(app.view_mode, ViewMode::Split(_)));
    }

    #[test]
    fn test_detail_scrolling() {
        let mut app = TuiApp::new();
        app.show_detail(0, 5);
        app.set_scroll(0, 10);

        // Up arrow should scroll up
        let key = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        handle_key_event(&mut app, key, 5);
        assert_eq!(app.get_scroll(0), 9);

        // Down arrow should scroll down
        let key = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        handle_key_event(&mut app, key, 5);
        assert_eq!(app.get_scroll(0), 10);
    }

    #[test]
    fn test_detail_node_switching() {
        let mut app = TuiApp::new();
        app.show_detail(1, 5);

        // Right arrow should go to next node
        let key = KeyEvent::new(KeyCode::Right, KeyModifiers::NONE);
        handle_key_event(&mut app, key, 5);
        assert_eq!(app.view_mode, ViewMode::Detail(2));

        // Left arrow should go to previous node
        let key = KeyEvent::new(KeyCode::Left, KeyModifiers::NONE);
        handle_key_event(&mut app, key, 5);
        assert_eq!(app.view_mode, ViewMode::Detail(1));
    }

    #[test]
    fn test_esc_to_summary() {
        let mut app = TuiApp::new();
        app.show_detail(0, 5);

        // Esc should return to summary
        let key = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        handle_key_event(&mut app, key, 5);
        assert_eq!(app.view_mode, ViewMode::Summary);
    }
}

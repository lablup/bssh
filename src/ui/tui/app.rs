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

//! TUI application state management
//!
//! This module manages the state of the interactive terminal UI, including
//! view modes, scroll positions, and user interaction state.

use std::collections::HashMap;

/// View mode for the TUI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewMode {
    /// Summary view showing all nodes with status
    Summary,
    /// Detail view showing a single node's full output
    Detail(usize),
    /// Split view showing 2-4 nodes side-by-side
    Split(Vec<usize>),
    /// Diff view comparing two nodes
    Diff(usize, usize),
}

/// Main TUI application state
///
/// This struct maintains all state needed for the interactive terminal UI,
/// including current view mode, scroll positions per node, and UI flags.
pub struct TuiApp {
    /// Current view mode
    pub view_mode: ViewMode,
    /// Scroll positions for each node (node_index -> scroll_line)
    pub scroll_positions: HashMap<usize, usize>,
    /// Auto-scroll to bottom (follow mode)
    pub follow_mode: bool,
    /// Whether the application should quit
    pub should_quit: bool,
    /// Whether to show help overlay
    pub show_help: bool,
    /// Track if UI needs redraw (for performance optimization)
    pub needs_redraw: bool,
    /// Track last rendered data sizes for change detection
    pub last_data_sizes: HashMap<usize, (usize, usize)>, // node_id -> (stdout_size, stderr_size)
    /// Whether all tasks have been completed
    pub all_tasks_completed: bool,
}

impl TuiApp {
    /// Create a new TUI application in summary view
    pub fn new() -> Self {
        Self {
            view_mode: ViewMode::Summary,
            scroll_positions: HashMap::new(),
            follow_mode: true, // Auto-scroll by default
            should_quit: false,
            show_help: false,
            needs_redraw: true, // Initial draw needed
            last_data_sizes: HashMap::new(),
            all_tasks_completed: false,
        }
    }

    /// Check if data has changed for any node
    pub fn check_data_changes(&mut self, streams: &[crate::executor::NodeStream]) -> bool {
        let mut has_changes = false;

        for (idx, stream) in streams.iter().enumerate() {
            let new_sizes = (stream.stdout().len(), stream.stderr().len());

            if let Some(&old_sizes) = self.last_data_sizes.get(&idx) {
                if old_sizes != new_sizes {
                    has_changes = true;
                    self.last_data_sizes.insert(idx, new_sizes);
                    self.needs_redraw = true;
                }
            } else {
                // New node, needs redraw
                self.last_data_sizes.insert(idx, new_sizes);
                has_changes = true;
                self.needs_redraw = true;
            }
        }

        has_changes
    }

    /// Mark that UI needs redrawing
    pub fn mark_needs_redraw(&mut self) {
        self.needs_redraw = true;
    }

    /// Check if redraw is needed and reset flag
    pub fn should_redraw(&mut self) -> bool {
        if self.needs_redraw {
            self.needs_redraw = false;
            true
        } else {
            false
        }
    }

    /// Switch to summary view
    pub fn show_summary(&mut self) {
        self.view_mode = ViewMode::Summary;
        self.needs_redraw = true;
    }

    /// Switch to detail view for a specific node
    pub fn show_detail(&mut self, node_index: usize, num_nodes: usize) {
        if node_index < num_nodes {
            self.view_mode = ViewMode::Detail(node_index);
            self.needs_redraw = true;
        }
    }

    /// Switch to split view with given node indices
    pub fn show_split(&mut self, indices: Vec<usize>, num_nodes: usize) {
        // Validate indices and limit to 4 nodes
        let valid_indices: Vec<_> = indices
            .into_iter()
            .filter(|&i| i < num_nodes)
            .take(4)
            .collect();

        if valid_indices.len() >= 2 {
            self.view_mode = ViewMode::Split(valid_indices);
            self.needs_redraw = true;
        }
    }

    /// Switch to diff view comparing two nodes
    pub fn show_diff(&mut self, node_a: usize, node_b: usize, num_nodes: usize) {
        if node_a < num_nodes && node_b < num_nodes && node_a != node_b {
            self.view_mode = ViewMode::Diff(node_a, node_b);
            self.needs_redraw = true;
        }
    }

    /// Toggle follow mode (auto-scroll)
    pub fn toggle_follow(&mut self) {
        self.follow_mode = !self.follow_mode;
        self.needs_redraw = true;
    }

    /// Toggle help overlay
    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
        self.needs_redraw = true;
    }

    /// Get scroll position for a node
    pub fn get_scroll(&self, node_index: usize) -> usize {
        self.scroll_positions.get(&node_index).copied().unwrap_or(0)
    }

    /// Set scroll position for a node with memory limit
    pub fn set_scroll(&mut self, node_index: usize, position: usize) {
        // Limit HashMap size to prevent unbounded memory growth
        // Keep only last 100 node scroll positions (more than enough for typical use)
        const MAX_SCROLL_ENTRIES: usize = 100;

        if self.scroll_positions.len() >= MAX_SCROLL_ENTRIES
            && !self.scroll_positions.contains_key(&node_index)
        {
            // Remove oldest entry (arbitrary - could use LRU if needed)
            if let Some(first_key) = self.scroll_positions.keys().next().copied() {
                self.scroll_positions.remove(&first_key);
            }
        }

        self.scroll_positions.insert(node_index, position);
    }

    /// Scroll up in current detail view
    pub fn scroll_up(&mut self, lines: usize) {
        if let ViewMode::Detail(idx) = self.view_mode {
            let pos = self.get_scroll(idx);
            self.set_scroll(idx, pos.saturating_sub(lines));
            // Disable follow mode when manually scrolling
            self.follow_mode = false;
            self.needs_redraw = true;
        }
    }

    /// Scroll down in current detail view
    pub fn scroll_down(&mut self, lines: usize, max_lines: usize) {
        if let ViewMode::Detail(idx) = self.view_mode {
            let pos = self.get_scroll(idx);
            let new_pos = (pos + lines).min(max_lines);
            self.set_scroll(idx, new_pos);
            // Disable follow mode when manually scrolling
            self.follow_mode = false;
            self.needs_redraw = true;
        }
    }

    /// Switch to next node in detail view
    pub fn next_node(&mut self, num_nodes: usize) {
        if let ViewMode::Detail(idx) = self.view_mode {
            let next = (idx + 1) % num_nodes;
            self.view_mode = ViewMode::Detail(next);
            self.needs_redraw = true;
        }
    }

    /// Switch to previous node in detail view
    pub fn prev_node(&mut self, num_nodes: usize) {
        if let ViewMode::Detail(idx) = self.view_mode {
            let prev = if idx == 0 { num_nodes - 1 } else { idx - 1 };
            self.view_mode = ViewMode::Detail(prev);
            self.needs_redraw = true;
        }
    }

    /// Quit the application
    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    /// Mark all tasks as completed
    pub fn mark_all_tasks_completed(&mut self) {
        if !self.all_tasks_completed {
            self.all_tasks_completed = true;
            self.needs_redraw = true;
        }
    }

    /// Get help text for current view mode
    pub fn get_help_text(&self) -> Vec<(&'static str, &'static str)> {
        let mut help = vec![
            ("q", "Quit"),
            ("Esc", "Back to summary"),
            ("?", "Toggle help"),
        ];

        match &self.view_mode {
            ViewMode::Summary => {
                help.extend_from_slice(&[
                    ("1-9", "View node detail"),
                    ("s", "Split view (2-4 nodes)"),
                    ("d", "Diff view (compare 2 nodes)"),
                ]);
            }
            ViewMode::Detail(_) => {
                help.extend_from_slice(&[
                    ("↑/↓", "Scroll up/down"),
                    ("←/→", "Previous/next node"),
                    ("f", "Toggle auto-scroll"),
                    ("PgUp/PgDn", "Scroll page"),
                    ("Home/End", "Scroll to top/bottom"),
                ]);
            }
            ViewMode::Split(_) => {
                help.extend_from_slice(&[("1-4", "Focus on node")]);
            }
            ViewMode::Diff(_, _) => {
                help.extend_from_slice(&[("↑/↓", "Sync scroll")]);
            }
        }

        help
    }
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_creation() {
        let app = TuiApp::new();
        assert_eq!(app.view_mode, ViewMode::Summary);
        assert!(app.follow_mode);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_switch_to_detail() {
        let mut app = TuiApp::new();
        app.show_detail(2, 5);
        assert_eq!(app.view_mode, ViewMode::Detail(2));

        // Invalid index should not change view
        let prev_mode = app.view_mode.clone();
        app.show_detail(10, 5);
        assert_eq!(app.view_mode, prev_mode);
    }

    #[test]
    fn test_scroll_positions() {
        let mut app = TuiApp::new();

        app.set_scroll(0, 10);
        assert_eq!(app.get_scroll(0), 10);
        assert_eq!(app.get_scroll(1), 0); // Default
    }

    #[test]
    fn test_scroll_up_down() {
        let mut app = TuiApp::new();
        app.show_detail(0, 5);

        app.set_scroll(0, 10);
        app.scroll_up(3);
        assert_eq!(app.get_scroll(0), 7);
        assert!(!app.follow_mode); // Should disable follow

        app.scroll_down(5, 20);
        assert_eq!(app.get_scroll(0), 12);
    }

    #[test]
    fn test_node_navigation() {
        let mut app = TuiApp::new();
        app.show_detail(1, 5);

        app.next_node(5);
        assert_eq!(app.view_mode, ViewMode::Detail(2));

        app.prev_node(5);
        assert_eq!(app.view_mode, ViewMode::Detail(1));

        // Test wrapping
        app.show_detail(4, 5);
        app.next_node(5);
        assert_eq!(app.view_mode, ViewMode::Detail(0));

        app.show_detail(0, 5);
        app.prev_node(5);
        assert_eq!(app.view_mode, ViewMode::Detail(4));
    }

    #[test]
    fn test_split_view() {
        let mut app = TuiApp::new();

        // Valid split view
        app.show_split(vec![0, 1, 2], 5);
        assert_eq!(app.view_mode, ViewMode::Split(vec![0, 1, 2]));

        // Too few nodes
        app.show_split(vec![0], 5);
        assert_eq!(app.view_mode, ViewMode::Split(vec![0, 1, 2])); // No change

        // Invalid indices filtered out
        app.show_split(vec![0, 1, 10, 11], 5);
        assert_eq!(app.view_mode, ViewMode::Split(vec![0, 1]));
    }

    #[test]
    fn test_diff_view() {
        let mut app = TuiApp::new();

        app.show_diff(0, 1, 5);
        assert_eq!(app.view_mode, ViewMode::Diff(0, 1));

        // Same node should not work
        app.show_diff(2, 2, 5);
        assert_eq!(app.view_mode, ViewMode::Diff(0, 1)); // No change
    }

    #[test]
    fn test_toggle_follow() {
        let mut app = TuiApp::new();
        assert!(app.follow_mode);

        app.toggle_follow();
        assert!(!app.follow_mode);

        app.toggle_follow();
        assert!(app.follow_mode);
    }
}

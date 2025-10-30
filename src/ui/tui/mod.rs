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

//! Interactive TUI for real-time multi-node monitoring
//!
//! This module provides an interactive terminal user interface built with ratatui
//! for monitoring parallel command execution across multiple nodes. It supports
//! multiple view modes including summary, detail, split, and diff views.

pub mod app;
pub mod event;
pub mod progress;
pub mod terminal_guard;
pub mod views;

use crate::executor::MultiNodeStreamManager;
use anyhow::Result;
use app::{TuiApp, ViewMode};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;
use terminal_guard::TerminalGuard;

/// Run the TUI event loop
///
/// This function sets up the terminal, runs the event loop, and cleans up
/// on exit. It handles keyboard input and updates the display based on the
/// current view mode. Terminal cleanup is guaranteed via RAII guards.
pub async fn run_tui(
    manager: &mut MultiNodeStreamManager,
    cluster_name: &str,
    command: &str,
) -> Result<()> {
    // Setup terminal with automatic cleanup guard
    let _terminal_guard = TerminalGuard::new()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    // Hide cursor during TUI operation
    terminal.hide_cursor()?;

    let mut app = TuiApp::new();

    // Main event loop
    let result = run_event_loop(&mut terminal, &mut app, manager, cluster_name, command).await;

    // Show cursor before exit (guard will handle the rest)
    terminal.show_cursor()?;

    // The terminal guard will automatically clean up when dropped

    result
}

/// Minimum terminal dimensions for TUI
const MIN_TERMINAL_WIDTH: u16 = 40;
const MIN_TERMINAL_HEIGHT: u16 = 10;

/// Main event loop
async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
    manager: &mut MultiNodeStreamManager,
    cluster_name: &str,
    command: &str,
) -> Result<()> {
    loop {
        // Poll all node streams for new output
        manager.poll_all();

        // Check terminal size before rendering
        let size = terminal.size()?;
        if size.width < MIN_TERMINAL_WIDTH || size.height < MIN_TERMINAL_HEIGHT {
            // Render minimal error message for small terminal
            terminal.draw(render_size_error)?;
        } else {
            // Render normal UI
            terminal.draw(|f| render_ui(f, app, manager, cluster_name, command))?;
        }

        // Handle keyboard input (with timeout)
        if let Some(key) = event::poll_event(Duration::from_millis(100))? {
            event::handle_key_event(app, key, manager.total_count());
        }

        // Check exit conditions
        if app.should_quit || manager.all_complete() {
            break;
        }

        // Small delay to prevent CPU spinning
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Ok(())
}

/// Render the UI based on current view mode
fn render_ui(
    f: &mut ratatui::Frame,
    app: &TuiApp,
    manager: &MultiNodeStreamManager,
    cluster_name: &str,
    command: &str,
) {
    // Render based on view mode
    match &app.view_mode {
        ViewMode::Summary => {
            views::summary::render(f, manager, cluster_name, command);
        }
        ViewMode::Detail(idx) => {
            if let Some(stream) = manager.streams().get(*idx) {
                let scroll = app.get_scroll(*idx);
                views::detail::render(f, stream, *idx, scroll, app.follow_mode);
            }
        }
        ViewMode::Split(indices) => {
            views::split::render(f, manager, indices);
        }
        ViewMode::Diff(a, b) => {
            let streams = manager.streams();
            if let (Some(stream_a), Some(stream_b)) = (streams.get(*a), streams.get(*b)) {
                // For now, use 0 as scroll position (TODO: implement diff scroll)
                views::diff::render(f, stream_a, stream_b, *a, *b, 0);
            }
        }
    }

    // Render help overlay if enabled
    if app.show_help {
        render_help_overlay(f, app);
    }
}

/// Render help overlay
fn render_help_overlay(f: &mut ratatui::Frame, app: &TuiApp) {
    use ratatui::{
        layout::Alignment,
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Clear, Paragraph},
    };

    // Create a centered popup
    let area = centered_rect(60, 60, f.area());

    // Clear the background
    f.render_widget(Clear, area);

    let help_items = app.get_help_text();
    let mut lines = vec![
        Line::from(Span::styled(
            "Keyboard Shortcuts",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    for (key, description) in help_items {
        lines.push(Line::from(vec![
            Span::styled(format!(" {key:<12} "), Style::default().fg(Color::Yellow)),
            Span::raw(description),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press ? or Esc to close",
        Style::default().fg(Color::DarkGray),
    )));

    let help = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .alignment(Alignment::Left);

    f.render_widget(help, area);
}

/// Render error message for terminal too small
fn render_size_error(f: &mut ratatui::Frame) {
    use ratatui::{
        layout::Alignment,
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph},
    };

    let message = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Terminal too small!",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "Minimum size: {MIN_TERMINAL_WIDTH}x{MIN_TERMINAL_HEIGHT}"
        )),
        Line::from(format!(
            "Current size: {}x{}",
            f.area().width,
            f.area().height
        )),
        Line::from(""),
        Line::from("Please resize your terminal"),
        Line::from("or press 'q' to quit"),
    ];

    let paragraph = Paragraph::new(message)
        .block(
            Block::default()
                .title(" Error ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .alignment(Alignment::Center);

    // Try to center the message if there's enough space
    let area = if f.area().width >= 30 && f.area().height >= 8 {
        centered_rect(80, 60, f.area())
    } else {
        f.area()
    };

    f.render_widget(paragraph, area);
}

/// Helper function to create a centered rectangle
fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    use ratatui::layout::{Constraint, Direction, Layout};

    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

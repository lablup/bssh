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
pub mod log_buffer;
pub mod log_layer;
pub mod progress;
pub mod terminal_guard;
pub mod views;

use crate::executor::MultiNodeStreamManager;
use anyhow::Result;
use app::{TuiApp, ViewMode};
use log_buffer::LogBuffer;
use log_layer::TuiLogLayer;
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use terminal_guard::TerminalGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Result of TUI execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiExitReason {
    /// User explicitly quit (pressed 'q' or Ctrl+C)
    UserQuit,
    /// All tasks completed naturally
    AllTasksCompleted,
}

/// Run the TUI event loop
///
/// This function sets up the terminal, runs the event loop, and cleans up
/// on exit. It handles keyboard input and updates the display based on the
/// current view mode. Terminal cleanup is guaranteed via RAII guards.
///
/// Returns `TuiExitReason` to indicate whether the user quit or all tasks completed.
pub async fn run_tui(
    manager: &mut MultiNodeStreamManager,
    cluster_name: &str,
    command: &str,
    _batch_mode: bool, // Reserved for future use; TUI has its own quit handling
) -> Result<TuiExitReason> {
    // Create shared log buffer
    let log_buffer = Arc::new(Mutex::new(LogBuffer::default()));

    run_tui_with_log_buffer(manager, cluster_name, command, _batch_mode, log_buffer).await
}

/// Run the TUI event loop with a pre-configured log buffer
///
/// This variant allows passing a shared log buffer that can be connected
/// to a TuiLogLayer for capturing tracing events.
pub async fn run_tui_with_log_buffer(
    manager: &mut MultiNodeStreamManager,
    cluster_name: &str,
    command: &str,
    _batch_mode: bool,
    log_buffer: Arc<Mutex<LogBuffer>>,
) -> Result<TuiExitReason> {
    // Setup terminal with automatic cleanup guard
    let _terminal_guard = TerminalGuard::new()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    // Hide cursor during TUI operation
    terminal.hide_cursor()?;

    let mut app = TuiApp::with_log_buffer(log_buffer);

    // Main event loop
    let exit_reason =
        run_event_loop(&mut terminal, &mut app, manager, cluster_name, command).await?;

    // Show cursor before exit (guard will handle the rest)
    terminal.show_cursor()?;

    // The terminal guard will automatically clean up when dropped

    Ok(exit_reason)
}

/// Initialize TUI-mode logging with a custom layer
///
/// Returns the shared log buffer that can be passed to `run_tui_with_log_buffer`.
/// This should be called before entering TUI mode to capture all logs.
pub fn init_tui_logging(verbosity: u8) -> Arc<Mutex<LogBuffer>> {
    let log_buffer = Arc::new(Mutex::new(LogBuffer::default()));
    let tui_layer = TuiLogLayer::new(Arc::clone(&log_buffer));

    // Create filter based on verbosity
    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        match verbosity {
            0 => EnvFilter::new("bssh=warn"),
            1 => EnvFilter::new("bssh=info"),
            2 => EnvFilter::new("bssh=debug,russh=debug"),
            _ => EnvFilter::new("bssh=trace,russh=trace,russh_sftp=debug"),
        }
    };

    // Initialize the subscriber with TUI layer
    tracing_subscriber::registry()
        .with(filter)
        .with(tui_layer)
        .init();

    log_buffer
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
) -> Result<TuiExitReason> {
    // Force initial render
    app.mark_needs_redraw();

    loop {
        // Poll all node streams for new output
        manager.poll_all();

        // Check if data has changed
        let streams = manager.streams();
        let data_changed = app.check_data_changes(streams);

        // Check if there are new log entries
        let log_changed = app.check_log_updates();

        // Check terminal size before rendering
        let size = terminal.size()?;
        let size_ok = size.width >= MIN_TERMINAL_WIDTH && size.height >= MIN_TERMINAL_HEIGHT;

        // Only render if needed (data changed, log changed, user input, or terminal resized)
        if app.should_redraw() || data_changed || log_changed {
            if !size_ok {
                // Render minimal error message for small terminal
                terminal.draw(render_size_error)?;
            } else {
                // Render normal UI
                terminal.draw(|f| render_ui(f, app, manager, cluster_name, command))?;
            }
        }

        // Handle keyboard input (with timeout)
        if let Some(key) = event::poll_event(Duration::from_millis(100))? {
            event::handle_key_event(app, key, manager.total_count());
            // Key events usually require redraw
            app.mark_needs_redraw();
        }

        // Check if all tasks are complete and mark it
        if manager.all_complete() {
            app.mark_all_tasks_completed();
        }

        // Check exit condition (only quit when user explicitly requests)
        if app.should_quit {
            // Determine exit reason: user quit vs all tasks completed
            let exit_reason = if app.all_tasks_completed {
                TuiExitReason::AllTasksCompleted
            } else {
                TuiExitReason::UserQuit
            };
            return Ok(exit_reason);
        }

        // Small delay to prevent CPU spinning
        // This is our main loop interval
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Render the UI based on current view mode
fn render_ui(
    f: &mut ratatui::Frame,
    app: &TuiApp,
    manager: &MultiNodeStreamManager,
    cluster_name: &str,
    command: &str,
) {
    // Calculate layout with optional log panel
    let (main_area, log_area) =
        views::log_panel::calculate_layout(f.area(), app.log_panel_height, app.log_panel_visible);

    // Calculate layout with log panel
    // main_area is used for rendering the main content
    // log_area (if present) is used for rendering the log panel

    // Render based on view mode in the main area
    match &app.view_mode {
        ViewMode::Summary => {
            views::summary::render_in_area(
                f,
                main_area,
                manager,
                cluster_name,
                command,
                app.all_tasks_completed,
            );
        }
        ViewMode::Detail(idx) => {
            if let Some(stream) = manager.streams().get(*idx) {
                let scroll = app.get_scroll(*idx);
                views::detail::render_in_area(
                    f,
                    main_area,
                    stream,
                    *idx,
                    scroll,
                    app.follow_mode,
                    app.all_tasks_completed,
                );
            }
        }
        ViewMode::Split(indices) => {
            views::split::render_in_area(f, main_area, manager, indices);
        }
        ViewMode::Diff(a, b) => {
            let streams = manager.streams();
            if let (Some(stream_a), Some(stream_b)) = (streams.get(*a), streams.get(*b)) {
                views::diff::render_in_area(f, main_area, stream_a, stream_b, *a, *b, 0);
            }
        }
    }

    // Render log panel if visible
    if let Some(log_area) = log_area {
        views::log_panel::render(
            f,
            log_area,
            &app.log_buffer,
            app.log_scroll_offset,
            app.log_show_timestamps,
        );
    }

    // Render help overlay if enabled (on top of everything)
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
        Style::default().fg(Color::Gray),
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

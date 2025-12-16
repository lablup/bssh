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

//! Log panel view for displaying captured log entries
//!
//! This module provides a TUI panel that displays log entries captured
//! during TUI mode, color-coded by log level.

use crate::ui::tui::log_buffer::LogBuffer;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use std::sync::{Arc, Mutex};
use tracing::Level;

/// Minimum height for the log panel (in lines)
pub const MIN_LOG_PANEL_HEIGHT: u16 = 3;

/// Maximum height for the log panel (in lines)
pub const MAX_LOG_PANEL_HEIGHT: u16 = 10;

/// Default height for the log panel (in lines)
pub const DEFAULT_LOG_PANEL_HEIGHT: u16 = 3;

/// Get the color for a log level
fn level_color(level: Level) -> Color {
    match level {
        Level::ERROR => Color::Red,
        Level::WARN => Color::Yellow,
        Level::INFO => Color::White,
        Level::DEBUG => Color::DarkGray,
        Level::TRACE => Color::DarkGray,
    }
}

/// Get the styled level indicator
fn level_span(level: Level) -> Span<'static> {
    let (text, color) = match level {
        Level::ERROR => ("ERROR", Color::Red),
        Level::WARN => (" WARN", Color::Yellow),
        Level::INFO => (" INFO", Color::White),
        Level::DEBUG => ("DEBUG", Color::DarkGray),
        Level::TRACE => ("TRACE", Color::DarkGray),
    };
    Span::styled(
        text,
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

/// Render the log panel
///
/// # Arguments
/// * `f` - The ratatui frame to render to
/// * `area` - The area to render the panel in
/// * `buffer` - The shared log buffer
/// * `scroll_offset` - Number of entries to scroll up from the bottom
/// * `show_timestamps` - Whether to show timestamps in log entries
pub fn render(
    f: &mut Frame,
    area: Rect,
    buffer: &Arc<Mutex<LogBuffer>>,
    scroll_offset: usize,
    show_timestamps: bool,
) {
    // Calculate available lines for log entries (excluding borders)
    let available_lines = area.height.saturating_sub(2) as usize;

    // Clone entries with minimal lock time to avoid UI jitter under heavy logging
    let (entries, total) = if let Ok(buffer) = buffer.lock() {
        let total = buffer.len();
        // Clone entries to release lock quickly
        let entries: Vec<_> = buffer
            .get_window(scroll_offset, available_lines)
            .into_iter()
            .cloned()
            .collect();
        (entries, total)
    } else {
        (Vec::new(), 0)
    };

    // Build display lines outside the lock
    let lines: Vec<Line> = entries
        .iter()
        .map(|entry| {
            let mut spans = Vec::new();

            // Add timestamp if enabled
            if show_timestamps {
                spans.push(Span::styled(
                    format!("{} ", entry.timestamp.format("%H:%M:%S")),
                    Style::default().fg(Color::DarkGray),
                ));
            }

            // Add level indicator
            spans.push(Span::raw("["));
            spans.push(level_span(entry.level));
            spans.push(Span::raw("] "));

            // Add target (module name)
            let short_target = entry.target.rsplit("::").next().unwrap_or(&entry.target);
            spans.push(Span::styled(
                format!("{short_target}: "),
                Style::default().fg(Color::Cyan),
            ));

            // Add message with level-based coloring
            spans.push(Span::styled(
                entry.message.clone(),
                Style::default().fg(level_color(entry.level)),
            ));

            Line::from(spans)
        })
        .collect();

    // Create scroll indicator
    let scroll_indicator = if scroll_offset > 0 {
        format!(" Logs ({} more below) ", scroll_offset)
    } else if total > available_lines {
        format!(" Logs ({} entries) ", total)
    } else {
        " Logs ".to_string()
    };

    // Fill remaining lines if needed
    let mut display_lines = lines;
    while display_lines.len() < available_lines {
        display_lines.insert(0, Line::from(""));
    }

    let paragraph = Paragraph::new(display_lines).block(
        Block::default()
            .title(scroll_indicator)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(paragraph, area);
}

/// Render an empty log panel placeholder
pub fn render_empty(f: &mut Frame, area: Rect) {
    let paragraph = Paragraph::new(vec![Line::from(Span::styled(
        "No logs captured",
        Style::default().fg(Color::DarkGray),
    ))])
    .block(
        Block::default()
            .title(" Logs ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(paragraph, area);
}

/// Calculate the layout for the log panel
///
/// Returns (main_area, log_panel_area) tuple
pub fn calculate_layout(
    total_area: Rect,
    log_panel_height: u16,
    log_panel_visible: bool,
) -> (Rect, Option<Rect>) {
    if !log_panel_visible {
        return (total_area, None);
    }

    let panel_height = log_panel_height.clamp(MIN_LOG_PANEL_HEIGHT, MAX_LOG_PANEL_HEIGHT);

    // Ensure we have enough space for the log panel
    if total_area.height <= panel_height + MIN_LOG_PANEL_HEIGHT {
        // Not enough space, hide log panel
        return (total_area, None);
    }

    let main_height = total_area.height - panel_height;

    let main_area = Rect {
        x: total_area.x,
        y: total_area.y,
        width: total_area.width,
        height: main_height,
    };

    let log_area = Rect {
        x: total_area.x,
        y: total_area.y + main_height,
        width: total_area.width,
        height: panel_height,
    };

    (main_area, Some(log_area))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_layout_visible() {
        let total = Rect::new(0, 0, 80, 24);
        let (main, log) = calculate_layout(total, 5, true);

        assert_eq!(main.height, 19);
        assert!(log.is_some());
        let log = log.unwrap();
        assert_eq!(log.height, 5);
        assert_eq!(log.y, 19);
    }

    #[test]
    fn test_calculate_layout_hidden() {
        let total = Rect::new(0, 0, 80, 24);
        let (main, log) = calculate_layout(total, 5, false);

        assert_eq!(main.height, 24);
        assert!(log.is_none());
    }

    #[test]
    fn test_calculate_layout_too_small() {
        let total = Rect::new(0, 0, 80, 5);
        let (main, log) = calculate_layout(total, 5, true);

        // Should hide log panel when not enough space
        assert_eq!(main.height, 5);
        assert!(log.is_none());
    }

    #[test]
    fn test_level_color() {
        assert_eq!(level_color(Level::ERROR), Color::Red);
        assert_eq!(level_color(Level::WARN), Color::Yellow);
        assert_eq!(level_color(Level::INFO), Color::White);
        assert_eq!(level_color(Level::DEBUG), Color::DarkGray);
    }
}

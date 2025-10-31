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

//! Detail view showing a single node's full output with scrolling

use crate::executor::{ExecutionStatus, NodeStream};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Render the detail view for a single node
pub fn render(
    f: &mut Frame,
    stream: &NodeStream,
    node_index: usize,
    scroll_pos: usize,
    follow_mode: bool,
    all_tasks_completed: bool,
) {
    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Output content
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    render_header(f, chunks[0], stream, node_index);
    render_output(f, chunks[1], stream, scroll_pos, follow_mode);
    render_footer(f, chunks[2], follow_mode, all_tasks_completed);
}

/// Render the header with node information
fn render_header(f: &mut Frame, area: Rect, stream: &NodeStream, node_index: usize) {
    let node = &stream.node;
    let status_text = match stream.status() {
        ExecutionStatus::Pending => ("Pending", Color::Gray),
        ExecutionStatus::Running => ("Running", Color::Blue),
        ExecutionStatus::Completed => ("Completed", Color::Green),
        ExecutionStatus::Failed(msg) => {
            let title = format!(
                " [{}] {}:{} ({}) - Failed: {} ",
                node_index + 1,
                node.host,
                node.port,
                node.username,
                msg
            );
            let header = Paragraph::new(Line::from(Span::styled(
                title,
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )))
            .block(Block::default().borders(Borders::ALL));

            f.render_widget(header, area);
            return;
        }
    };

    let title = format!(
        " [{}] {}:{} ({}) - {} ",
        node_index + 1,
        node.host,
        node.port,
        node.username,
        status_text.0
    );

    let header = Paragraph::new(Line::from(Span::styled(
        title,
        Style::default()
            .fg(status_text.1)
            .add_modifier(Modifier::BOLD),
    )))
    .block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

/// Render the output content with scrolling
fn render_output(
    f: &mut Frame,
    area: Rect,
    stream: &NodeStream,
    scroll_pos: usize,
    follow_mode: bool,
) {
    // Combine stdout and stderr
    let stdout = String::from_utf8_lossy(stream.stdout());
    let stderr = String::from_utf8_lossy(stream.stderr());

    let mut lines: Vec<Line> = Vec::new();

    // Add stdout lines
    for line in stdout.lines() {
        lines.push(Line::from(line.to_string()));
    }

    // Add stderr lines in red
    if !stderr.is_empty() {
        lines.push(Line::from(Span::styled(
            "--- stderr ---",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));

        for line in stderr.lines() {
            lines.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Red),
            )));
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "(no output yet)",
            Style::default().fg(Color::Gray),
        )));
    }

    // Calculate scroll position with bounds checking
    let viewport_height = area.height.saturating_sub(2) as usize; // Minus borders
    let total_lines = lines.len();

    // Ensure viewport height is at least 1 to avoid division by zero issues
    let viewport_height = viewport_height.max(1);

    // Calculate maximum scroll position
    let max_scroll = total_lines.saturating_sub(viewport_height);

    let scroll = if follow_mode {
        // Auto-scroll to bottom
        max_scroll
    } else {
        // Manual scroll position with bounds checking
        scroll_pos.min(max_scroll)
    };

    // Ensure scroll is within valid range
    let scroll = scroll.min(total_lines.saturating_sub(1));

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::LEFT | Borders::RIGHT))
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

/// Render the footer with help text
fn render_footer(f: &mut Frame, area: Rect, follow_mode: bool, all_tasks_completed: bool) {
    let follow_indicator = if follow_mode {
        Span::styled("[FOLLOW] ", Style::default().fg(Color::Green))
    } else {
        Span::raw("")
    };

    let mut spans = vec![
        follow_indicator,
        Span::styled(" [←/→] ", Style::default().fg(Color::Yellow)),
        Span::raw("Switch "),
        Span::styled(" [Esc] ", Style::default().fg(Color::Yellow)),
        Span::raw("Summary "),
        Span::styled(" [↑/↓] ", Style::default().fg(Color::Yellow)),
        Span::raw("Scroll "),
        Span::styled(" [f] ", Style::default().fg(Color::Yellow)),
        Span::raw("Follow "),
        Span::styled(" [q] ", Style::default().fg(Color::Yellow)),
        Span::raw("Quit "),
    ];

    // Add completion message if all tasks are done
    if all_tasks_completed {
        spans.push(Span::raw(" │ "));
        spans.push(Span::styled(
            "✓ All tasks completed",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let help_text = Line::from(spans);

    let footer = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));

    f.render_widget(footer, area);
}

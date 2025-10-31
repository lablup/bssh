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

//! Diff view comparing two nodes side-by-side

use crate::executor::NodeStream;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Render the diff view comparing two nodes
pub fn render(
    f: &mut Frame,
    stream_a: &NodeStream,
    stream_b: &NodeStream,
    node_a_idx: usize,
    node_b_idx: usize,
    scroll_pos: usize,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Split content
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    render_header(f, chunks[0]);

    // Split content area into two columns
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    render_node_output(f, content_chunks[0], stream_a, node_a_idx, scroll_pos);
    render_node_output(f, content_chunks[1], stream_b, node_b_idx, scroll_pos);

    render_footer(f, chunks[2]);
}

/// Render the header
fn render_header(f: &mut Frame, area: Rect) {
    let header = Paragraph::new(Line::from(Span::styled(
        " Diff View - Comparing nodes side-by-side ",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )))
    .block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

/// Render output for a single node
fn render_node_output(
    f: &mut Frame,
    area: Rect,
    stream: &NodeStream,
    node_idx: usize,
    scroll_pos: usize,
) {
    let node = &stream.node;

    // Create title
    let title = format!(" [{}] {} ", node_idx + 1, node.host);

    // Get output
    let stdout = String::from_utf8_lossy(stream.stdout());
    let lines: Vec<Line> = if stdout.is_empty() {
        vec![Line::from(Span::styled(
            "(no output)",
            Style::default().fg(Color::Gray),
        ))]
    } else {
        stdout
            .lines()
            .map(|line| Line::from(line.to_string()))
            .collect()
    };

    // Apply scroll
    let viewport_height = area.height.saturating_sub(2) as usize;
    let scroll = scroll_pos.min(lines.len().saturating_sub(viewport_height));

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

/// Render the footer with help text
fn render_footer(f: &mut Frame, area: Rect) {
    let help_text = Line::from(vec![
        Span::styled(" [↑/↓] ", Style::default().fg(Color::Yellow)),
        Span::raw("Sync scroll "),
        Span::styled(" [Esc] ", Style::default().fg(Color::Yellow)),
        Span::raw("Summary "),
        Span::styled(" [q] ", Style::default().fg(Color::Yellow)),
        Span::raw("Quit "),
    ]);

    let footer = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));

    f.render_widget(footer, area);
}

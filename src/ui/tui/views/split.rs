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

//! Split view showing 2-4 nodes side-by-side

use crate::executor::{ExecutionStatus, MultiNodeStreamManager};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Render the split view
pub fn render(f: &mut Frame, manager: &MultiNodeStreamManager, indices: &[usize]) {
    let num_panes = indices.len().min(4);

    if num_panes < 2 {
        // Fallback to error message
        render_error(f, "Split view requires at least 2 nodes");
        return;
    }

    // Create layout based on number of panes
    let (rows, cols) = match num_panes {
        2 => (1, 2),
        3 => (2, 2), // 2x2 with one empty
        4 => (2, 2),
        _ => (1, 2),
    };

    // Split into rows
    let mut row_constraints = Vec::new();
    for _ in 0..rows {
        row_constraints.push(Constraint::Percentage((100 / rows) as u16));
    }
    row_constraints.push(Constraint::Length(2)); // Footer

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(row_constraints)
        .split(f.area());

    // Render each row
    let mut pane_index = 0;
    for row in 0..rows {
        if pane_index >= num_panes {
            break;
        }

        // Split row into columns
        let col_constraints = vec![Constraint::Percentage(50); cols];
        let col_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(col_constraints)
            .split(main_chunks[row]);

        for col in 0..cols {
            if pane_index >= num_panes {
                break;
            }

            let node_idx = indices[pane_index];
            if let Some(stream) = manager.streams().get(node_idx) {
                render_pane(f, col_chunks[col], stream, node_idx);
            }

            pane_index += 1;
        }
    }

    // Render footer
    render_footer(f, main_chunks[rows]);
}

/// Render a single pane for a node
fn render_pane(f: &mut Frame, area: Rect, stream: &crate::executor::NodeStream, node_idx: usize) {
    let node = &stream.node;

    // Determine status and color
    let (status_icon, status_color) = match stream.status() {
        ExecutionStatus::Pending => ("⊙", Color::DarkGray),
        ExecutionStatus::Running => ("⟳", Color::Blue),
        ExecutionStatus::Completed => ("✓", Color::Green),
        ExecutionStatus::Failed(_) => ("✗", Color::Red),
    };

    // Create title with node info
    let title = format!(" [{}] {} {} ", node_idx + 1, status_icon, node.host);

    // Get output lines
    let stdout = String::from_utf8_lossy(stream.stdout());
    let lines: Vec<Line> = if stdout.is_empty() {
        vec![Line::from(Span::styled(
            "(no output)",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        // Show last N lines that fit in the pane
        let max_lines = area.height.saturating_sub(3) as usize; // Minus borders and title
        let all_lines: Vec<_> = stdout.lines().collect();
        let start = all_lines.len().saturating_sub(max_lines);
        all_lines[start..]
            .iter()
            .map(|&line| Line::from(line.to_string()))
            .collect()
    };

    let block = Block::default()
        .title(title)
        .title_style(
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(status_color));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

/// Render error message
fn render_error(f: &mut Frame, message: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(f.area());

    let error = Paragraph::new(Line::from(Span::styled(
        message,
        Style::default().fg(Color::Red),
    )))
    .block(
        Block::default()
            .title(" Error ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)),
    );

    f.render_widget(error, chunks[0]);
}

/// Render the footer with help text
fn render_footer(f: &mut Frame, area: Rect) {
    let help_text = Line::from(vec![
        Span::styled(" [1-4] ", Style::default().fg(Color::Yellow)),
        Span::raw("Focus "),
        Span::styled(" [Esc] ", Style::default().fg(Color::Yellow)),
        Span::raw("Summary "),
        Span::styled(" [q] ", Style::default().fg(Color::Yellow)),
        Span::raw("Quit "),
    ]);

    let footer = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));

    f.render_widget(footer, area);
}

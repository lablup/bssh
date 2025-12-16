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

//! Summary view showing all nodes with status and progress

use crate::executor::{ExecutionStatus, MultiNodeStreamManager};
use crate::ui::tui::progress::{extract_status_message, parse_progress_from_output};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Render the summary view
pub fn render(
    f: &mut Frame,
    manager: &MultiNodeStreamManager,
    cluster_name: &str,
    command: &str,
    all_tasks_completed: bool,
) {
    render_in_area(
        f,
        f.area(),
        manager,
        cluster_name,
        command,
        all_tasks_completed,
    );
}

/// Render the summary view in a specific area
pub fn render_in_area(
    f: &mut Frame,
    area: Rect,
    manager: &MultiNodeStreamManager,
    cluster_name: &str,
    command: &str,
    all_tasks_completed: bool,
) {
    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Node list
            Constraint::Length(3), // Footer
        ])
        .split(area);

    render_header(f, chunks[0], cluster_name, command, manager);
    render_node_list(f, chunks[1], manager);
    render_footer(f, chunks[2], all_tasks_completed);
}

/// Render the header with cluster name and command
fn render_header(
    f: &mut Frame,
    area: Rect,
    cluster_name: &str,
    command: &str,
    manager: &MultiNodeStreamManager,
) {
    let total = manager.total_count();
    let completed = manager.completed_count();
    let failed = manager.failed_count();

    let title = format!(" Cluster: {cluster_name} - {command} ");

    let in_progress = total - completed - failed;
    let status = format!(
        " Total: {} • ✓ {} • ✗ {} • {} in progress ",
        total, completed, failed, in_progress
    );

    let header_text = vec![Line::from(vec![
        Span::styled(
            title,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(status, Style::default().fg(Color::White)),
    ])];

    let header = Paragraph::new(header_text).block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

/// Render the list of nodes with status
fn render_node_list(f: &mut Frame, area: Rect, manager: &MultiNodeStreamManager) {
    let streams = manager.streams();

    let mut lines = Vec::new();

    for (i, stream) in streams.iter().enumerate() {
        let node_label = format!("[{}]", i + 1);
        let node_name = &stream.node.host;

        // Determine status icon and color
        let (icon, color) = match stream.status() {
            ExecutionStatus::Pending => ("⊙", Color::Gray),
            ExecutionStatus::Running => ("⟳", Color::Blue),
            ExecutionStatus::Completed => ("✓", Color::Green),
            ExecutionStatus::Failed(msg) => {
                // Show failed node with error message
                lines.push(Line::from(vec![
                    Span::styled(format!("{node_label} "), Style::default().fg(Color::Yellow)),
                    Span::styled(
                        format!("{node_name:<20} "),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled("✗ ", Style::default().fg(Color::Red)),
                    Span::styled(msg, Style::default().fg(Color::Red)),
                ]));
                continue;
            }
        };

        // Try to parse progress from output
        let progress = parse_progress_from_output(stream.stdout());

        // Build the line for this node
        let mut line_spans = vec![
            Span::styled(format!("{node_label} "), Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{node_name:<20} "),
                Style::default().fg(Color::White),
            ),
            Span::styled(format!("{icon} "), Style::default().fg(color)),
        ];

        if let Some(prog) = progress {
            // Show progress bar
            let bar_width = 20;
            let filled = ((prog / 100.0) * bar_width as f32) as usize;
            let bar = format!(
                "[{}{}] {:>3.0}%",
                "=".repeat(filled),
                " ".repeat(bar_width - filled),
                prog
            );
            line_spans.push(Span::styled(bar, Style::default().fg(Color::Cyan)));

            // Try to add status message
            if let Some(status_msg) = extract_status_message(stream.stdout()) {
                let truncated = if status_msg.len() > 40 {
                    format!("{}...", &status_msg[..37])
                } else {
                    status_msg
                };
                line_spans.push(Span::raw(" "));
                line_spans.push(Span::styled(truncated, Style::default().fg(Color::Gray)));
            }
        } else {
            // No progress, show status or recent output
            let status_text = match stream.status() {
                ExecutionStatus::Pending => "Waiting...".to_string(),
                ExecutionStatus::Running => extract_status_message(stream.stdout())
                    .unwrap_or_else(|| "Running...".to_string()),
                ExecutionStatus::Completed => {
                    if let Some(exit_code) = stream.exit_code() {
                        format!("Completed (exit: {exit_code})")
                    } else {
                        "Completed".to_string()
                    }
                }
                ExecutionStatus::Failed(_) => unreachable!(),
            };

            let truncated = if status_text.len() > 60 {
                format!("{}...", &status_text[..57])
            } else {
                status_text
            };
            line_spans.push(Span::styled(truncated, Style::default().fg(Color::Gray)));
        }

        lines.push(Line::from(line_spans));
    }

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::LEFT | Borders::RIGHT))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

/// Render the footer with help text
fn render_footer(f: &mut Frame, area: Rect, all_tasks_completed: bool) {
    let mut spans = vec![
        Span::styled(" [1-9] ", Style::default().fg(Color::Yellow)),
        Span::raw("Detail "),
        Span::styled(" [s] ", Style::default().fg(Color::Yellow)),
        Span::raw("Split "),
        Span::styled(" [d] ", Style::default().fg(Color::Yellow)),
        Span::raw("Diff "),
        Span::styled(" [l] ", Style::default().fg(Color::Yellow)),
        Span::raw("Log "),
        Span::styled(" [q] ", Style::default().fg(Color::Yellow)),
        Span::raw("Quit "),
        Span::styled(" [?] ", Style::default().fg(Color::Yellow)),
        Span::raw("Help "),
    ];

    // Add completion message if all tasks are done
    if all_tasks_completed {
        spans.push(Span::raw(" │ "));
        spans.push(Span::styled(
            "✓ All tasks completed - Press 'q' or 'Esc' to exit",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let help_text = Line::from(spans);

    let footer = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));

    f.render_widget(footer, area);
}

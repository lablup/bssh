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

use crate::executor::ExecutionResult;
use crate::node::Node;
use owo_colors::OwoColorize;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub enum NodeStatus {
    Pending,
    Connecting,
    Executing,
    Success,
    Failed(String),
}

impl NodeStatus {
    pub fn symbol(&self) -> String {
        match self {
            NodeStatus::Pending => "○".dimmed().to_string(),
            NodeStatus::Connecting => "◐".yellow().to_string(),
            NodeStatus::Executing => "◑".blue().to_string(),
            NodeStatus::Success => "●".green().to_string(),
            NodeStatus::Failed(_) => "●".red().to_string(),
        }
    }

    pub fn colored_text(&self) -> String {
        match self {
            NodeStatus::Pending => "Pending".dimmed().to_string(),
            NodeStatus::Connecting => "Connecting".yellow().to_string(),
            NodeStatus::Executing => "Executing".blue().to_string(),
            NodeStatus::Success => "Success".green().to_string(),
            NodeStatus::Failed(msg) => format!("Failed: {msg}").red().to_string(),
        }
    }
}

pub struct NodeGrid {
    nodes: Vec<(Node, NodeStatus)>,
    columns: usize,
}

impl NodeGrid {
    pub fn new(nodes: Vec<Node>) -> Self {
        let terminal_width = terminal_size::terminal_size()
            .map(|(w, _)| w.0 as usize)
            .unwrap_or(80);

        // Each node cell takes approximately 25 chars (node name + status)
        let columns = (terminal_width / 25).clamp(1, 4);

        let nodes = nodes
            .into_iter()
            .map(|node| (node, NodeStatus::Pending))
            .collect();

        Self { nodes, columns }
    }

    pub fn update_status(&mut self, node: &Node, status: NodeStatus) {
        if let Some(entry) = self.nodes.iter_mut().find(|(n, _)| n == node) {
            entry.1 = status;
        }
    }

    pub fn display(&self) -> String {
        let mut output = String::new();
        let mut current_col = 0;

        for (node, status) in &self.nodes {
            let node_str = format!("{node}");
            let node_display = if node_str.width() > 18 {
                format!("{}...", &node_str.chars().take(15).collect::<String>())
            } else {
                node_str
            };

            let cell = format!("{} {:<18}", status.symbol(), node_display);
            output.push_str(&cell);

            current_col += 1;
            if current_col >= self.columns {
                output.push('\n');
                current_col = 0;
            } else {
                output.push_str("  ");
            }
        }

        if current_col > 0 {
            output.push('\n');
        }

        output
    }

    pub fn display_compact(&self) -> String {
        let mut output = String::new();
        let success_count = self
            .nodes
            .iter()
            .filter(|(_, s)| matches!(s, NodeStatus::Success))
            .count();
        let failed_count = self
            .nodes
            .iter()
            .filter(|(_, s)| matches!(s, NodeStatus::Failed(_)))
            .count();
        let pending_count = self
            .nodes
            .iter()
            .filter(|(_, s)| matches!(s, NodeStatus::Pending))
            .count();
        let in_progress = self.nodes.len() - success_count - failed_count - pending_count;

        let status_bar = format!(
            "{} {} {} {} {} {} {} {}",
            "●".green(),
            success_count.to_string().green(),
            "●".red(),
            failed_count.to_string().red(),
            "◑".blue(),
            in_progress.to_string().blue(),
            "○".dimmed(),
            pending_count.to_string().dimmed()
        );

        output.push_str(&format!("Nodes [{}]: {}\n", self.nodes.len(), status_bar));

        // Show failed nodes if any
        let failed_nodes: Vec<_> = self
            .nodes
            .iter()
            .filter(|(_, s)| matches!(s, NodeStatus::Failed(_)))
            .collect();

        if !failed_nodes.is_empty() {
            output.push_str(&format!("\n{}\n", "Failed nodes:".red().bold()));
            for (node, status) in failed_nodes {
                if let NodeStatus::Failed(msg) = status {
                    output.push_str(&format!(
                        "  {} {}: {}\n",
                        "✗".red(),
                        node.to_string().red(),
                        msg.dimmed()
                    ));
                }
            }
        }

        output
    }
}

pub struct OutputFormatter;

impl OutputFormatter {
    pub fn format_header(title: &str) -> String {
        let terminal_width = terminal_size::terminal_size()
            .map(|(w, _)| w.0 as usize)
            .unwrap_or(80);

        let border = "─".repeat(terminal_width);
        let title_text = format!(" {title} ");
        let title_styled = title_text.cyan().bold().to_string();
        let padding = (terminal_width.saturating_sub(title.width() + 2)) / 2;

        format!(
            "{}\n{}{}{}\n{}",
            border.dimmed(),
            " ".repeat(padding),
            title_styled,
            " ".repeat(terminal_width.saturating_sub(padding + title.width() + 2)),
            border.dimmed()
        )
    }

    pub fn format_node_output(result: &ExecutionResult, verbose: bool) -> String {
        let mut output = String::new();

        let node_str = result.node.to_string();
        let status_symbol = if result.is_success() {
            "✓".green().to_string()
        } else {
            "✗".red().to_string()
        };

        output.push_str(&format!("\n{} {}\n", status_symbol, node_str.bold()));

        match &result.result {
            Ok(cmd_result) => {
                if cmd_result.is_success() {
                    let stdout = cmd_result.stdout_string();
                    if !stdout.is_empty() {
                        output.push_str(&Self::format_output_box(&stdout, false));
                    }

                    if verbose {
                        let stderr = cmd_result.stderr_string();
                        if !stderr.is_empty() {
                            output.push_str(&format!("\n{}\n", "stderr:".yellow()));
                            output.push_str(&Self::format_output_box(&stderr, true));
                        }
                    }
                } else {
                    output.push_str(&format!(
                        "{} Exit code: {}\n",
                        "⚠".yellow(),
                        cmd_result.exit_status.to_string().yellow()
                    ));

                    let stdout = cmd_result.stdout_string();
                    if !stdout.is_empty() {
                        output.push_str(&Self::format_output_box(&stdout, false));
                    }

                    let stderr = cmd_result.stderr_string();
                    if !stderr.is_empty() {
                        output.push_str(&format!("\n{}\n", "stderr:".red()));
                        output.push_str(&Self::format_output_box(&stderr, true));
                    }
                }
            }
            Err(e) => {
                output.push_str(&format!("{} Error: {}\n", "✗".red(), e.to_string().red()));
            }
        }

        output
    }

    fn format_output_box(content: &str, is_error: bool) -> String {
        let terminal_width = terminal_size::terminal_size()
            .map(|(w, _)| w.0 as usize)
            .unwrap_or(80);

        let mut output = String::new();
        let indent = "  ";
        let max_width = terminal_width.saturating_sub(4);

        for line in content.lines() {
            if line.width() > max_width {
                // Wrap long lines
                let mut remaining = line;
                while remaining.width() > max_width {
                    let (chunk, rest) = Self::split_at_width(remaining, max_width);
                    if is_error {
                        output.push_str(&format!("{}{}\n", indent, chunk.dimmed()));
                    } else {
                        output.push_str(&format!("{indent}{chunk}\n"));
                    }
                    remaining = rest;
                }
                if !remaining.is_empty() {
                    if is_error {
                        output.push_str(&format!("{}{}\n", indent, remaining.dimmed()));
                    } else {
                        output.push_str(&format!("{indent}{remaining}\n"));
                    }
                }
            } else if is_error {
                output.push_str(&format!("{}{}\n", indent, line.dimmed()));
            } else {
                output.push_str(&format!("{indent}{line}\n"));
            }
        }

        output
    }

    fn split_at_width(s: &str, max_width: usize) -> (&str, &str) {
        let mut width = 0;
        let mut split_pos = 0;

        for (i, ch) in s.char_indices() {
            let ch_width = ch.width().unwrap_or(0);
            if width + ch_width > max_width {
                break;
            }
            width += ch_width;
            split_pos = i + ch.len_utf8();
        }

        s.split_at(split_pos)
    }

    pub fn format_summary(total: usize, success: usize, failed: usize) -> String {
        let mut parts = Vec::new();

        parts.push(format!("{} nodes", total.to_string().bold()));

        if success > 0 {
            parts.push(format!(
                "{} {}",
                success.to_string().green().bold(),
                "successful".green()
            ));
        }

        if failed > 0 {
            parts.push(format!(
                "{} {}",
                failed.to_string().red().bold(),
                "failed".red()
            ));
        }

        let summary = parts.join(" • ");

        format!(
            "\n{}\n{}\n{}\n",
            "═"
                .repeat(
                    terminal_size::terminal_size()
                        .map(|(w, _)| w.0 as usize)
                        .unwrap_or(80)
                )
                .dimmed(),
            format!(" Summary: {summary} ").bold(),
            "═"
                .repeat(
                    terminal_size::terminal_size()
                        .map(|(w, _)| w.0 as usize)
                        .unwrap_or(80)
                )
                .dimmed()
        )
    }

    pub fn format_command_header(command: &str, node_count: usize) -> String {
        format!(
            "\n{} {} on {} {}:\n{}\n",
            "►".cyan().bold(),
            "Executing".cyan(),
            node_count.to_string().bold(),
            if node_count == 1 { "node" } else { "nodes" },
            format!("  {command}").dimmed()
        )
    }
}

pub fn print_welcome_banner() {
    let banner = r"
╭───────────────────────────────────────╮
│      bssh - Backend.AI SSH Tool       │
│     Parallel Command Execution        │
╰───────────────────────────────────────╯
";
    println!("{}", banner.cyan());
}

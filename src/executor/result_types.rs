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

//! Result types for parallel execution operations.

use anyhow::Result;
use owo_colors::OwoColorize;
use std::path::PathBuf;

use crate::node::Node;
use crate::ssh::client::CommandResult;
use crate::ui::OutputFormatter;

/// Result of executing a command on a single node.
#[derive(Debug)]
pub struct ExecutionResult {
    pub node: Node,
    pub result: Result<CommandResult>,
    /// Whether this node is identified as the main rank.
    ///
    /// The main rank (rank 0) is typically the coordinator in distributed computing.
    /// Its exit code is used as the final exit code in MainRank strategy.
    pub is_main_rank: bool,
}

impl ExecutionResult {
    pub fn is_success(&self) -> bool {
        matches!(&self.result, Ok(cmd_result) if cmd_result.is_success())
    }

    /// Get the exit code for this result.
    ///
    /// Returns the actual exit code from the command, or 1 if there was a connection error.
    pub fn get_exit_code(&self) -> i32 {
        match &self.result {
            Ok(cmd_result) => cmd_result.exit_status as i32,
            Err(_) => 1, // Connection/execution error treated as exit code 1
        }
    }

    pub fn print_output(&self, verbose: bool) {
        print!("{}", OutputFormatter::format_node_output(self, verbose));
    }
}

/// Result of uploading a file to a single node.
#[derive(Debug)]
pub struct UploadResult {
    pub node: Node,
    pub result: Result<()>,
}

impl UploadResult {
    pub fn is_success(&self) -> bool {
        self.result.is_ok()
    }

    pub fn print_summary(&self) {
        match &self.result {
            Ok(()) => {
                println!(
                    "{} {}: {}",
                    "●".green(),
                    self.node.to_string().bold(),
                    "File uploaded successfully".green()
                );
            }
            Err(e) => {
                println!(
                    "{} {}: {}",
                    "●".red(),
                    self.node.to_string().bold(),
                    "Failed to upload file".red()
                );
                // Show full error chain
                let error_chain = format!("{e:#}");
                for line in error_chain.lines() {
                    println!("    {}", line.dimmed());
                }
            }
        }
    }
}

/// Result of downloading a file from a single node.
#[derive(Debug)]
pub struct DownloadResult {
    pub node: Node,
    pub result: Result<PathBuf>,
}

impl DownloadResult {
    pub fn is_success(&self) -> bool {
        self.result.is_ok()
    }

    pub fn print_summary(&self) {
        match &self.result {
            Ok(path) => {
                println!(
                    "{} {}: {} {:?}",
                    "●".green(),
                    self.node.to_string().bold(),
                    "File downloaded to".green(),
                    path
                );
            }
            Err(e) => {
                println!(
                    "{} {}: {}",
                    "●".red(),
                    self.node.to_string().bold(),
                    "Failed to download file".red()
                );
                // Show full error chain
                let error_chain = format!("{e:#}");
                for line in error_chain.lines() {
                    println!("    {}", line.dimmed());
                }
            }
        }
    }
}

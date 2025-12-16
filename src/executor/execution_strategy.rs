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

//! Execution strategies and task management for parallel operations.

use anyhow::Result;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::node::Node;

use super::connection_manager::{
    download_from_node, execute_on_node_with_jump_hosts, upload_to_node, ExecutionConfig,
};
use super::result_types::{DownloadResult, ExecutionResult, UploadResult};

/// Progress bar tick rate configuration.
const PROGRESS_BAR_TICK_RATE_MS: u64 = 80;
const DOWNLOAD_PROGRESS_TICK_RATE_MS: u64 = 100;

/// Create a progress bar style for operations.
pub(crate) fn create_progress_style() -> Result<ProgressStyle> {
    ProgressStyle::default_bar()
        .template("{prefix:.bold} {spinner:.cyan} {msg}")
        .map_err(|e| anyhow::anyhow!("Failed to create progress bar template: {e}"))
        .map(|style| style.tick_chars("⣾⣽⣻⢿⡿⣟⣯⣷ "))
}

/// Format node display name for progress bars.
pub(crate) fn format_node_display(node: &Node) -> String {
    if node.to_string().len() > 20 {
        format!("{}...", &node.to_string()[..17])
    } else {
        node.to_string()
    }
}

/// Execute a command task on a single node with progress tracking.
pub(crate) async fn execute_command_task(
    node: Node,
    command: String,
    config: ExecutionConfig<'_>,
    semaphore: Arc<Semaphore>,
    pb: ProgressBar,
) -> ExecutionResult {
    let _permit = match semaphore.acquire().await {
        Ok(permit) => permit,
        Err(e) => {
            pb.finish_with_message(format!("{} {}", "●".red(), "Semaphore closed".red()));
            return ExecutionResult {
                node,
                result: Err(anyhow::anyhow!("Semaphore acquisition failed: {e}")),
                is_main_rank: false, // Will be updated by caller
            };
        }
    };

    pb.set_message(format!("{}", "Executing...".blue()));

    let result = execute_on_node_with_jump_hosts(node.clone(), &command, &config).await;

    match &result {
        Ok(cmd_result) => {
            if cmd_result.is_success() {
                pb.finish_with_message(format!("{} {}", "●".green(), "Success".green()));
            } else {
                pb.finish_with_message(format!(
                    "{} Exit code: {}",
                    "●".red(),
                    cmd_result.exit_status.to_string().red()
                ));
            }
        }
        Err(e) => {
            let error_msg = format!("{e:#}");
            let first_line = error_msg.lines().next().unwrap_or("Unknown error");
            let short_error = if first_line.len() > 50 {
                format!("{}...", &first_line[..47])
            } else {
                first_line.to_string()
            };
            pb.finish_with_message(format!("{} {}", "●".red(), short_error.red()));
        }
    }

    ExecutionResult {
        node,
        result,
        is_main_rank: false, // Will be updated by caller
    }
}

/// Upload a file task to a single node with progress tracking.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_file_task(
    node: Node,
    local_path: std::path::PathBuf,
    remote_path: String,
    key_path: Option<String>,
    strict_mode: crate::ssh::known_hosts::StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    jump_hosts: Option<String>,
    connect_timeout: Option<u64>,
    semaphore: Arc<Semaphore>,
    pb: ProgressBar,
) -> UploadResult {
    let _permit = match semaphore.acquire().await {
        Ok(permit) => permit,
        Err(e) => {
            pb.finish_with_message(format!("{} {}", "●".red(), "Semaphore closed".red()));
            return UploadResult {
                node,
                result: Err(anyhow::anyhow!("Semaphore acquisition failed: {e}")),
            };
        }
    };

    pb.set_message(format!("{}", "Uploading (SFTP)...".blue()));

    let result = upload_to_node(
        node.clone(),
        &local_path,
        &remote_path,
        key_path.as_deref(),
        strict_mode,
        use_agent,
        use_password,
        jump_hosts.as_deref(),
        connect_timeout,
    )
    .await;

    match &result {
        Ok(()) => {
            pb.finish_with_message(format!("{} {}", "●".green(), "Uploaded".green()));
        }
        Err(e) => {
            let error_msg = format!("{e:#}");
            let first_line = error_msg.lines().next().unwrap_or("Unknown error");
            let short_error = if first_line.len() > 50 {
                format!("{}...", &first_line[..47])
            } else {
                first_line.to_string()
            };
            pb.finish_with_message(format!("{} {}", "●".red(), short_error.red()));
        }
    }

    UploadResult { node, result }
}

/// Download a file task from a single node with progress tracking.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_file_task(
    node: Node,
    remote_path: String,
    local_dir: std::path::PathBuf,
    key_path: Option<String>,
    strict_mode: crate::ssh::known_hosts::StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    jump_hosts: Option<String>,
    connect_timeout: Option<u64>,
    semaphore: Arc<Semaphore>,
    pb: ProgressBar,
) -> DownloadResult {
    let _permit = match semaphore.acquire().await {
        Ok(permit) => permit,
        Err(e) => {
            pb.finish_with_message(format!("{} {}", "●".red(), "Semaphore closed".red()));
            return DownloadResult {
                node,
                result: Err(anyhow::anyhow!("Semaphore acquisition failed: {e}")),
            };
        }
    };

    pb.set_message(format!("{}", "Downloading (SFTP)...".blue()));

    // Generate unique filename for each node
    let filename = if let Some(file_name) = Path::new(&remote_path).file_name() {
        format!(
            "{}_{}",
            node.host.replace(':', "_"),
            file_name.to_string_lossy()
        )
    } else {
        format!("{}_download", node.host.replace(':', "_"))
    };
    let local_path = local_dir.join(filename);

    let result = download_from_node(
        node.clone(),
        &remote_path,
        &local_path,
        key_path.as_deref(),
        strict_mode,
        use_agent,
        use_password,
        jump_hosts.as_deref(),
        connect_timeout,
    )
    .await;

    match &result {
        Ok(path) => {
            pb.finish_with_message(format!("✓ Downloaded to {}", path.display()));
        }
        Err(e) => {
            pb.finish_with_message(format!("✗ Error: {e}"));
        }
    }

    DownloadResult {
        node,
        result: result.map(|_| local_path),
    }
}

/// Setup a progress bar for a node operation.
pub(crate) fn setup_progress_bar(
    multi_progress: &MultiProgress,
    node: &Node,
    style: ProgressStyle,
    initial_message: &str,
) -> ProgressBar {
    let pb = multi_progress.add(ProgressBar::new_spinner());
    pb.set_style(style);
    let node_display = format_node_display(node);
    pb.set_prefix(format!("[{node_display}]"));
    pb.set_message(format!("{}", initial_message.cyan()));
    pb.enable_steady_tick(std::time::Duration::from_millis(PROGRESS_BAR_TICK_RATE_MS));
    pb
}

/// Setup a progress bar for download operations.
pub(crate) fn setup_download_progress_bar(
    multi_progress: &MultiProgress,
    node: &Node,
    style: ProgressStyle,
    remote_path: &str,
) -> ProgressBar {
    let pb = multi_progress.add(ProgressBar::new_spinner());
    pb.set_style(style);
    pb.set_prefix(format!("[{node}]"));
    pb.set_message(format!("Downloading {remote_path}"));
    pb.enable_steady_tick(std::time::Duration::from_millis(
        DOWNLOAD_PROGRESS_TICK_RATE_MS,
    ));
    pb
}

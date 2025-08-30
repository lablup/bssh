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

use anyhow::Result;
use futures::future::join_all;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::node::Node;
use crate::ssh::{
    client::{CommandResult, ConnectionConfig},
    known_hosts::StrictHostKeyChecking,
    SshClient,
};

/// Configuration for node execution
#[derive(Clone)]
struct ExecutionConfig<'a> {
    key_path: Option<&'a str>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    timeout: Option<u64>,
    jump_hosts: Option<&'a str>,
}
use crate::ui::OutputFormatter;

pub struct ParallelExecutor {
    nodes: Vec<Node>,
    max_parallel: usize,
    key_path: Option<String>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    timeout: Option<u64>,
    jump_hosts: Option<String>,
}

impl ParallelExecutor {
    pub fn new(nodes: Vec<Node>, max_parallel: usize, key_path: Option<String>) -> Self {
        Self::new_with_strict_mode(
            nodes,
            max_parallel,
            key_path,
            StrictHostKeyChecking::AcceptNew,
        )
    }

    pub fn new_with_strict_mode(
        nodes: Vec<Node>,
        max_parallel: usize,
        key_path: Option<String>,
        strict_mode: StrictHostKeyChecking,
    ) -> Self {
        Self {
            nodes,
            max_parallel,
            key_path,
            strict_mode,
            use_agent: false,
            use_password: false,
            timeout: None,
            jump_hosts: None,
        }
    }

    pub fn new_with_strict_mode_and_agent(
        nodes: Vec<Node>,
        max_parallel: usize,
        key_path: Option<String>,
        strict_mode: StrictHostKeyChecking,
        use_agent: bool,
    ) -> Self {
        Self {
            nodes,
            max_parallel,
            key_path,
            strict_mode,
            use_agent,
            use_password: false,
            timeout: None,
            jump_hosts: None,
        }
    }

    pub fn new_with_all_options(
        nodes: Vec<Node>,
        max_parallel: usize,
        key_path: Option<String>,
        strict_mode: StrictHostKeyChecking,
        use_agent: bool,
        use_password: bool,
    ) -> Self {
        Self {
            nodes,
            max_parallel,
            key_path,
            strict_mode,
            use_agent,
            use_password,
            timeout: None,
            jump_hosts: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Option<u64>) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_jump_hosts(mut self, jump_hosts: Option<String>) -> Self {
        self.jump_hosts = jump_hosts;
        self
    }

    pub async fn execute(&self, command: &str) -> Result<Vec<ExecutionResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();

        let style = ProgressStyle::default_bar()
            .template("{prefix:.bold} {spinner:.cyan} {msg}")
            .map_err(|e| anyhow::anyhow!("Failed to create progress bar template: {}", e))?
            .tick_chars("⣾⣽⣻⢿⡿⣟⣯⣷ ");

        let tasks: Vec<_> = self
            .nodes
            .iter()
            .map(|node| {
                let node = node.clone();
                let command = command.to_string();
                let key_path = self.key_path.clone();
                let strict_mode = self.strict_mode;
                let use_agent = self.use_agent;
                let use_password = self.use_password;
                let timeout = self.timeout;
                let jump_hosts = self.jump_hosts.clone();
                let semaphore = Arc::clone(&semaphore);
                let pb = multi_progress.add(ProgressBar::new_spinner());
                pb.set_style(style.clone());
                let node_display = if node.to_string().len() > 20 {
                    format!("{}...", &node.to_string()[..17])
                } else {
                    node.to_string()
                };
                pb.set_prefix(format!("[{node_display}]"));
                pb.set_message(format!("{}", "Connecting...".cyan()));
                // Progress bar tick rate design:
                // - 80ms provides smooth visual updates without excessive CPU usage
                // - Fast enough for responsive UI feedback during connections
                // - Slower than video refresh rates to avoid unnecessary work
                const PROGRESS_BAR_TICK_RATE_MS: u64 = 80;
                pb.enable_steady_tick(std::time::Duration::from_millis(PROGRESS_BAR_TICK_RATE_MS));

                tokio::spawn(async move {
                    let _permit = match semaphore.acquire().await {
                        Ok(permit) => permit,
                        Err(e) => {
                            pb.finish_with_message(format!(
                                "{} {}",
                                "●".red(),
                                "Semaphore closed".red()
                            ));
                            return ExecutionResult {
                                node,
                                result: Err(anyhow::anyhow!("Semaphore acquisition failed: {}", e)),
                            };
                        }
                    };

                    pb.set_message(format!("{}", "Executing...".blue()));

                    let exec_config = ExecutionConfig {
                        key_path: key_path.as_deref(),
                        strict_mode,
                        use_agent,
                        use_password,
                        timeout,
                        jump_hosts: jump_hosts.as_deref(),
                    };

                    let result =
                        execute_on_node_with_jump_hosts(node.clone(), &command, &exec_config).await;

                    match &result {
                        Ok(cmd_result) => {
                            if cmd_result.is_success() {
                                pb.finish_with_message(format!(
                                    "{} {}",
                                    "●".green(),
                                    "Success".green()
                                ));
                            } else {
                                pb.finish_with_message(format!(
                                    "{} Exit code: {}",
                                    "●".red(),
                                    cmd_result.exit_status.to_string().red()
                                ));
                            }
                        }
                        Err(e) => {
                            let error_msg = format!("{e}");
                            let short_error = if error_msg.len() > 40 {
                                format!("{}...", &error_msg[..37])
                            } else {
                                error_msg
                            };
                            pb.finish_with_message(format!("{} {}", "●".red(), short_error.red()));
                        }
                    }

                    ExecutionResult { node, result }
                })
            })
            .collect();

        let results = join_all(tasks).await;

        // Collect results, handling any task panics
        let mut execution_results = Vec::new();
        for result in results {
            match result {
                Ok(exec_result) => execution_results.push(exec_result),
                Err(e) => {
                    tracing::error!("Task failed: {}", e);
                }
            }
        }

        Ok(execution_results)
    }

    pub async fn upload_file(
        &self,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<Vec<UploadResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();

        let style = ProgressStyle::default_bar()
            .template("{prefix:.bold} {spinner:.cyan} {msg}")
            .map_err(|e| {
                anyhow::anyhow!("Failed to create progress bar template for upload: {}", e)
            })?
            .tick_chars("⣾⣽⣻⢿⡿⣟⣯⣷ ");

        let tasks: Vec<_> = self
            .nodes
            .iter()
            .map(|node| {
                let node = node.clone();
                let local_path = local_path.to_path_buf();
                let remote_path = remote_path.to_string();
                let key_path = self.key_path.clone();
                let strict_mode = self.strict_mode;
                let use_agent = self.use_agent;
                let use_password = self.use_password;
                let semaphore = Arc::clone(&semaphore);
                let pb = multi_progress.add(ProgressBar::new_spinner());
                pb.set_style(style.clone());
                let node_display = if node.to_string().len() > 20 {
                    format!("{}...", &node.to_string()[..17])
                } else {
                    node.to_string()
                };
                pb.set_prefix(format!("[{node_display}]"));
                pb.set_message(format!("{}", "Connecting...".cyan()));
                // Progress bar tick rate design:
                // - 80ms provides smooth visual updates without excessive CPU usage
                // - Fast enough for responsive UI feedback during connections
                // - Slower than video refresh rates to avoid unnecessary work
                const PROGRESS_BAR_TICK_RATE_MS: u64 = 80;
                pb.enable_steady_tick(std::time::Duration::from_millis(PROGRESS_BAR_TICK_RATE_MS));

                tokio::spawn(async move {
                    let _permit = match semaphore.acquire().await {
                        Ok(permit) => permit,
                        Err(e) => {
                            pb.finish_with_message(format!(
                                "{} {}",
                                "●".red(),
                                "Semaphore closed".red()
                            ));
                            return UploadResult {
                                node,
                                result: Err(anyhow::anyhow!("Semaphore acquisition failed: {}", e)),
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
                    )
                    .await;

                    match &result {
                        Ok(()) => {
                            pb.finish_with_message(format!(
                                "{} {}",
                                "●".green(),
                                "Uploaded".green()
                            ));
                        }
                        Err(e) => {
                            let error_msg = format!("{e}");
                            let short_error = if error_msg.len() > 40 {
                                format!("{}...", &error_msg[..37])
                            } else {
                                error_msg
                            };
                            pb.finish_with_message(format!("{} {}", "●".red(), short_error.red()));
                        }
                    }

                    UploadResult { node, result }
                })
            })
            .collect();

        let results = join_all(tasks).await;

        // Collect results, handling any task panics
        let mut upload_results = Vec::new();
        for result in results {
            match result {
                Ok(upload_result) => upload_results.push(upload_result),
                Err(e) => {
                    tracing::error!("Task failed: {}", e);
                }
            }
        }

        Ok(upload_results)
    }

    pub async fn download_file(
        &self,
        remote_path: &str,
        local_dir: &Path,
    ) -> Result<Vec<DownloadResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();

        let style = ProgressStyle::default_bar()
            .template("{prefix:.bold} {spinner:.cyan} {msg}")
            .map_err(|e| {
                anyhow::anyhow!("Failed to create progress bar template for download: {}", e)
            })?
            .tick_chars("⣾⣽⣻⢿⡿⣟⣯⣷ ");

        let tasks: Vec<_> = self
            .nodes
            .iter()
            .map(|node| {
                let node = node.clone();
                let remote_path = remote_path.to_string();
                let local_dir = local_dir.to_path_buf();
                let key_path = self.key_path.clone();
                let strict_mode = self.strict_mode;
                let use_agent = self.use_agent;
                let use_password = self.use_password;
                let semaphore = Arc::clone(&semaphore);
                let pb = multi_progress.add(ProgressBar::new_spinner());
                pb.set_style(style.clone());
                let node_display = if node.to_string().len() > 20 {
                    format!("{}...", &node.to_string()[..17])
                } else {
                    node.to_string()
                };
                pb.set_prefix(format!("[{node_display}]"));
                pb.set_message(format!("{}", "Connecting...".cyan()));
                // Progress bar tick rate design:
                // - 80ms provides smooth visual updates without excessive CPU usage
                // - Fast enough for responsive UI feedback during connections
                // - Slower than video refresh rates to avoid unnecessary work
                const PROGRESS_BAR_TICK_RATE_MS: u64 = 80;
                pb.enable_steady_tick(std::time::Duration::from_millis(PROGRESS_BAR_TICK_RATE_MS));

                tokio::spawn(async move {
                    let _permit = match semaphore.acquire().await {
                        Ok(permit) => permit,
                        Err(e) => {
                            pb.finish_with_message(format!(
                                "{} {}",
                                "●".red(),
                                "Semaphore closed".red()
                            ));
                            return DownloadResult {
                                node,
                                result: Err(anyhow::anyhow!("Semaphore acquisition failed: {}", e)),
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
                })
            })
            .collect();

        let results = join_all(tasks).await;

        // Collect results, handling any task panics
        let mut download_results = Vec::new();
        for result in results {
            match result {
                Ok(download_result) => download_results.push(download_result),
                Err(e) => {
                    tracing::error!("Task failed: {}", e);
                }
            }
        }

        Ok(download_results)
    }

    pub async fn download_files(
        &self,
        remote_paths: Vec<String>,
        local_dir: &Path,
    ) -> Result<Vec<DownloadResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();

        let style = ProgressStyle::default_bar()
            .template("{prefix:.bold} {spinner:.cyan} {msg}")
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create progress bar template for multi-download: {}",
                    e
                )
            })?
            .tick_chars("⣾⣽⣻⢿⡿⣟⣯⣷ ");

        let mut all_results = Vec::new();

        for remote_path in remote_paths {
            let tasks: Vec<_> = self
                .nodes
                .iter()
                .map(|node| {
                    let node = node.clone();
                    let remote_path = remote_path.clone();
                    let local_dir = local_dir.to_path_buf();
                    let key_path = self.key_path.clone();
                    let strict_mode = self.strict_mode;
                    let use_agent = self.use_agent;
                    let use_password = self.use_password;
                    let semaphore = Arc::clone(&semaphore);
                    let pb = multi_progress.add(ProgressBar::new_spinner());
                    pb.set_style(style.clone());
                    pb.set_prefix(format!("[{node}]"));
                    pb.set_message(format!("Downloading {remote_path}"));
                    // Progress bar tick rate for downloads:
                    // - 100ms provides adequate feedback for file transfer progress
                    // - Slightly slower than connection progress (less frequent updates needed)
                    // - Balances responsiveness with system resources
                    const DOWNLOAD_PROGRESS_TICK_RATE_MS: u64 = 100;
                    pb.enable_steady_tick(std::time::Duration::from_millis(
                        DOWNLOAD_PROGRESS_TICK_RATE_MS,
                    ));

                    tokio::spawn(async move {
                        let _permit = match semaphore.acquire().await {
                            Ok(permit) => permit,
                            Err(e) => {
                                pb.finish_with_message(format!(
                                    "{} {}",
                                    "●".red(),
                                    "Semaphore closed".red()
                                ));
                                return DownloadResult {
                                    node,
                                    result: Err(anyhow::anyhow!(
                                        "Semaphore acquisition failed: {}",
                                        e
                                    )),
                                };
                            }
                        };

                        // Generate unique filename for each node and file
                        let filename = if let Some(file_name) = Path::new(&remote_path).file_name()
                        {
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
                        )
                        .await;

                        match &result {
                            Ok(path) => {
                                pb.finish_with_message(format!("✓ Downloaded {}", path.display()));
                            }
                            Err(e) => {
                                pb.finish_with_message(format!("✗ Failed: {e}"));
                            }
                        }

                        DownloadResult {
                            node,
                            result: result.map(|_| local_path),
                        }
                    })
                })
                .collect();

            let results = join_all(tasks).await;

            // Collect results for this file
            for result in results {
                match result {
                    Ok(download_result) => all_results.push(download_result),
                    Err(e) => {
                        tracing::error!("Task failed: {}", e);
                    }
                }
            }
        }

        Ok(all_results)
    }
}

async fn execute_on_node_with_jump_hosts(
    node: Node,
    command: &str,
    config: &ExecutionConfig<'_>,
) -> Result<CommandResult> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = config.key_path.map(Path::new);

    let connection_config = ConnectionConfig {
        key_path,
        strict_mode: Some(config.strict_mode),
        use_agent: config.use_agent,
        use_password: config.use_password,
        timeout_seconds: config.timeout,
        jump_hosts_spec: config.jump_hosts,
    };

    client
        .connect_and_execute_with_jump_hosts(command, &connection_config)
        .await
}

async fn upload_to_node(
    node: Node,
    local_path: &Path,
    remote_path: &str,
    key_path: Option<&str>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
) -> Result<()> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    // Check if the local path is a directory
    if local_path.is_dir() {
        client
            .upload_dir(
                local_path,
                remote_path,
                key_path,
                Some(strict_mode),
                use_agent,
                use_password,
            )
            .await
    } else {
        client
            .upload_file(
                local_path,
                remote_path,
                key_path,
                Some(strict_mode),
                use_agent,
                use_password,
            )
            .await
    }
}

async fn download_from_node(
    node: Node,
    remote_path: &str,
    local_path: &Path,
    key_path: Option<&str>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
) -> Result<std::path::PathBuf> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    // This function handles both files and directories
    // The caller should check if it's a directory and use the appropriate method
    client
        .download_file(
            remote_path,
            local_path,
            key_path,
            Some(strict_mode),
            use_agent,
            use_password,
        )
        .await?;

    Ok(local_path.to_path_buf())
}

pub async fn download_dir_from_node(
    node: Node,
    remote_path: &str,
    local_path: &Path,
    key_path: Option<&str>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
) -> Result<std::path::PathBuf> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    client
        .download_dir(
            remote_path,
            local_path,
            key_path,
            Some(strict_mode),
            use_agent,
            use_password,
        )
        .await?;

    Ok(local_path.to_path_buf())
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub node: Node,
    pub result: Result<CommandResult>,
}

impl ExecutionResult {
    pub fn is_success(&self) -> bool {
        matches!(&self.result, Ok(cmd_result) if cmd_result.is_success())
    }

    pub fn print_output(&self, verbose: bool) {
        print!("{}", OutputFormatter::format_node_output(self, verbose));
    }
}

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
                    "{} {}: {} - {}",
                    "●".red(),
                    self.node.to_string().bold(),
                    "Failed to upload file".red(),
                    e.to_string().dimmed()
                );
            }
        }
    }
}

#[derive(Debug)]
pub struct DownloadResult {
    pub node: Node,
    pub result: Result<std::path::PathBuf>,
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
                    "{} {}: {} - {}",
                    "●".red(),
                    self.node.to_string().bold(),
                    "Failed to download file".red(),
                    e.to_string().dimmed()
                );
            }
        }
    }
}

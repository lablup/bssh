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

//! Core parallel executor implementation.

use anyhow::Result;
use futures::future::join_all;
use indicatif::MultiProgress;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::node::Node;
use crate::ssh::known_hosts::StrictHostKeyChecking;

use super::connection_manager::{download_from_node, ExecutionConfig};
use super::execution_strategy::{
    create_progress_style, download_file_task, execute_command_task, setup_download_progress_bar,
    setup_progress_bar, upload_file_task,
};
use super::rank_detector::RankDetector;
use super::result_types::{DownloadResult, ExecutionResult, UploadResult};

/// Parallel executor for running commands across multiple nodes.
pub struct ParallelExecutor {
    pub(crate) nodes: Vec<Node>,
    pub(crate) max_parallel: usize,
    pub(crate) key_path: Option<String>,
    pub(crate) strict_mode: StrictHostKeyChecking,
    pub(crate) use_agent: bool,
    pub(crate) use_password: bool,
    #[cfg(target_os = "macos")]
    pub(crate) use_keychain: bool,
    pub(crate) timeout: Option<u64>,
    pub(crate) jump_hosts: Option<String>,
}

impl ParallelExecutor {
    /// Create a new parallel executor with default strict mode.
    pub fn new(nodes: Vec<Node>, max_parallel: usize, key_path: Option<String>) -> Self {
        Self::new_with_strict_mode(
            nodes,
            max_parallel,
            key_path,
            StrictHostKeyChecking::AcceptNew,
        )
    }

    /// Create a new parallel executor with specified strict mode.
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
            #[cfg(target_os = "macos")]
            use_keychain: false,
            timeout: None,
            jump_hosts: None,
        }
    }

    /// Create a new parallel executor with strict mode and agent support.
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
            #[cfg(target_os = "macos")]
            use_keychain: false,
            timeout: None,
            jump_hosts: None,
        }
    }

    /// Create a new parallel executor with all authentication options.
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
            #[cfg(target_os = "macos")]
            use_keychain: false,
            timeout: None,
            jump_hosts: None,
        }
    }

    /// Set command execution timeout.
    pub fn with_timeout(mut self, timeout: Option<u64>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set jump hosts for connections.
    pub fn with_jump_hosts(mut self, jump_hosts: Option<String>) -> Self {
        self.jump_hosts = jump_hosts;
        self
    }

    /// Set whether to use macOS Keychain for passphrase storage/retrieval (macOS only).
    #[cfg(target_os = "macos")]
    pub fn with_keychain(mut self, use_keychain: bool) -> Self {
        self.use_keychain = use_keychain;
        self
    }

    /// Execute a command on all nodes in parallel.
    pub async fn execute(&self, command: &str) -> Result<Vec<ExecutionResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();
        let style = create_progress_style()?;

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
                #[cfg(target_os = "macos")]
                let use_keychain = self.use_keychain;
                let timeout = self.timeout;
                let jump_hosts = self.jump_hosts.clone();
                let semaphore = Arc::clone(&semaphore);
                let pb = setup_progress_bar(&multi_progress, &node, style.clone(), "Connecting...");

                tokio::spawn(async move {
                    let config = ExecutionConfig {
                        key_path: key_path.as_deref(),
                        strict_mode,
                        use_agent,
                        use_password,
                        #[cfg(target_os = "macos")]
                        use_keychain,
                        timeout,
                        jump_hosts: jump_hosts.as_deref(),
                    };

                    execute_command_task(node, command, config, semaphore, pb).await
                })
            })
            .collect();

        let results = join_all(tasks).await;
        self.collect_results(results)
    }

    /// Upload a file to all nodes in parallel.
    pub async fn upload_file(
        &self,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<Vec<UploadResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();
        let style = create_progress_style()?;

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
                let jump_hosts = self.jump_hosts.clone();
                let semaphore = Arc::clone(&semaphore);
                let pb = setup_progress_bar(&multi_progress, &node, style.clone(), "Connecting...");

                tokio::spawn(upload_file_task(
                    node,
                    local_path,
                    remote_path,
                    key_path,
                    strict_mode,
                    use_agent,
                    use_password,
                    jump_hosts,
                    semaphore,
                    pb,
                ))
            })
            .collect();

        let results = join_all(tasks).await;
        self.collect_upload_results(results)
    }

    /// Download a file from all nodes in parallel.
    pub async fn download_file(
        &self,
        remote_path: &str,
        local_dir: &Path,
    ) -> Result<Vec<DownloadResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();
        let style = create_progress_style()?;

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
                let jump_hosts = self.jump_hosts.clone();
                let semaphore = Arc::clone(&semaphore);
                let pb = setup_progress_bar(&multi_progress, &node, style.clone(), "Connecting...");

                tokio::spawn(download_file_task(
                    node,
                    remote_path,
                    local_dir,
                    key_path,
                    strict_mode,
                    use_agent,
                    use_password,
                    jump_hosts,
                    semaphore,
                    pb,
                ))
            })
            .collect();

        let results = join_all(tasks).await;
        self.collect_download_results(results)
    }

    /// Download multiple files from all nodes.
    pub async fn download_files(
        &self,
        remote_paths: Vec<String>,
        local_dir: &Path,
    ) -> Result<Vec<DownloadResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();
        let style = create_progress_style()?;

        let mut all_results = Vec::new();

        for remote_path in remote_paths {
            let tasks: Vec<_> = self
                .nodes
                .iter()
                .map(|node| {
                    let node = node.clone();
                    let remote_path = remote_path.clone();
                    let local_dir = local_dir.to_path_buf();
                    let semaphore = Arc::clone(&semaphore);
                    let pb = setup_download_progress_bar(
                        &multi_progress,
                        &node,
                        style.clone(),
                        &remote_path,
                    );

                    // Generate unique filename for each node and file
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

                    let key_path = self.key_path.clone();
                    let strict_mode = self.strict_mode;
                    let use_agent = self.use_agent;
                    let use_password = self.use_password;
                    let jump_hosts = self.jump_hosts.clone();

                    tokio::spawn(async move {
                        let _permit = match semaphore.acquire().await {
                            Ok(permit) => permit,
                            Err(e) => {
                                pb.finish_with_message(format!("✗ Semaphore failed: {e}"));
                                return DownloadResult {
                                    node,
                                    result: Err(anyhow::anyhow!(
                                        "Semaphore acquisition failed: {e}"
                                    )),
                                };
                            }
                        };

                        let result = download_from_node(
                            node.clone(),
                            &remote_path,
                            &local_path,
                            key_path.as_deref(),
                            strict_mode,
                            use_agent,
                            use_password,
                            jump_hosts.as_deref(),
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

    /// Collect execution results, handling any task panics.
    fn collect_results(
        &self,
        results: Vec<Result<ExecutionResult, tokio::task::JoinError>>,
    ) -> Result<Vec<ExecutionResult>> {
        let mut execution_results = Vec::new();
        for result in results {
            match result {
                Ok(exec_result) => execution_results.push(exec_result),
                Err(e) => {
                    tracing::error!("Task failed: {}", e);
                }
            }
        }

        // Identify and mark the main rank
        if let Some(main_idx) = RankDetector::identify_main_rank(&self.nodes) {
            // Find the result corresponding to the main rank node
            // The results should be in the same order as nodes
            if let Some(main_result) = execution_results.get_mut(main_idx) {
                main_result.is_main_rank = true;
            }
        }

        Ok(execution_results)
    }

    /// Collect upload results, handling any task panics.
    fn collect_upload_results(
        &self,
        results: Vec<Result<UploadResult, tokio::task::JoinError>>,
    ) -> Result<Vec<UploadResult>> {
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

    /// Collect download results, handling any task panics.
    fn collect_download_results(
        &self,
        results: Vec<Result<DownloadResult, tokio::task::JoinError>>,
    ) -> Result<Vec<DownloadResult>> {
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
}

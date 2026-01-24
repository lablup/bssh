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
use crate::security::SudoPassword;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::SshConnectionConfig;
use crate::ssh::SshConfig;

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
    pub(crate) connect_timeout: Option<u64>,
    pub(crate) jump_hosts: Option<String>,
    pub(crate) sudo_password: Option<Arc<SudoPassword>>,
    pub(crate) batch: bool,
    pub(crate) fail_fast: bool,
    pub(crate) ssh_config: Option<SshConfig>,
    /// SSH connection configuration (keepalive settings)
    pub(crate) ssh_connection_config: SshConnectionConfig,
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
            connect_timeout: None,
            jump_hosts: None,
            sudo_password: None,
            batch: false,
            fail_fast: false,
            ssh_config: None,
            ssh_connection_config: SshConnectionConfig::default(),
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
            connect_timeout: None,
            jump_hosts: None,
            sudo_password: None,
            batch: false,
            fail_fast: false,
            ssh_config: None,
            ssh_connection_config: SshConnectionConfig::default(),
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
            connect_timeout: None,
            jump_hosts: None,
            sudo_password: None,
            batch: false,
            fail_fast: false,
            ssh_config: None,
            ssh_connection_config: SshConnectionConfig::default(),
        }
    }

    /// Set command execution timeout.
    pub fn with_timeout(mut self, timeout: Option<u64>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set SSH connection timeout.
    pub fn with_connect_timeout(mut self, connect_timeout: Option<u64>) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    /// Set jump hosts for connections.
    pub fn with_jump_hosts(mut self, jump_hosts: Option<String>) -> Self {
        self.jump_hosts = jump_hosts;
        self
    }

    /// Set SSH config for ProxyJump directive resolution.
    pub fn with_ssh_config(mut self, ssh_config: Option<SshConfig>) -> Self {
        self.ssh_config = ssh_config;
        self
    }

    /// Set whether to use macOS Keychain for passphrase storage/retrieval (macOS only).
    #[cfg(target_os = "macos")]
    pub fn with_keychain(mut self, use_keychain: bool) -> Self {
        self.use_keychain = use_keychain;
        self
    }

    /// Set sudo password for automatic sudo authentication.
    ///
    /// When set, the executor will automatically detect sudo password prompts
    /// and inject the password when commands require sudo privileges.
    pub fn with_sudo_password(mut self, sudo_password: Option<Arc<SudoPassword>>) -> Self {
        self.sudo_password = sudo_password;
        self
    }

    /// Set batch mode for signal handling.
    ///
    /// When set to true, a single Ctrl+C will immediately terminate all jobs.
    /// When false (default), first Ctrl+C shows status, second terminates.
    pub fn with_batch_mode(mut self, batch: bool) -> Self {
        self.batch = batch;
        self
    }

    /// Enable fail-fast mode (pdsh -k compatibility).
    ///
    /// When enabled, execution stops immediately when any node fails:
    /// - Connection failure to any host
    /// - Non-zero exit code from any command
    ///
    /// Pending commands are cancelled and running commands are terminated gracefully.
    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// Set SSH connection configuration (keepalive settings).
    ///
    /// Configures keepalive interval and maximum attempts to prevent
    /// idle connection timeouts during long-running operations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bssh::executor::ParallelExecutor;
    /// use bssh::ssh::tokio_client::SshConnectionConfig;
    /// use bssh::node::Node;
    ///
    /// let nodes = vec![Node::new("example.com".to_string(), 22, "user".to_string())];
    ///
    /// let config = SshConnectionConfig::new()
    ///     .with_keepalive_interval(Some(30))
    ///     .with_keepalive_max(5);
    ///
    /// let executor = ParallelExecutor::new(nodes, 10, None)
    ///     .with_ssh_connection_config(config);
    /// ```
    pub fn with_ssh_connection_config(mut self, config: SshConnectionConfig) -> Self {
        self.ssh_connection_config = config;
        self
    }

    /// Execute a command on all nodes in parallel.
    pub async fn execute(&self, command: &str) -> Result<Vec<ExecutionResult>> {
        use std::time::Duration;
        use tokio::signal;

        // Use fail-fast execution if enabled
        if self.fail_fast {
            return self.execute_with_fail_fast(command).await;
        }

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
                let connect_timeout = self.connect_timeout;
                let jump_hosts = self.jump_hosts.clone();
                let sudo_password = self.sudo_password.clone();
                let semaphore = Arc::clone(&semaphore);
                let pb = setup_progress_bar(&multi_progress, &node, style.clone(), "Connecting...");

                let ssh_config_ref = self.ssh_config.clone();
                let ssh_connection_config = self.ssh_connection_config.clone();

                tokio::spawn(async move {
                    let config = ExecutionConfig {
                        key_path: key_path.as_deref(),
                        strict_mode,
                        use_agent,
                        use_password,
                        #[cfg(target_os = "macos")]
                        use_keychain,
                        timeout,
                        connect_timeout,
                        jump_hosts: jump_hosts.as_deref(),
                        sudo_password: sudo_password.clone(),
                        ssh_config: ssh_config_ref.as_ref(),
                        ssh_connection_config: Some(&ssh_connection_config),
                    };

                    execute_command_task(node, command, config, semaphore, pb).await
                })
            })
            .collect();

        // Handle signal interruption with batch mode support
        let mut first_ctrl_c = false;
        let mut ctrl_c_time: Option<std::time::Instant> = None;
        let mut pending_handles = tasks;

        loop {
            tokio::select! {
                // Handle Ctrl+C signal
                _ = signal::ctrl_c() => {
                    if self.batch {
                        // Batch mode: immediately terminate on first Ctrl+C
                        eprintln!("\nReceived Ctrl+C (batch mode). Terminating all jobs...");
                        for handle in pending_handles.drain(..) {
                            handle.abort();
                        }
                        // Exit with SIGINT exit code (130)
                        std::process::exit(130);
                    } else {
                        // Non-batch mode: two-stage Ctrl+C
                        if !first_ctrl_c {
                            // First Ctrl+C: show status
                            first_ctrl_c = true;
                            ctrl_c_time = Some(std::time::Instant::now());
                            eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                            // Count pending handles as running
                            let running_count = pending_handles.len();
                            let completed_count = self.nodes.len() - running_count;
                            eprintln!("Status: {} running, {} completed", running_count, completed_count);
                        } else {
                            // Second Ctrl+C: terminate
                            if let Some(first_time) = ctrl_c_time {
                                if first_time.elapsed() <= Duration::from_secs(1) {
                                    eprintln!("Received second Ctrl+C. Terminating all jobs...");
                                    for handle in pending_handles.drain(..) {
                                        handle.abort();
                                    }
                                    // Exit with SIGINT exit code (130)
                                    std::process::exit(130);
                                } else {
                                    // Too much time passed, reset
                                    first_ctrl_c = true;
                                    ctrl_c_time = Some(std::time::Instant::now());
                                    eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                                    // Show current status (matching behavior of first Ctrl+C)
                                    let running_count = pending_handles.len();
                                    let completed_count = self.nodes.len() - running_count;
                                    eprintln!("Status: {} running, {} completed", running_count, completed_count);
                                }
                            }
                        }
                    }
                }
                // Wait for all tasks to complete
                results = join_all(pending_handles.iter_mut()) => {
                    return self.collect_results(results);
                }
            }

            // Small sleep to avoid busy waiting
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Execute a command with fail-fast mode enabled.
    ///
    /// Stops execution immediately when any node fails (connection error or non-zero exit code).
    /// Cancels pending commands and terminates running commands gracefully.
    async fn execute_with_fail_fast(&self, command: &str) -> Result<Vec<ExecutionResult>> {
        use tokio::sync::watch;

        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();
        let style = create_progress_style()?;

        // Cancellation token: false = continue, true = cancelled
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let cancel_tx = Arc::new(cancel_tx);

        // Track all spawned task handles
        let mut handles: Vec<tokio::task::JoinHandle<ExecutionResult>> =
            Vec::with_capacity(self.nodes.len());

        let ssh_config_for_tasks = self.ssh_config.clone();
        let ssh_connection_config_for_tasks = self.ssh_connection_config.clone();

        // Spawn tasks for each node
        for node in &self.nodes {
            let node = node.clone();
            let command = command.to_string();
            let key_path = self.key_path.clone();
            let strict_mode = self.strict_mode;
            let use_agent = self.use_agent;
            let use_password = self.use_password;
            #[cfg(target_os = "macos")]
            let use_keychain = self.use_keychain;
            let timeout = self.timeout;
            let connect_timeout = self.connect_timeout;
            let jump_hosts = self.jump_hosts.clone();
            let sudo_password = self.sudo_password.clone();
            let semaphore = Arc::clone(&semaphore);
            let pb = setup_progress_bar(&multi_progress, &node, style.clone(), "Connecting...");
            let mut cancel_rx = cancel_rx.clone();
            let ssh_config_ref = ssh_config_for_tasks.clone();
            let ssh_connection_config_ref = ssh_connection_config_for_tasks.clone();

            let handle = tokio::spawn(async move {
                // Check if already cancelled before acquiring semaphore
                if *cancel_rx.borrow() {
                    pb.finish_with_message("○ Cancelled".to_string());
                    return ExecutionResult {
                        node,
                        result: Err(anyhow::anyhow!("Execution cancelled due to fail-fast")),
                        is_main_rank: false,
                    };
                }

                // Race between semaphore acquisition and cancellation
                let permit = tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => {
                        pb.finish_with_message("○ Cancelled".to_string());
                        return ExecutionResult {
                            node,
                            result: Err(anyhow::anyhow!("Execution cancelled due to fail-fast")),
                            is_main_rank: false,
                        };
                    }
                    permit = semaphore.acquire() => {
                        match permit {
                            Ok(p) => p,
                            Err(e) => {
                                pb.finish_with_message("● Semaphore closed".to_string());
                                return ExecutionResult {
                                    node,
                                    result: Err(anyhow::anyhow!("Semaphore acquisition failed: {e}")),
                                    is_main_rank: false,
                                };
                            }
                        }
                    }
                };

                // Check cancellation again after acquiring semaphore
                if *cancel_rx.borrow() {
                    drop(permit);
                    pb.finish_with_message("○ Cancelled".to_string());
                    return ExecutionResult {
                        node,
                        result: Err(anyhow::anyhow!("Execution cancelled due to fail-fast")),
                        is_main_rank: false,
                    };
                }

                pb.set_message("Executing...".to_string());

                let config = ExecutionConfig {
                    key_path: key_path.as_deref(),
                    strict_mode,
                    use_agent,
                    use_password,
                    #[cfg(target_os = "macos")]
                    use_keychain,
                    timeout,
                    connect_timeout,
                    jump_hosts: jump_hosts.as_deref(),
                    sudo_password: sudo_password.clone(),
                    ssh_config: ssh_config_ref.as_ref(),
                    ssh_connection_config: Some(&ssh_connection_config_ref),
                };

                // Execute the command (keeping the permit alive)
                let result = super::connection_manager::execute_on_node_with_jump_hosts(
                    node.clone(),
                    &command,
                    &config,
                )
                .await;

                // Release the permit explicitly
                drop(permit);

                // Format result
                match &result {
                    Ok(cmd_result) => {
                        if cmd_result.is_success() {
                            pb.finish_with_message("● Success".to_string());
                        } else {
                            pb.finish_with_message(format!(
                                "● Exit code: {}",
                                cmd_result.exit_status
                            ));
                        }
                    }
                    Err(e) => {
                        let error_msg = format!("{e:#}");
                        let first_line = error_msg.lines().next().unwrap_or("Unknown error");
                        let short_error = if first_line.len() > 50 {
                            // Find a valid char boundary at or before position 47
                            let mut end = 47.min(first_line.len());
                            while end > 0 && !first_line.is_char_boundary(end) {
                                end -= 1;
                            }
                            format!("{}...", &first_line[..end])
                        } else {
                            first_line.to_string()
                        };
                        pb.finish_with_message(format!("● {short_error}"));
                    }
                }

                ExecutionResult {
                    node,
                    result,
                    is_main_rank: false,
                }
            });

            handles.push(handle);
        }

        // Collect results, checking for failures as they complete
        let mut results: Vec<ExecutionResult> = Vec::with_capacity(handles.len());
        let mut first_failure: Option<(Node, String)> = None;

        // Process tasks as they complete
        while !handles.is_empty() {
            // Wait for any task to complete
            let (completed_result, index, remaining) = futures::future::select_all(handles).await;
            handles = remaining;

            match completed_result {
                Ok(exec_result) => {
                    // Check if this is a failure
                    let is_failure = !exec_result.is_success();
                    let node_info = exec_result.node.clone();

                    // Store failure info if this is the first failure
                    if is_failure && first_failure.is_none() {
                        let error_msg = match &exec_result.result {
                            Ok(cmd_result) => format!("exit code {}", cmd_result.exit_status),
                            Err(e) => format!("{e}"),
                        };
                        first_failure = Some((node_info.clone(), error_msg));

                        // Signal cancellation to remaining tasks
                        let _ = cancel_tx.send(true);

                        // Report failure
                        eprintln!(
                            "\n[fail-fast] Execution stopped: {} failed ({})",
                            node_info,
                            first_failure
                                .as_ref()
                                .map(|(_, e)| e.as_str())
                                .unwrap_or("unknown error")
                        );
                    }

                    results.push(exec_result);
                }
                Err(e) => {
                    // Task panicked
                    tracing::error!("Task panicked at index {}: {}", index, e);
                    if let Some(node) = self.nodes.get(index) {
                        let error_msg = format!("Task panicked: {e}");
                        if first_failure.is_none() {
                            first_failure = Some((node.clone(), error_msg.clone()));
                            let _ = cancel_tx.send(true);
                            eprintln!("\n[fail-fast] Execution stopped: {} panicked", node);
                        }
                        results.push(ExecutionResult {
                            node: node.clone(),
                            result: Err(anyhow::anyhow!("{}", error_msg)),
                            is_main_rank: false,
                        });
                    }
                }
            }
        }

        // Reorder results to match original node order
        let mut ordered_results: Vec<Option<ExecutionResult>> =
            (0..self.nodes.len()).map(|_| None).collect();
        for result in results {
            if let Some(idx) = self
                .nodes
                .iter()
                .position(|n| n.host == result.node.host && n.port == result.node.port)
            {
                ordered_results[idx] = Some(result);
            }
        }

        // Convert to final result vector, filling in missing results for cancelled tasks
        let final_results: Vec<ExecutionResult> = ordered_results
            .into_iter()
            .enumerate()
            .map(|(idx, opt_result)| {
                opt_result.unwrap_or_else(|| ExecutionResult {
                    node: self.nodes[idx].clone(),
                    result: Err(anyhow::anyhow!("Task did not complete (cancelled)")),
                    is_main_rank: false,
                })
            })
            .collect();

        self.collect_results(final_results.into_iter().map(Ok).collect())
    }

    /// Upload a file to all nodes in parallel.
    pub async fn upload_file(
        &self,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<Vec<UploadResult>> {
        use std::time::Duration;
        use tokio::signal;

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
                let connect_timeout = self.connect_timeout;
                let semaphore = Arc::clone(&semaphore);
                let pb = setup_progress_bar(&multi_progress, &node, style.clone(), "Connecting...");

                let ssh_config_ref = self.ssh_config.clone();

                tokio::spawn(upload_file_task(
                    node,
                    local_path,
                    remote_path,
                    key_path,
                    strict_mode,
                    use_agent,
                    use_password,
                    jump_hosts,
                    connect_timeout,
                    ssh_config_ref,
                    semaphore,
                    pb,
                ))
            })
            .collect();

        // Handle signal interruption with batch mode support
        let mut first_ctrl_c = false;
        let mut ctrl_c_time: Option<std::time::Instant> = None;
        let mut pending_handles = tasks;

        loop {
            tokio::select! {
                // Handle Ctrl+C signal
                _ = signal::ctrl_c() => {
                    if self.batch {
                        // Batch mode: immediately terminate on first Ctrl+C
                        eprintln!("\nReceived Ctrl+C (batch mode). Terminating all uploads...");
                        for handle in pending_handles.drain(..) {
                            handle.abort();
                        }
                        // Exit with SIGINT exit code (130)
                        std::process::exit(130);
                    } else {
                        // Non-batch mode: two-stage Ctrl+C
                        if !first_ctrl_c {
                            // First Ctrl+C: show status
                            first_ctrl_c = true;
                            ctrl_c_time = Some(std::time::Instant::now());
                            eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                            // Count pending handles as running
                            let running_count = pending_handles.len();
                            let completed_count = self.nodes.len() - running_count;
                            eprintln!("Status: {} running, {} completed", running_count, completed_count);
                        } else {
                            // Second Ctrl+C: terminate
                            if let Some(first_time) = ctrl_c_time {
                                if first_time.elapsed() <= Duration::from_secs(1) {
                                    eprintln!("Received second Ctrl+C. Terminating all uploads...");
                                    for handle in pending_handles.drain(..) {
                                        handle.abort();
                                    }
                                    // Exit with SIGINT exit code (130)
                                    std::process::exit(130);
                                } else {
                                    // Too much time passed, reset
                                    first_ctrl_c = true;
                                    ctrl_c_time = Some(std::time::Instant::now());
                                    eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                                    // Show current status (matching behavior of first Ctrl+C)
                                    let running_count = pending_handles.len();
                                    let completed_count = self.nodes.len() - running_count;
                                    eprintln!("Status: {} running, {} completed", running_count, completed_count);
                                }
                            }
                        }
                    }
                }
                // Wait for all tasks to complete
                results = join_all(pending_handles.iter_mut()) => {
                    return self.collect_upload_results(results);
                }
            }

            // Small sleep to avoid busy waiting
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Download a file from all nodes in parallel.
    pub async fn download_file(
        &self,
        remote_path: &str,
        local_dir: &Path,
    ) -> Result<Vec<DownloadResult>> {
        use std::time::Duration;
        use tokio::signal;

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
                let connect_timeout = self.connect_timeout;
                let semaphore = Arc::clone(&semaphore);
                let pb = setup_progress_bar(&multi_progress, &node, style.clone(), "Connecting...");
                let ssh_config_ref = self.ssh_config.clone();

                tokio::spawn(download_file_task(
                    node,
                    remote_path,
                    local_dir,
                    key_path,
                    strict_mode,
                    use_agent,
                    use_password,
                    jump_hosts,
                    connect_timeout,
                    ssh_config_ref,
                    semaphore,
                    pb,
                ))
            })
            .collect();

        // Handle signal interruption with batch mode support
        let mut first_ctrl_c = false;
        let mut ctrl_c_time: Option<std::time::Instant> = None;
        let mut pending_handles = tasks;

        loop {
            tokio::select! {
                // Handle Ctrl+C signal
                _ = signal::ctrl_c() => {
                    if self.batch {
                        // Batch mode: immediately terminate on first Ctrl+C
                        eprintln!("\nReceived Ctrl+C (batch mode). Terminating all downloads...");
                        for handle in pending_handles.drain(..) {
                            handle.abort();
                        }
                        // Exit with SIGINT exit code (130)
                        std::process::exit(130);
                    } else {
                        // Non-batch mode: two-stage Ctrl+C
                        if !first_ctrl_c {
                            // First Ctrl+C: show status
                            first_ctrl_c = true;
                            ctrl_c_time = Some(std::time::Instant::now());
                            eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                            // Count pending handles as running
                            let running_count = pending_handles.len();
                            let completed_count = self.nodes.len() - running_count;
                            eprintln!("Status: {} running, {} completed", running_count, completed_count);
                        } else {
                            // Second Ctrl+C: terminate
                            if let Some(first_time) = ctrl_c_time {
                                if first_time.elapsed() <= Duration::from_secs(1) {
                                    eprintln!("Received second Ctrl+C. Terminating all downloads...");
                                    for handle in pending_handles.drain(..) {
                                        handle.abort();
                                    }
                                    // Exit with SIGINT exit code (130)
                                    std::process::exit(130);
                                } else {
                                    // Too much time passed, reset
                                    first_ctrl_c = true;
                                    ctrl_c_time = Some(std::time::Instant::now());
                                    eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                                    // Show current status (matching behavior of first Ctrl+C)
                                    let running_count = pending_handles.len();
                                    let completed_count = self.nodes.len() - running_count;
                                    eprintln!("Status: {} running, {} completed", running_count, completed_count);
                                }
                            }
                        }
                    }
                }
                // Wait for all tasks to complete
                results = join_all(pending_handles.iter_mut()) => {
                    return self.collect_download_results(results);
                }
            }

            // Small sleep to avoid busy waiting
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Download multiple files from all nodes.
    pub async fn download_files(
        &self,
        remote_paths: Vec<String>,
        local_dir: &Path,
    ) -> Result<Vec<DownloadResult>> {
        use std::time::Duration;
        use tokio::signal;

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
                    let connect_timeout = self.connect_timeout;
                    let ssh_config_ref = self.ssh_config.clone();

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
                            connect_timeout,
                            ssh_config_ref.as_ref(),
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

            // Handle signal interruption with batch mode support
            let mut first_ctrl_c = false;
            let mut ctrl_c_time: Option<std::time::Instant> = None;
            let mut pending_handles = tasks;

            loop {
                tokio::select! {
                    // Handle Ctrl+C signal
                    _ = signal::ctrl_c() => {
                        if self.batch {
                            // Batch mode: immediately terminate on first Ctrl+C
                            eprintln!("\nReceived Ctrl+C (batch mode). Terminating all downloads...");
                            for handle in pending_handles.drain(..) {
                                handle.abort();
                            }
                            // Exit with SIGINT exit code (130)
                            std::process::exit(130);
                        } else {
                            // Non-batch mode: two-stage Ctrl+C
                            if !first_ctrl_c {
                                // First Ctrl+C: show status
                                first_ctrl_c = true;
                                ctrl_c_time = Some(std::time::Instant::now());
                                eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                                // Count pending handles as running
                                let running_count = pending_handles.len();
                                let completed_count = self.nodes.len() - running_count;
                                eprintln!("Status: {} running, {} completed", running_count, completed_count);
                            } else {
                                // Second Ctrl+C: terminate
                                if let Some(first_time) = ctrl_c_time {
                                    if first_time.elapsed() <= Duration::from_secs(1) {
                                        eprintln!("Received second Ctrl+C. Terminating all downloads...");
                                        for handle in pending_handles.drain(..) {
                                            handle.abort();
                                        }
                                        // Exit with SIGINT exit code (130)
                                        std::process::exit(130);
                                    } else {
                                        // Too much time passed, reset
                                        first_ctrl_c = true;
                                        ctrl_c_time = Some(std::time::Instant::now());
                                        eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                                        // Show current status (matching behavior of first Ctrl+C)
                                        let running_count = pending_handles.len();
                                        let completed_count = self.nodes.len() - running_count;
                                        eprintln!("Status: {} running, {} completed", running_count, completed_count);
                                    }
                                }
                            }
                        }
                    }
                    // Wait for all tasks to complete
                    results = join_all(pending_handles.iter_mut()) => {
                        // Collect results for this file
                        for result in results {
                            match result {
                                Ok(download_result) => all_results.push(download_result),
                                Err(e) => {
                                    tracing::error!("Task failed: {}", e);
                                }
                            }
                        }
                        break;
                    }
                }

                // Small sleep to avoid busy waiting
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        Ok(all_results)
    }

    /// Collect execution results, handling any task panics.
    fn collect_results(
        &self,
        results: Vec<Result<ExecutionResult, tokio::task::JoinError>>,
    ) -> Result<Vec<ExecutionResult>> {
        // Identify main rank before collecting results
        let main_idx = RankDetector::identify_main_rank(&self.nodes);

        let mut execution_results = Vec::new();
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(mut exec_result) => {
                    // Mark as main rank if this index matches
                    if Some(idx) == main_idx {
                        exec_result.is_main_rank = true;
                    }
                    execution_results.push(exec_result);
                }
                Err(e) => {
                    tracing::error!(
                        "Task failed for node {}: {}",
                        self.nodes
                            .get(idx)
                            .map(|n| n.host.as_str())
                            .unwrap_or("unknown"),
                        e
                    );
                    // Create a failed result to maintain index mapping
                    if let Some(node) = self.nodes.get(idx) {
                        let failed_result = ExecutionResult {
                            node: node.clone(),
                            result: Err(anyhow::anyhow!("Task execution failed: {e}")),
                            is_main_rank: Some(idx) == main_idx,
                        };
                        execution_results.push(failed_result);
                    }
                }
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

    /// Execute a command with streaming output support
    ///
    /// This method enables real-time output streaming from all nodes with configurable
    /// output modes:
    /// - Normal: Traditional batch mode (same as execute())
    /// - Stream: Real-time with [node] prefixes
    /// - File: Save per-node output to files
    ///
    /// # Arguments
    /// * `command` - The command to execute
    /// * `output_mode` - How to handle output (Normal/Stream/File)
    ///
    /// # Returns
    /// Vector of execution results, one per node
    pub async fn execute_with_streaming(
        &self,
        command: &str,
        output_mode: super::output_mode::OutputMode,
    ) -> Result<Vec<ExecutionResult>> {
        // For Normal mode, use existing execute() method for backward compatibility
        if output_mode.is_normal() {
            return self.execute(command).await;
        }

        use super::stream_manager::MultiNodeStreamManager;
        use crate::ssh::client::ConnectionConfig;
        use crate::ssh::SshClient;
        use tokio::sync::mpsc;

        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let mut manager = MultiNodeStreamManager::new();
        let mut handles = Vec::new();

        // Spawn tasks for each node with streaming
        for node in &self.nodes {
            let (tx, rx) = mpsc::channel(1000);
            manager.add_stream(node.clone(), rx);

            let node_clone = node.clone();
            let command = command.to_string();
            let key_path = self.key_path.clone();
            let strict_mode = self.strict_mode;
            let use_agent = self.use_agent;
            let use_password = self.use_password;
            #[cfg(target_os = "macos")]
            let use_keychain = self.use_keychain;
            let timeout = self.timeout;
            let connect_timeout = self.connect_timeout;
            let jump_hosts = self.jump_hosts.clone();
            let sudo_password = self.sudo_password.clone();
            let semaphore = Arc::clone(&semaphore);

            let handle = tokio::spawn(async move {
                // Use defer pattern to ensure cleanup even on panic
                struct CleanupGuard<T> {
                    _permit: Option<T>,
                }

                impl<T> Drop for CleanupGuard<T> {
                    fn drop(&mut self) {
                        tracing::trace!("Releasing semaphore permit in cleanup guard");
                    }
                }

                // Acquire semaphore with guard
                let permit = match semaphore.acquire().await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!("Failed to acquire semaphore: {}", e);
                        return (
                            node_clone,
                            Err(anyhow::anyhow!("Semaphore acquisition failed")),
                        );
                    }
                };

                let _guard = CleanupGuard {
                    _permit: Some(permit),
                };

                let mut client = SshClient::new(
                    node_clone.host.clone(),
                    node_clone.port,
                    node_clone.username.clone(),
                );

                let config = ConnectionConfig {
                    key_path: key_path.as_deref().map(Path::new),
                    strict_mode: Some(strict_mode),
                    use_agent,
                    use_password,
                    #[cfg(target_os = "macos")]
                    use_keychain,
                    timeout_seconds: timeout,
                    connect_timeout_seconds: connect_timeout,
                    jump_hosts_spec: jump_hosts.as_deref(),
                };

                // Execute with or without sudo password support
                let result = if let Some(ref sudo_pwd) = sudo_password {
                    match client
                        .connect_and_execute_with_sudo(&command, &config, tx.clone(), sudo_pwd)
                        .await
                    {
                        Ok(exit_status) => {
                            tracing::debug!(
                                "Sudo command completed for {}: exit code {}",
                                node_clone.host,
                                exit_status
                            );
                            (node_clone, Ok(exit_status))
                        }
                        Err(e) => {
                            tracing::error!("Sudo command failed for {}: {}", node_clone.host, e);
                            (node_clone, Err(e))
                        }
                    }
                } else {
                    match client
                        .connect_and_execute_with_output_streaming(&command, &config, tx.clone())
                        .await
                    {
                        Ok(exit_status) => {
                            tracing::debug!(
                                "Command completed for {}: exit code {}",
                                node_clone.host,
                                exit_status
                            );
                            (node_clone, Ok(exit_status))
                        }
                        Err(e) => {
                            tracing::error!("Command failed for {}: {}", node_clone.host, e);
                            (node_clone, Err(e))
                        }
                    }
                };

                // Explicitly drop the channel to signal completion
                drop(tx);
                result
            });

            handles.push(handle);
        }

        // Execute based on mode and ensure cleanup
        let no_prefix = output_mode.is_no_prefix();
        let result = if output_mode.is_tui() {
            // TUI mode: interactive terminal UI
            self.handle_tui_mode(&mut manager, handles, command).await
        } else if output_mode.is_stream() {
            // Stream mode: output in real-time with optional [node] prefixes
            self.handle_stream_mode(&mut manager, handles, no_prefix)
                .await
        } else if let Some(output_dir) = output_mode.output_dir() {
            // File mode: save to per-node files
            self.handle_file_mode(&mut manager, handles, output_dir, no_prefix)
                .await
        } else {
            // Fallback to normal mode
            self.execute(command).await
        };

        result
    }

    /// Handle stream mode output with optional [node] prefixes
    async fn handle_stream_mode(
        &self,
        manager: &mut super::stream_manager::MultiNodeStreamManager,
        handles: Vec<tokio::task::JoinHandle<(Node, Result<u32>)>>,
        no_prefix: bool,
    ) -> Result<Vec<ExecutionResult>> {
        use super::output_sync::NodeOutputWriter;
        use std::time::Duration;
        use tokio::signal;

        let mut pending_handles = handles;
        let mut results = Vec::new();
        let mut first_ctrl_c = false;
        let mut ctrl_c_time: Option<std::time::Instant> = None;

        // Poll until all tasks complete
        loop {
            tokio::select! {
                // Handle Ctrl+C signal
                _ = signal::ctrl_c() => {
                    if self.batch {
                        // Batch mode: immediately terminate on first Ctrl+C
                        eprintln!("\nReceived Ctrl+C (batch mode). Terminating all jobs...");
                        for handle in pending_handles.drain(..) {
                            handle.abort();
                        }
                        // Exit with SIGINT exit code (130)
                        std::process::exit(130);
                    } else {
                        // Non-batch mode: two-stage Ctrl+C
                        if !first_ctrl_c {
                            // First Ctrl+C: show status
                            first_ctrl_c = true;
                            ctrl_c_time = Some(std::time::Instant::now());
                            eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                            // Show current status
                            let running_count = pending_handles.len();
                            let completed_count = manager.streams().iter()
                                .filter(|s| matches!(s.status(), super::stream_manager::ExecutionStatus::Completed))
                                .count();
                            eprintln!("Status: {} running, {} completed", running_count, completed_count);
                        } else {
                            // Second Ctrl+C: terminate
                            if let Some(first_time) = ctrl_c_time {
                                if first_time.elapsed() <= Duration::from_secs(1) {
                                    eprintln!("Received second Ctrl+C. Terminating all jobs...");
                                    for handle in pending_handles.drain(..) {
                                        handle.abort();
                                    }
                                    // Exit with SIGINT exit code (130)
                                    std::process::exit(130);
                                } else {
                                    // Too much time passed, reset
                                    first_ctrl_c = true;
                                    ctrl_c_time = Some(std::time::Instant::now());
                                    eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                                    // Show current status (matching behavior of first Ctrl+C)
                                    let running_count = pending_handles.len();
                                    let completed_count = manager.streams().iter()
                                        .filter(|s| matches!(s.status(), super::stream_manager::ExecutionStatus::Completed))
                                        .count();
                                    eprintln!("Status: {} running, {} completed", running_count, completed_count);
                                }
                            }
                        }
                    }
                }
                _ = async {
                    if pending_handles.is_empty() && manager.all_complete() {
                        return;
                    }

                    tokio::time::sleep(Duration::from_millis(1)).await;
                } => {
                    // Check if all tasks are done
                    if pending_handles.is_empty() && manager.all_complete() {
                        break;
                    }
                }
            }

            // Continue with regular processing
            // Poll all streams for new output
            manager.poll_all();

            // Output any new data with optional [node] prefixes using synchronized writes
            for stream in manager.streams_mut() {
                let stdout = stream.take_stdout();
                let stderr = stream.take_stderr();

                if !stdout.is_empty() {
                    // Use lossy conversion to handle non-UTF8 data gracefully
                    let text = String::from_utf8_lossy(&stdout);
                    let writer = NodeOutputWriter::new_with_no_prefix(&stream.node.host, no_prefix);
                    if let Err(e) = writer.write_stdout_lines(&text) {
                        tracing::error!("Failed to write stdout for {}: {}", stream.node.host, e);
                    }
                }

                if !stderr.is_empty() {
                    // Use lossy conversion to handle non-UTF8 data gracefully
                    let text = String::from_utf8_lossy(&stderr);
                    let writer = NodeOutputWriter::new_with_no_prefix(&stream.node.host, no_prefix);
                    if let Err(e) = writer.write_stderr_lines(&text) {
                        tracing::error!("Failed to write stderr for {}: {}", stream.node.host, e);
                    }
                }
            }

            // Check for completed tasks and handle panics
            let mut i = 0;
            while i < pending_handles.len() {
                if pending_handles[i].is_finished() {
                    let handle = pending_handles.remove(i);
                    // Check if task panicked
                    if let Err(e) = &handle.await {
                        tracing::error!("Task panicked: {}", e);
                        // Continue processing other nodes
                    }
                } else {
                    i += 1;
                }
            }

            // Small sleep to avoid busy waiting
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // After all handles complete, do final polls to ensure all Disconnected messages are processed
        // This handles race condition where task completes but rx hasn't detected channel closure yet
        for _ in 0..5 {
            manager.poll_all();
            if manager.all_complete() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Collect final results from all streams
        for stream in manager.streams() {
            use crate::ssh::client::CommandResult;

            let result =
                if let super::stream_manager::ExecutionStatus::Failed(err) = stream.status() {
                    Err(anyhow::anyhow!("{err}"))
                } else {
                    Ok(CommandResult {
                        host: stream.node.host.clone(),
                        output: Vec::new(), // stdout already printed
                        stderr: Vec::new(), // stderr already printed
                        exit_status: stream.exit_code().unwrap_or(1),
                    })
                };

            results.push(ExecutionResult {
                node: stream.node.clone(),
                result,
                is_main_rank: false, // Will be set by collect_results
            });
        }

        self.collect_results(results.into_iter().map(Ok).collect())
    }

    /// Handle TUI mode output with interactive terminal UI
    async fn handle_tui_mode(
        &self,
        manager: &mut super::stream_manager::MultiNodeStreamManager,
        handles: Vec<tokio::task::JoinHandle<(Node, Result<u32>)>>,
        command: &str,
    ) -> Result<Vec<ExecutionResult>> {
        use crate::ui::tui;
        use std::time::Duration;

        // Determine cluster name (use first node's host or "cluster" as default)
        let cluster_name = self
            .nodes
            .first()
            .map(|n| n.host.as_str())
            .unwrap_or("cluster");

        let mut pending_handles = handles;

        // Run TUI event loop - this will block until user quits or all complete
        // The TUI itself will handle polling the manager
        let user_quit = match tui::run_tui(manager, cluster_name, command, self.batch).await {
            Ok(tui::TuiExitReason::UserQuit) => true,
            Ok(tui::TuiExitReason::AllTasksCompleted) => false,
            Err(e) => {
                tracing::error!("TUI error: {}", e);
                false
            }
        };

        // Clean up any remaining handles
        // If user explicitly quit, abort the handles instead of waiting
        for handle in pending_handles.drain(..) {
            if user_quit {
                handle.abort();
            } else if let Err(e) = handle.await {
                tracing::error!("Task error: {}", e);
            }
        }

        // Final polls to ensure all Disconnected messages are processed
        for _ in 0..5 {
            manager.poll_all();
            if manager.all_complete() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Collect final results from all streams
        let mut results = Vec::new();
        for stream in manager.streams() {
            use crate::ssh::client::CommandResult;

            let result =
                if let super::stream_manager::ExecutionStatus::Failed(err) = stream.status() {
                    Err(anyhow::anyhow!("{err}"))
                } else {
                    let output = stream.stdout().to_vec();
                    let stderr = stream.stderr().to_vec();
                    let exit_status = stream.exit_code().unwrap_or(0);
                    let host = stream.node.host.clone();

                    Ok(CommandResult {
                        host,
                        output,
                        stderr,
                        exit_status,
                    })
                };

            results.push(ExecutionResult {
                node: stream.node.clone(),
                result,
                is_main_rank: false, // Will be set by collect_results
            });
        }

        self.collect_results(results.into_iter().map(Ok).collect())
    }

    /// Handle file mode output - save to per-node files
    async fn handle_file_mode(
        &self,
        manager: &mut super::stream_manager::MultiNodeStreamManager,
        handles: Vec<tokio::task::JoinHandle<(Node, Result<u32>)>>,
        output_dir: &Path,
        no_prefix: bool,
    ) -> Result<Vec<ExecutionResult>> {
        use std::time::Duration;
        use tokio::fs;

        // Validate output directory
        if output_dir.exists() && !output_dir.is_dir() {
            return Err(anyhow::anyhow!(
                "Output path exists but is not a directory: {}",
                output_dir.display()
            ));
        }

        // Create output directory if it doesn't exist with proper error handling
        if let Err(e) = fs::create_dir_all(output_dir).await {
            return Err(anyhow::anyhow!(
                "Failed to create output directory '{}': {} - Check permissions",
                output_dir.display(),
                e
            ));
        }

        // Check if we can write to the directory
        let test_file = output_dir.join(".bssh_test_write");
        match fs::File::create(&test_file).await {
            Ok(_) => {
                // Clean up test file
                let _ = fs::remove_file(&test_file).await;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Output directory '{}' is not writable: {}",
                    output_dir.display(),
                    e
                ));
            }
        }

        // Log output directory for user reference
        tracing::info!(
            "Writing node outputs to directory: {}",
            output_dir.display()
        );

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

        let mut pending_handles = handles;
        let mut first_ctrl_c = false;
        let mut ctrl_c_time: Option<std::time::Instant> = None;

        // Poll until all tasks complete with signal handling
        loop {
            tokio::select! {
                // Handle Ctrl+C signal
                _ = tokio::signal::ctrl_c() => {
                    if self.batch {
                        // Batch mode: immediately terminate on first Ctrl+C
                        eprintln!("\nReceived Ctrl+C (batch mode). Terminating all jobs...");
                        for handle in pending_handles.drain(..) {
                            handle.abort();
                        }
                        // Exit with SIGINT exit code (130)
                        std::process::exit(130);
                    } else {
                        // Non-batch mode: two-stage Ctrl+C
                        if !first_ctrl_c {
                            // First Ctrl+C: show status
                            first_ctrl_c = true;
                            ctrl_c_time = Some(std::time::Instant::now());
                            eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                            // Show current status
                            let running_count = pending_handles.len();
                            let completed_count = manager.streams().iter()
                                .filter(|s| matches!(s.status(), super::stream_manager::ExecutionStatus::Completed))
                                .count();
                            eprintln!("Status: {} running, {} completed", running_count, completed_count);
                        } else {
                            // Second Ctrl+C: terminate
                            if let Some(first_time) = ctrl_c_time {
                                if first_time.elapsed() <= Duration::from_secs(1) {
                                    eprintln!("Received second Ctrl+C. Terminating all jobs...");
                                    for handle in pending_handles.drain(..) {
                                        handle.abort();
                                    }
                                    // Exit with SIGINT exit code (130)
                                    std::process::exit(130);
                                } else {
                                    // Too much time passed, reset
                                    first_ctrl_c = true;
                                    ctrl_c_time = Some(std::time::Instant::now());
                                    eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

                                    // Show current status (matching behavior of first Ctrl+C)
                                    let running_count = pending_handles.len();
                                    let completed_count = manager.streams().iter()
                                        .filter(|s| matches!(s.status(), super::stream_manager::ExecutionStatus::Completed))
                                        .count();
                                    eprintln!("Status: {} running, {} completed", running_count, completed_count);
                                }
                            }
                        }
                    }
                }
                _ = async {
                    if pending_handles.is_empty() && manager.all_complete() {
                        return;
                    }

                    tokio::time::sleep(Duration::from_millis(1)).await;
                } => {
                    // Check if all tasks are done
                    if pending_handles.is_empty() && manager.all_complete() {
                        break;
                    }
                }
            }

            // Continue with regular processing
            manager.poll_all();

            // Check for completed tasks
            pending_handles.retain_mut(|handle| !handle.is_finished());

            // Small sleep to avoid busy waiting
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Final polls to ensure all Disconnected messages are processed
        for _ in 0..5 {
            manager.poll_all();
            if manager.all_complete() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Write output files for each node
        let mut results = Vec::new();

        for stream in manager.streams() {
            use crate::ssh::client::CommandResult;

            let hostname = stream.node.host.replace([':', '/'], "_");
            let stdout_path = output_dir.join(format!("{hostname}_{timestamp}.stdout"));
            let stderr_path = output_dir.join(format!("{hostname}_{timestamp}.stderr"));

            // Write stdout with error handling
            if !stream.stdout().is_empty() {
                match fs::write(&stdout_path, stream.stdout()).await {
                    Ok(_) => {
                        // Use synchronized output to prevent interleaving
                        let writer = super::output_sync::NodeOutputWriter::new_with_no_prefix(
                            &stream.node.host,
                            no_prefix,
                        );
                        if let Err(e) = writer
                            .write_stdout(&format!("Output saved to {}", stdout_path.display()))
                        {
                            tracing::error!(
                                "Failed to write status for {}: {}",
                                stream.node.host,
                                e
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to write stdout for {} to {}: {}",
                            stream.node.host,
                            stdout_path.display(),
                            e
                        );
                        // Continue processing other nodes despite error
                    }
                }
            }

            // Write stderr with error handling
            if !stream.stderr().is_empty() {
                match fs::write(&stderr_path, stream.stderr()).await {
                    Ok(_) => {
                        // Use synchronized output to prevent interleaving
                        let writer = super::output_sync::NodeOutputWriter::new_with_no_prefix(
                            &stream.node.host,
                            no_prefix,
                        );
                        if let Err(e) = writer
                            .write_stdout(&format!("Errors saved to {}", stderr_path.display()))
                        {
                            tracing::error!(
                                "Failed to write status for {}: {}",
                                stream.node.host,
                                e
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to write stderr for {} to {}: {}",
                            stream.node.host,
                            stderr_path.display(),
                            e
                        );
                        // Continue processing other nodes despite error
                    }
                }
            }

            let result =
                if let super::stream_manager::ExecutionStatus::Failed(err) = stream.status() {
                    Err(anyhow::anyhow!("{err}"))
                } else {
                    Ok(CommandResult {
                        host: stream.node.host.clone(),
                        output: stream.stdout().to_vec(),
                        stderr: stream.stderr().to_vec(),
                        exit_status: stream.exit_code().unwrap_or(0),
                    })
                };

            results.push(ExecutionResult {
                node: stream.node.clone(),
                result,
                is_main_rank: false,
            });
        }

        self.collect_results(results.into_iter().map(Ok).collect())
    }
}

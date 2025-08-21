use anyhow::Result;
use futures::future::join_all;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::node::Node;
use crate::ssh::{client::CommandResult, known_hosts::StrictHostKeyChecking, SshClient};

pub struct ParallelExecutor {
    nodes: Vec<Node>,
    max_parallel: usize,
    key_path: Option<String>,
    strict_mode: StrictHostKeyChecking,
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
        }
    }

    pub async fn execute(&self, command: &str) -> Result<Vec<ExecutionResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let multi_progress = MultiProgress::new();

        let style = ProgressStyle::default_bar()
            .template("{prefix:.bold.dim} {spinner:.green} {msg}")
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");

        let tasks: Vec<_> = self
            .nodes
            .iter()
            .map(|node| {
                let node = node.clone();
                let command = command.to_string();
                let key_path = self.key_path.clone();
                let strict_mode = self.strict_mode;
                let semaphore = Arc::clone(&semaphore);
                let pb = multi_progress.add(ProgressBar::new_spinner());
                pb.set_style(style.clone());
                pb.set_prefix(format!("[{node}]"));
                pb.set_message("Connecting...");
                pb.enable_steady_tick(std::time::Duration::from_millis(100));

                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    pb.set_message("Executing command...");

                    let result =
                        execute_on_node(node.clone(), &command, key_path.as_deref(), strict_mode)
                            .await;

                    match &result {
                        Ok(cmd_result) => {
                            if cmd_result.is_success() {
                                pb.finish_with_message("✓ Success");
                            } else {
                                pb.finish_with_message(format!(
                                    "✗ Exit code: {}",
                                    cmd_result.exit_status
                                ));
                            }
                        }
                        Err(e) => {
                            pb.finish_with_message(format!("✗ Error: {e}"));
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
}

async fn execute_on_node(
    node: Node,
    command: &str,
    key_path: Option<&str>,
    strict_mode: StrictHostKeyChecking,
) -> Result<CommandResult> {
    let mut client = SshClient::new(node.host.clone(), node.port, node.username.clone());

    let key_path = key_path.map(Path::new);

    client
        .connect_and_execute_with_host_check(command, key_path, Some(strict_mode))
        .await
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
        println!("\n{}", "=".repeat(60));
        println!("Host: {}", self.node);
        println!("{}", "=".repeat(60));

        match &self.result {
            Ok(cmd_result) => {
                if !cmd_result.output.is_empty() {
                    println!("{}", cmd_result.stdout_string());
                }

                if !cmd_result.stderr.is_empty() && (verbose || !cmd_result.is_success()) {
                    eprintln!("STDERR:\n{}", cmd_result.stderr_string());
                }

                if !cmd_result.is_success() {
                    eprintln!("Exit code: {}", cmd_result.exit_status);
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
            }
        }
    }
}

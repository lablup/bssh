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
use std::path::Path;
use std::sync::Arc;

use crate::executor::{
    ExecutionResult, ExitCodeStrategy, OutputMode, ParallelExecutor, RankDetector,
};
use crate::node::Node;
use crate::security::{Password, SudoPassword};
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::{Error as SshError, SshConnectionConfigResolver};
use crate::ssh::{CliTtyMode, SshConfig};
use crate::ui::OutputFormatter;
use crate::utils::output::save_outputs_to_files;

pub struct ExecuteCommandParams<'a> {
    pub nodes: Vec<Node>,
    pub command: &'a str,
    pub max_parallel: usize,
    pub key_path: Option<&'a Path>,
    pub verbose: bool,
    pub strict_mode: StrictHostKeyChecking,
    pub use_agent: bool,
    pub use_password: bool,
    /// Pre-collected SSH password collected once by the dispatcher and shared
    /// (via `Arc::clone`) with every per-node SSH connection task. When
    /// `use_password` is `true`, this should be `Some(_)`.
    pub ssh_password: Option<Arc<Password>>,
    #[cfg(target_os = "macos")]
    pub use_keychain: bool,
    pub output_dir: Option<&'a Path>,
    pub stream: bool,
    pub no_prefix: bool,
    pub byte_transparent: bool,
    pub timeout: Option<u64>,
    pub connect_timeout: Option<u64>,
    pub jump_hosts: Option<&'a str>,
    pub require_all_success: bool,
    pub check_all_nodes: bool,
    pub sudo_password: Option<Arc<SudoPassword>>,
    pub batch: bool,
    pub fail_fast: bool,
    pub ssh_config: Option<&'a SshConfig>,
    pub tty_mode: CliTtyMode,
    /// Per-host SSH connection configuration resolver.
    pub ssh_connection_config_resolver: SshConnectionConfigResolver,
}

const SSH_CLIENT_FAILURE_EXIT_CODE: i32 = 255;

pub(crate) fn is_ssh_client_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<SshError>()
            .is_some_and(SshError::is_ssh_client_failure)
    })
}

fn calculate_execution_exit_code(
    results: &[ExecutionResult],
    main_idx: Option<usize>,
    strategy: ExitCodeStrategy,
    ssh_single_destination: bool,
) -> i32 {
    if ssh_single_destination {
        return results
            .first()
            .map(|result| match &result.result {
                Ok(_) => result.get_exit_code(),
                Err(error) if is_ssh_client_failure(error) => SSH_CLIENT_FAILURE_EXIT_CODE,
                Err(_) => result.get_exit_code(),
            })
            .unwrap_or(SSH_CLIENT_FAILURE_EXIT_CODE);
    }

    strategy.calculate(results, main_idx)
}

pub async fn execute_command(params: ExecuteCommandParams<'_>) -> Result<()> {
    if !params.byte_transparent {
        println!(
            "{}",
            OutputFormatter::format_command_header(params.command, params.nodes.len())
        );
    }

    execute_command_without_forwarding(params).await
}

/// Execute command without port forwarding (original implementation)
async fn execute_command_without_forwarding(params: ExecuteCommandParams<'_>) -> Result<()> {
    // Save nodes for later use (before moving into executor)
    let nodes_for_rank_detection = params.nodes.clone();

    let key_path = params.key_path.map(|p| p.to_string_lossy().to_string());
    let executor = ParallelExecutor::new_with_all_options(
        params.nodes,
        params.max_parallel,
        key_path,
        params.strict_mode,
        params.use_agent,
        params.use_password,
    )
    .with_timeout(params.timeout)
    .with_connect_timeout(params.connect_timeout)
    .with_jump_hosts(params.jump_hosts.map(|s| s.to_string()))
    .with_sudo_password(params.sudo_password)
    .with_ssh_password(params.ssh_password)
    .with_batch_mode(params.batch)
    .with_fail_fast(params.fail_fast)
    .with_ssh_config(params.ssh_config.cloned())
    .with_tty_mode(params.tty_mode)
    .with_ssh_connection_config_resolver(params.ssh_connection_config_resolver);

    // Set keychain usage if on macOS
    #[cfg(target_os = "macos")]
    let executor = executor.with_keychain(params.use_keychain);

    let output_mode = if params.byte_transparent && params.output_dir.is_none() {
        OutputMode::raw_stream()
    } else {
        OutputMode::from_args_with_no_prefix(
            params.stream,
            params.output_dir.map(|p| p.to_path_buf()),
            params.no_prefix,
        )
    };

    // Execute with appropriate mode
    let results = if output_mode.is_normal() {
        // Use traditional execution for backward compatibility
        executor.execute(params.command).await?
    } else {
        // Use streaming execution for --stream or --output-dir
        executor
            .execute_with_streaming(params.command, output_mode.clone())
            .await?
    };

    // Save outputs to files if output_dir is specified and not already handled by file mode
    // (File mode already saves outputs, so only save for normal mode with output_dir)
    if let Some(dir) = params.output_dir
        && !params.stream
    {
        // Only save if not in stream mode (file mode saves automatically)
        save_outputs_to_files(&results, dir, params.command).await?;
    }

    // Print results (skip if already printed in stream mode)
    if output_mode.is_normal() {
        for result in &results {
            result.print_output(params.verbose);
        }
    }

    let success_count = results.iter().filter(|r| r.is_success()).count();
    let failed_count = results.len() - success_count;

    if !params.byte_transparent {
        println!(
            "{}",
            OutputFormatter::format_summary(results.len(), success_count, failed_count)
        );
    }

    // Determine exit code strategy from CLI flags
    let strategy = if params.require_all_success {
        ExitCodeStrategy::RequireAllSuccess
    } else if params.check_all_nodes {
        ExitCodeStrategy::MainRankWithFailureCheck
    } else {
        ExitCodeStrategy::MainRank // Default in v1.2.0+
    };

    // Identify main rank
    let main_idx = RankDetector::identify_main_rank(&nodes_for_rank_detection);

    // OpenSSH reserves 255 for client-side failures. Apply that contract only
    // to the byte-transparent, single-destination SSH mode; multi-host bssh
    // aggregation keeps its existing ExitCodeStrategy behavior.
    let exit_code = calculate_execution_exit_code(
        &results,
        main_idx,
        strategy,
        params.byte_transparent && nodes_for_rank_detection.len() == 1,
    );

    // Exit with the calculated exit code
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::client::CommandResult;
    use anyhow::anyhow;

    fn result(result: Result<CommandResult>) -> ExecutionResult {
        ExecutionResult {
            node: Node::new("host".to_string(), 22, "user".to_string()),
            result,
            is_main_rank: true,
        }
    }

    fn remote_status(status: u32) -> ExecutionResult {
        result(Ok(CommandResult {
            host: "host".to_string(),
            output: Vec::new(),
            stderr: Vec::new(),
            exit_status: status,
        }))
    }

    #[test]
    fn ssh_single_destination_client_failure_exits_255() {
        let results = [result(Err(anyhow::Error::new(SshError::TcpConnect {
            host: "host".to_string(),
            port: 22,
            source: std::io::Error::from_raw_os_error(libc::ECONNREFUSED),
        })))];

        assert_eq!(
            calculate_execution_exit_code(&results, Some(0), ExitCodeStrategy::MainRank, true,),
            255
        );

        let timeout = [result(Err(anyhow::Error::new(
            SshError::ConnectionTimeout {
                host: "host".to_string(),
                port: 22,
                seconds: 1,
                stage: "connection setup or authentication",
            },
        )))];
        assert_eq!(
            calculate_execution_exit_code(&timeout, Some(0), ExitCodeStrategy::MainRank, true,),
            255
        );
    }

    #[test]
    fn ssh_single_destination_preserves_remote_status() {
        for status in [0, 42, 255] {
            assert_eq!(
                calculate_execution_exit_code(
                    &[remote_status(status)],
                    Some(0),
                    ExitCodeStrategy::MainRank,
                    true,
                ),
                status as i32
            );
        }
    }

    #[test]
    fn ssh_single_destination_local_error_keeps_generic_status() {
        let results = [result(Err(anyhow!("local validation failed")))];

        assert_eq!(
            calculate_execution_exit_code(&results, Some(0), ExitCodeStrategy::MainRank, true,),
            1
        );
    }

    #[test]
    fn multi_host_connection_error_keeps_existing_aggregation_status() {
        let results = [result(Err(anyhow!("connection refused")))];

        assert_eq!(
            calculate_execution_exit_code(&results, Some(0), ExitCodeStrategy::MainRank, false,),
            1
        );
    }
}

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
use owo_colors::OwoColorize;
use std::path::Path;
use std::sync::Arc;

use crate::commands::error_format::format_connection_error;
use crate::executor::{ExecutionResult, ParallelExecutor};
use crate::node::Node;
use crate::security::Password;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ssh::tokio_client::SshConnectionConfig;
use crate::ui::OutputFormatter;

/// Exit code reported when bssh itself could not complete the connectivity
/// check: no targeted host answered, no host was resolved, or a hard error was
/// raised before the first connection attempt.
///
/// OpenSSH reserves 255 for "ssh itself encountered an error" as opposed to a
/// status forwarded from a remote command. `ping` runs no remote command, so
/// every total failure is by definition an ssh-level failure, and a caller can
/// use this value to tell "I could not reach anything" apart from the exit code
/// 1 that means "the cluster is partially degraded".
pub const PING_SSH_LEVEL_FAILURE: i32 = 255;

/// Aggregate result of a `bssh ping` run, returned so the caller can translate
/// it into the process exit status.
///
/// # Exit code contract
///
/// | Scenario | Exit code |
/// |---|---|
/// | Every targeted host connected and authenticated | 0 |
/// | At least one host reachable, at least one failed | 1 |
/// | No host succeeded (including an empty host list) | 255 |
///
/// The 0/1 boundary is [`ExitCodeStrategy::RequireAllSuccess`]: ping is a health
/// check, so it is only green when every node is green.
/// [`ExitCodeStrategy::MainRank`] does not apply, because ping runs no user
/// command whose status could be forwarded. Total failure is escalated to
/// [`PING_SSH_LEVEL_FAILURE`] on top of that strategy.
///
/// [`ExitCodeStrategy::RequireAllSuccess`]: crate::executor::ExitCodeStrategy::RequireAllSuccess
/// [`ExitCodeStrategy::MainRank`]: crate::executor::ExitCodeStrategy::MainRank
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PingOutcome {
    /// Number of hosts that were targeted.
    pub total: usize,
    /// Number of hosts that connected and authenticated.
    pub succeeded: usize,
    /// Number of hosts that could not be reached.
    pub failed: usize,
}

impl PingOutcome {
    /// Count successes and failures from the executor results.
    pub fn from_results(results: &[ExecutionResult]) -> Self {
        let succeeded = results.iter().filter(|r| r.is_success()).count();
        Self {
            total: results.len(),
            succeeded,
            failed: results.len() - succeeded,
        }
    }

    /// Process exit status for this outcome, per the contract on
    /// [`PingOutcome`].
    pub fn exit_code(&self) -> i32 {
        if self.succeeded == 0 {
            // Nothing answered, so bssh never got a usable connection. This
            // also covers an empty host list.
            PING_SSH_LEVEL_FAILURE
        } else if self.failed > 0 {
            // RequireAllSuccess: any failure is a failure.
            1
        } else {
            0
        }
    }
}

/// Test connectivity to every node.
///
/// `ssh_connection_config` carries the resolved keepalive, compression, and
/// address family settings so `bssh ping -6` tests the same address family the
/// real connection would use.
///
/// Returns the per-host tally as a [`PingOutcome`]; the caller turns it into the
/// process exit status. An `Err` means bssh failed before it could evaluate any
/// host, which the caller maps to [`PING_SSH_LEVEL_FAILURE`] rather than to the
/// exit code 1 that means "some hosts answered and some did not".
#[allow(clippy::too_many_arguments)]
pub async fn ping_nodes(
    nodes: Vec<Node>,
    max_parallel: usize,
    key_path: Option<&Path>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    #[cfg(target_os = "macos")] use_keychain: bool,
    timeout: Option<u64>,
    connect_timeout: Option<u64>,
    jump_hosts: Option<String>,
    ssh_password: Option<Arc<Password>>,
    ssh_connection_config: SshConnectionConfig,
) -> Result<PingOutcome> {
    println!(
        "{}",
        OutputFormatter::format_command_header("ping", nodes.len())
    );

    let key_path = key_path.map(|p| p.to_string_lossy().to_string());

    // For ping command, just use the provided timeout or default
    // Don't override user's timeout setting
    let ping_timeout = timeout;

    let executor = ParallelExecutor::new_with_all_options(
        nodes.clone(),
        max_parallel,
        key_path,
        strict_mode,
        use_agent,
        use_password,
    )
    .with_timeout(ping_timeout)
    .with_connect_timeout(connect_timeout)
    .with_jump_hosts(jump_hosts)
    .with_ssh_password(ssh_password)
    .with_ssh_connection_config(ssh_connection_config);

    #[cfg(target_os = "macos")]
    let executor = executor.with_keychain(use_keychain);

    // Use normal execution (no TUI, no streaming) for ping
    let results = executor.execute("true").await?;
    let outcome = PingOutcome::from_results(&results);

    println!("\n{} {}\n", "▶".cyan(), "Connection Test Results".bold());

    for result in &results {
        if result.is_success() {
            println!(
                "  {} {} - {}",
                "●".green(),
                result.node.to_string().bold(),
                "Connected".green()
            );
        } else {
            println!(
                "  {} {} - {}",
                "●".red(),
                result.node.to_string().bold(),
                "Failed".red()
            );
            if let Err(e) = &result.result {
                // Display the full error chain for better debugging
                let error_chain = format_connection_error(e);
                // Split by newlines and indent each line
                for (i, line) in error_chain.lines().enumerate() {
                    if i == 0 {
                        println!("    {} {}", "└".dimmed(), line.dimmed());
                    } else {
                        println!("      {}", line.dimmed());
                    }
                }
            }
        }
    }

    println!(
        "{}",
        OutputFormatter::format_summary(outcome.total, outcome.succeeded, outcome.failed)
    );

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::ExitCodeStrategy;
    use crate::ssh::client::CommandResult;
    use anyhow::anyhow;

    fn reachable(host: &str) -> ExecutionResult {
        ExecutionResult {
            node: Node::new(host.to_string(), 22, "user".to_string()),
            result: Ok(CommandResult {
                host: host.to_string(),
                output: Vec::new(),
                stderr: Vec::new(),
                exit_status: 0,
            }),
            is_main_rank: false,
        }
    }

    fn unreachable(host: &str) -> ExecutionResult {
        ExecutionResult {
            node: Node::new(host.to_string(), 22, "user".to_string()),
            result: Err(anyhow!("Connection refused")),
            is_main_rank: false,
        }
    }

    #[test]
    fn all_hosts_reachable_exits_zero() {
        let outcome = PingOutcome::from_results(&[reachable("host1"), reachable("host2")]);

        assert_eq!(outcome.succeeded, 2);
        assert_eq!(outcome.failed, 0);
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn partial_failure_exits_one() {
        let outcome = PingOutcome::from_results(&[
            reachable("host1"),
            unreachable("host2"),
            reachable("host3"),
        ]);

        assert_eq!(outcome.succeeded, 2);
        assert_eq!(outcome.failed, 1);
        assert_eq!(outcome.exit_code(), 1);
    }

    #[test]
    fn total_failure_exits_255() {
        let outcome = PingOutcome::from_results(&[unreachable("host1"), unreachable("host2")]);

        assert_eq!(outcome.succeeded, 0);
        assert_eq!(outcome.failed, 2);
        assert_eq!(outcome.exit_code(), PING_SSH_LEVEL_FAILURE);
    }

    #[test]
    fn empty_host_list_exits_255() {
        let outcome = PingOutcome::from_results(&[]);

        assert_eq!(outcome.total, 0);
        assert_eq!(outcome.exit_code(), PING_SSH_LEVEL_FAILURE);
    }

    #[test]
    fn matches_require_all_success_whenever_a_host_answered() {
        // The 0/1 boundary is ExitCodeStrategy::RequireAllSuccess. Ping only
        // departs from it when nothing answered at all, where OpenSSH's 255
        // takes over.
        let cases = vec![
            vec![reachable("host1"), reachable("host2")],
            vec![reachable("host1"), unreachable("host2")],
            vec![unreachable("host1"), reachable("host2")],
        ];

        for results in cases {
            let outcome = PingOutcome::from_results(&results);
            assert_eq!(
                outcome.exit_code(),
                ExitCodeStrategy::RequireAllSuccess.calculate(&results, None),
                "ping must agree with RequireAllSuccess when at least one host answered"
            );
        }
    }
}

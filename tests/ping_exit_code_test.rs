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

//! Integration tests for the `bssh ping` exit code contract.
//!
//! Two layers are covered:
//!
//! 1. Contract tests over `PingOutcome`, which is the value `main` hands to
//!    `std::process::exit`. These follow the style of
//!    `tests/exit_code_integration_test.rs` and pin all three cases: 0, 1, 255.
//! 2. Process-level tests that run the real binary and assert the observed exit
//!    status. These cover every case reachable without a live SSH endpoint: all
//!    hosts unreachable, and the pre-connection failures (configuration load
//!    failure, no host resolved). The 0 and 1 cases need a host that actually
//!    accepts an SSH connection, so they are pinned at the `PingOutcome`
//!    boundary instead.

use std::path::Path;
use std::process::Command;

use anyhow::anyhow;
use bssh::commands::ping::{PING_SSH_LEVEL_FAILURE, PingOutcome};
use bssh::executor::{ExecutionResult, ExitCodeStrategy};
use bssh::node::Node;
use bssh::ssh::client::CommandResult;
use tempfile::NamedTempFile;

/// A host that connected and authenticated.
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

/// A host that could not be reached.
fn unreachable(host: &str) -> ExecutionResult {
    ExecutionResult {
        node: Node::new(host.to_string(), 22, "user".to_string()),
        result: Err(anyhow!("Connection refused")),
        is_main_rank: false,
    }
}

#[test]
fn all_hosts_reachable_yields_exit_code_0() {
    let outcome =
        PingOutcome::from_results(&[reachable("host1"), reachable("host2"), reachable("host3")]);

    assert_eq!(outcome.exit_code(), 0, "every host answered");
}

#[test]
fn partial_failure_yields_exit_code_1() {
    let outcome =
        PingOutcome::from_results(&[reachable("host1"), unreachable("host2"), reachable("host3")]);

    assert_eq!(
        outcome.exit_code(),
        1,
        "a partially degraded cluster is exit code 1"
    );
    assert_eq!(
        outcome.exit_code(),
        ExitCodeStrategy::RequireAllSuccess.calculate(
            &[reachable("host1"), unreachable("host2"), reachable("host3")],
            None
        ),
        "the 0/1 boundary must stay aligned with RequireAllSuccess"
    );
}

#[test]
fn total_failure_yields_exit_code_255() {
    let outcome = PingOutcome::from_results(&[unreachable("host1"), unreachable("host2")]);

    assert_eq!(
        outcome.exit_code(),
        PING_SSH_LEVEL_FAILURE,
        "no host answered, so bssh itself failed"
    );
}

#[test]
fn empty_host_list_yields_exit_code_255() {
    let outcome = PingOutcome::from_results(&[]);

    assert_eq!(outcome.exit_code(), PING_SSH_LEVEL_FAILURE);
}

/// Build a `bssh` invocation isolated from the developer's environment: no SSH
/// agent, no `~/.ssh/config`, no Backend.AI cluster variables.
fn bssh() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bssh"));
    cmd.env_remove("SSH_AUTH_SOCK")
        .env_remove("BACKENDAI_CLUSTER_HOSTS")
        .env_remove("BACKENDAI_CLUSTER_HOST")
        .env_remove("BACKENDAI_CLUSTER_ROLE")
        .args(["--ssh-config", "/dev/null"]);
    cmd
}

/// A config file with no clusters, so the run depends only on `-H`.
fn empty_config() -> NamedTempFile {
    let file = NamedTempFile::new().expect("failed to create temporary config file");
    std::fs::write(file.path(), "clusters: {}\n").expect("failed to write temporary config file");
    file
}

/// Run `bssh` to completion and return its exit code.
fn run(args: &[&str], config: Option<&Path>) -> i32 {
    let mut cmd = bssh();
    if let Some(path) = config {
        cmd.arg("--config").arg(path);
    }
    let output = cmd.args(args).output().expect("failed to run bssh");

    output
        .status
        .code()
        .unwrap_or_else(|| panic!("bssh was terminated by a signal: {:?}", output.status))
}

#[test]
fn ping_with_no_reachable_host_exits_255() {
    let config = empty_config();
    let code = run(
        &[
            "--connect-timeout",
            "2",
            "-H",
            // RFC 2606 reserves .invalid, so this never resolves.
            "bssh-unreachable-host.invalid",
            "ping",
        ],
        Some(config.path()),
    );

    assert_eq!(
        code, PING_SSH_LEVEL_FAILURE,
        "ping must report 255 when no host answered"
    );
}

#[test]
fn ping_with_unloadable_config_exits_255() {
    let code = run(
        &[
            "--config",
            "/nonexistent-directory-for-bssh-tests/config.yaml",
            "-H",
            "bssh-unreachable-host.invalid",
            "ping",
        ],
        None,
    );

    assert_eq!(
        code, PING_SSH_LEVEL_FAILURE,
        "a pre-connection failure must report 255, not 1"
    );
}

#[test]
fn ping_with_no_host_resolved_exits_255() {
    let config = empty_config();
    let code = run(
        &[
            "-H",
            "bssh-unreachable-host.invalid",
            "--filter",
            "no-such-host",
            "ping",
        ],
        Some(config.path()),
    );

    assert_eq!(
        code, PING_SSH_LEVEL_FAILURE,
        "resolving to zero hosts must report 255, not 1"
    );
}

#[test]
fn non_ping_subcommands_keep_the_generic_failure_exit_code() {
    // The 255 mapping is scoped to ping. Any other subcommand still exits 1 on
    // the same pre-connection failure.
    let code = run(
        &[
            "--config",
            "/nonexistent-directory-for-bssh-tests/config.yaml",
            "-H",
            "bssh-unreachable-host.invalid",
            "true",
        ],
        None,
    );

    assert_eq!(code, 1, "non-ping paths keep the generic exit code 1");
}

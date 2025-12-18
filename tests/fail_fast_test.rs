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

//! Tests for fail-fast (--fail-fast / -k) functionality.
//!
//! These tests verify the fail-fast execution mode that stops immediately
//! when any node fails (connection error or non-zero exit code).

use bssh::executor::{ExecutionResult, ParallelExecutor};
use bssh::node::Node;
use bssh::ssh::client::CommandResult;
use bssh::ssh::known_hosts::StrictHostKeyChecking;
use serial_test::serial;

/// Helper to create a success result
fn success_result(host: &str) -> ExecutionResult {
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

/// Helper to create a failure result with specific exit code
fn failure_result(host: &str, exit_code: u32) -> ExecutionResult {
    ExecutionResult {
        node: Node::new(host.to_string(), 22, "user".to_string()),
        result: Ok(CommandResult {
            host: host.to_string(),
            output: Vec::new(),
            stderr: Vec::new(),
            exit_status: exit_code,
        }),
        is_main_rank: false,
    }
}

/// Helper to create an error result (connection failure)
fn error_result(host: &str, error_msg: &str) -> ExecutionResult {
    ExecutionResult {
        node: Node::new(host.to_string(), 22, "user".to_string()),
        result: Err(anyhow::anyhow!("{}", error_msg)),
        is_main_rank: false,
    }
}

#[test]
#[serial]
fn test_fail_fast_builder_method() {
    // Test that the builder method can be called (compile-time check)
    // Note: fail_fast is pub(crate), so we can only verify the builder API works
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
    ];

    // Create executor without fail-fast (default)
    let _executor = ParallelExecutor::new(nodes.clone(), 10, None);

    // Create executor with fail-fast enabled
    let _executor = ParallelExecutor::new(nodes.clone(), 10, None).with_fail_fast(true);

    // Create executor with fail-fast disabled explicitly
    let _executor = ParallelExecutor::new(nodes, 10, None).with_fail_fast(false);

    // If we reach here, the builder API compiles correctly
}

#[test]
#[serial]
fn test_fail_fast_all_options_constructor() {
    // Test that all constructor variants can be chained with fail_fast
    let nodes = vec![Node::new("host1".to_string(), 22, "user".to_string())];

    // Test that with_fail_fast can be chained with any constructor
    let _executor = ParallelExecutor::new(nodes.clone(), 10, None).with_fail_fast(true);

    let _executor =
        ParallelExecutor::new_with_strict_mode(nodes.clone(), 10, None, StrictHostKeyChecking::Yes)
            .with_fail_fast(true);

    let _executor = ParallelExecutor::new_with_strict_mode_and_agent(
        nodes.clone(),
        10,
        None,
        StrictHostKeyChecking::Yes,
        true,
    )
    .with_fail_fast(true);

    let _executor = ParallelExecutor::new_with_all_options(
        nodes,
        10,
        None,
        StrictHostKeyChecking::Yes,
        true,
        false,
    )
    .with_fail_fast(true);

    // If we reach here, all constructors work with with_fail_fast()
}

#[test]
#[serial]
fn test_fail_fast_result_classification() {
    // Test that results are correctly classified as success/failure

    // Success case
    let result = success_result("host1");
    assert!(result.is_success(), "Exit code 0 should be success");

    // Non-zero exit code cases
    let result = failure_result("host1", 1);
    assert!(!result.is_success(), "Exit code 1 should be failure");

    let result = failure_result("host1", 137);
    assert!(
        !result.is_success(),
        "Exit code 137 (OOM) should be failure"
    );

    let result = failure_result("host1", 139);
    assert!(
        !result.is_success(),
        "Exit code 139 (SIGSEGV) should be failure"
    );

    // Connection error case
    let result = error_result("host1", "Connection refused");
    assert!(
        !result.is_success(),
        "Connection error should be classified as failure"
    );
}

#[test]
#[serial]
fn test_fail_fast_exit_code_extraction() {
    // Test exit code extraction from results

    let result = success_result("host1");
    assert_eq!(
        result.get_exit_code(),
        0,
        "Success should return exit code 0"
    );

    let result = failure_result("host1", 42);
    assert_eq!(result.get_exit_code(), 42, "Should return actual exit code");

    let result = error_result("host1", "Connection error");
    assert_eq!(
        result.get_exit_code(),
        1,
        "Connection error should return exit code 1"
    );
}

#[test]
#[serial]
fn test_fail_fast_with_require_all_success_interaction() {
    // Test that fail-fast can be combined with require_all_success
    // They complement each other: fail-fast stops early, require_all_success affects exit code

    // Scenario: fail-fast stops on first failure, but final exit code is determined by strategy
    let results = [
        success_result("host1"),
        failure_result("host2", 1),
        // host3 would be cancelled by fail-fast
        error_result("host3", "Execution cancelled due to fail-fast"),
    ];

    // All three should be considered for final exit code determination
    let has_any_failure = results.iter().any(|r| !r.is_success());
    assert!(
        has_any_failure,
        "Should detect failure in results even with cancelled tasks"
    );
}

#[test]
#[serial]
fn test_cancellation_error_message() {
    // Verify the specific error message for cancelled tasks
    let result = error_result("host1", "Execution cancelled due to fail-fast");

    // Check that the error message is preserved
    if let Err(e) = &result.result {
        let msg = format!("{}", e);
        assert!(
            msg.contains("fail-fast"),
            "Cancellation error should mention fail-fast: {msg}"
        );
    } else {
        panic!("Expected error result for cancelled task");
    }
}

/// Test that the --fail-fast flag is correctly parsed
#[test]
#[serial]
fn test_cli_fail_fast_flag_parsing() {
    use bssh::cli::Cli;
    use clap::Parser;

    // Test short form -k
    let args = ["bssh", "-H", "host1,host2", "-k", "echo test"];
    let cli = Cli::try_parse_from(args).expect("Should parse with -k flag");
    assert!(cli.fail_fast, "Short flag -k should set fail_fast=true");

    // Test long form --fail-fast
    let args = ["bssh", "-H", "host1,host2", "--fail-fast", "echo test"];
    let cli = Cli::try_parse_from(args).expect("Should parse with --fail-fast flag");
    assert!(
        cli.fail_fast,
        "Long flag --fail-fast should set fail_fast=true"
    );

    // Test without flag (default)
    let args = ["bssh", "-H", "host1,host2", "echo test"];
    let cli = Cli::try_parse_from(args).expect("Should parse without fail-fast flag");
    assert!(!cli.fail_fast, "Default should be fail_fast=false");
}

/// Test that fail-fast works with different parallelism settings
#[test]
#[serial]
fn test_fail_fast_with_parallelism() {
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
        Node::new("host3".to_string(), 22, "user".to_string()),
        Node::new("host4".to_string(), 22, "user".to_string()),
        Node::new("host5".to_string(), 22, "user".to_string()),
    ];

    // Test with high parallelism (all tasks start immediately)
    let _executor = ParallelExecutor::new(nodes.clone(), 10, None).with_fail_fast(true);

    // Test with low parallelism (some tasks wait in queue)
    let _executor = ParallelExecutor::new(nodes.clone(), 2, None).with_fail_fast(true);

    // Test with parallelism of 1 (sequential)
    let _executor = ParallelExecutor::new(nodes, 1, None).with_fail_fast(true);

    // If we reach here, fail_fast can be combined with any parallelism setting
}

/// Test fail-fast interaction with other flags
#[test]
#[serial]
fn test_fail_fast_flag_combinations() {
    use bssh::cli::Cli;
    use clap::Parser;

    // fail-fast + require-all-success
    let args = [
        "bssh",
        "-H",
        "host1,host2",
        "--fail-fast",
        "--require-all-success",
        "echo test",
    ];
    let cli = Cli::try_parse_from(args).expect("Should parse with both flags");
    assert!(cli.fail_fast);
    assert!(cli.require_all_success);

    // fail-fast + check-all-nodes
    let args = [
        "bssh",
        "-H",
        "host1,host2",
        "--fail-fast",
        "--check-all-nodes",
        "echo test",
    ];
    let cli = Cli::try_parse_from(args).expect("Should parse with fail-fast and check-all-nodes");
    assert!(cli.fail_fast);
    assert!(cli.check_all_nodes);

    // fail-fast + verbose
    let args = ["bssh", "-H", "host1,host2", "-k", "-v", "echo test"];
    let cli = Cli::try_parse_from(args).expect("Should parse with fail-fast and verbose");
    assert!(cli.fail_fast);
    assert_eq!(cli.verbose, 1);

    // fail-fast + timeout
    let args = [
        "bssh",
        "-H",
        "host1,host2",
        "-k",
        "--timeout",
        "60",
        "echo test",
    ];
    let cli = Cli::try_parse_from(args).expect("Should parse with fail-fast and timeout");
    assert!(cli.fail_fast);
    assert_eq!(cli.timeout, Some(60));
}

/// Test that -k doesn't conflict with existing short options
#[test]
#[serial]
fn test_k_flag_no_conflict() {
    use bssh::cli::Cli;
    use clap::Parser;

    // Verify -k is distinct from other flags
    // The -k flag is now assigned to fail-fast (pdsh compatibility)

    let args = ["bssh", "-H", "host1", "-k", "uptime"];
    let result = Cli::try_parse_from(args);
    assert!(result.is_ok(), "-k should be a valid flag");

    let cli = result.unwrap();
    assert!(cli.fail_fast, "-k should set fail_fast=true");
}

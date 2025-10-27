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

//! Integration tests for exit code strategy functionality.
//!
//! These tests verify the end-to-end behavior of exit code handling,
//! including rank detection and strategy application.

use bssh::executor::{ExecutionResult, ExitCodeStrategy, RankDetector};
use bssh::node::Node;
use bssh::ssh::client::CommandResult;

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

#[test]
fn test_main_rank_strategy_preserves_exit_code() {
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
        Node::new("host3".to_string(), 22, "user".to_string()),
    ];

    // Simulate SIGSEGV on main rank
    let results = vec![
        failure_result("host1", 139), // Main rank - SIGSEGV
        success_result("host2"),
        success_result("host3"),
    ];

    let main_idx = RankDetector::identify_main_rank(&nodes);
    let exit_code = ExitCodeStrategy::MainRank.calculate(&results, main_idx);

    assert_eq!(exit_code, 139, "Should preserve SIGSEGV exit code");
}

#[test]
fn test_require_all_success_any_failure() {
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
    ];

    // One node fails
    let results = vec![success_result("host1"), failure_result("host2", 137)];

    let main_idx = RankDetector::identify_main_rank(&nodes);
    let exit_code = ExitCodeStrategy::RequireAllSuccess.calculate(&results, main_idx);

    assert_eq!(exit_code, 1, "Should return 1 when any node fails");
}

#[test]
fn test_hybrid_strategy_main_ok_others_fail() {
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
        Node::new("host3".to_string(), 22, "user".to_string()),
    ];

    // Main succeeds, others fail
    let results = vec![
        success_result("host1"), // Main rank
        failure_result("host2", 1),
        failure_result("host3", 1),
    ];

    let main_idx = RankDetector::identify_main_rank(&nodes);
    let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, main_idx);

    assert_eq!(
        exit_code, 1,
        "Should return 1 when main succeeds but others fail"
    );
}

#[test]
fn test_hybrid_strategy_main_fails() {
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
    ];

    // Main fails with timeout
    let results = vec![
        failure_result("host1", 124), // Main rank - timeout
        success_result("host2"),
    ];

    let main_idx = RankDetector::identify_main_rank(&nodes);
    let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, main_idx);

    assert_eq!(exit_code, 124, "Should preserve main rank exit code");
}

#[test]
fn test_backendai_main_rank_detection() {
    // Set Backend.AI environment
    std::env::set_var("BACKENDAI_CLUSTER_ROLE", "main");
    std::env::set_var("BACKENDAI_CLUSTER_HOST", "host2");

    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()), // This should be main
        Node::new("host3".to_string(), 22, "user".to_string()),
    ];

    let main_idx = RankDetector::identify_main_rank(&nodes);
    assert_eq!(
        main_idx,
        Some(1),
        "Should detect host2 as main rank via Backend.AI env"
    );

    // Cleanup
    std::env::remove_var("BACKENDAI_CLUSTER_ROLE");
    std::env::remove_var("BACKENDAI_CLUSTER_HOST");
}

#[test]
fn test_exit_code_strategy_comprehensive() {
    // Test matrix covering all strategies and scenarios
    let test_cases = vec![
        // (strategy, main_ok, others_ok, expected_main_exit, expected_result)
        (ExitCodeStrategy::MainRank, true, true, 0, 0),
        (ExitCodeStrategy::MainRank, false, true, 139, 139),
        (ExitCodeStrategy::MainRank, true, false, 0, 0), // Main OK → 0
        (ExitCodeStrategy::MainRank, false, false, 137, 137),
        (ExitCodeStrategy::RequireAllSuccess, true, true, 0, 0),
        (ExitCodeStrategy::RequireAllSuccess, false, true, 139, 1),
        (ExitCodeStrategy::RequireAllSuccess, true, false, 0, 1),
        (ExitCodeStrategy::RequireAllSuccess, false, false, 137, 1),
        (ExitCodeStrategy::MainRankWithFailureCheck, true, true, 0, 0),
        (
            ExitCodeStrategy::MainRankWithFailureCheck,
            false,
            true,
            139,
            139,
        ),
        (
            ExitCodeStrategy::MainRankWithFailureCheck,
            true,
            false,
            0,
            1,
        ), // Hybrid
        (
            ExitCodeStrategy::MainRankWithFailureCheck,
            false,
            false,
            137,
            137,
        ),
    ];

    for (strategy, main_ok, others_ok, main_exit, expected) in test_cases {
        let nodes = vec![
            Node::new("host1".to_string(), 22, "user".to_string()),
            Node::new("host2".to_string(), 22, "user".to_string()),
        ];

        let results = vec![
            if main_ok {
                success_result("host1")
            } else {
                failure_result("host1", main_exit)
            },
            if others_ok {
                success_result("host2")
            } else {
                failure_result("host2", 1)
            },
        ];

        let main_idx = RankDetector::identify_main_rank(&nodes);
        let exit_code = strategy.calculate(&results, main_idx);

        assert_eq!(
            exit_code, expected,
            "Strategy {:?}: main_ok={}, others_ok={}, main_exit={} → expected {}",
            strategy, main_ok, others_ok, main_exit, expected
        );
    }
}

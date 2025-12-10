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

#[test]
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
            "Strategy {strategy:?}: main_ok={main_ok}, others_ok={others_ok}, main_exit={main_exit} → expected {expected}"
        );
    }
}

#[test]
#[serial]
fn test_main_rank_marking_in_results() {
    // Verify that main rank is properly identified and marked in results
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
        Node::new("host3".to_string(), 22, "user".to_string()),
    ];

    let mut results = [
        success_result("host1"),
        success_result("host2"),
        success_result("host3"),
    ];

    // Simulate marking by rank detector
    let main_idx = RankDetector::identify_main_rank(&nodes);
    assert_eq!(
        main_idx,
        Some(0),
        "First node should be main rank by default"
    );

    // Mark the main rank (this is what parallel executor does)
    if let Some(idx) = main_idx {
        results[idx].is_main_rank = true;
    }

    // Verify marking
    assert!(
        results[0].is_main_rank,
        "First result should be marked as main rank"
    );
    assert!(
        !results[1].is_main_rank,
        "Second result should not be main rank"
    );
    assert!(
        !results[2].is_main_rank,
        "Third result should not be main rank"
    );
}

#[test]
#[serial]
fn test_main_rank_marking_with_backendai_env() {
    // Test that Backend.AI environment affects rank marking
    std::env::set_var("BACKENDAI_CLUSTER_ROLE", "main");
    std::env::set_var("BACKENDAI_CLUSTER_HOST", "host3");

    let nodes = vec![
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
        Node::new("host3".to_string(), 22, "user".to_string()),
    ];

    let mut results = [
        success_result("host1"),
        success_result("host2"),
        success_result("host3"),
    ];

    // Identify main rank with Backend.AI env
    let main_idx = RankDetector::identify_main_rank(&nodes);
    assert_eq!(
        main_idx,
        Some(2),
        "host3 should be identified as main rank via Backend.AI env"
    );

    // Mark the main rank
    if let Some(idx) = main_idx {
        results[idx].is_main_rank = true;
    }

    // Verify marking
    assert!(
        !results[0].is_main_rank,
        "host1 should not be marked as main rank"
    );
    assert!(
        !results[1].is_main_rank,
        "host2 should not be marked as main rank"
    );
    assert!(
        results[2].is_main_rank,
        "host3 should be marked as main rank"
    );

    // Cleanup
    std::env::remove_var("BACKENDAI_CLUSTER_ROLE");
    std::env::remove_var("BACKENDAI_CLUSTER_HOST");
}

#[test]
#[serial]
fn test_strategy_with_all_connection_errors() {
    use anyhow::anyhow;

    let nodes = [
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
    ];

    // All nodes have connection errors
    let results = vec![
        ExecutionResult {
            node: nodes[0].clone(),
            result: Err(anyhow!("Connection timeout")),
            is_main_rank: true, // Main rank has error
        },
        ExecutionResult {
            node: nodes[1].clone(),
            result: Err(anyhow!("Connection refused")),
            is_main_rank: false,
        },
    ];

    let main_idx = Some(0);

    // MainRank strategy should return 1 (connection error treated as exit 1)
    let exit_code = ExitCodeStrategy::MainRank.calculate(&results, main_idx);
    assert_eq!(exit_code, 1, "Connection error should return exit code 1");

    // RequireAllSuccess should also return 1
    let exit_code = ExitCodeStrategy::RequireAllSuccess.calculate(&results, main_idx);
    assert_eq!(
        exit_code, 1,
        "Any failure should return 1 in RequireAllSuccess"
    );

    // Hybrid strategy should return 0 for main rank (error treated as non-zero) or 1
    let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, main_idx);
    assert_eq!(
        exit_code, 1,
        "Main rank connection error should return 1 in hybrid mode"
    );
}

#[test]
#[serial]
fn test_strategy_with_mixed_errors() {
    use anyhow::anyhow;

    let nodes = [
        Node::new("host1".to_string(), 22, "user".to_string()),
        Node::new("host2".to_string(), 22, "user".to_string()),
        Node::new("host3".to_string(), 22, "user".to_string()),
    ];

    // Mixed: success, connection error, exit code failure
    let results = vec![
        success_result("host1"), // Main rank succeeds
        ExecutionResult {
            node: nodes[1].clone(),
            result: Err(anyhow!("Connection timeout")), // Connection error
            is_main_rank: false,
        },
        failure_result("host3", 137), // OOM kill
    ];

    let main_idx = Some(0);

    // MainRank: should return 0 (main succeeded)
    let exit_code = ExitCodeStrategy::MainRank.calculate(&results, main_idx);
    assert_eq!(exit_code, 0, "Main rank succeeded, should return 0");

    // RequireAllSuccess: should return 1 (some nodes failed)
    let exit_code = ExitCodeStrategy::RequireAllSuccess.calculate(&results, main_idx);
    assert_eq!(
        exit_code, 1,
        "Some nodes failed, should return 1 in RequireAllSuccess"
    );

    // Hybrid: should return 1 (main OK but others failed)
    let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, main_idx);
    assert_eq!(
        exit_code, 1,
        "Main OK but others failed, should return 1 in hybrid mode"
    );
}

#[test]
#[serial]
fn test_main_rank_index_boundary() {
    // Test with main rank at last position
    let results = vec![
        success_result("host1"),
        failure_result("host2", 1),
        failure_result("host3", 139), // Main rank at index 2
    ];

    let main_idx = Some(2); // Last node is main

    let exit_code = ExitCodeStrategy::MainRank.calculate(&results, main_idx);
    assert_eq!(
        exit_code, 139,
        "Should return exit code from last node (main rank)"
    );
}

#[test]
#[serial]
fn test_strategy_selection_logic() {
    // This tests the logic that would be in exec.rs for selecting strategy based on flags
    // Simulating the flag combinations:

    // Default: neither flag set
    let require_all_success = false;
    let check_all_nodes = false;
    let strategy = if require_all_success {
        ExitCodeStrategy::RequireAllSuccess
    } else if check_all_nodes {
        ExitCodeStrategy::MainRankWithFailureCheck
    } else {
        ExitCodeStrategy::MainRank
    };
    assert_eq!(
        strategy,
        ExitCodeStrategy::MainRank,
        "Default should be MainRank"
    );

    // --require-all-success flag
    let require_all_success = true;
    let check_all_nodes = false;
    let strategy = if require_all_success {
        ExitCodeStrategy::RequireAllSuccess
    } else if check_all_nodes {
        ExitCodeStrategy::MainRankWithFailureCheck
    } else {
        ExitCodeStrategy::MainRank
    };
    assert_eq!(
        strategy,
        ExitCodeStrategy::RequireAllSuccess,
        "--require-all-success should select RequireAllSuccess"
    );

    // --check-all-nodes flag
    let require_all_success = false;
    let check_all_nodes = true;
    let strategy = if require_all_success {
        ExitCodeStrategy::RequireAllSuccess
    } else if check_all_nodes {
        ExitCodeStrategy::MainRankWithFailureCheck
    } else {
        ExitCodeStrategy::MainRank
    };
    assert_eq!(
        strategy,
        ExitCodeStrategy::MainRankWithFailureCheck,
        "--check-all-nodes should select MainRankWithFailureCheck"
    );

    // Both flags set: --require-all-success takes precedence
    let require_all_success = true;
    let check_all_nodes = true;
    let strategy = if require_all_success {
        ExitCodeStrategy::RequireAllSuccess
    } else if check_all_nodes {
        ExitCodeStrategy::MainRankWithFailureCheck
    } else {
        ExitCodeStrategy::MainRank
    };
    assert_eq!(
        strategy,
        ExitCodeStrategy::RequireAllSuccess,
        "When both flags set, --require-all-success should take precedence"
    );
}

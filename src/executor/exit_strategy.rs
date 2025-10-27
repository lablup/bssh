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

//! Exit code calculation strategies for distributed execution.
//!
//! This module defines how bssh determines the final exit code when executing
//! commands across multiple nodes. Different strategies are appropriate for
//! different use cases:
//!
//! - **MainRank** (default): Returns the main rank's exit code, matching standard
//!   MPI tools (mpirun, srun, mpiexec). Best for MPI workloads and CI/CD integration.
//!
//! - **RequireAllSuccess**: Returns 0 only if all nodes succeeded, 1 otherwise.
//!   This was the default behavior in v1.0-v1.1. Best for health checks and
//!   monitoring where all nodes must be operational.
//!
//! - **MainRankWithFailureCheck**: Returns the main rank's exit code if it's
//!   non-zero, or 1 if the main rank succeeded but other nodes failed. Hybrid
//!   approach that preserves error diagnostics while ensuring failures are noticed.

use crate::executor::result_types::ExecutionResult;

/// Strategy for calculating the final exit code from multiple node results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCodeStrategy {
    /// Return main rank's exit code (DEFAULT in v1.2+).
    ///
    /// Matches standard MPI tools: mpirun, srun, mpiexec.
    /// Preserves actual exit codes (139=SIGSEGV, 137=OOM, etc.) for diagnostics.
    ///
    /// # Use Cases
    /// - MPI workloads and distributed computing
    /// - CI/CD pipelines requiring exit code inspection
    /// - Shell scripts with error handling logic
    /// - When debugging requires specific exit codes
    MainRank,

    /// Return 0 only if ALL nodes succeeded (v1.0-v1.1 behavior).
    ///
    /// Returns exit code 1 if any node failed, regardless of the specific error.
    /// Useful when all nodes must be operational.
    ///
    /// # Use Cases
    /// - Health checks and monitoring
    /// - Cluster validation
    /// - When any failure should be treated equally
    RequireAllSuccess,

    /// Hybrid: Return main rank exit code if non-zero, or 1 if main OK but others failed.
    ///
    /// Combines the diagnostic benefits of MainRank with the safety of RequireAllSuccess.
    ///
    /// # Use Cases
    /// - When you need detailed error codes but also want to catch failures on any node
    /// - Production deployments where both diagnostics and completeness matter
    MainRankWithFailureCheck,
}

impl ExitCodeStrategy {
    /// Calculate the final exit code based on the strategy.
    ///
    /// # Arguments
    /// * `results` - Execution results from all nodes
    /// * `main_idx` - Index of the main rank node (if known)
    ///
    /// # Returns
    /// The exit code to be returned by the bssh process
    ///
    /// # Examples
    /// ```
    /// use bssh::executor::exit_strategy::ExitCodeStrategy;
    /// // See tests for usage examples
    /// ```
    pub fn calculate(&self, results: &[ExecutionResult], main_idx: Option<usize>) -> i32 {
        match self {
            Self::MainRank => {
                // Return main rank's exit code
                main_idx
                    .and_then(|i| results.get(i))
                    .map(|r| r.get_exit_code())
                    .unwrap_or(1) // If no main rank identified, return failure
            }

            Self::RequireAllSuccess => {
                // Old behavior: any failure → 1
                if results.iter().any(|r| !r.is_success()) {
                    1
                } else {
                    0
                }
            }

            Self::MainRankWithFailureCheck => {
                // Get main rank's exit code
                let main_code = main_idx
                    .and_then(|i| results.get(i))
                    .map(|r| r.get_exit_code())
                    .unwrap_or(0);

                // Check if any other node failed
                let other_failed = results
                    .iter()
                    .enumerate()
                    .any(|(i, r)| Some(i) != main_idx && !r.is_success());

                if main_code != 0 {
                    main_code // Main failed → return its code
                } else if other_failed {
                    1 // Main OK but others failed → 1
                } else {
                    0 // All OK
                }
            }
        }
    }
}

impl Default for ExitCodeStrategy {
    /// Default strategy is MainRank (v1.2.0+).
    ///
    /// This matches standard MPI tool behavior and provides better diagnostics.
    fn default() -> Self {
        Self::MainRank
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use crate::ssh::client::CommandResult;
    use anyhow::anyhow;

    fn create_success_result(host: &str) -> ExecutionResult {
        ExecutionResult {
            node: Node::new(host.to_string(), 22, "user".to_string()),
            result: Ok(CommandResult {
                host: host.to_string(),
                output: Vec::new(),
                stderr: Vec::new(),
                exit_status: 0,
            }),
            is_main_rank: false, // Will be set by caller if needed
        }
    }

    fn create_failure_result(host: &str, exit_code: i32) -> ExecutionResult {
        ExecutionResult {
            node: Node::new(host.to_string(), 22, "user".to_string()),
            result: Ok(CommandResult {
                host: host.to_string(),
                output: Vec::new(),
                stderr: Vec::new(),
                exit_status: exit_code as u32,
            }),
            is_main_rank: false, // Will be set by caller if needed
        }
    }

    fn create_error_result(host: &str) -> ExecutionResult {
        ExecutionResult {
            node: Node::new(host.to_string(), 22, "user".to_string()),
            result: Err(anyhow!("Connection failed")),
            is_main_rank: false, // Will be set by caller if needed
        }
    }

    #[test]
    fn test_default_strategy_is_main_rank() {
        assert_eq!(ExitCodeStrategy::default(), ExitCodeStrategy::MainRank);
    }

    #[test]
    fn test_main_rank_all_success() {
        let results = vec![
            create_success_result("host1"),
            create_success_result("host2"),
            create_success_result("host3"),
        ];

        let exit_code = ExitCodeStrategy::MainRank.calculate(&results, Some(0));
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_main_rank_main_failed_with_segfault() {
        let results = vec![
            create_failure_result("host1", 139), // SIGSEGV
            create_success_result("host2"),
            create_success_result("host3"),
        ];

        let exit_code = ExitCodeStrategy::MainRank.calculate(&results, Some(0));
        assert_eq!(exit_code, 139); // Preserve actual exit code
    }

    #[test]
    fn test_main_rank_main_ok_other_failed() {
        let results = vec![
            create_success_result("host1"),
            create_failure_result("host2", 1),
            create_success_result("host3"),
        ];

        let exit_code = ExitCodeStrategy::MainRank.calculate(&results, Some(0));
        assert_eq!(exit_code, 0); // Main rank succeeded, that's what matters
    }

    #[test]
    fn test_main_rank_all_failed() {
        let results = vec![
            create_failure_result("host1", 137), // OOM
            create_failure_result("host2", 1),
            create_failure_result("host3", 1),
        ];

        let exit_code = ExitCodeStrategy::MainRank.calculate(&results, Some(0));
        assert_eq!(exit_code, 137); // Return main rank's specific exit code
    }

    #[test]
    fn test_main_rank_no_main_identified() {
        let results = vec![
            create_success_result("host1"),
            create_success_result("host2"),
        ];

        let exit_code = ExitCodeStrategy::MainRank.calculate(&results, None);
        assert_eq!(exit_code, 1); // No main rank → failure
    }

    #[test]
    fn test_main_rank_with_connection_error() {
        let results = vec![create_error_result("host1"), create_success_result("host2")];

        let exit_code = ExitCodeStrategy::MainRank.calculate(&results, Some(0));
        assert_eq!(exit_code, 1); // Connection error treated as exit code 1
    }

    #[test]
    fn test_require_all_success_all_ok() {
        let results = vec![
            create_success_result("host1"),
            create_success_result("host2"),
            create_success_result("host3"),
        ];

        let exit_code = ExitCodeStrategy::RequireAllSuccess.calculate(&results, Some(0));
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_require_all_success_one_failed() {
        let results = vec![
            create_success_result("host1"),
            create_failure_result("host2", 139), // Specific exit code doesn't matter
            create_success_result("host3"),
        ];

        let exit_code = ExitCodeStrategy::RequireAllSuccess.calculate(&results, Some(0));
        assert_eq!(exit_code, 1); // Any failure → 1
    }

    #[test]
    fn test_require_all_success_all_failed() {
        let results = vec![
            create_failure_result("host1", 139),
            create_failure_result("host2", 137),
            create_failure_result("host3", 1),
        ];

        let exit_code = ExitCodeStrategy::RequireAllSuccess.calculate(&results, Some(0));
        assert_eq!(exit_code, 1);
    }

    #[test]
    fn test_require_all_success_with_error() {
        let results = vec![create_success_result("host1"), create_error_result("host2")];

        let exit_code = ExitCodeStrategy::RequireAllSuccess.calculate(&results, Some(0));
        assert_eq!(exit_code, 1);
    }

    #[test]
    fn test_hybrid_all_success() {
        let results = vec![
            create_success_result("host1"),
            create_success_result("host2"),
            create_success_result("host3"),
        ];

        let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, Some(0));
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_hybrid_main_failed() {
        let results = vec![
            create_failure_result("host1", 139),
            create_success_result("host2"),
            create_success_result("host3"),
        ];

        let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, Some(0));
        assert_eq!(exit_code, 139); // Return main's specific exit code
    }

    #[test]
    fn test_hybrid_main_ok_other_failed() {
        let results = vec![
            create_success_result("host1"),
            create_failure_result("host2", 137),
            create_success_result("host3"),
        ];

        let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, Some(0));
        assert_eq!(exit_code, 1); // Main OK but others failed → 1
    }

    #[test]
    fn test_hybrid_all_failed() {
        let results = vec![
            create_failure_result("host1", 139),
            create_failure_result("host2", 137),
            create_failure_result("host3", 1),
        ];

        let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, Some(0));
        assert_eq!(exit_code, 139); // Main's exit code takes precedence
    }

    #[test]
    fn test_hybrid_no_main_all_ok() {
        let results = vec![
            create_success_result("host1"),
            create_success_result("host2"),
        ];

        let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, None);
        assert_eq!(exit_code, 0); // No main rank but all succeeded
    }

    #[test]
    fn test_hybrid_no_main_with_failures() {
        let results = vec![
            create_success_result("host1"),
            create_failure_result("host2", 1),
        ];

        let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, None);
        assert_eq!(exit_code, 1); // No main rank + failures → 1
    }

    #[test]
    fn test_main_rank_non_zero_index() {
        let results = vec![
            create_success_result("host1"),
            create_failure_result("host2", 124), // Timeout
            create_success_result("host3"),
        ];

        // host2 (index 1) is main rank
        let exit_code = ExitCodeStrategy::MainRank.calculate(&results, Some(1));
        assert_eq!(exit_code, 124);
    }

    #[test]
    fn test_empty_results() {
        let results: Vec<ExecutionResult> = vec![];

        // MainRank with no results
        let exit_code = ExitCodeStrategy::MainRank.calculate(&results, None);
        assert_eq!(exit_code, 1);

        // RequireAllSuccess with no results (vacuous truth)
        let exit_code = ExitCodeStrategy::RequireAllSuccess.calculate(&results, None);
        assert_eq!(exit_code, 0);

        // Hybrid with no results
        let exit_code = ExitCodeStrategy::MainRankWithFailureCheck.calculate(&results, None);
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_large_exit_code() {
        // Test with exit code that would overflow i32 if not handled properly
        let large_exit_code = u32::MAX; // 4294967295
        let results = vec![ExecutionResult {
            node: Node::new("host1".to_string(), 22, "user".to_string()),
            result: Ok(CommandResult {
                host: "host1".to_string(),
                output: Vec::new(),
                stderr: Vec::new(),
                exit_status: large_exit_code,
            }),
            is_main_rank: true,
        }];

        // Should handle large exit codes without panic
        let exit_code = ExitCodeStrategy::MainRank.calculate(&results, Some(0));
        assert_eq!(exit_code, i32::MAX); // Should be clamped to i32::MAX
    }
}

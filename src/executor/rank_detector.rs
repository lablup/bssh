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

//! Main rank detection for distributed execution.
//!
//! In distributed computing environments (MPI, HPC clusters), the "main rank" or "rank 0"
//! is the primary node that coordinates execution. This module provides functionality
//! to identify the main rank node using hierarchical detection:
//!
//! 1. Backend.AI environment variables (BACKENDAI_CLUSTER_ROLE=main)
//! 2. Backend.AI hostname matching (BACKENDAI_CLUSTER_HOST)
//! 3. Fallback to first node in the list
//!
//! This enables bssh to align with standard MPI tools (mpirun, srun, mpiexec) by
//! returning the main rank's exit code by default.

use crate::node::Node;
use std::env;

/// Detector for identifying the main rank in a cluster.
pub struct RankDetector;

impl RankDetector {
    /// Identify the main rank index in the nodes array.
    ///
    /// Uses hierarchical detection strategy:
    /// 1. Check if BACKENDAI_CLUSTER_ROLE=main (Backend.AI native)
    /// 2. Try to match BACKENDAI_CLUSTER_HOST with node list
    /// 3. Fallback to first node (index 0) if nodes exist
    ///
    /// # Arguments
    /// * `nodes` - Array of nodes to search
    ///
    /// # Returns
    /// * `Some(index)` - Index of the main rank node
    /// * `None` - If nodes array is empty
    ///
    /// # Examples
    /// ```
    /// use bssh::node::Node;
    /// use bssh::executor::rank_detector::RankDetector;
    ///
    /// let nodes = vec![
    ///     Node::new("host1".to_string(), 22, "user".to_string()),
    ///     Node::new("host2".to_string(), 22, "user".to_string()),
    /// ];
    ///
    /// let main_idx = RankDetector::identify_main_rank(&nodes);
    /// assert!(main_idx.is_some());
    /// ```
    pub fn identify_main_rank(nodes: &[Node]) -> Option<usize> {
        // Empty nodes array - no main rank
        if nodes.is_empty() {
            return None;
        }

        // 1. Check Backend.AI CLUSTER_ROLE environment variable
        if Self::is_backendai_main() {
            // Try to match by hostname
            if let Some(host) = Self::get_backendai_host() {
                // Find node matching the Backend.AI host
                if let Some(idx) = nodes.iter().position(|n| n.host == host) {
                    return Some(idx);
                }
            }
        }

        // 2. Fallback: First node is main rank (standard convention)
        Some(0)
    }

    /// Check if current environment indicates this is the main rank in Backend.AI.
    ///
    /// Returns true if BACKENDAI_CLUSTER_ROLE environment variable is set to "main".
    fn is_backendai_main() -> bool {
        env::var("BACKENDAI_CLUSTER_ROLE")
            .ok()
            .map(|role| role.to_lowercase() == "main")
            .unwrap_or(false)
    }

    /// Get the Backend.AI cluster host from environment.
    ///
    /// Returns the value of BACKENDAI_CLUSTER_HOST if set.
    fn get_backendai_host() -> Option<String> {
        env::var("BACKENDAI_CLUSTER_HOST").ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_nodes_returns_none() {
        let nodes: Vec<Node> = vec![];
        assert_eq!(RankDetector::identify_main_rank(&nodes), None);
    }

    #[test]
    fn test_fallback_to_first_node() {
        let nodes = vec![
            Node::new("host1".to_string(), 22, "user".to_string()),
            Node::new("host2".to_string(), 22, "user".to_string()),
            Node::new("host3".to_string(), 22, "user".to_string()),
        ];

        // Without Backend.AI env vars, should return first node
        assert_eq!(RankDetector::identify_main_rank(&nodes), Some(0));
    }

    #[test]
    fn test_backendai_role_detection() {
        // Set environment variable
        env::set_var("BACKENDAI_CLUSTER_ROLE", "main");

        assert!(RankDetector::is_backendai_main());

        // Cleanup
        env::remove_var("BACKENDAI_CLUSTER_ROLE");
    }

    #[test]
    fn test_backendai_role_case_insensitive() {
        env::set_var("BACKENDAI_CLUSTER_ROLE", "MAIN");
        assert!(RankDetector::is_backendai_main());

        env::set_var("BACKENDAI_CLUSTER_ROLE", "Main");
        assert!(RankDetector::is_backendai_main());

        // Cleanup
        env::remove_var("BACKENDAI_CLUSTER_ROLE");
    }

    #[test]
    fn test_backendai_role_non_main() {
        env::set_var("BACKENDAI_CLUSTER_ROLE", "sub");
        assert!(!RankDetector::is_backendai_main());

        // Cleanup
        env::remove_var("BACKENDAI_CLUSTER_ROLE");
    }

    #[test]
    fn test_backendai_host_matching() {
        let nodes = vec![
            Node::new("host1".to_string(), 22, "user".to_string()),
            Node::new("host2".to_string(), 22, "user".to_string()),
            Node::new("host3".to_string(), 22, "user".to_string()),
        ];

        // Set Backend.AI environment
        env::set_var("BACKENDAI_CLUSTER_ROLE", "main");
        env::set_var("BACKENDAI_CLUSTER_HOST", "host2");

        // Should find host2 at index 1
        assert_eq!(RankDetector::identify_main_rank(&nodes), Some(1));

        // Cleanup
        env::remove_var("BACKENDAI_CLUSTER_ROLE");
        env::remove_var("BACKENDAI_CLUSTER_HOST");
    }

    #[test]
    fn test_backendai_host_not_found_fallback() {
        let nodes = vec![
            Node::new("host1".to_string(), 22, "user".to_string()),
            Node::new("host2".to_string(), 22, "user".to_string()),
        ];

        // Set Backend.AI environment with non-existent host
        env::set_var("BACKENDAI_CLUSTER_ROLE", "main");
        env::set_var("BACKENDAI_CLUSTER_HOST", "nonexistent");

        // Should fallback to first node
        assert_eq!(RankDetector::identify_main_rank(&nodes), Some(0));

        // Cleanup
        env::remove_var("BACKENDAI_CLUSTER_ROLE");
        env::remove_var("BACKENDAI_CLUSTER_HOST");
    }

    #[test]
    fn test_single_node() {
        let nodes = vec![Node::new("host1".to_string(), 22, "user".to_string())];

        assert_eq!(RankDetector::identify_main_rank(&nodes), Some(0));
    }
}

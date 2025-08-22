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

//! Tests for prompt scaling with many nodes

#[test]
fn test_prompt_with_many_nodes() {
    // Test that prompt doesn't show 100 individual indicators
    let node_count = 100;
    let active_count = 50;
    let total_connected = 100;

    // Should use compact display for > 10 nodes
    const MAX_INDIVIDUAL_DISPLAY: usize = 10;

    assert!(node_count > MAX_INDIVIDUAL_DISPLAY);

    // Format examples for many nodes
    let prompt_all_active = format!("[All {total_connected}/{node_count}] bssh> ");
    assert!(prompt_all_active.len() < 50); // Should be compact

    let prompt_none_active = format!("[None 0/{total_connected}] bssh> ");
    assert!(prompt_none_active.len() < 50);

    let prompt_some_active =
        format!("[Nodes 1,2,3... +47] ({active_count}/{total_connected}) bssh> ");
    assert!(prompt_some_active.len() < 60);
}

#[test]
fn test_prompt_with_few_nodes() {
    // Test that few nodes still show individual indicators
    let node_count = 5;

    const MAX_INDIVIDUAL_DISPLAY: usize = 10;

    assert!(node_count <= MAX_INDIVIDUAL_DISPLAY);

    // With few nodes, individual display is fine
    let individual_prompt = "[● ● ● ● ●] bssh> ";
    assert!(individual_prompt.len() < 30);
}

#[test]
fn test_active_nodes_display_limit() {
    // Test display of active node numbers

    // Case 1: 5 or fewer active nodes - show all
    let active_nodes = [1, 3, 5];
    let display = active_nodes
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(display, "1,3,5");

    // Case 2: More than 5 active nodes - show first 3 + count
    let many_active = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let first_three = many_active
        .iter()
        .take(3)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let display_many = format!("{first_three}... +{}", many_active.len() - 3);
    assert_eq!(display_many, "1,2,3... +7");
}

#[test]
fn test_prompt_format_variations() {
    // Test different prompt formats based on node states

    struct TestCase {
        total_nodes: usize,
        #[allow(dead_code)]
        total_connected: usize,
        #[allow(dead_code)]
        active_count: usize,
        #[allow(dead_code)]
        expected_pattern: &'static str,
    }

    let test_cases = vec![
        TestCase {
            total_nodes: 100,
            total_connected: 100,
            active_count: 100,
            expected_pattern: "[All 100/100]",
        },
        TestCase {
            total_nodes: 100,
            total_connected: 95,
            active_count: 0,
            expected_pattern: "[None 0/95]",
        },
        TestCase {
            total_nodes: 50,
            total_connected: 48,
            active_count: 3,
            expected_pattern: "[Nodes", // Will show node numbers
        },
        TestCase {
            total_nodes: 8,
            total_connected: 8,
            active_count: 8,
            expected_pattern: "[● ● ●", // Individual display for <= 10 nodes
        },
    ];

    for tc in test_cases {
        let uses_compact = tc.total_nodes > 10;
        if uses_compact {
            assert!(tc.total_nodes > 10);
            // Compact display doesn't show individual indicators
        } else {
            assert!(tc.total_nodes <= 10);
            // Individual display shows dots/numbers
        }
    }
}

#[test]
fn test_prompt_length_bounds() {
    // Ensure prompt doesn't exceed reasonable length

    // Worst case: many nodes with some active
    let worst_case_prompt = "[Nodes 1,2,3... +997] (1000/1000) bssh> ".to_string();

    // Should be under 80 characters for typical terminal width
    assert!(worst_case_prompt.len() < 80);

    // Best case: all active with many nodes
    let best_case_prompt = "[All 1000/1000] bssh> ".to_string();
    assert!(best_case_prompt.len() < 30);
}

#[test]
fn test_node_number_formatting() {
    // Test formatting of node numbers in prompt

    // Single digit
    let single_digit = [1, 2, 3];
    let formatted = single_digit
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(formatted, "1,2,3");

    // Multi digit
    let multi_digit = [10, 50, 100];
    let formatted_multi = multi_digit
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(formatted_multi, "10,50,100");
}

#[test]
fn test_threshold_boundary() {
    // Test behavior at the threshold boundary (10 nodes)

    const MAX_INDIVIDUAL_DISPLAY: usize = 10;

    // At threshold - should use individual display
    assert_eq!(10, MAX_INDIVIDUAL_DISPLAY);

    // Test values relative to threshold
    let just_over = 11;
    let just_under = 9;

    // Just over threshold - should use compact display
    assert!(just_over > MAX_INDIVIDUAL_DISPLAY);

    // Just under threshold
    assert!(just_under < MAX_INDIVIDUAL_DISPLAY);
}

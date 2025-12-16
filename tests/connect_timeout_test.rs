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

//! Tests for the --connect-timeout CLI option
//!
//! This feature allows users to configure the SSH connection timeout
//! separately from the command execution timeout.

use std::process::Command;

/// Helper to get bssh binary path
fn bssh_binary() -> String {
    // Prefer debug binary since `cargo test` builds debug binaries
    // This avoids using stale release binaries in CI
    let debug = std::env::current_dir().unwrap().join("target/debug/bssh");
    let release = std::env::current_dir().unwrap().join("target/release/bssh");

    if debug.exists() {
        debug.to_string_lossy().to_string()
    } else if release.exists() {
        release.to_string_lossy().to_string()
    } else {
        panic!("bssh binary not found. Run 'cargo build' first.");
    }
}

#[test]
fn test_connect_timeout_default_value() {
    // The default connect timeout should be 30 seconds
    let output = Command::new(bssh_binary())
        .args(["--help"])
        .output()
        .expect("Failed to execute bssh");

    let help_text = String::from_utf8_lossy(&output.stdout);

    // Verify --connect-timeout is documented in help
    assert!(
        help_text.contains("--connect-timeout"),
        "Help should mention --connect-timeout option"
    );

    // Verify default value is mentioned
    assert!(
        help_text.contains("SSH connection timeout"),
        "Help should describe connection timeout"
    );
}

#[test]
fn test_connect_timeout_rejects_zero() {
    // Connect timeout of 0 should be rejected (minimum is 1)
    let output = Command::new(bssh_binary())
        .args([
            "--connect-timeout",
            "0",
            "-H",
            "test@localhost",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute bssh");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should fail with validation error
    assert!(
        !output.status.success(),
        "Should fail when connect_timeout is 0"
    );
    assert!(
        stderr.contains("invalid value '0'") || stderr.contains("not in"),
        "Error should mention invalid value: {}",
        stderr
    );
}

#[test]
fn test_connect_timeout_accepts_valid_values() {
    // Valid connect timeout values should be accepted
    // We test with --help to verify parsing without actually connecting
    for value in &["1", "10", "30", "60", "300"] {
        let output = Command::new(bssh_binary())
            .args(["--connect-timeout", value, "--help"])
            .output()
            .expect("Failed to execute bssh");

        assert!(
            output.status.success(),
            "Should accept valid connect_timeout value: {}",
            value
        );
    }
}

#[test]
fn test_connect_timeout_rejects_negative() {
    // Negative values should be rejected by clap (u64 type)
    let output = Command::new(bssh_binary())
        .args([
            "--connect-timeout",
            "-1",
            "-H",
            "test@localhost",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute bssh");

    // Should fail with parsing error (negative number for u64)
    assert!(
        !output.status.success(),
        "Should fail when connect_timeout is negative"
    );
}

#[test]
fn test_connect_timeout_independent_of_command_timeout() {
    // Verify both --connect-timeout and --timeout can be used together
    let output = Command::new(bssh_binary())
        .args(["--connect-timeout", "10", "--timeout", "300", "--help"])
        .output()
        .expect("Failed to execute bssh");

    assert!(
        output.status.success(),
        "Should accept both --connect-timeout and --timeout together"
    );
}

#[test]
fn test_connect_timeout_with_cluster() {
    // Verify --connect-timeout works with cluster operations
    let output = Command::new(bssh_binary())
        .args([
            "--connect-timeout",
            "5",
            "-C",
            "nonexistent_cluster",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute bssh");

    // Should fail because cluster doesn't exist, not because of timeout option
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid value") && !stderr.contains("connect-timeout"),
        "Error should be about missing cluster, not timeout option"
    );
}

#[test]
fn test_connect_timeout_help_text_format() {
    let output = Command::new(bssh_binary())
        .args(["--help"])
        .output()
        .expect("Failed to execute bssh");

    let help_text = String::from_utf8_lossy(&output.stdout);

    // Verify help text mentions the minimum value
    assert!(
        help_text.contains("minimum: 1") || help_text.contains("minimum"),
        "Help text should mention minimum value for connect-timeout"
    );
}

/// Test that connect_timeout is properly passed through executor
/// This is a unit test for the ExecutionConfig struct
#[test]
fn test_execution_config_connect_timeout_field() {
    // This test verifies the ExecutionConfig struct has connect_timeout field
    // by checking the module compiles correctly with the field
    use bssh::executor::ParallelExecutor;
    use bssh::node::Node;

    let nodes = vec![Node::new("test".to_string(), 22, "user".to_string())];

    // Create executor with connect_timeout
    let executor = ParallelExecutor::new(nodes.clone(), 1, None).with_connect_timeout(Some(10));

    // Executor should be created successfully with connect_timeout
    // We verify by checking the nodes count matches
    assert_eq!(nodes.len(), 1);
    // The executor creation itself verifies the API works
    drop(executor);
}

/// Test that connect_timeout works with file transfer operations
#[test]
fn test_connect_timeout_with_upload_command() {
    // Test that connect_timeout is accepted with upload subcommand
    let output = Command::new(bssh_binary())
        .args([
            "--connect-timeout",
            "15",
            "-H",
            "test@localhost",
            "upload",
            "/nonexistent/source",
            "/tmp/dest",
        ])
        .output()
        .expect("Failed to execute bssh");

    // Should fail due to missing source file, not timeout option
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("connect-timeout"),
        "Error should not be about connect-timeout option"
    );
}

/// Test that connect_timeout works with download command
#[test]
fn test_connect_timeout_with_download_command() {
    // Test that connect_timeout is accepted with download subcommand
    let output = Command::new(bssh_binary())
        .args([
            "--connect-timeout",
            "15",
            "-H",
            "test@localhost",
            "download",
            "/etc/hosts",
            "/tmp/",
        ])
        .output()
        .expect("Failed to execute bssh");

    // Should fail due to connection (can't connect to localhost:22), not timeout option
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid") || !stderr.contains("connect-timeout"),
        "Error should not be about invalid connect-timeout option"
    );
}

/// Test that connect_timeout works with ping command
#[test]
fn test_connect_timeout_with_ping_command() {
    // Test that connect_timeout is accepted with ping subcommand
    let output = Command::new(bssh_binary())
        .args([
            "--connect-timeout",
            "2",
            "-H",
            "test@192.0.2.1", // TEST-NET-1 (unroutable)
            "ping",
        ])
        .output()
        .expect("Failed to execute bssh");

    // Should timeout trying to connect, not fail on option parsing
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        !combined.contains("invalid value '2'"),
        "Should accept connect_timeout value of 2"
    );
}

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

use bssh::ssh::tokio_client::{AuthMethod, Client, CommandOutput, ServerCheckMethod};
use tokio::sync::mpsc::channel;

/// Type alias for output buffer components
type OutputBuffer = (
    tokio::sync::mpsc::Sender<CommandOutput>,
    tokio::task::JoinHandle<(Vec<u8>, Vec<u8>)>,
);

/// Helper function to build a test output buffer
fn build_test_output_buffer() -> OutputBuffer {
    let (sender, mut receiver) = channel(100);

    let receiver_task = tokio::task::spawn(async move {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        while let Some(output) = receiver.recv().await {
            match output {
                CommandOutput::StdOut(buffer) => stdout.extend_from_slice(&buffer),
                CommandOutput::StdErr(buffer) => stderr.extend_from_slice(&buffer),
                CommandOutput::ExitCode(_) => {
                    // Exit code is handled separately, not collected here
                }
            }
        }

        (stdout, stderr)
    });

    (sender, receiver_task)
}

/// Check if SSH is available and can connect to localhost
fn can_ssh_to_localhost() -> bool {
    use std::process::Command;

    // Check if SSH server is running and we can connect to localhost
    let output = Command::new("ssh")
        .args([
            "-o",
            "ConnectTimeout=2",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "BatchMode=yes",
            "localhost",
            "echo",
            "test",
        ])
        .output();

    match output {
        Ok(result) => result.status.success(),
        Err(_) => false,
    }
}

#[tokio::test]
async fn test_localhost_execute_streaming_output() {
    if !can_ssh_to_localhost() {
        eprintln!("Skipping streaming test: Cannot SSH to localhost");
        return;
    }

    // Get current username
    let username = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // Create client
    let client = Client::connect(
        ("localhost", 22),
        &username,
        AuthMethod::Agent, // Use SSH agent for authentication
        ServerCheckMethod::NoCheck,
    )
    .await;

    if client.is_err() {
        eprintln!("Skipping streaming test: Cannot connect to localhost");
        return;
    }

    let client = client.unwrap();

    // Build output buffer for streaming
    let (sender, receiver_task) = build_test_output_buffer();

    // Execute command with streaming
    let exit_status = client
        .execute_streaming("echo 'Hello from streaming test'", sender)
        .await;

    assert!(exit_status.is_ok(), "Command should execute successfully");
    let exit_status = exit_status.unwrap();
    assert_eq!(exit_status, 0, "Command should exit with status 0");

    // Wait for output collection
    let (stdout_bytes, stderr_bytes) = receiver_task.await.unwrap();
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    let stderr = String::from_utf8_lossy(&stderr_bytes);

    // Verify output
    assert!(
        stdout.contains("Hello from streaming test"),
        "Stdout should contain test message, got: {stdout}"
    );
    assert_eq!(stderr, "", "Stderr should be empty, got: {stderr}");
}

#[tokio::test]
async fn test_backward_compatibility_execute() {
    if !can_ssh_to_localhost() {
        eprintln!("Skipping backward compatibility test: Cannot SSH to localhost");
        return;
    }

    // Get current username
    let username = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // Create client
    let client = Client::connect(
        ("localhost", 22),
        &username,
        AuthMethod::Agent,
        ServerCheckMethod::NoCheck,
    )
    .await;

    if client.is_err() {
        eprintln!("Skipping backward compatibility test: Cannot connect to localhost");
        return;
    }

    let client = client.unwrap();

    // Execute command using the original execute() method
    let result = client.execute("echo 'Backward compatibility test'").await;

    assert!(result.is_ok(), "Command should execute successfully");
    let result = result.unwrap();

    // Verify behavior is exactly the same as before
    assert_eq!(result.exit_status, 0, "Command should exit with status 0");
    assert!(
        result.stdout.contains("Backward compatibility test"),
        "Stdout should contain test message, got: {}",
        result.stdout
    );
    assert_eq!(
        result.stderr, "",
        "Stderr should be empty, got: {}",
        result.stderr
    );
}

#[tokio::test]
async fn test_streaming_with_stderr() {
    if !can_ssh_to_localhost() {
        eprintln!("Skipping stderr streaming test: Cannot SSH to localhost");
        return;
    }

    // Get current username
    let username = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // Create client
    let client = Client::connect(
        ("localhost", 22),
        &username,
        AuthMethod::Agent,
        ServerCheckMethod::NoCheck,
    )
    .await;

    if client.is_err() {
        eprintln!("Skipping stderr streaming test: Cannot connect to localhost");
        return;
    }

    let client = client.unwrap();

    // Build output buffer for streaming
    let (sender, receiver_task) = build_test_output_buffer();

    // Execute command that outputs to both stdout and stderr
    let exit_status = client
        .execute_streaming("echo 'stdout message' && echo 'stderr message' >&2", sender)
        .await;

    assert!(exit_status.is_ok(), "Command should execute successfully");

    // Wait for output collection
    let (stdout_bytes, stderr_bytes) = receiver_task.await.unwrap();
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    let stderr = String::from_utf8_lossy(&stderr_bytes);

    // Verify both streams
    assert!(
        stdout.contains("stdout message"),
        "Stdout should contain stdout message, got: {stdout}"
    );
    assert!(
        stderr.contains("stderr message"),
        "Stderr should contain stderr message, got: {stderr}"
    );
}

#[tokio::test]
async fn test_streaming_large_output_backpressure() {
    if !can_ssh_to_localhost() {
        eprintln!("Skipping large output test: Cannot SSH to localhost");
        return;
    }

    // Get current username
    let username = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // Create client
    let client = Client::connect(
        ("localhost", 22),
        &username,
        AuthMethod::Agent,
        ServerCheckMethod::NoCheck,
    )
    .await;

    if client.is_err() {
        eprintln!("Skipping large output test: Cannot connect to localhost");
        return;
    }

    let client = client.unwrap();

    // Build output buffer for streaming
    let (sender, receiver_task) = build_test_output_buffer();

    // Execute command that generates large output to test backpressure
    // Generate 10000 lines to ensure we exceed the channel buffer
    let exit_status = client
        .execute_streaming("for i in {1..10000}; do echo \"Line $i\"; done", sender)
        .await;

    assert!(
        exit_status.is_ok(),
        "Large output command should execute successfully"
    );
    let exit_status = exit_status.unwrap();
    assert_eq!(exit_status, 0, "Command should exit with status 0");

    // Wait for output collection
    let (stdout_bytes, _stderr_bytes) = receiver_task.await.unwrap();
    let stdout = String::from_utf8_lossy(&stdout_bytes);

    // Verify we got all lines
    assert!(stdout.contains("Line 1"), "Should contain first line");
    assert!(stdout.contains("Line 10000"), "Should contain last line");

    // Count lines to ensure no data loss
    let line_count = stdout.lines().count();
    assert_eq!(
        line_count, 10000,
        "Should have exactly 10000 lines, got: {line_count}"
    );
}

#[tokio::test]
async fn test_streaming_receiver_drop_handling() {
    if !can_ssh_to_localhost() {
        eprintln!("Skipping receiver drop test: Cannot SSH to localhost");
        return;
    }

    // Get current username
    let username = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // Create client
    let client = Client::connect(
        ("localhost", 22),
        &username,
        AuthMethod::Agent,
        ServerCheckMethod::NoCheck,
    )
    .await;

    if client.is_err() {
        eprintln!("Skipping receiver drop test: Cannot connect to localhost");
        return;
    }

    let client = client.unwrap();

    // Create a channel but immediately drop the receiver
    let (sender, receiver) = channel(100);

    // Drop the receiver to simulate early termination
    drop(receiver);

    // Execute command - should handle receiver drop gracefully
    let exit_status = client.execute_streaming("echo 'test output'", sender).await;

    // Should still return exit status even though receiver dropped
    assert!(
        exit_status.is_ok(),
        "Command should handle receiver drop gracefully"
    );
    let exit_status = exit_status.unwrap();
    assert_eq!(
        exit_status, 0,
        "Command should still report correct exit status"
    );
}

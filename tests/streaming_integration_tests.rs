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

//! Streaming Execution Integration Tests
//!
//! This module tests the streaming execution infrastructure including:
//! - NodeStream and RollingBuffer behavior
//! - MultiNodeStreamManager coordination
//! - stdout/stderr separation
//! - Partial output handling
//! - Connection failure scenarios

use bssh::executor::{ExecutionStatus, MultiNodeStreamManager, NodeStream};
use bssh::node::Node;
use bssh::ssh::tokio_client::CommandOutput;
use russh::CryptoVec;
use tokio::sync::mpsc;

// ============================================================================
// NodeStream Basic Tests
// ============================================================================

#[tokio::test]
async fn test_node_stream_creation() {
    let node = Node::new("test-host".to_string(), 22, "testuser".to_string());
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    let stream = NodeStream::new(node.clone(), rx);

    assert_eq!(stream.node.host, "test-host");
    assert_eq!(stream.node.port, 22);
    assert_eq!(stream.node.username, "testuser");
    assert_eq!(stream.status(), &ExecutionStatus::Pending);
    assert_eq!(stream.exit_code(), None);
    assert!(!stream.is_closed());
    assert!(!stream.is_complete());
    assert!(stream.stdout().is_empty());
    assert!(stream.stderr().is_empty());
}

#[tokio::test]
async fn test_node_stream_receives_stdout() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send stdout data
    let data = CryptoVec::from(b"Hello, World!".to_vec());
    tx.send(CommandOutput::StdOut(data)).await.unwrap();

    // Poll should receive data
    assert!(stream.poll(), "Poll should return true when data received");
    assert_eq!(stream.stdout(), b"Hello, World!");
    assert_eq!(
        stream.status(),
        &ExecutionStatus::Running,
        "Status should be Running after receiving data"
    );
}

#[tokio::test]
async fn test_node_stream_receives_stderr() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send stderr data
    let data = CryptoVec::from(b"Error: something went wrong".to_vec());
    tx.send(CommandOutput::StdErr(data)).await.unwrap();

    stream.poll();
    assert_eq!(stream.stderr(), b"Error: something went wrong");
    assert!(stream.stdout().is_empty(), "stdout should be empty");
}

#[tokio::test]
async fn test_node_stream_stdout_stderr_separation() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send both stdout and stderr
    let stdout_data = CryptoVec::from(b"stdout output".to_vec());
    let stderr_data = CryptoVec::from(b"stderr output".to_vec());
    tx.send(CommandOutput::StdOut(stdout_data)).await.unwrap();
    tx.send(CommandOutput::StdErr(stderr_data)).await.unwrap();

    stream.poll();
    assert_eq!(stream.stdout(), b"stdout output");
    assert_eq!(stream.stderr(), b"stderr output");
}

#[tokio::test]
async fn test_node_stream_multiple_chunks() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send multiple chunks
    for i in 1..=5 {
        let data = CryptoVec::from(format!("chunk{i}").into_bytes());
        tx.send(CommandOutput::StdOut(data)).await.unwrap();
    }

    stream.poll();
    assert_eq!(stream.stdout(), b"chunk1chunk2chunk3chunk4chunk5");
}

#[tokio::test]
async fn test_node_stream_exit_code_success() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send exit code and close channel
    tx.send(CommandOutput::ExitCode(0)).await.unwrap();
    drop(tx);

    stream.poll();
    assert_eq!(stream.exit_code(), Some(0));
    assert!(stream.is_closed());
    assert!(stream.is_complete());
    assert_eq!(stream.status(), &ExecutionStatus::Completed);
}

#[tokio::test]
async fn test_node_stream_exit_code_failure() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send non-zero exit code
    tx.send(CommandOutput::ExitCode(1)).await.unwrap();
    drop(tx);

    stream.poll();
    assert_eq!(stream.exit_code(), Some(1));
    assert!(stream.is_complete());
    assert!(
        matches!(stream.status(), ExecutionStatus::Failed(msg) if msg.contains("Exit code: 1")),
        "Expected Failed status with exit code 1, got {:?}",
        stream.status()
    );
}

#[tokio::test]
async fn test_node_stream_take_buffers() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send data
    let stdout = CryptoVec::from(b"stdout data".to_vec());
    let stderr = CryptoVec::from(b"stderr data".to_vec());
    tx.send(CommandOutput::StdOut(stdout)).await.unwrap();
    tx.send(CommandOutput::StdErr(stderr)).await.unwrap();

    stream.poll();

    // Take stdout
    let taken_stdout = stream.take_stdout();
    assert_eq!(taken_stdout, b"stdout data");
    assert!(
        stream.stdout().is_empty(),
        "stdout should be empty after take"
    );

    // Take stderr
    let taken_stderr = stream.take_stderr();
    assert_eq!(taken_stderr, b"stderr data");
    assert!(
        stream.stderr().is_empty(),
        "stderr should be empty after take"
    );
}

#[tokio::test]
async fn test_node_stream_channel_disconnect() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Just drop the sender without sending exit code
    drop(tx);

    stream.poll();
    assert!(stream.is_closed());
    assert!(stream.is_complete());
    // Should complete successfully without exit code
    assert_eq!(stream.status(), &ExecutionStatus::Completed);
}

// ============================================================================
// MultiNodeStreamManager Tests
// ============================================================================

#[tokio::test]
async fn test_manager_empty() {
    let manager = MultiNodeStreamManager::new();

    assert_eq!(manager.total_count(), 0);
    assert_eq!(manager.completed_count(), 0);
    assert_eq!(manager.failed_count(), 0);
    assert!(
        !manager.all_complete(),
        "Empty manager should not be 'all complete'"
    );
}

#[tokio::test]
async fn test_manager_add_streams() {
    let mut manager = MultiNodeStreamManager::new();

    for i in 1..=5 {
        let node = Node::new(format!("host{i}"), 22, "user".to_string());
        let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
        manager.add_stream(node, rx);
    }

    assert_eq!(manager.total_count(), 5);
    assert_eq!(manager.streams().len(), 5);
}

#[tokio::test]
async fn test_manager_poll_all() {
    let mut manager = MultiNodeStreamManager::new();

    let node1 = Node::new("host1".to_string(), 22, "user".to_string());
    let (tx1, rx1) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node1, rx1);

    let node2 = Node::new("host2".to_string(), 22, "user".to_string());
    let (tx2, rx2) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node2, rx2);

    // Send data to both streams
    let data1 = CryptoVec::from(b"output1".to_vec());
    let data2 = CryptoVec::from(b"output2".to_vec());
    tx1.send(CommandOutput::StdOut(data1)).await.unwrap();
    tx2.send(CommandOutput::StdOut(data2)).await.unwrap();

    // Poll all should receive from both
    assert!(manager.poll_all());
    assert_eq!(manager.streams()[0].stdout(), b"output1");
    assert_eq!(manager.streams()[1].stdout(), b"output2");
}

#[tokio::test]
async fn test_manager_all_complete() {
    let mut manager = MultiNodeStreamManager::new();

    let node1 = Node::new("host1".to_string(), 22, "user".to_string());
    let (tx1, rx1) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node1, rx1);

    let node2 = Node::new("host2".to_string(), 22, "user".to_string());
    let (tx2, rx2) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node2, rx2);

    assert!(!manager.all_complete());

    // Complete both streams
    drop(tx1);
    drop(tx2);

    manager.poll_all();
    assert!(manager.all_complete());
    assert_eq!(manager.completed_count(), 2);
}

#[tokio::test]
async fn test_manager_partial_completion() {
    let mut manager = MultiNodeStreamManager::new();

    let node1 = Node::new("host1".to_string(), 22, "user".to_string());
    let (tx1, rx1) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node1, rx1);

    let node2 = Node::new("host2".to_string(), 22, "user".to_string());
    let (_tx2, rx2) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node2, rx2);

    // Complete only first stream
    drop(tx1);

    manager.poll_all();
    assert!(!manager.all_complete());
    assert_eq!(manager.completed_count(), 1);
}

#[tokio::test]
async fn test_manager_failed_count() {
    let mut manager = MultiNodeStreamManager::new();

    let node1 = Node::new("host1".to_string(), 22, "user".to_string());
    let (tx1, rx1) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node1, rx1);

    let node2 = Node::new("host2".to_string(), 22, "user".to_string());
    let (tx2, rx2) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node2, rx2);

    // First stream completes successfully
    tx1.send(CommandOutput::ExitCode(0)).await.unwrap();
    drop(tx1);

    // Second stream fails
    tx2.send(CommandOutput::ExitCode(1)).await.unwrap();
    drop(tx2);

    manager.poll_all();
    assert_eq!(
        manager.completed_count(),
        1,
        "One should be completed successfully"
    );
    assert_eq!(manager.failed_count(), 1, "One should be failed");
    assert!(manager.all_complete());
}

#[tokio::test]
async fn test_manager_mutable_streams_access() {
    let mut manager = MultiNodeStreamManager::new();

    let node = Node::new("host".to_string(), 22, "user".to_string());
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node, rx);

    // Should be able to mutate streams
    let streams = manager.streams_mut();
    streams[0].set_status(ExecutionStatus::Running);

    assert_eq!(manager.streams()[0].status(), &ExecutionStatus::Running);
}

// ============================================================================
// Partial Output Handling Tests
// ============================================================================

#[tokio::test]
async fn test_partial_output_accumulation() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Simulate partial line output
    let chunk1 = CryptoVec::from(b"partial ".to_vec());
    let chunk2 = CryptoVec::from(b"line ".to_vec());
    let chunk3 = CryptoVec::from(b"complete\n".to_vec());

    tx.send(CommandOutput::StdOut(chunk1)).await.unwrap();
    stream.poll();
    assert_eq!(stream.stdout(), b"partial ");

    tx.send(CommandOutput::StdOut(chunk2)).await.unwrap();
    stream.poll();
    assert_eq!(stream.stdout(), b"partial line ");

    tx.send(CommandOutput::StdOut(chunk3)).await.unwrap();
    stream.poll();
    assert_eq!(stream.stdout(), b"partial line complete\n");
}

#[tokio::test]
async fn test_interleaved_stdout_stderr() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send interleaved stdout and stderr
    tx.send(CommandOutput::StdOut(CryptoVec::from(b"out1".to_vec())))
        .await
        .unwrap();
    tx.send(CommandOutput::StdErr(CryptoVec::from(b"err1".to_vec())))
        .await
        .unwrap();
    tx.send(CommandOutput::StdOut(CryptoVec::from(b"out2".to_vec())))
        .await
        .unwrap();
    tx.send(CommandOutput::StdErr(CryptoVec::from(b"err2".to_vec())))
        .await
        .unwrap();

    stream.poll();

    // Should be separated correctly
    assert_eq!(stream.stdout(), b"out1out2");
    assert_eq!(stream.stderr(), b"err1err2");
}

// ============================================================================
// Connection Failure Scenario Tests
// ============================================================================

#[tokio::test]
async fn test_stream_immediate_close() {
    let node = Node::new(
        "unreachable.example.com".to_string(),
        22,
        "user".to_string(),
    );
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Immediately close without any data
    drop(tx);

    stream.poll();
    assert!(stream.is_closed());
    assert!(stream.is_complete());
    assert!(stream.stdout().is_empty());
    assert!(stream.stderr().is_empty());
}

#[tokio::test]
async fn test_stream_set_status_manually() {
    let node = Node::new("host".to_string(), 22, "user".to_string());
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Manually set failed status (as would happen on connection error)
    stream.set_status(ExecutionStatus::Failed("Connection refused".to_string()));

    assert!(
        matches!(stream.status(), ExecutionStatus::Failed(msg) if msg.contains("Connection refused")),
        "Expected Failed status with connection refused, got {:?}",
        stream.status()
    );
}

#[tokio::test]
async fn test_manager_mixed_connection_states() {
    let mut manager = MultiNodeStreamManager::new();

    // Node 1: Connects and completes
    let node1 = Node::new("host1".to_string(), 22, "user".to_string());
    let (tx1, rx1) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node1, rx1);
    tx1.send(CommandOutput::StdOut(CryptoVec::from(b"success".to_vec())))
        .await
        .unwrap();
    tx1.send(CommandOutput::ExitCode(0)).await.unwrap();
    drop(tx1);

    // Node 2: Connection fails immediately
    let node2 = Node::new("host2".to_string(), 22, "user".to_string());
    let (tx2, rx2) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node2, rx2);
    drop(tx2); // Simulate connection failure

    // Node 3: Partially completes then fails
    let node3 = Node::new("host3".to_string(), 22, "user".to_string());
    let (tx3, rx3) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node3, rx3);
    tx3.send(CommandOutput::StdOut(CryptoVec::from(b"partial".to_vec())))
        .await
        .unwrap();
    tx3.send(CommandOutput::ExitCode(1)).await.unwrap();
    drop(tx3);

    manager.poll_all();

    assert_eq!(manager.total_count(), 3);
    assert!(manager.all_complete());
    assert_eq!(manager.completed_count(), 2); // node1 and node2 (connection failures are "completed")
    assert_eq!(manager.failed_count(), 1); // node3 with exit code 1
}

// ============================================================================
// Performance and Stress Tests
// ============================================================================

#[tokio::test]
async fn test_high_throughput_single_stream() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(1000);
    let mut stream = NodeStream::new(node, rx);

    // Send many small chunks
    let chunk = CryptoVec::from(vec![b'x'; 100]);
    for _ in 0..1000 {
        tx.send(CommandOutput::StdOut(chunk.clone())).await.unwrap();
    }

    // Poll all data
    while stream.poll() {
        // Keep polling
    }

    assert_eq!(
        stream.stdout().len(),
        100 * 1000,
        "Should have received all data"
    );
}

#[tokio::test]
async fn test_many_concurrent_streams() {
    let mut manager = MultiNodeStreamManager::new();
    let mut senders = Vec::new();

    // Create 50 streams
    for i in 0..50 {
        let node = Node::new(format!("host{i}"), 22, "user".to_string());
        let (tx, rx) = mpsc::channel::<CommandOutput>(100);
        manager.add_stream(node, rx);
        senders.push(tx);
    }

    // Send data to all streams
    for (i, tx) in senders.iter().enumerate() {
        let data = CryptoVec::from(format!("output from node {i}").into_bytes());
        tx.send(CommandOutput::StdOut(data)).await.unwrap();
    }

    manager.poll_all();

    // Verify all streams received their data
    for (i, stream) in manager.streams().iter().enumerate() {
        let expected = format!("output from node {i}");
        assert_eq!(
            stream.stdout(),
            expected.as_bytes(),
            "Stream {i} should have correct data"
        );
    }
}

#[tokio::test]
async fn test_poll_returns_false_when_no_data() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Poll without sending data should return false
    assert!(!stream.poll(), "Poll should return false when no data");
}

#[tokio::test]
async fn test_manager_poll_all_returns_correctly() {
    let mut manager = MultiNodeStreamManager::new();

    let node = Node::new("host".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node, rx);

    // No data yet
    assert!(!manager.poll_all(), "Should return false when no data");

    // Send data
    let data = CryptoVec::from(b"data".to_vec());
    tx.send(CommandOutput::StdOut(data)).await.unwrap();

    assert!(manager.poll_all(), "Should return true when data received");
}

// ============================================================================
// Unicode and Binary Data Tests
// ============================================================================

#[tokio::test]
async fn test_stream_with_unicode_output() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send unicode data with actual Korean, Chinese, and Emoji characters
    let data = CryptoVec::from(
        "Hello, World! Korean: 안녕 Chinese: 你好 Emoji: 🚀🎉"
            .as_bytes()
            .to_vec(),
    );
    tx.send(CommandOutput::StdOut(data)).await.unwrap();

    stream.poll();
    let output = String::from_utf8_lossy(stream.stdout());
    assert!(
        output.contains("Hello, World!"),
        "Should contain ASCII text"
    );
    assert!(output.contains("안녕"), "Should contain Korean text");
    assert!(output.contains("你好"), "Should contain Chinese text");
    assert!(output.contains("🚀"), "Should contain emoji");
}

#[tokio::test]
async fn test_stream_with_binary_output() {
    let node = Node::new("localhost".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    let mut stream = NodeStream::new(node, rx);

    // Send binary data with null bytes
    let binary_data: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00];
    let data = CryptoVec::from(binary_data.clone());
    tx.send(CommandOutput::StdOut(data)).await.unwrap();

    stream.poll();
    assert_eq!(stream.stdout(), binary_data.as_slice());
}

// ============================================================================
// TuiApp Data Change Detection Tests
// ============================================================================

#[tokio::test]
async fn test_app_data_change_detection() {
    use bssh::ui::tui::app::TuiApp;

    let mut app = TuiApp::new();
    let mut manager = MultiNodeStreamManager::new();

    let node = Node::new("host".to_string(), 22, "user".to_string());
    let (tx, rx) = mpsc::channel::<CommandOutput>(100);
    manager.add_stream(node, rx);

    // Initial check - should detect new node
    let changed = app.check_data_changes(manager.streams());
    assert!(changed, "Should detect new node");

    // Check again without changes - should not detect change
    let changed = app.check_data_changes(manager.streams());
    assert!(!changed, "Should not detect change when data is same");

    // Send data
    let data = CryptoVec::from(b"new output".to_vec());
    tx.send(CommandOutput::StdOut(data)).await.unwrap();
    manager.poll_all();

    // Check again - should detect change
    let changed = app.check_data_changes(manager.streams());
    assert!(changed, "Should detect data change");
}

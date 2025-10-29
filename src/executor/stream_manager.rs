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

//! Multi-node stream management for real-time output processing.
//!
//! This module provides independent stream buffering and management for each node
//! in a multi-node execution context. Each node maintains its own output buffers
//! and execution state, allowing for non-blocking polling and flexible output modes.

use crate::node::Node;
use crate::ssh::tokio_client::CommandOutput;
use tokio::sync::mpsc;

/// Maximum buffer size per stream (10MB)
/// This prevents memory exhaustion when nodes produce large amounts of output
const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// A rolling buffer that maintains a fixed maximum size
/// When the buffer exceeds MAX_BUFFER_SIZE, old data is discarded
#[derive(Debug)]
struct RollingBuffer {
    data: Vec<u8>,
    total_bytes_received: usize,
    bytes_dropped: usize,
}

impl RollingBuffer {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            total_bytes_received: 0,
            bytes_dropped: 0,
        }
    }

    /// Append data to the buffer, dropping old data if necessary
    fn append(&mut self, new_data: &[u8]) {
        self.total_bytes_received += new_data.len();
        self.data.extend_from_slice(new_data);

        // If buffer exceeds maximum size, keep only the most recent data
        if self.data.len() > MAX_BUFFER_SIZE {
            let overflow = self.data.len() - MAX_BUFFER_SIZE;
            self.bytes_dropped += overflow;

            // Remove old data from the beginning
            self.data.drain(0..overflow);

            // Log warning about dropped data
            tracing::warn!(
                "Buffer overflow: dropped {} bytes (total dropped: {})",
                overflow,
                self.bytes_dropped
            );
        }
    }

    /// Get the current buffer contents
    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Take the buffer contents and clear it
    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }

    /// Check if data has been dropped
    fn has_overflow(&self) -> bool {
        self.bytes_dropped > 0
    }
}

/// Execution status for a node's command
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Command has not started yet
    Pending,
    /// Command is currently running
    Running,
    /// Command completed successfully
    Completed,
    /// Command failed with error message
    Failed(String),
}

/// Independent output stream for a single node
///
/// Each node maintains its own buffers for stdout and stderr,
/// along with execution status and exit code. This allows for
/// independent processing of each node's output without blocking
/// on other nodes.
///
/// Buffers are limited to MAX_BUFFER_SIZE to prevent memory exhaustion.
/// When buffers exceed this limit, old data is automatically discarded.
pub struct NodeStream {
    /// The node this stream is associated with
    pub node: Node,
    /// Channel receiver for command output
    receiver: mpsc::Receiver<CommandOutput>,
    /// Buffer for standard output (with overflow protection)
    stdout_buffer: RollingBuffer,
    /// Buffer for standard error (with overflow protection)
    stderr_buffer: RollingBuffer,
    /// Current execution status
    status: ExecutionStatus,
    /// Exit code (if completed)
    exit_code: Option<u32>,
    /// Whether this stream has been closed
    closed: bool,
}

impl NodeStream {
    /// Create a new node stream
    pub fn new(node: Node, receiver: mpsc::Receiver<CommandOutput>) -> Self {
        Self {
            node,
            receiver,
            stdout_buffer: RollingBuffer::new(),
            stderr_buffer: RollingBuffer::new(),
            status: ExecutionStatus::Pending,
            exit_code: None,
            closed: false,
        }
    }

    /// Poll for new output (non-blocking)
    ///
    /// Returns true if new data was received, false if no data was available
    pub fn poll(&mut self) -> bool {
        let mut received_data = false;

        // Update status to running if we receive any output
        if self.status == ExecutionStatus::Pending {
            self.status = ExecutionStatus::Running;
        }

        // Non-blocking poll of the channel
        loop {
            match self.receiver.try_recv() {
                Ok(output) => {
                    received_data = true;
                    match output {
                        CommandOutput::StdOut(data) => {
                            self.stdout_buffer.append(&data);
                            if self.stdout_buffer.has_overflow() {
                                tracing::warn!(
                                    "Node {} stdout buffer overflow - old data discarded",
                                    self.node.host
                                );
                            }
                        }
                        CommandOutput::StdErr(data) => {
                            self.stderr_buffer.append(&data);
                            if self.stderr_buffer.has_overflow() {
                                tracing::warn!(
                                    "Node {} stderr buffer overflow - old data discarded",
                                    self.node.host
                                );
                            }
                        }
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    // No more data available right now
                    break;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Channel closed - mark as completed if not already failed
                    self.closed = true;
                    if self.status != ExecutionStatus::Failed(String::new()) {
                        self.status = ExecutionStatus::Completed;
                    }
                    tracing::debug!("Channel disconnected for node {}", self.node.host);
                    break;
                }
            }
        }

        received_data
    }

    /// Get reference to stdout buffer
    pub fn stdout(&self) -> &[u8] {
        self.stdout_buffer.as_slice()
    }

    /// Get reference to stderr buffer
    pub fn stderr(&self) -> &[u8] {
        self.stderr_buffer.as_slice()
    }

    /// Take stdout buffer and clear it
    ///
    /// This is useful for consuming output in chunks while streaming
    pub fn take_stdout(&mut self) -> Vec<u8> {
        self.stdout_buffer.take()
    }

    /// Take stderr buffer and clear it
    ///
    /// This is useful for consuming output in chunks while streaming
    pub fn take_stderr(&mut self) -> Vec<u8> {
        self.stderr_buffer.take()
    }

    /// Get current execution status
    pub fn status(&self) -> &ExecutionStatus {
        &self.status
    }

    /// Set execution status
    pub fn set_status(&mut self, status: ExecutionStatus) {
        self.status = status;
    }

    /// Get exit code if available
    pub fn exit_code(&self) -> Option<u32> {
        self.exit_code
    }

    /// Set exit code
    pub fn set_exit_code(&mut self, code: u32) {
        self.exit_code = Some(code);
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Check if execution is complete
    pub fn is_complete(&self) -> bool {
        matches!(
            self.status,
            ExecutionStatus::Completed | ExecutionStatus::Failed(_)
        ) && self.closed
    }
}

/// Manager for coordinating multiple node streams
///
/// This manager handles polling all node streams in a non-blocking manner
/// and provides access to their current state and output.
pub struct MultiNodeStreamManager {
    streams: Vec<NodeStream>,
}

impl MultiNodeStreamManager {
    /// Create a new empty stream manager
    pub fn new() -> Self {
        Self {
            streams: Vec::new(),
        }
    }

    /// Add a new node stream
    pub fn add_stream(&mut self, node: Node, receiver: mpsc::Receiver<CommandOutput>) {
        self.streams.push(NodeStream::new(node, receiver));
    }

    /// Poll all streams for new output (non-blocking)
    ///
    /// Returns true if any stream received new data
    pub fn poll_all(&mut self) -> bool {
        let mut any_received = false;
        for stream in &mut self.streams {
            if stream.poll() {
                any_received = true;
            }
        }
        any_received
    }

    /// Get all streams
    pub fn streams(&self) -> &[NodeStream] {
        &self.streams
    }

    /// Get mutable access to all streams
    pub fn streams_mut(&mut self) -> &mut [NodeStream] {
        &mut self.streams
    }

    /// Check if all streams are complete
    pub fn all_complete(&self) -> bool {
        !self.streams.is_empty() && self.streams.iter().all(|s| s.is_complete())
    }

    /// Get count of completed streams
    pub fn completed_count(&self) -> usize {
        self.streams.iter().filter(|s| s.is_complete()).count()
    }

    /// Get count of failed streams
    pub fn failed_count(&self) -> usize {
        self.streams
            .iter()
            .filter(|s| matches!(s.status(), ExecutionStatus::Failed(_)))
            .count()
    }

    /// Get total stream count
    pub fn total_count(&self) -> usize {
        self.streams.len()
    }
}

impl Default for MultiNodeStreamManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::CryptoVec;

    #[test]
    fn test_node_stream_creation() {
        let node = Node::new("localhost".to_string(), 22, "test".to_string());
        let (_tx, rx) = mpsc::channel(100);
        let stream = NodeStream::new(node, rx);

        assert_eq!(stream.status(), &ExecutionStatus::Pending);
        assert_eq!(stream.exit_code(), None);
        assert!(!stream.is_closed());
        assert!(!stream.is_complete());
    }

    #[tokio::test]
    async fn test_node_stream_polling() {
        let node = Node::new("localhost".to_string(), 22, "test".to_string());
        let (tx, rx) = mpsc::channel(100);
        let mut stream = NodeStream::new(node, rx);

        // Send some output
        let data = CryptoVec::from(b"test output".to_vec());
        tx.send(CommandOutput::StdOut(data)).await.unwrap();

        // Poll should receive data
        assert!(stream.poll());
        assert_eq!(stream.stdout(), b"test output");
        assert_eq!(stream.status(), &ExecutionStatus::Running);
    }

    #[tokio::test]
    async fn test_node_stream_take_buffers() {
        let node = Node::new("localhost".to_string(), 22, "test".to_string());
        let (tx, rx) = mpsc::channel(100);
        let mut stream = NodeStream::new(node, rx);

        // Send output
        let data = CryptoVec::from(b"test".to_vec());
        tx.send(CommandOutput::StdOut(data)).await.unwrap();

        stream.poll();
        let stdout = stream.take_stdout();
        assert_eq!(stdout, b"test");
        assert!(stream.stdout().is_empty());
    }

    #[tokio::test]
    async fn test_node_stream_completion() {
        let node = Node::new("localhost".to_string(), 22, "test".to_string());
        let (tx, rx) = mpsc::channel(100);
        let mut stream = NodeStream::new(node, rx);

        // Close channel
        drop(tx);

        // Poll should detect closure
        stream.poll();
        assert!(stream.is_closed());
        assert!(stream.is_complete());
        assert_eq!(stream.status(), &ExecutionStatus::Completed);
    }

    #[tokio::test]
    async fn test_multi_node_stream_manager() {
        let mut manager = MultiNodeStreamManager::new();

        // Add multiple streams
        let node1 = Node::new("host1".to_string(), 22, "node1".to_string());
        let (_tx1, rx1) = mpsc::channel(100);
        manager.add_stream(node1, rx1);

        let node2 = Node::new("host2".to_string(), 22, "node2".to_string());
        let (_tx2, rx2) = mpsc::channel(100);
        manager.add_stream(node2, rx2);

        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.completed_count(), 0);
    }

    #[tokio::test]
    async fn test_multi_node_stream_poll_all() {
        let mut manager = MultiNodeStreamManager::new();

        let node1 = Node::new("host1".to_string(), 22, "node1".to_string());
        let (tx1, rx1) = mpsc::channel(100);
        manager.add_stream(node1, rx1);

        // Send data
        let data = CryptoVec::from(b"output1".to_vec());
        tx1.send(CommandOutput::StdOut(data)).await.unwrap();

        // Poll all should receive data
        assert!(manager.poll_all());
        assert_eq!(manager.streams()[0].stdout(), b"output1");
    }

    #[tokio::test]
    async fn test_multi_node_stream_all_complete() {
        let mut manager = MultiNodeStreamManager::new();

        let node1 = Node::new("host1".to_string(), 22, "node1".to_string());
        let (tx1, rx1) = mpsc::channel(100);
        manager.add_stream(node1, rx1);

        let node2 = Node::new("host2".to_string(), 22, "node2".to_string());
        let (tx2, rx2) = mpsc::channel(100);
        manager.add_stream(node2, rx2);

        // Close both channels
        drop(tx1);
        drop(tx2);

        // Poll should detect both completed
        manager.poll_all();
        assert!(manager.all_complete());
        assert_eq!(manager.completed_count(), 2);
    }
}

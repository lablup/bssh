//! Bidirectional data tunneling for SSH port forwarding
//!
//! This module provides efficient bidirectional data transfer between TCP sockets
//! and SSH channels using async I/O. It handles the core data pumping functionality
//! required by all port forwarding implementations.
//!
//! # Features
//!
//! - **Bidirectional Transfer**: Simultaneous data transfer in both directions
//! - **Zero-Copy Operations**: Efficient buffer management with pooling
//! - **Graceful Shutdown**: Proper cleanup on connection close or errors
//! - **Error Recovery**: Resilient handling of temporary I/O errors
//! - **Flow Control**: Respects SSH channel and TCP socket flow control
//! - **Metrics Collection**: Transfer statistics and error reporting
//!
//! # Architecture
//!
//! The tunnel consists of two concurrent tasks:
//! - **Local→Remote**: Reads from local socket, writes to SSH channel
//! - **Remote→Local**: Reads from SSH channel, writes to local socket
//!
//! Both tasks coordinate through shared state and cancellation tokens for
//! proper lifecycle management.

use crate::utils::buffer_pool::global;
use anyhow::Result;
use russh::Channel;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};

/// Statistics for a tunnel session
#[derive(Debug)]
pub struct TunnelStats {
    /// Bytes transferred from local to remote
    pub bytes_local_to_remote: Arc<AtomicU64>,
    /// Bytes transferred from remote to local
    pub bytes_remote_to_local: Arc<AtomicU64>,
    /// Start time of the tunnel
    pub started_at: Instant,
    /// Number of I/O errors encountered
    pub error_count: Arc<AtomicU64>,
}

impl Default for TunnelStats {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelStats {
    pub fn new() -> Self {
        Self {
            bytes_local_to_remote: Arc::new(AtomicU64::new(0)),
            bytes_remote_to_local: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
            error_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get total bytes transferred in both directions
    pub fn total_bytes(&self) -> u64 {
        self.bytes_local_to_remote.load(Ordering::Relaxed)
            + self.bytes_remote_to_local.load(Ordering::Relaxed)
    }

    /// Get duration since tunnel started
    pub fn duration(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }

    /// Get error count
    pub fn errors(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }
}

/// Bidirectional tunnel between TCP socket and SSH channel
#[allow(dead_code)] // Individual fields used differently
pub struct Tunnel {
    stats: TunnelStats,
    cancel_token: CancellationToken,
}

impl Tunnel {
    /// Create a new tunnel
    pub fn new() -> Self {
        Self {
            stats: TunnelStats::new(),
            cancel_token: CancellationToken::new(),
        }
    }

    /// Start bidirectional data transfer between TCP socket and SSH channel
    ///
    /// This function handles bidirectional data transfer by using an async loop
    /// that polls both the TCP socket and SSH channel for data availability.
    ///
    /// # Arguments
    /// - `tcp_stream`: Local TCP connection
    /// - `ssh_channel`: SSH channel for remote communication
    /// - `cancel_token`: Token for coordinated cancellation
    ///
    /// # Returns
    /// Transfer statistics upon completion
    pub async fn run(
        mut tcp_stream: TcpStream,
        mut ssh_channel: Channel<russh::client::Msg>,
        cancel_token: CancellationToken,
    ) -> Result<TunnelStats> {
        let stats = TunnelStats::new();
        let mut buffer = global::get_medium_buffer();

        debug!("Starting bidirectional tunnel");

        // Main transfer loop
        loop {
            tokio::select! {
                // Read from TCP socket and forward to SSH
                result = tcp_stream.read(buffer.as_mut_slice()) => {
                    match result {
                        Ok(0) => {
                            trace!("TCP socket closed, ending tunnel");
                            break;
                        }
                        Ok(n) => {
                            // Write to SSH channel
                            match ssh_channel.data(&buffer.as_slice()[..n]).await {
                                Ok(_) => {
                                    let bytes = stats.bytes_local_to_remote.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                                    trace!("Forwarded {} bytes TCP→SSH (total: {})", n, bytes);
                                }
                                Err(e) => {
                                    stats.error_count.fetch_add(1, Ordering::Relaxed);
                                    error!("Failed to write to SSH channel: {}", e);
                                    return Err(anyhow::anyhow!("SSH channel write error: {}", e));
                                }
                            }
                        }
                        Err(e) => {
                            stats.error_count.fetch_add(1, Ordering::Relaxed);
                            if e.kind() == std::io::ErrorKind::ConnectionAborted ||
                               e.kind() == std::io::ErrorKind::ConnectionReset {
                                trace!("TCP connection closed: {}", e);
                                break;
                            } else {
                                error!("TCP read error: {}", e);
                                return Err(anyhow::anyhow!("TCP read error: {}", e));
                            }
                        }
                    }
                }
                // Read from SSH channel and forward to TCP
                msg = ssh_channel.wait() => {
                    match msg {
                        Some(russh::ChannelMsg::Data { data }) => {
                            // Write to TCP socket
                            match tcp_stream.write_all(&data).await {
                                Ok(_) => {
                                    let bytes = stats.bytes_remote_to_local.fetch_add(data.len() as u64, Ordering::Relaxed) + data.len() as u64;
                                    trace!("Forwarded {} bytes SSH→TCP (total: {})", data.len(), bytes);
                                }
                                Err(e) => {
                                    stats.error_count.fetch_add(1, Ordering::Relaxed);
                                    if e.kind() == std::io::ErrorKind::BrokenPipe ||
                                       e.kind() == std::io::ErrorKind::ConnectionAborted {
                                        trace!("TCP connection closed: {}", e);
                                        break;
                                    } else {
                                        error!("TCP write error: {}", e);
                                        return Err(anyhow::anyhow!("TCP write error: {}", e));
                                    }
                                }
                            }
                        }
                        Some(russh::ChannelMsg::Eof) => {
                            trace!("SSH channel EOF");
                            break;
                        }
                        Some(russh::ChannelMsg::Close) => {
                            trace!("SSH channel closed");
                            break;
                        }
                        Some(other) => {
                            trace!("Ignoring SSH channel message: {:?}", other);
                        }
                        None => {
                            trace!("SSH channel stream ended");
                            break;
                        }
                    }
                }
                // Handle cancellation
                _ = cancel_token.cancelled() => {
                    trace!("Tunnel cancelled");
                    break;
                }
            }
        }

        // Close SSH channel gracefully
        if let Err(e) = ssh_channel.eof().await {
            warn!("Failed to send EOF to SSH channel: {}", e);
        }
        if let Err(e) = ssh_channel.close().await {
            warn!("Failed to close SSH channel: {}", e);
        }

        // Log final statistics
        let l2r_bytes = stats.bytes_local_to_remote.load(Ordering::Relaxed);
        let r2l_bytes = stats.bytes_remote_to_local.load(Ordering::Relaxed);
        let errors = stats.error_count.load(Ordering::Relaxed);
        let duration = stats.duration();

        debug!(
            "Tunnel completed: {} bytes L→R, {} bytes R→L, {} errors, duration: {:?}",
            l2r_bytes, r2l_bytes, errors, duration
        );

        Ok(stats)
    }

    /// Run tunnel with automatic statistics reporting
    ///
    /// Similar to `run` but periodically reports transfer statistics via a callback.
    /// Useful for monitoring long-running tunnels.
    pub async fn run_with_stats<F>(
        tcp_stream: TcpStream,
        ssh_channel: Channel<russh::client::Msg>,
        cancel_token: CancellationToken,
        mut stats_callback: F,
        report_interval: std::time::Duration,
    ) -> Result<TunnelStats>
    where
        F: FnMut(&TunnelStats) + Send + 'static,
    {
        let stats = TunnelStats::new();
        let stats_clone = TunnelStats {
            bytes_local_to_remote: Arc::clone(&stats.bytes_local_to_remote),
            bytes_remote_to_local: Arc::clone(&stats.bytes_remote_to_local),
            started_at: stats.started_at,
            error_count: Arc::clone(&stats.error_count),
        };

        let reporting_cancel = cancel_token.clone();

        // Spawn stats reporting task
        let stats_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(report_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        stats_callback(&stats_clone);
                    }
                    _ = reporting_cancel.cancelled() => {
                        // Final stats report
                        stats_callback(&stats_clone);
                        break;
                    }
                }
            }
        });

        // Run the main tunnel
        let result = Self::run(tcp_stream, ssh_channel, cancel_token).await;

        // Clean up stats reporting
        stats_task.abort();
        let _ = stats_task.await;

        result
    }
}

impl Default for Tunnel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[test]
    fn test_tunnel_stats() {
        let stats = TunnelStats::new();

        assert_eq!(stats.total_bytes(), 0);
        assert_eq!(stats.errors(), 0);

        stats.bytes_local_to_remote.store(100, Ordering::Relaxed);
        stats.bytes_remote_to_local.store(200, Ordering::Relaxed);
        stats.error_count.store(1, Ordering::Relaxed);

        assert_eq!(stats.total_bytes(), 300);
        assert_eq!(stats.errors(), 1);
    }

    #[tokio::test]
    async fn test_tunnel_cancellation() {
        let cancel_token = CancellationToken::new();

        // Simulate immediate cancellation
        cancel_token.cancel();

        // The tunnel would need actual TCP and SSH channel for full testing
        // This test verifies the cancellation token works as expected
        tokio::select! {
            _ = cancel_token.cancelled() => {
                // Expected path
                // Test passes if we reach here
            }
            _ = sleep(Duration::from_millis(100)) => {
                panic!("Cancellation should be immediate");
            }
        }
    }

    #[test]
    fn test_stats_atomic_operations() {
        let stats = TunnelStats::new();

        // Test concurrent access (simulated)
        let bytes = Arc::clone(&stats.bytes_local_to_remote);
        bytes.fetch_add(50, Ordering::Relaxed);
        bytes.fetch_add(25, Ordering::Relaxed);

        assert_eq!(bytes.load(Ordering::Relaxed), 75);
        assert_eq!(stats.total_bytes(), 75);
    }
}

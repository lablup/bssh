//! Buffer pool for reducing allocations in hot paths
//!
//! Provides reusable buffer pools to avoid frequent allocations/deallocations
//! in SSH I/O operations, PTY data processing, and file transfers.

use std::sync::{Arc, Mutex, OnceLock};

/// Buffer size constants - carefully chosen for different use cases
///
/// Buffer pool tier design rationale:
/// - Three tiers handle different I/O patterns efficiently
/// - Sizes chosen to match common SSH protocol and terminal patterns
/// - Exponential scaling (1KB -> 8KB -> 64KB) reduces memory waste
///
/// Small buffer (1KB) for terminal key sequences and short responses
/// - Optimal for individual key presses and command responses
/// - Matches typical terminal line lengths and ANSI sequences
/// - Minimizes memory waste for frequent small allocations
const SMALL_BUFFER_SIZE: usize = 1024;

/// Medium buffer (8KB) for SSH command I/O and multi-line output
/// - Optimal for command execution output and multi-line responses
/// - Balances memory usage with syscall efficiency
/// - Matches common SSH channel packet sizes
const MEDIUM_BUFFER_SIZE: usize = 8192;

/// Large buffer (64KB) for SFTP file transfers and bulk operations
/// - Optimal for file transfer operations and large data streams
/// - Reduces syscall overhead for high-throughput operations
/// - Standard size for network I/O buffers in high-performance applications
const LARGE_BUFFER_SIZE: usize = 65536;

/// Maximum number of buffers to keep in each pool tier
/// Buffer pool size design:
/// - 16 buffers per tier balances memory reuse with memory usage
/// - Enough to handle concurrent operations without frequent allocation
/// - Prevents unbounded memory growth under high load
/// - Total pooled memory per tier: 16KB (small), 128KB (medium), 1MB (large)
const MAX_POOL_SIZE: usize = 16;

/// A reusable buffer that automatically returns to the pool when dropped
pub struct PooledBuffer {
    buffer: Vec<u8>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PooledBuffer {
    /// Get the underlying buffer as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    /// Get the underlying buffer as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the buffer capacity
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Get the buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the buffer contents (but keep capacity)
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Resize the buffer to the given length
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.buffer.resize(new_len, value);
    }

    /// Get mutable access to the underlying Vec
    pub fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }

    /// Get immutable access to the underlying Vec
    pub fn as_vec(&self) -> &Vec<u8> {
        &self.buffer
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Clear the buffer and return it to the pool
        self.buffer.clear();

        if let Ok(mut pool) = self.pool.lock() {
            if pool.len() < MAX_POOL_SIZE {
                pool.push(std::mem::take(&mut self.buffer));
            }
        }
    }
}

/// Thread-safe buffer pool for different buffer sizes
pub struct BufferPool {
    small_buffers: Arc<Mutex<Vec<Vec<u8>>>>,
    medium_buffers: Arc<Mutex<Vec<Vec<u8>>>>,
    large_buffers: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new() -> Self {
        Self {
            small_buffers: Arc::new(Mutex::new(Vec::new())),
            medium_buffers: Arc::new(Mutex::new(Vec::new())),
            large_buffers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get a small buffer (1KB) for terminal I/O
    pub fn get_small_buffer(&self) -> PooledBuffer {
        self.get_buffer_from_pool(&self.small_buffers, SMALL_BUFFER_SIZE)
    }

    /// Get a medium buffer (8KB) for SSH command I/O
    pub fn get_medium_buffer(&self) -> PooledBuffer {
        self.get_buffer_from_pool(&self.medium_buffers, MEDIUM_BUFFER_SIZE)
    }

    /// Get a large buffer (64KB) for SFTP transfers
    pub fn get_large_buffer(&self) -> PooledBuffer {
        self.get_buffer_from_pool(&self.large_buffers, LARGE_BUFFER_SIZE)
    }

    /// Get a buffer with custom capacity
    pub fn get_buffer_with_capacity(&self, capacity: usize) -> PooledBuffer {
        // Choose the appropriate pool based on capacity
        if capacity <= SMALL_BUFFER_SIZE {
            self.get_small_buffer()
        } else if capacity <= MEDIUM_BUFFER_SIZE {
            self.get_medium_buffer()
        } else {
            self.get_large_buffer()
        }
    }

    /// Internal method to get buffer from specific pool
    fn get_buffer_from_pool(
        &self,
        pool: &Arc<Mutex<Vec<Vec<u8>>>>,
        default_capacity: usize,
    ) -> PooledBuffer {
        let buffer = if let Ok(mut pool_guard) = pool.lock() {
            pool_guard
                .pop()
                .unwrap_or_else(|| Vec::with_capacity(default_capacity))
        } else {
            Vec::with_capacity(default_capacity)
        };

        PooledBuffer {
            buffer,
            pool: Arc::clone(pool),
        }
    }

    /// Get statistics about the buffer pool
    pub fn stats(&self) -> BufferPoolStats {
        let small_count = self.small_buffers.lock().map(|p| p.len()).unwrap_or(0);
        let medium_count = self.medium_buffers.lock().map(|p| p.len()).unwrap_or(0);
        let large_count = self.large_buffers.lock().map(|p| p.len()).unwrap_or(0);

        BufferPoolStats {
            small_buffers_pooled: small_count,
            medium_buffers_pooled: medium_count,
            large_buffers_pooled: large_count,
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for buffer pool usage
#[derive(Debug, Clone)]
pub struct BufferPoolStats {
    pub small_buffers_pooled: usize,
    pub medium_buffers_pooled: usize,
    pub large_buffers_pooled: usize,
}

/// Global buffer pool instance
static GLOBAL_BUFFER_POOL: OnceLock<BufferPool> = OnceLock::new();

/// Get the global buffer pool instance
pub fn global_buffer_pool() -> &'static BufferPool {
    GLOBAL_BUFFER_POOL.get_or_init(BufferPool::new)
}

/// Convenience functions for getting buffers from global pool
pub mod global {
    use super::*;

    /// Get a small buffer from the global pool
    pub fn get_small_buffer() -> PooledBuffer {
        global_buffer_pool().get_small_buffer()
    }

    /// Get a medium buffer from the global pool
    pub fn get_medium_buffer() -> PooledBuffer {
        global_buffer_pool().get_medium_buffer()
    }

    /// Get a large buffer from the global pool
    pub fn get_large_buffer() -> PooledBuffer {
        global_buffer_pool().get_large_buffer()
    }

    /// Get a buffer with specific capacity from the global pool
    pub fn get_buffer_with_capacity(capacity: usize) -> PooledBuffer {
        global_buffer_pool().get_buffer_with_capacity(capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_basic() {
        let pool = BufferPool::new();

        // Get a buffer and use it
        {
            let mut buffer = pool.get_small_buffer();
            buffer.as_mut_vec().extend_from_slice(b"hello");
            assert_eq!(buffer.len(), 5);
            assert_eq!(buffer.as_slice(), b"hello");
        } // Buffer is returned to pool here

        // Get another buffer - should reuse the previous one
        let buffer2 = pool.get_small_buffer();
        assert_eq!(buffer2.len(), 0); // Should be cleared
        assert!(buffer2.capacity() >= SMALL_BUFFER_SIZE);
    }

    #[test]
    fn test_buffer_pool_stats() {
        let pool = BufferPool::new();
        let stats = pool.stats();
        assert_eq!(stats.small_buffers_pooled, 0);

        // Create and drop a buffer
        {
            let _buffer = pool.get_small_buffer();
        }

        let stats = pool.stats();
        assert_eq!(stats.small_buffers_pooled, 1);
    }

    #[test]
    fn test_global_buffer_pool() {
        let buffer1 = global::get_small_buffer();
        let buffer2 = global::get_medium_buffer();
        let buffer3 = global::get_large_buffer();

        assert!(buffer1.capacity() >= SMALL_BUFFER_SIZE);
        assert!(buffer2.capacity() >= MEDIUM_BUFFER_SIZE);
        assert!(buffer3.capacity() >= LARGE_BUFFER_SIZE);
    }
}

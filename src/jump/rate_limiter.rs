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

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

/// Token bucket rate limiter for connection attempts
///
/// Prevents DoS attacks by limiting the rate of connection attempts
/// per host. Uses a token bucket algorithm with configurable capacity
/// and refill rate.
#[derive(Debug, Clone)]
pub struct ConnectionRateLimiter {
    /// Token buckets per host
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    /// Maximum tokens per bucket (burst capacity)
    max_tokens: u32,
    /// Tokens refilled per second
    refill_rate: f64,
    /// Duration after which inactive buckets are cleaned up
    cleanup_after: Duration,
}

#[derive(Debug)]
struct TokenBucket {
    /// Current token count
    tokens: f64,
    /// Last refill timestamp
    last_refill: Instant,
    /// Last access timestamp (for cleanup)
    last_access: Instant,
}

impl ConnectionRateLimiter {
    /// Create a new rate limiter with default settings
    ///
    /// Default: 10 connections burst, 2 connections/second sustained
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            max_tokens: 10,                          // Allow burst of 10 connections
            refill_rate: 2.0,                        // 2 connections per second sustained
            cleanup_after: Duration::from_secs(300), // Clean up after 5 minutes
        }
    }

    /// Create a new rate limiter with custom settings
    pub fn with_config(max_tokens: u32, refill_rate: f64) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            max_tokens,
            refill_rate,
            cleanup_after: Duration::from_secs(300),
        }
    }

    /// Try to acquire a token for a connection attempt
    ///
    /// Returns Ok(()) if a token was acquired, or an error if rate limited
    pub async fn try_acquire(&self, host: &str) -> Result<()> {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        // Clean up old buckets periodically
        if buckets.len() > 100 {
            self.cleanup_old_buckets(&mut buckets, now);
        }

        let bucket = buckets
            .entry(host.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: self.max_tokens as f64,
                last_refill: now,
                last_access: now,
            });

        // Refill tokens based on time elapsed
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * self.refill_rate;
        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.max_tokens as f64);
        bucket.last_refill = now;
        bucket.last_access = now;

        // Try to consume a token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let wait_time = (1.0 - bucket.tokens) / self.refill_rate;
            warn!(
                "Rate limit exceeded for host {}: wait {:.1}s before retry",
                host, wait_time
            );
            bail!(
                "Connection rate limit exceeded for {host}. Please wait {wait_time:.1} seconds before retrying."
            )
        }
    }

    /// Check if a host is currently rate limited without consuming a token
    pub async fn is_rate_limited(&self, host: &str) -> bool {
        let buckets = self.buckets.read().await;
        if let Some(bucket) = buckets.get(host) {
            let now = Instant::now();
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            let tokens_available =
                (bucket.tokens + elapsed * self.refill_rate).min(self.max_tokens as f64);
            tokens_available < 1.0
        } else {
            false
        }
    }

    /// Clean up old token buckets that haven't been used recently
    fn cleanup_old_buckets(&self, buckets: &mut HashMap<String, TokenBucket>, now: Instant) {
        buckets.retain(|_host, bucket| now.duration_since(bucket.last_access) < self.cleanup_after);
    }

    /// Reset rate limit for a specific host (useful for testing or admin override)
    pub async fn reset_host(&self, host: &str) {
        let mut buckets = self.buckets.write().await;
        buckets.remove(host);
    }

    /// Clear all rate limit data
    pub async fn clear_all(&self) {
        let mut buckets = self.buckets.write().await;
        buckets.clear();
    }
}

impl Default for ConnectionRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_burst() {
        let limiter = ConnectionRateLimiter::with_config(3, 1.0);

        // Should allow 3 connections in burst
        assert!(limiter.try_acquire("test.com").await.is_ok());
        assert!(limiter.try_acquire("test.com").await.is_ok());
        assert!(limiter.try_acquire("test.com").await.is_ok());

        // 4th should fail
        assert!(limiter.try_acquire("test.com").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_refills() {
        let limiter = ConnectionRateLimiter::with_config(2, 10.0); // Fast refill for testing

        // Use up tokens
        assert!(limiter.try_acquire("test.com").await.is_ok());
        assert!(limiter.try_acquire("test.com").await.is_ok());
        assert!(limiter.try_acquire("test.com").await.is_err());

        // Wait for refill
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should have refilled
        assert!(limiter.try_acquire("test.com").await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_per_host() {
        let limiter = ConnectionRateLimiter::with_config(1, 1.0);

        // Different hosts should have separate buckets
        assert!(limiter.try_acquire("host1.com").await.is_ok());
        assert!(limiter.try_acquire("host2.com").await.is_ok());

        // But same host should be limited
        assert!(limiter.try_acquire("host1.com").await.is_err());
    }
}

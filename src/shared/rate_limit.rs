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

//! Generic rate limiting using the token bucket algorithm.
//!
//! This module provides a reusable rate limiter that can be used for:
//! - Client: Connection attempt rate limiting
//! - Server: Authentication attempt rate limiting (fail2ban-like)
//!
//! # Token Bucket Algorithm
//!
//! The token bucket algorithm allows for bursting while maintaining
//! a sustained rate limit. Each bucket:
//! - Has a maximum capacity (burst size)
//! - Refills at a configured rate
//! - Requires one token per operation
//!
//! # Examples
//!
//! ```
//! use bssh::shared::rate_limit::{RateLimiter, RateLimitConfig};
//! use std::time::Duration;
//!
//! // Create a rate limiter for string keys (e.g., hostnames)
//! let config = RateLimitConfig::new(10, 2.0, Duration::from_secs(300));
//! let limiter: RateLimiter<String> = RateLimiter::with_config(config);
//!
//! // Use with different key types
//! // For IP addresses: RateLimiter<std::net::IpAddr>
//! // For user IDs: RateLimiter<u64>
//! ```

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

/// Configuration for rate limiting.
///
/// This struct defines the parameters for the token bucket algorithm:
/// - `max_tokens`: Maximum tokens (burst capacity)
/// - `refill_rate`: Tokens added per second
/// - `cleanup_after`: Duration after which inactive buckets are removed
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum tokens per bucket (burst capacity)
    pub max_tokens: u32,
    /// Tokens refilled per second
    pub refill_rate: f64,
    /// Duration after which inactive buckets are cleaned up
    pub cleanup_after: Duration,
}

impl RateLimitConfig {
    /// Create a new rate limit configuration.
    ///
    /// # Arguments
    ///
    /// * `max_tokens` - Maximum tokens per bucket (burst capacity)
    /// * `refill_rate` - Tokens refilled per second (sustained rate)
    /// * `cleanup_after` - Duration after which inactive buckets are removed
    ///
    /// # Examples
    ///
    /// ```
    /// use bssh::shared::rate_limit::RateLimitConfig;
    /// use std::time::Duration;
    ///
    /// // Allow burst of 10, sustained 2/sec, cleanup after 5 minutes
    /// let config = RateLimitConfig::new(10, 2.0, Duration::from_secs(300));
    /// ```
    pub fn new(max_tokens: u32, refill_rate: f64, cleanup_after: Duration) -> Self {
        Self {
            max_tokens,
            refill_rate,
            cleanup_after,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_tokens: 10,                          // Allow burst of 10 operations
            refill_rate: 2.0,                        // 2 operations per second sustained
            cleanup_after: Duration::from_secs(300), // Clean up after 5 minutes
        }
    }
}

/// Token bucket for a single key.
#[derive(Debug)]
struct TokenBucket {
    /// Current token count
    tokens: f64,
    /// Last refill timestamp
    last_refill: Instant,
    /// Last access timestamp (for cleanup)
    last_access: Instant,
}

/// Generic token bucket rate limiter.
///
/// This rate limiter can be used with any hashable key type, making it
/// suitable for various use cases:
/// - Connection rate limiting by hostname (String)
/// - Authentication rate limiting by IP address (IpAddr)
/// - API rate limiting by user ID (u64)
///
/// # Type Parameters
///
/// * `K` - The key type used to identify rate limit buckets.
///   Must implement `Hash`, `Eq`, `Clone`, and `Send + Sync`.
///
/// # Thread Safety
///
/// The rate limiter is thread-safe and can be shared across async tasks.
///
/// # Examples
///
/// ```
/// use bssh::shared::rate_limit::{RateLimiter, RateLimitConfig};
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///     let limiter: RateLimiter<String> = RateLimiter::new();
///
///     // Acquire a token for a host
///     if limiter.try_acquire(&"example.com".to_string()).await.is_ok() {
///         println!("Allowed");
///     } else {
///         println!("Rate limited");
///     }
/// }
/// ```
#[derive(Debug)]
pub struct RateLimiter<K>
where
    K: Hash + Eq + Clone + Send + Sync,
{
    /// Token buckets per key
    buckets: Arc<RwLock<HashMap<K, TokenBucket>>>,
    /// Rate limit configuration
    config: RateLimitConfig,
}

impl<K> RateLimiter<K>
where
    K: Hash + Eq + Clone + Send + Sync + std::fmt::Display,
{
    /// Create a new rate limiter with default settings.
    ///
    /// Default: 10 operations burst, 2 operations/second sustained,
    /// cleanup after 5 minutes of inactivity.
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            config: RateLimitConfig::default(),
        }
    }

    /// Create a new rate limiter with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The rate limit configuration
    ///
    /// # Examples
    ///
    /// ```
    /// use bssh::shared::rate_limit::{RateLimiter, RateLimitConfig};
    /// use std::time::Duration;
    ///
    /// let config = RateLimitConfig::new(5, 1.0, Duration::from_secs(60));
    /// let limiter: RateLimiter<String> = RateLimiter::with_config(config);
    /// ```
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a new rate limiter with simple configuration.
    ///
    /// # Arguments
    ///
    /// * `max_tokens` - Maximum tokens (burst capacity)
    /// * `refill_rate` - Tokens refilled per second
    ///
    /// # Examples
    ///
    /// ```
    /// use bssh::shared::rate_limit::RateLimiter;
    ///
    /// // Allow burst of 5, sustained 1/sec
    /// let limiter: RateLimiter<String> = RateLimiter::with_simple_config(5, 1.0);
    /// ```
    pub fn with_simple_config(max_tokens: u32, refill_rate: f64) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            config: RateLimitConfig {
                max_tokens,
                refill_rate,
                cleanup_after: Duration::from_secs(300),
            },
        }
    }

    /// Try to acquire a token for the given key.
    ///
    /// Returns `Ok(())` if a token was acquired, or an error if rate limited.
    ///
    /// # Arguments
    ///
    /// * `key` - The key identifying the rate limit bucket
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the operation is allowed
    /// - `Err(...)` if rate limited, with the wait time in the error message
    ///
    /// # Examples
    ///
    /// ```
    /// use bssh::shared::rate_limit::RateLimiter;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let limiter: RateLimiter<String> = RateLimiter::new();
    ///
    ///     match limiter.try_acquire(&"key".to_string()).await {
    ///         Ok(()) => println!("Allowed"),
    ///         Err(e) => println!("Rate limited: {e}"),
    ///     }
    /// }
    /// ```
    pub async fn try_acquire(&self, key: &K) -> Result<()> {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        // Clean up old buckets periodically
        if buckets.len() > 100 {
            self.cleanup_old_buckets(&mut buckets, now);
        }

        let bucket = buckets.entry(key.clone()).or_insert_with(|| TokenBucket {
            tokens: self.config.max_tokens as f64,
            last_refill: now,
            last_access: now,
        });

        // Refill tokens based on time elapsed
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * self.config.refill_rate;
        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.config.max_tokens as f64);
        bucket.last_refill = now;
        bucket.last_access = now;

        // Try to consume a token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let wait_time = (1.0 - bucket.tokens) / self.config.refill_rate;
            warn!(
                "Rate limit exceeded for {}: wait {:.1}s before retry",
                key, wait_time
            );
            bail!(
                "Rate limit exceeded for {key}. Please wait {wait_time:.1} seconds before retrying."
            )
        }
    }

    /// Check if a key is currently rate limited without consuming a token.
    ///
    /// This is useful for checking rate limit status without affecting the bucket.
    ///
    /// # Arguments
    ///
    /// * `key` - The key identifying the rate limit bucket
    ///
    /// # Returns
    ///
    /// `true` if the key is rate limited, `false` otherwise.
    pub async fn is_rate_limited(&self, key: &K) -> bool {
        let buckets = self.buckets.read().await;
        if let Some(bucket) = buckets.get(key) {
            let now = Instant::now();
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            let tokens_available = (bucket.tokens + elapsed * self.config.refill_rate)
                .min(self.config.max_tokens as f64);
            tokens_available < 1.0
        } else {
            false
        }
    }

    /// Get the current token count for a key.
    ///
    /// Returns `None` if the key has no bucket (never been rate limited).
    ///
    /// # Arguments
    ///
    /// * `key` - The key identifying the rate limit bucket
    ///
    /// # Returns
    ///
    /// The current (estimated) token count, or `None` if no bucket exists.
    pub async fn get_tokens(&self, key: &K) -> Option<f64> {
        let buckets = self.buckets.read().await;
        buckets.get(key).map(|bucket| {
            let now = Instant::now();
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            (bucket.tokens + elapsed * self.config.refill_rate).min(self.config.max_tokens as f64)
        })
    }

    /// Clean up old token buckets that haven't been used recently.
    fn cleanup_old_buckets(&self, buckets: &mut HashMap<K, TokenBucket>, now: Instant) {
        buckets.retain(|_key, bucket| {
            now.duration_since(bucket.last_access) < self.config.cleanup_after
        });
    }

    /// Reset rate limit for a specific key.
    ///
    /// This removes the bucket for the key, allowing a fresh start.
    /// Useful for testing or administrative overrides.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to reset
    pub async fn reset_key(&self, key: &K) {
        let mut buckets = self.buckets.write().await;
        buckets.remove(key);
    }

    /// Clear all rate limit data.
    ///
    /// This removes all buckets, resetting the rate limiter to initial state.
    pub async fn clear_all(&self) {
        let mut buckets = self.buckets.write().await;
        buckets.clear();
    }

    /// Get the number of tracked keys.
    ///
    /// Returns the number of keys currently being rate limited.
    pub async fn tracked_key_count(&self) -> usize {
        let buckets = self.buckets.read().await;
        buckets.len()
    }

    /// Get the rate limit configuration.
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

impl<K> Default for RateLimiter<K>
where
    K: Hash + Eq + Clone + Send + Sync + std::fmt::Display,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K> Clone for RateLimiter<K>
where
    K: Hash + Eq + Clone + Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            buckets: Arc::clone(&self.buckets),
            config: self.config.clone(),
        }
    }
}

/// Type alias for connection rate limiting by hostname.
///
/// This is a convenience type for the common use case of rate limiting
/// connection attempts per hostname string.
pub type ConnectionRateLimiter = RateLimiter<String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_burst() {
        let limiter: RateLimiter<String> = RateLimiter::with_simple_config(3, 1.0);

        // Should allow 3 operations in burst
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_ok());

        // 4th should fail
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_refills() {
        let limiter: RateLimiter<String> = RateLimiter::with_simple_config(2, 10.0); // Fast refill for testing

        // Use up tokens
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_err());

        // Wait for refill
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should have refilled
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_per_key() {
        let limiter: RateLimiter<String> = RateLimiter::with_simple_config(1, 1.0);

        // Different keys should have separate buckets
        assert!(limiter.try_acquire(&"host1.com".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"host2.com".to_string()).await.is_ok());

        // But same key should be limited
        assert!(limiter.try_acquire(&"host1.com".to_string()).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_with_numeric_key() {
        // Test with numeric keys (e.g., user IDs)
        let limiter: RateLimiter<u64> = RateLimiter::with_simple_config(2, 1.0);

        assert!(limiter.try_acquire(&1).await.is_ok());
        assert!(limiter.try_acquire(&1).await.is_ok());
        assert!(limiter.try_acquire(&1).await.is_err());
        assert!(limiter.try_acquire(&2).await.is_ok()); // Different key
    }

    #[tokio::test]
    async fn test_is_rate_limited() {
        let limiter: RateLimiter<String> = RateLimiter::with_simple_config(1, 1.0);

        // Initially not limited
        assert!(!limiter.is_rate_limited(&"test".to_string()).await);

        // Use up tokens
        assert!(limiter.try_acquire(&"test".to_string()).await.is_ok());

        // Now limited
        assert!(limiter.is_rate_limited(&"test".to_string()).await);
    }

    #[tokio::test]
    async fn test_reset_key() {
        let limiter: RateLimiter<String> = RateLimiter::with_simple_config(1, 1.0);

        // Use up tokens
        assert!(limiter.try_acquire(&"test".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"test".to_string()).await.is_err());

        // Reset
        limiter.reset_key(&"test".to_string()).await;

        // Should work again
        assert!(limiter.try_acquire(&"test".to_string()).await.is_ok());
    }

    #[tokio::test]
    async fn test_clear_all() {
        let limiter: RateLimiter<String> = RateLimiter::with_simple_config(1, 1.0);

        // Use up tokens for multiple keys
        assert!(limiter.try_acquire(&"host1".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"host2".to_string()).await.is_ok());
        assert_eq!(limiter.tracked_key_count().await, 2);

        // Clear all
        limiter.clear_all().await;

        // Should be empty
        assert_eq!(limiter.tracked_key_count().await, 0);

        // All should work again
        assert!(limiter.try_acquire(&"host1".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"host2".to_string()).await.is_ok());
    }
}

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

//! Token bucket rate limiter for connection attempts.
//!
//! This module re-exports the rate limiter from the shared module for
//! backward compatibility. New code should prefer importing directly from
//! `crate::shared::rate_limit`.
//!
//! # Migration Note
//!
//! The rate limiter has been moved to `crate::shared::rate_limit` and
//! generalized to work with any hashable key type. This module continues
//! to export `ConnectionRateLimiter` (which is `RateLimiter<String>`) for
//! backward compatibility.
//!
//! # Examples
//!
//! ```rust
//! // Old style (still works)
//! use bssh::jump::rate_limiter::ConnectionRateLimiter;
//!
//! // New style (preferred for new code)
//! use bssh::shared::rate_limit::{RateLimiter, RateLimitConfig};
//! ```

// Re-export the ConnectionRateLimiter type alias for backward compatibility
pub use crate::shared::rate_limit::ConnectionRateLimiter;

// Also re-export RateLimitConfig for users who want to configure the limiter
pub use crate::shared::rate_limit::RateLimitConfig;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_rate_limiter_allows_burst() {
        let limiter = ConnectionRateLimiter::with_simple_config(3, 1.0);

        // Should allow 3 connections in burst
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_ok());

        // 4th should fail
        assert!(limiter.try_acquire(&"test.com".to_string()).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_refills() {
        let limiter = ConnectionRateLimiter::with_simple_config(2, 10.0); // Fast refill for testing

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
    async fn test_rate_limiter_per_host() {
        let limiter = ConnectionRateLimiter::with_simple_config(1, 1.0);

        // Different hosts should have separate buckets
        assert!(limiter.try_acquire(&"host1.com".to_string()).await.is_ok());
        assert!(limiter.try_acquire(&"host2.com".to_string()).await.is_ok());

        // But same host should be limited
        assert!(limiter.try_acquire(&"host1.com".to_string()).await.is_err());
    }
}

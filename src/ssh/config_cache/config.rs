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

use std::time::Duration;

/// Configuration options for the SSH config cache
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in the cache (default: 100)
    pub max_entries: usize,
    /// Time-to-live for cache entries (default: 300 seconds)
    pub ttl: Duration,
    /// Whether caching is enabled (default: true)
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 100,
            ttl: Duration::from_secs(300), // 5 minutes
            enabled: true,
        }
    }
}

impl CacheConfig {
    /// Create a new cache configuration with specified parameters
    pub fn new(max_entries: usize, ttl: Duration, enabled: bool) -> Self {
        Self {
            max_entries,
            ttl,
            enabled,
        }
    }

    /// Create a disabled cache configuration
    pub fn disabled() -> Self {
        Self {
            max_entries: 0,
            ttl: Duration::from_secs(0),
            enabled: false,
        }
    }

    /// Create a cache configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            max_entries: std::env::var("BSSH_CACHE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            ttl: Duration::from_secs(
                std::env::var("BSSH_CACHE_TTL")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(300),
            ),
            enabled: std::env::var("BSSH_CACHE_ENABLED")
                .map(|s| s.to_lowercase() != "false" && s != "0")
                .unwrap_or(true),
        }
    }
}

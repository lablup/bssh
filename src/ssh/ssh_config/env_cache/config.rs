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

//! Configuration for the environment variable cache

use std::time::Duration;

/// Configuration for the environment variable cache
#[derive(Debug, Clone)]
pub struct EnvCacheConfig {
    /// Time-to-live for cache entries (default: 30 seconds)
    pub ttl: Duration,
    /// Whether caching is enabled (default: true)
    pub enabled: bool,
    /// Maximum cache size (default: 50 entries)
    pub max_entries: usize,
}

impl Default for EnvCacheConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(30), // 30 seconds TTL for environment variables
            enabled: true,
            max_entries: 50, // Conservative limit for environment variables
        }
    }
}

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

//! Cache statistics tracking for monitoring and debugging

/// Cache statistics for monitoring and debugging
#[derive(Debug, Clone, Default)]
pub struct EnvCacheStats {
    /// Total number of cache hits
    pub hits: u64,
    /// Total number of cache misses
    pub misses: u64,
    /// Number of entries evicted due to TTL expiration
    pub ttl_evictions: u64,
    /// Current number of entries in cache
    pub current_entries: usize,
    /// Maximum number of entries allowed
    #[allow(dead_code)]
    pub max_entries: usize,
}

impl EnvCacheStats {
    #[allow(dead_code)]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

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

/// Cache statistics for monitoring and debugging
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total number of cache hits
    pub hits: u64,
    /// Total number of cache misses
    pub misses: u64,
    /// Number of entries evicted due to TTL expiration
    pub ttl_evictions: u64,
    /// Number of entries evicted due to file modification
    pub stale_evictions: u64,
    /// Number of entries evicted due to LRU policy
    pub lru_evictions: u64,
    /// Current number of entries in cache
    pub current_entries: usize,
    /// Maximum number of entries allowed
    pub max_entries: usize,
}

impl CacheStats {
    /// Calculate the cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Calculate the cache miss rate
    pub fn miss_rate(&self) -> f64 {
        1.0 - self.hit_rate()
    }

    /// Get the total number of evictions
    pub fn total_evictions(&self) -> u64 {
        self.ttl_evictions + self.stale_evictions + self.lru_evictions
    }

    /// Get the total number of cache operations (hits + misses)
    pub fn total_operations(&self) -> u64 {
        self.hits + self.misses
    }

    /// Check if the cache is full
    pub fn is_full(&self) -> bool {
        self.current_entries >= self.max_entries
    }

    /// Get cache utilization percentage
    pub fn utilization(&self) -> f64 {
        if self.max_entries == 0 {
            0.0
        } else {
            (self.current_entries as f64 / self.max_entries as f64) * 100.0
        }
    }

    /// Reset all statistics
    pub fn reset(&mut self) {
        self.hits = 0;
        self.misses = 0;
        self.ttl_evictions = 0;
        self.stale_evictions = 0;
        self.lru_evictions = 0;
        // Keep current_entries and max_entries as they reflect current state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_stats_rates() {
        let mut stats = CacheStats {
            hits: 75,
            misses: 25,
            ..Default::default()
        };

        assert_eq!(stats.hit_rate(), 0.75);
        assert_eq!(stats.miss_rate(), 0.25);
        assert_eq!(stats.total_operations(), 100);

        // Test empty stats
        stats.reset();
        assert_eq!(stats.hit_rate(), 0.0);
        assert_eq!(stats.miss_rate(), 1.0);
    }

    #[test]
    fn test_cache_stats_evictions() {
        let stats = CacheStats {
            ttl_evictions: 10,
            stale_evictions: 5,
            lru_evictions: 3,
            ..Default::default()
        };

        assert_eq!(stats.total_evictions(), 18);
    }

    #[test]
    fn test_cache_stats_utilization() {
        let stats = CacheStats {
            current_entries: 50,
            max_entries: 100,
            ..Default::default()
        };

        assert_eq!(stats.utilization(), 50.0);
        assert!(!stats.is_full());

        let full_stats = CacheStats {
            current_entries: 100,
            max_entries: 100,
            ..Default::default()
        };

        assert!(full_stats.is_full());
        assert_eq!(full_stats.utilization(), 100.0);
    }
}

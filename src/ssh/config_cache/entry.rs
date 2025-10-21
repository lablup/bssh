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

use crate::ssh::SshConfig;
use std::time::{Duration, Instant, SystemTime};

/// Metadata about a cached SSH config entry
#[derive(Debug, Clone)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct CacheEntry {
    /// The cached SSH configuration
    pub(super) config: SshConfig,
    /// When this entry was cached
    pub(super) cached_at: Instant,
    /// File modification time when this entry was cached
    pub(super) file_mtime: SystemTime,
    /// Number of times this entry has been accessed
    pub(super) access_count: u64,
    /// Last access time
    pub(super) last_accessed: Instant,
}

impl CacheEntry {
    pub fn new(config: SshConfig, file_mtime: SystemTime) -> Self {
        let now = Instant::now();
        Self {
            config,
            cached_at: now,
            file_mtime,
            access_count: 0,
            last_accessed: now,
        }
    }

    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }

    pub fn is_stale(&self, current_mtime: SystemTime) -> bool {
        self.file_mtime != current_mtime
    }

    pub fn access(&mut self) -> &SshConfig {
        self.access_count += 1;
        self.last_accessed = Instant::now();
        &self.config
    }

    /// Get the age of this cache entry
    pub fn age(&self) -> Duration {
        self.cached_at.elapsed()
    }

    /// Get the duration since last access
    pub fn time_since_last_access(&self) -> Duration {
        self.last_accessed.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_expiration() {
        let config = SshConfig::new();
        let mtime = SystemTime::now();
        let mut entry = CacheEntry::new(config, mtime);

        // Fresh entry should not be expired
        assert!(!entry.is_expired(Duration::from_secs(300)));

        // Simulate time passing by creating an old entry
        entry.cached_at = Instant::now() - Duration::from_secs(400);
        assert!(entry.is_expired(Duration::from_secs(300)));
    }

    #[test]
    fn test_cache_entry_staleness() {
        let config = SshConfig::new();
        let old_mtime = SystemTime::UNIX_EPOCH;
        let new_mtime = SystemTime::now();

        let entry = CacheEntry::new(config, old_mtime);

        assert!(!entry.is_stale(old_mtime));
        assert!(entry.is_stale(new_mtime));
    }

    #[test]
    fn test_cache_entry_access() {
        let config = SshConfig::new();
        let mtime = SystemTime::now();
        let mut entry = CacheEntry::new(config, mtime);

        assert_eq!(entry.access_count, 0);
        let _ = entry.access();
        assert_eq!(entry.access_count, 1);
        let _ = entry.access();
        assert_eq!(entry.access_count, 2);
    }
}

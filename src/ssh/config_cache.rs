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
use anyhow::{Context, Result};
use lru::LruCache;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, trace};

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

/// Metadata about a cached SSH config entry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached SSH configuration
    config: SshConfig,
    /// When this entry was cached
    cached_at: Instant,
    /// File modification time when this entry was cached
    file_mtime: SystemTime,
    /// Number of times this entry has been accessed
    access_count: u64,
    /// Last access time
    last_accessed: Instant,
}

impl CacheEntry {
    fn new(config: SshConfig, file_mtime: SystemTime) -> Self {
        let now = Instant::now();
        Self {
            config,
            cached_at: now,
            file_mtime,
            access_count: 0,
            last_accessed: now,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }

    fn is_stale(&self, current_mtime: SystemTime) -> bool {
        self.file_mtime != current_mtime
    }

    fn access(&mut self) -> &SshConfig {
        self.access_count += 1;
        self.last_accessed = Instant::now();
        &self.config
    }
}

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
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    pub fn miss_rate(&self) -> f64 {
        1.0 - self.hit_rate()
    }
}

/// Thread-safe LRU cache for SSH configurations
pub struct SshConfigCache {
    /// LRU cache implementation
    cache: Arc<RwLock<LruCache<PathBuf, CacheEntry>>>,
    /// Cache configuration
    config: CacheConfig,
    /// Cache statistics
    stats: Arc<RwLock<CacheStats>>,
}

impl SshConfigCache {
    /// Create a new SSH config cache with default configuration
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Create a new SSH config cache with custom configuration
    pub fn with_config(config: CacheConfig) -> Self {
        let cache_size = std::num::NonZeroUsize::new(config.max_entries)
            .unwrap_or(std::num::NonZeroUsize::new(100).unwrap());

        let stats = CacheStats {
            max_entries: config.max_entries,
            ..Default::default()
        };

        Self {
            cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            config,
            stats: Arc::new(RwLock::new(stats)),
        }
    }

    /// Get an SSH config from cache or load it from file
    pub async fn get_or_load<P: AsRef<Path>>(&self, path: P) -> Result<SshConfig> {
        if !self.config.enabled {
            return SshConfig::load_from_file(path).await;
        }

        let path_ref = path.as_ref();
        let path = tokio::fs::canonicalize(path_ref)
            .await
            .with_context(|| format!("Failed to canonicalize path: {}", path_ref.display()))?;

        // Check if file exists and get its modification time
        let file_metadata = tokio::fs::metadata(&path)
            .await
            .with_context(|| format!("Failed to read file metadata: {}", path.display()))?;

        let current_mtime = file_metadata
            .modified()
            .with_context(|| format!("Failed to get modification time: {}", path.display()))?;

        // Try to get from cache first
        if let Some(config) = self.try_get_cached(&path, current_mtime)? {
            return Ok(config);
        }

        // Cache miss - load from file
        trace!("Cache miss for SSH config: {}", path.display());
        let config = SshConfig::load_from_file(&path)
            .await
            .with_context(|| format!("Failed to load SSH config from file: {}", path.display()))?;

        // Store in cache
        self.put(path, config.clone(), current_mtime);

        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.misses += 1;
        }

        Ok(config)
    }

    /// Try to get a cached entry, checking for expiration and staleness
    fn try_get_cached(&self, path: &Path, current_mtime: SystemTime) -> Result<Option<SshConfig>> {
        let mut cache = self.cache.write().unwrap();

        if let Some(entry) = cache.get_mut(path) {
            // Check if entry is expired
            if entry.is_expired(self.config.ttl) {
                debug!("SSH config cache entry expired: {}", path.display());
                cache.pop(path);

                let mut stats = self.stats.write().unwrap();
                stats.ttl_evictions += 1;
                return Ok(None);
            }

            // Check if entry is stale (file was modified)
            if entry.is_stale(current_mtime) {
                debug!("SSH config cache entry stale: {}", path.display());
                cache.pop(path);

                let mut stats = self.stats.write().unwrap();
                stats.stale_evictions += 1;
                return Ok(None);
            }

            // Entry is valid - access it and return
            let config = entry.access().clone();

            // Update statistics
            {
                let mut stats = self.stats.write().unwrap();
                stats.hits += 1;
            }

            trace!("SSH config cache hit: {}", path.display());
            return Ok(Some(config));
        }

        Ok(None)
    }

    /// Put an entry in the cache
    fn put(&self, path: PathBuf, config: SshConfig, file_mtime: SystemTime) {
        let mut cache = self.cache.write().unwrap();

        // Check if we're evicting an entry due to LRU policy
        let will_evict = cache.len() >= cache.cap().get();

        let entry = CacheEntry::new(config, file_mtime);
        cache.put(path.clone(), entry);

        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            if will_evict {
                stats.lru_evictions += 1;
            }
            stats.current_entries = cache.len();
        }

        trace!("SSH config cached: {}", path.display());
    }

    /// Load SSH config from default locations with caching
    pub async fn load_default(&self) -> Result<SshConfig> {
        if !self.config.enabled {
            return SshConfig::load_default().await;
        }

        // Try user-specific SSH config first
        if let Some(home_dir) = dirs::home_dir() {
            let user_config = home_dir.join(".ssh").join("config");
            if tokio::fs::try_exists(&user_config).await.unwrap_or(false) {
                return self.get_or_load(&user_config).await;
            }
        }

        // Try system-wide SSH config
        let system_config = Path::new("/etc/ssh/ssh_config");
        if tokio::fs::try_exists(system_config).await.unwrap_or(false) {
            return self.get_or_load(system_config).await;
        }

        // Return empty config if no files found
        Ok(SshConfig::new())
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();

        let mut stats = self.stats.write().unwrap();
        stats.current_entries = 0;
    }

    /// Remove a specific entry from the cache
    pub async fn remove<P: AsRef<Path>>(&self, path: P) -> Option<SshConfig> {
        let path = path.as_ref();
        if let Ok(canonical_path) = tokio::fs::canonicalize(path).await {
            let mut cache = self.cache.write().unwrap();
            let entry = cache.pop(&canonical_path)?;

            let mut stats = self.stats.write().unwrap();
            stats.current_entries = cache.len();

            Some(entry.config)
        } else {
            None
        }
    }

    /// Get current cache statistics
    pub fn stats(&self) -> CacheStats {
        self.stats.read().unwrap().clone()
    }

    /// Get cache configuration
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Update cache configuration (will clear cache if max_entries changed)
    pub fn update_config(&mut self, new_config: CacheConfig) {
        if new_config.max_entries != self.config.max_entries {
            // Need to recreate cache with new size
            let cache_size = std::num::NonZeroUsize::new(new_config.max_entries)
                .unwrap_or(std::num::NonZeroUsize::new(100).unwrap());

            self.cache = Arc::new(RwLock::new(LruCache::new(cache_size)));

            let mut stats = self.stats.write().unwrap();
            stats.max_entries = new_config.max_entries;
            stats.current_entries = 0;
        }

        self.config = new_config;
    }

    /// Perform cache maintenance (remove expired and stale entries)
    pub async fn maintain(&self) -> usize {
        if !self.config.enabled {
            return 0;
        }

        let mut to_remove = Vec::new();
        let mut expired_count = 0;
        let mut stale_count = 0;

        // Collect keys to check and expired entries (can't remove while iterating)
        // We'll use tokio::spawn to check file metadata concurrently
        let mut check_tasks = Vec::new();

        {
            // Scope the lock to release it before awaiting
            let cache = self.cache.write().unwrap();

            for (path, entry) in cache.iter() {
                if entry.is_expired(self.config.ttl) {
                    to_remove.push(path.clone());
                    expired_count += 1;
                } else {
                    let path_clone = path.clone();
                    let entry_mtime = entry.file_mtime;
                    check_tasks.push(tokio::spawn(async move {
                        if let Ok(metadata) = tokio::fs::metadata(&path_clone).await {
                            if let Ok(current_mtime) = metadata.modified() {
                                (path_clone, entry_mtime != current_mtime, true)
                            } else {
                                (path_clone, false, false)
                            }
                        } else {
                            // File doesn't exist anymore
                            (path_clone, true, false)
                        }
                    }));
                }
            }
        } // Lock is dropped here

        // Wait for all file checks to complete
        for task in check_tasks {
            if let Ok((path, is_stale, _file_exists)) = task.await {
                if is_stale {
                    to_remove.push(path);
                    stale_count += 1;
                }
            }
        }

        // Remove expired and stale entries
        {
            let mut cache = self.cache.write().unwrap();
            for path in &to_remove {
                cache.pop(path);
            }
        }

        let removed_count = to_remove.len();

        // Update statistics
        {
            let cache = self.cache.read().unwrap();
            let mut stats = self.stats.write().unwrap();
            stats.ttl_evictions += expired_count as u64;
            stats.stale_evictions += stale_count as u64;
            stats.current_entries = cache.len();
        }

        if removed_count > 0 {
            debug!(
                "SSH config cache maintenance: removed {} entries ({} expired, {} stale)",
                removed_count, expired_count, stale_count
            );
        }

        removed_count
    }

    /// Get detailed information about cache entries (for debugging)
    pub fn debug_info(&self) -> HashMap<PathBuf, String> {
        let cache = self.cache.read().unwrap();
        let mut info = HashMap::new();

        for (path, entry) in cache.iter() {
            let age = entry.cached_at.elapsed();
            let is_expired = entry.is_expired(self.config.ttl);
            let last_accessed = entry.last_accessed.elapsed();

            let status = if is_expired { "EXPIRED" } else { "VALID" };

            info.insert(
                path.clone(),
                format!(
                    "Status: {}, Age: {:?}, Accesses: {}, Last accessed: {:?} ago",
                    status, age, entry.access_count, last_accessed
                ),
            );
        }

        info
    }
}

impl Default for SshConfigCache {
    fn default() -> Self {
        Self::new()
    }
}

// Global cache instance using once_cell for thread-safe lazy initialization
use once_cell::sync::Lazy;

/// Global SSH config cache instance
pub static GLOBAL_CACHE: Lazy<SshConfigCache> = Lazy::new(|| {
    let config = CacheConfig {
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
    };

    debug!(
        "Initializing SSH config cache with {} max entries, {:?} TTL, enabled: {}",
        config.max_entries, config.ttl, config.enabled
    );

    SshConfigCache::with_config(config)
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();
        assert_eq!(config.max_entries, 100);
        assert_eq!(config.ttl, Duration::from_secs(300));
        assert!(config.enabled);
    }

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
    fn test_cache_basic_operations() {
        let cache = SshConfigCache::new();

        // Create a temporary SSH config file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "Host example").unwrap();
        writeln!(temp_file, "    HostName example.com").unwrap();

        let path = temp_file.path().to_path_buf();

        // First load should be a cache miss
        let config1 = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        assert_eq!(config1.hosts.len(), 1);

        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);

        // Second load should be a cache hit
        let config2 = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        assert_eq!(config2.hosts.len(), 1);

        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.hit_rate(), 0.5);
    }

    #[test]
    fn test_cache_file_modification_detection() {
        let cache = SshConfigCache::new();

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "Host example").unwrap();
        writeln!(temp_file, "    HostName example.com").unwrap();
        temp_file.flush().unwrap();

        let path = temp_file.path().to_path_buf();

        // Load initial config
        let config1 = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        assert_eq!(config1.hosts.len(), 1);

        // Modify the file
        std::thread::sleep(Duration::from_millis(10)); // Ensure different mtime
        writeln!(temp_file, "Host another").unwrap();
        writeln!(temp_file, "    HostName another.com").unwrap();
        temp_file.flush().unwrap();

        // Should detect file modification and reload
        let config2 = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        assert_eq!(config2.hosts.len(), 2);

        let stats = cache.stats();
        assert_eq!(stats.stale_evictions, 1);
    }

    #[test]
    fn test_cache_ttl_expiration() {
        let config = CacheConfig {
            max_entries: 10,
            ttl: Duration::from_millis(50),
            enabled: true,
        };
        let cache = SshConfigCache::with_config(config);

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "Host example").unwrap();
        writeln!(temp_file, "    HostName example.com").unwrap();

        let path = temp_file.path().to_path_buf();

        // Load initial config
        let _config1 = tokio_test::block_on(cache.get_or_load(&path)).unwrap();

        // Wait for TTL to expire
        std::thread::sleep(Duration::from_millis(100));

        // Should reload due to TTL expiration
        let _config2 = tokio_test::block_on(cache.get_or_load(&path)).unwrap();

        let stats = cache.stats();
        assert_eq!(stats.ttl_evictions, 1);
    }

    #[test]
    fn test_cache_clear_and_remove() {
        let cache = SshConfigCache::new();

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "Host example").unwrap();
        writeln!(temp_file, "    HostName example.com").unwrap();

        let path = temp_file.path().to_path_buf();

        // Load config
        let _config = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        assert_eq!(cache.stats().current_entries, 1);

        // Remove specific entry
        let removed_config = tokio_test::block_on(cache.remove(&path));
        assert!(removed_config.is_some());
        assert_eq!(cache.stats().current_entries, 0);

        // Load again and clear all
        let _config = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        assert_eq!(cache.stats().current_entries, 1);

        cache.clear();
        assert_eq!(cache.stats().current_entries, 0);
    }

    #[test]
    fn test_cache_maintenance() {
        let config = CacheConfig {
            max_entries: 10,
            ttl: Duration::from_millis(50),
            enabled: true,
        };
        let cache = SshConfigCache::with_config(config);

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "Host example").unwrap();
        writeln!(temp_file, "    HostName example.com").unwrap();

        let path = temp_file.path().to_path_buf();

        // Load config
        let _config = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        assert_eq!(cache.stats().current_entries, 1);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(100));

        // Run maintenance
        let removed = tokio_test::block_on(cache.maintain());
        assert_eq!(removed, 1);
        assert_eq!(cache.stats().current_entries, 0);
    }

    #[test]
    fn test_cache_disabled() {
        let config = CacheConfig {
            max_entries: 10,
            ttl: Duration::from_secs(300),
            enabled: false,
        };
        let cache = SshConfigCache::with_config(config);

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "Host example").unwrap();
        writeln!(temp_file, "    HostName example.com").unwrap();

        let path = temp_file.path().to_path_buf();

        // Should not use cache when disabled
        let _config1 = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        let _config2 = tokio_test::block_on(cache.get_or_load(&path)).unwrap();

        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.current_entries, 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = SshConfigCache::new();
        let stats = cache.stats();

        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate(), 0.0);
        assert_eq!(stats.miss_rate(), 1.0);
        assert_eq!(stats.current_entries, 0);
        assert_eq!(stats.max_entries, 100);
    }
}

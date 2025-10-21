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

use super::config::CacheConfig;
use super::entry::CacheEntry;
use super::stats::CacheStats;
use crate::ssh::SshConfig;
use anyhow::{Context, Result};
use lru::LruCache;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::time::timeout;
use tracing::{debug, trace};

/// Thread-safe LRU cache for SSH configurations
pub struct SshConfigCache {
    /// LRU cache implementation
    pub(super) cache: Arc<RwLock<LruCache<PathBuf, CacheEntry>>>,
    /// Cache configuration
    pub(super) config: CacheConfig,
    /// Cache statistics
    pub(super) stats: Arc<RwLock<CacheStats>>,
}

impl SshConfigCache {
    /// Create a new SSH config cache with default configuration
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Create a new SSH config cache with custom configuration
    pub fn with_config(config: CacheConfig) -> Self {
        let cache_size = std::num::NonZeroUsize::new(config.max_entries).unwrap_or_else(|| {
            std::num::NonZeroUsize::new(100).expect("NonZeroUsize::new(100) should never fail")
        });

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
        if let Err(e) = self.put(path, config.clone(), current_mtime) {
            // Log cache put error but don't fail the operation
            tracing::warn!("Failed to cache SSH config: {}", e);
        }

        // Update statistics
        {
            let mut stats = timeout(Duration::from_secs(1), async {
                tokio::task::yield_now().await;
                self.stats.write()
            })
            .await
            .map_err(|_| anyhow::anyhow!("Timeout acquiring stats write lock"))?
            .map_err(|e| anyhow::anyhow!("Stats lock poisoned: {e}"))?;
            stats.misses += 1;
        }

        Ok(config)
    }

    /// Try to get a cached entry, checking for expiration and staleness
    fn try_get_cached(&self, path: &Path, current_mtime: SystemTime) -> Result<Option<SshConfig>> {
        let mut cache = self
            .cache
            .write()
            .map_err(|e| anyhow::anyhow!("Cache write lock poisoned: {e}"))?;

        if let Some(entry) = cache.get_mut(path) {
            // Check if entry is expired
            if entry.is_expired(self.config.ttl) {
                debug!("SSH config cache entry expired: {}", path.display());
                cache.pop(path);

                let mut stats = self.stats.write().map_err(|e| {
                    anyhow::anyhow!("Stats write lock poisoned during TTL eviction: {e}")
                })?;
                stats.ttl_evictions += 1;
                return Ok(None);
            }

            // Check if entry is stale (file was modified)
            if entry.is_stale(current_mtime) {
                debug!("SSH config cache entry stale: {}", path.display());
                cache.pop(path);

                let mut stats = self.stats.write().map_err(|e| {
                    anyhow::anyhow!("Stats write lock poisoned during stale eviction: {e}")
                })?;
                stats.stale_evictions += 1;
                return Ok(None);
            }

            // Entry is valid - access it and return
            let config = entry.access().clone();

            // Update statistics
            {
                let mut stats = self.stats.write().map_err(|e| {
                    anyhow::anyhow!("Stats write lock poisoned during cache hit: {e}")
                })?;
                stats.hits += 1;
            }

            trace!("SSH config cache hit: {}", path.display());
            return Ok(Some(config));
        }

        Ok(None)
    }

    /// Put an entry in the cache
    fn put(&self, path: PathBuf, config: SshConfig, file_mtime: SystemTime) -> Result<()> {
        let mut cache = self
            .cache
            .write()
            .map_err(|e| anyhow::anyhow!("Cache write lock poisoned in put: {e}"))?;

        // Check if we're evicting an entry due to LRU policy
        let will_evict = cache.len() >= cache.cap().get();

        let entry = CacheEntry::new(config, file_mtime);
        cache.put(path.clone(), entry);

        // Update statistics
        {
            let mut stats = self
                .stats
                .write()
                .map_err(|e| anyhow::anyhow!("Stats write lock poisoned in put: {e}"))?;
            if will_evict {
                stats.lru_evictions += 1;
            }
            stats.current_entries = cache.len();
        }

        trace!("SSH config cached: {}", path.display());
        Ok(())
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
    pub fn clear(&self) -> Result<()> {
        let mut cache = self
            .cache
            .write()
            .map_err(|e| anyhow::anyhow!("Cache write lock poisoned in clear: {e}"))?;
        cache.clear();

        let mut stats = self
            .stats
            .write()
            .map_err(|e| anyhow::anyhow!("Stats write lock poisoned in clear: {e}"))?;
        stats.current_entries = 0;
        Ok(())
    }

    /// Remove a specific entry from the cache
    pub async fn remove<P: AsRef<Path>>(&self, path: P) -> Result<Option<SshConfig>> {
        let path = path.as_ref();
        if let Ok(canonical_path) = tokio::fs::canonicalize(path).await {
            let mut cache = self
                .cache
                .write()
                .map_err(|e| anyhow::anyhow!("Cache write lock poisoned in remove: {e}"))?;
            let entry = cache.pop(&canonical_path);

            if entry.is_some() {
                let mut stats = self
                    .stats
                    .write()
                    .map_err(|e| anyhow::anyhow!("Stats write lock poisoned in remove: {e}"))?;
                stats.current_entries = cache.len();
            }

            Ok(entry.map(|e| e.config))
        } else {
            Ok(None)
        }
    }

    /// Get current cache statistics
    pub fn stats(&self) -> Result<CacheStats> {
        self.stats
            .read()
            .map_err(|e| anyhow::anyhow!("Stats read lock poisoned: {e}"))
            .map(|stats| stats.clone())
    }

    /// Get cache configuration
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Update cache configuration (will clear cache if max_entries changed)
    pub fn update_config(&mut self, new_config: CacheConfig) {
        if new_config.max_entries != self.config.max_entries {
            // Need to recreate cache with new size
            let cache_size =
                std::num::NonZeroUsize::new(new_config.max_entries).unwrap_or_else(|| {
                    std::num::NonZeroUsize::new(100)
                        .expect("NonZeroUsize::new(100) should never fail")
                });

            self.cache = Arc::new(RwLock::new(LruCache::new(cache_size)));

            // Update stats - if this fails, the cache has already been recreated
            // so we continue with the new config
            if let Ok(mut stats) = self.stats.write() {
                stats.max_entries = new_config.max_entries;
                stats.current_entries = 0;
            }
        }

        self.config = new_config;
    }
}

impl Default for SshConfigCache {
    fn default() -> Self {
        Self::new()
    }
}

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

        let stats = cache.stats().unwrap();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);

        // Second load should be a cache hit
        let config2 = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        assert_eq!(config2.hosts.len(), 1);

        let stats = cache.stats().unwrap();
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

        let stats = cache.stats().unwrap();
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

        let stats = cache.stats().unwrap();
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
        assert_eq!(cache.stats().unwrap().current_entries, 1);

        // Remove specific entry
        let removed_config = tokio_test::block_on(cache.remove(&path)).unwrap();
        assert!(removed_config.is_some());
        assert_eq!(cache.stats().unwrap().current_entries, 0);

        // Load again and clear all
        let _config = tokio_test::block_on(cache.get_or_load(&path)).unwrap();
        assert_eq!(cache.stats().unwrap().current_entries, 1);

        cache.clear().unwrap();
        assert_eq!(cache.stats().unwrap().current_entries, 0);
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
        assert_eq!(cache.stats().unwrap().current_entries, 1);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(100));

        // Run maintenance
        let removed = tokio_test::block_on(cache.maintain()).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(cache.stats().unwrap().current_entries, 0);
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

        let stats = cache.stats().unwrap();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.current_entries, 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = SshConfigCache::new();
        let stats = cache.stats().unwrap();

        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate(), 0.0);
        assert_eq!(stats.miss_rate(), 1.0);
        assert_eq!(stats.current_entries, 0);
        assert_eq!(stats.max_entries, 100);
    }
}

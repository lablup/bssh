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

//! Environment variable caching for SSH path expansion
//!
//! This module provides efficient caching of safe environment variables to improve
//! performance during path expansion operations while maintaining security.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

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

/// A cached environment variable entry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The environment variable value
    value: Option<String>,
    /// When this entry was cached
    cached_at: Instant,
    /// Number of times this entry has been accessed
    access_count: u64,
}

impl CacheEntry {
    fn new(value: Option<String>) -> Self {
        Self {
            value,
            cached_at: Instant::now(),
            access_count: 0,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }

    fn access(&mut self) -> &Option<String> {
        self.access_count += 1;
        &self.value
    }
}

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
    pub max_entries: usize,
}

impl EnvCacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Thread-safe cache for environment variables used in SSH path expansion
pub struct EnvironmentCache {
    /// Cache storage
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Cache configuration
    config: EnvCacheConfig,
    /// Cache statistics
    stats: Arc<RwLock<EnvCacheStats>>,
    /// Whitelist of safe environment variables
    safe_variables: std::collections::HashSet<&'static str>,
}

impl EnvironmentCache {
    /// Create a new environment cache with default configuration
    pub fn new() -> Self {
        Self::with_config(EnvCacheConfig::default())
    }

    /// Create a new environment cache with custom configuration
    pub fn with_config(config: EnvCacheConfig) -> Self {
        let mut stats = EnvCacheStats::default();
        stats.max_entries = config.max_entries;

        // Define the whitelist of safe environment variables
        // This is the same whitelist used in path.rs for security
        let safe_variables = std::collections::HashSet::from([
            // User identity variables (generally safe)
            "HOME",
            "USER",
            "LOGNAME", 
            "USERNAME",
            // SSH-specific variables (contextually safe)
            "SSH_AUTH_SOCK",
            "SSH_CONNECTION",
            "SSH_CLIENT",
            "SSH_TTY",
            // Locale settings (safe for paths)
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LC_MESSAGES",
            // Safe system variables
            "TMPDIR",
            "TEMP",
            "TMP",
            // Terminal-related (generally safe)
            "TERM",
            "COLORTERM",
        ]);

        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(stats)),
            safe_variables,
        }
    }

    /// Get an environment variable value from cache or system
    ///
    /// # Arguments
    /// * `var_name` - The environment variable name to retrieve
    ///
    /// # Returns
    /// * `Ok(Some(String))` - Variable exists and has a value
    /// * `Ok(None)` - Variable doesn't exist or is not in whitelist
    /// * `Err(anyhow::Error)` - Error occurred during retrieval
    pub fn get_env_var(&self, var_name: &str) -> Result<Option<String>, anyhow::Error> {
        if !self.config.enabled {
            // Cache disabled - fetch directly from environment
            return if self.safe_variables.contains(var_name) {
                Ok(std::env::var(var_name).ok())
            } else {
                tracing::warn!(
                    "Blocked access to non-whitelisted environment variable '{}' (cache disabled)",
                    var_name
                );
                Ok(None)
            };
        }

        // Security check: Only allow whitelisted variables
        if !self.safe_variables.contains(var_name) {
            tracing::warn!(
                "Blocked access to non-whitelisted environment variable '{}'",
                var_name
            );
            return Ok(None);
        }

        // Try to get from cache first
        if let Some(value) = self.try_get_cached(var_name)? {
            return Ok(value);
        }

        // Cache miss - fetch from environment
        let value = std::env::var(var_name).ok();
        
        // Store in cache
        self.put(var_name.to_string(), value.clone());

        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.misses += 1;
        }

        tracing::trace!("Environment variable cache miss: {}", var_name);
        Ok(value)
    }

    /// Try to get a cached entry, checking for expiration
    fn try_get_cached(&self, var_name: &str) -> Result<Option<Option<String>>, anyhow::Error> {
        let mut cache = self.cache.write().unwrap();

        if let Some(entry) = cache.get_mut(var_name) {
            // Check if entry is expired
            if entry.is_expired(self.config.ttl) {
                tracing::trace!("Environment variable cache entry expired: {}", var_name);
                cache.remove(var_name);
                
                let mut stats = self.stats.write().unwrap();
                stats.ttl_evictions += 1;
                return Ok(None);
            }

            // Entry is valid - access it and return
            let value = entry.access().clone();

            // Update statistics
            {
                let mut stats = self.stats.write().unwrap();
                stats.hits += 1;
            }

            tracing::trace!("Environment variable cache hit: {}", var_name);
            return Ok(Some(value));
        }

        Ok(None)
    }

    /// Put an entry in the cache
    fn put(&self, var_name: String, value: Option<String>) {
        let mut cache = self.cache.write().unwrap();

        // Check cache size limit and evict if necessary
        if cache.len() >= self.config.max_entries {
            // Find the least recently used entry (oldest cached_at)
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
                tracing::debug!("Evicted environment variable from cache due to size limit: {}", oldest_key);
            }
        }

        let entry = CacheEntry::new(value);
        cache.insert(var_name.clone(), entry);

        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.current_entries = cache.len();
        }

        tracing::trace!("Environment variable cached: {}", var_name);
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();

        let mut stats = self.stats.write().unwrap();
        stats.current_entries = 0;
    }

    /// Remove a specific entry from the cache
    pub fn remove(&self, var_name: &str) -> Option<String> {
        let mut cache = self.cache.write().unwrap();
        let entry = cache.remove(var_name)?;

        let mut stats = self.stats.write().unwrap();
        stats.current_entries = cache.len();

        entry.value
    }

    /// Get current cache statistics
    pub fn stats(&self) -> EnvCacheStats {
        self.stats.read().unwrap().clone()
    }

    /// Get cache configuration
    pub fn config(&self) -> &EnvCacheConfig {
        &self.config
    }

    /// Perform cache maintenance (remove expired entries)
    pub fn maintain(&self) -> usize {
        if !self.config.enabled {
            return 0;
        }

        let mut cache = self.cache.write().unwrap();
        let mut expired_keys = Vec::new();

        // Collect expired keys
        for (key, entry) in cache.iter() {
            if entry.is_expired(self.config.ttl) {
                expired_keys.push(key.clone());
            }
        }

        // Remove expired entries
        for key in &expired_keys {
            cache.remove(key);
        }

        let removed_count = expired_keys.len();

        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.ttl_evictions += removed_count as u64;
            stats.current_entries = cache.len();
        }

        if removed_count > 0 {
            tracing::debug!(
                "Environment cache maintenance: removed {} expired entries",
                removed_count
            );
        }

        removed_count
    }

    /// Refresh cache by clearing all entries
    /// This forces all environment variables to be re-read from the system
    pub fn refresh(&self) {
        self.clear();
        tracing::debug!("Environment variable cache refreshed");
    }

    /// Get detailed information about cache entries (for debugging)
    pub fn debug_info(&self) -> HashMap<String, String> {
        let cache = self.cache.read().unwrap();
        let mut info = HashMap::new();

        for (key, entry) in cache.iter() {
            let age = entry.cached_at.elapsed();
            let is_expired = entry.is_expired(self.config.ttl);
            let has_value = entry.value.is_some();

            let status = if is_expired { "EXPIRED" } else { "VALID" };

            info.insert(
                key.clone(),
                format!(
                    "Status: {}, Age: {:?}, Accesses: {}, Has value: {}",
                    status, age, entry.access_count, has_value
                ),
            );
        }

        info
    }

    /// Check if a variable is in the safe whitelist
    pub fn is_safe_variable(&self, var_name: &str) -> bool {
        self.safe_variables.contains(var_name)
    }

    /// Get the list of safe environment variables
    pub fn safe_variables(&self) -> Vec<&'static str> {
        self.safe_variables.iter().copied().collect()
    }
}

impl Default for EnvironmentCache {
    fn default() -> Self {
        Self::new()
    }
}

// Global environment cache instance using once_cell for thread-safe lazy initialization
/// Global environment variable cache instance
pub static GLOBAL_ENV_CACHE: Lazy<EnvironmentCache> = Lazy::new(|| {
    let config = EnvCacheConfig {
        ttl: Duration::from_secs(
            std::env::var("BSSH_ENV_CACHE_TTL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        ),
        enabled: std::env::var("BSSH_ENV_CACHE_ENABLED")
            .map(|s| s.to_lowercase() != "false" && s != "0")
            .unwrap_or(true),
        max_entries: std::env::var("BSSH_ENV_CACHE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50),
    };

    tracing::debug!(
        "Initializing environment variable cache with {} max entries, {:?} TTL, enabled: {}",
        config.max_entries, config.ttl, config.enabled
    );

    EnvironmentCache::with_config(config)
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_env_cache_config_default() {
        let config = EnvCacheConfig::default();
        assert_eq!(config.ttl, Duration::from_secs(30));
        assert!(config.enabled);
        assert_eq!(config.max_entries, 50);
    }

    #[test]
    fn test_cache_entry_expiration() {
        let mut entry = CacheEntry::new(Some("test".to_string()));
        
        // Fresh entry should not be expired
        assert!(!entry.is_expired(Duration::from_secs(60)));

        // Simulate time passing
        entry.cached_at = Instant::now() - Duration::from_secs(120);
        assert!(entry.is_expired(Duration::from_secs(60)));
    }

    #[test]
    fn test_env_cache_basic_operations() {
        let cache = EnvironmentCache::new();

        // Test getting a safe environment variable
        if let Ok(home_value) = cache.get_env_var("HOME") {
            // Should not be None since HOME is typically set
            if let Some(value) = home_value {
                assert!(!value.is_empty());
                
                // Second call should be a cache hit
                let cached_value = cache.get_env_var("HOME").unwrap();
                assert_eq!(cached_value, Some(value));
            }
        }

        let stats = cache.stats();
        assert!(stats.hits > 0 || stats.misses > 0);
    }

    #[test]
    fn test_env_cache_unsafe_variable_blocked() {
        let cache = EnvironmentCache::new();
        
        // Try to access a dangerous variable
        let result = cache.get_env_var("PATH").unwrap();
        assert_eq!(result, None); // Should be blocked
        
        // Check that it's not considered safe
        assert!(!cache.is_safe_variable("PATH"));
        assert!(!cache.is_safe_variable("LD_PRELOAD"));
        
        // Check that safe variables are allowed
        assert!(cache.is_safe_variable("HOME"));
        assert!(cache.is_safe_variable("USER"));
    }

    #[test]
    fn test_env_cache_ttl_expiration() {
        let config = EnvCacheConfig {
            ttl: Duration::from_millis(50),
            enabled: true,
            max_entries: 10,
        };
        let cache = EnvironmentCache::with_config(config);

        // Get a variable to cache it
        let _result1 = cache.get_env_var("HOME");
        
        // Wait for TTL to expire
        std::thread::sleep(Duration::from_millis(100));
        
        // Should miss cache due to expiration
        let _result2 = cache.get_env_var("HOME");
        
        let stats = cache.stats();
        assert!(stats.ttl_evictions > 0);
    }

    #[test]
    fn test_env_cache_size_limit() {
        let config = EnvCacheConfig {
            ttl: Duration::from_secs(60),
            enabled: true,
            max_entries: 2, // Very small limit
        };
        let cache = EnvironmentCache::with_config(config);

        // Fill cache beyond limit
        let _r1 = cache.get_env_var("HOME");
        let _r2 = cache.get_env_var("USER");  
        let _r3 = cache.get_env_var("TMPDIR"); // Should evict oldest

        let stats = cache.stats();
        assert!(stats.current_entries <= 2);
    }

    #[test]
    fn test_env_cache_clear_and_refresh() {
        let cache = EnvironmentCache::new();
        
        // Cache some variables
        let _r1 = cache.get_env_var("HOME");
        assert!(cache.stats().current_entries > 0);
        
        // Clear cache
        cache.clear();
        assert_eq!(cache.stats().current_entries, 0);
        
        // Cache again and refresh
        let _r2 = cache.get_env_var("HOME");
        assert!(cache.stats().current_entries > 0);
        
        cache.refresh();
        assert_eq!(cache.stats().current_entries, 0);
    }

    #[test] 
    fn test_env_cache_maintenance() {
        let config = EnvCacheConfig {
            ttl: Duration::from_millis(50),
            enabled: true,
            max_entries: 10,
        };
        let cache = EnvironmentCache::with_config(config);

        // Cache a variable
        let _result = cache.get_env_var("HOME");
        assert!(cache.stats().current_entries > 0);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(100));

        // Run maintenance
        let removed = cache.maintain();
        assert!(removed > 0);
        assert_eq!(cache.stats().current_entries, 0);
    }

    #[test]
    fn test_env_cache_disabled() {
        let config = EnvCacheConfig {
            ttl: Duration::from_secs(60),
            enabled: false,
            max_entries: 10,
        };
        let cache = EnvironmentCache::with_config(config);

        // Should not use cache when disabled
        let _r1 = cache.get_env_var("HOME");
        let _r2 = cache.get_env_var("HOME");

        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.current_entries, 0);
    }

    #[test]
    fn test_env_cache_stats() {
        let cache = EnvironmentCache::new();
        let stats = cache.stats();

        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate(), 0.0);
        assert_eq!(stats.current_entries, 0);
        assert_eq!(stats.max_entries, 50);
    }

    #[test]
    fn test_env_cache_safe_variables_list() {
        let cache = EnvironmentCache::new();
        let safe_vars = cache.safe_variables();
        
        assert!(safe_vars.contains(&"HOME"));
        assert!(safe_vars.contains(&"USER"));
        assert!(safe_vars.contains(&"SSH_AUTH_SOCK"));
        assert!(!safe_vars.contains(&"PATH"));
        assert!(!safe_vars.contains(&"LD_PRELOAD"));
    }

    #[test]
    fn test_env_cache_concurrent_access() {
        let cache = Arc::new(EnvironmentCache::new());
        let counter = Arc::new(AtomicUsize::new(0));
        
        let mut handles = vec![];
        
        // Spawn multiple threads accessing the cache
        for _ in 0..10 {
            let cache_clone = Arc::clone(&cache);
            let counter_clone = Arc::clone(&counter);
            
            let handle = std::thread::spawn(move || {
                for _ in 0..100 {
                    if cache_clone.get_env_var("HOME").is_ok() {
                        counter_clone.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Should have successful accesses
        assert!(counter.load(Ordering::Relaxed) > 0);
        
        // Cache should have entries
        let stats = cache.stats();
        assert!(stats.hits + stats.misses > 0);
    }
}
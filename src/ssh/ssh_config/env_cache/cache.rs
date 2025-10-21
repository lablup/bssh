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

//! Core caching logic for environment variables

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::config::EnvCacheConfig;
use super::entry::CacheEntry;
use super::maintenance;
use super::stats::EnvCacheStats;
use super::validation;

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
        let stats = EnvCacheStats {
            max_entries: config.max_entries,
            ..Default::default()
        };

        let safe_variables = validation::create_safe_variables();

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
                .min_by_key(|(_, entry)| entry.cached_at())
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
                tracing::debug!(
                    "Evicted environment variable from cache due to size limit: {}",
                    oldest_key
                );
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
    #[allow(dead_code)]
    pub fn clear(&self) {
        maintenance::clear_cache(&self.cache, &self.stats);
    }

    /// Remove a specific entry from the cache
    #[allow(dead_code)]
    pub fn remove(&self, var_name: &str) -> Option<String> {
        maintenance::remove_entry(&self.cache, &self.stats, var_name)
    }

    /// Get current cache statistics
    #[allow(dead_code)]
    pub fn stats(&self) -> EnvCacheStats {
        self.stats.read().unwrap().clone()
    }

    /// Get cache configuration
    #[allow(dead_code)]
    pub fn config(&self) -> &EnvCacheConfig {
        &self.config
    }

    /// Perform cache maintenance (remove expired entries)
    #[allow(dead_code)]
    pub fn maintain(&self) -> usize {
        maintenance::maintain_cache(
            &self.cache,
            &self.stats,
            self.config.ttl,
            self.config.enabled,
        )
    }

    /// Refresh cache by clearing all entries
    /// This forces all environment variables to be re-read from the system
    #[allow(dead_code)]
    pub fn refresh(&self) {
        self.clear();
        tracing::debug!("Environment variable cache refreshed");
    }

    /// Get detailed information about cache entries (for debugging)
    #[allow(dead_code)]
    pub fn debug_info(&self) -> HashMap<String, String> {
        maintenance::get_debug_info(&self.cache, self.config.ttl)
    }

    /// Check if a variable is in the safe whitelist
    #[allow(dead_code)]
    pub fn is_safe_variable(&self, var_name: &str) -> bool {
        self.safe_variables.contains(var_name)
    }

    /// Get the list of safe environment variables
    #[allow(dead_code)]
    pub fn safe_variables(&self) -> Vec<&'static str> {
        self.safe_variables.iter().copied().collect()
    }
}

impl Default for EnvironmentCache {
    fn default() -> Self {
        Self::new()
    }
}

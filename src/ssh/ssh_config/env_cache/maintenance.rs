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

//! Cache maintenance operations for cleaning expired entries

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use super::entry::CacheEntry;
use super::stats::EnvCacheStats;

/// Perform cache maintenance by removing expired entries
pub fn maintain_cache(
    cache: &RwLock<HashMap<String, CacheEntry>>,
    stats: &RwLock<EnvCacheStats>,
    ttl: Duration,
    enabled: bool,
) -> usize {
    if !enabled {
        return 0;
    }

    let mut cache = cache.write().unwrap();
    let mut expired_keys = Vec::new();

    // Collect expired keys
    for (key, entry) in cache.iter() {
        if entry.is_expired(ttl) {
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
        let mut stats = stats.write().unwrap();
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

/// Clear all entries from the cache
pub fn clear_cache(cache: &RwLock<HashMap<String, CacheEntry>>, stats: &RwLock<EnvCacheStats>) {
    let mut cache = cache.write().unwrap();
    cache.clear();

    let mut stats = stats.write().unwrap();
    stats.current_entries = 0;
}

/// Remove a specific entry from the cache
pub fn remove_entry(
    cache: &RwLock<HashMap<String, CacheEntry>>,
    stats: &RwLock<EnvCacheStats>,
    var_name: &str,
) -> Option<String> {
    let mut cache = cache.write().unwrap();
    let entry = cache.remove(var_name)?;

    let mut stats = stats.write().unwrap();
    stats.current_entries = cache.len();

    entry.value().clone()
}

/// Get debug information about cache entries
pub fn get_debug_info(
    cache: &RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
) -> HashMap<String, String> {
    let cache = cache.read().unwrap();
    let mut info = HashMap::new();

    for (key, entry) in cache.iter() {
        let age = entry.cached_at().elapsed();
        let is_expired = entry.is_expired(ttl);
        let has_value = entry.value().is_some();

        let status = if is_expired { "EXPIRED" } else { "VALID" };

        info.insert(
            key.clone(),
            format!(
                "Status: {}, Age: {:?}, Accesses: {}, Has value: {}",
                status,
                age,
                entry.access_count(),
                has_value
            ),
        );
    }

    info
}

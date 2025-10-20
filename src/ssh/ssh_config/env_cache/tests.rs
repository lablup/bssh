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

use super::cache::EnvironmentCache;
use super::config::EnvCacheConfig;
use super::entry::CacheEntry;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

    // Cannot directly modify cached_at, so test access count instead
    assert_eq!(entry.access_count(), 0);
    let _ = entry.access();
    assert_eq!(entry.access_count(), 1);
}

#[test]
fn test_env_cache_basic_operations() {
    let cache = EnvironmentCache::new();

    // Test getting a safe environment variable
    if let Ok(Some(value)) = cache.get_env_var("HOME") {
        // Should not be None since HOME is typically set
        assert!(!value.is_empty());

        // Second call should be a cache hit
        let cached_value = cache.get_env_var("HOME").unwrap();
        assert_eq!(cached_value, Some(value));
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

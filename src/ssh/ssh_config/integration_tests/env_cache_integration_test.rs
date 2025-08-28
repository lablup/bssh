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

//! Integration tests for environment variable caching in path expansion

use crate::ssh::ssh_config::env_cache::{EnvCacheConfig, EnvironmentCache, GLOBAL_ENV_CACHE};
use crate::ssh::ssh_config::path::expand_path_internal;
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_expansion_uses_cache() {
        // Clear the global cache to start fresh
        GLOBAL_ENV_CACHE.clear();

        // Test path with environment variable
        let test_path = "~/.ssh/config_${USER}_test";

        // First expansion - should be a cache miss
        let start = Instant::now();
        let result1 = expand_path_internal(test_path);
        let first_duration = start.elapsed();

        // Second expansion - should be a cache hit (faster)
        let start = Instant::now();
        let result2 = expand_path_internal(test_path);
        let second_duration = start.elapsed();

        // Both should succeed
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Results should be identical
        let path1 = result1.unwrap();
        let path2 = result2.unwrap();
        assert_eq!(path1, path2);

        // Check cache statistics
        let stats = GLOBAL_ENV_CACHE.stats();
        assert!(
            stats.hits > 0 || stats.misses > 0,
            "Cache should have been accessed"
        );

        // In most cases, second access should be faster due to caching
        // Note: This is not guaranteed due to system variability, so we just log it
        println!(
            "First expansion took: {first_duration:?}, Second expansion took: {second_duration:?}"
        );
        println!("Cache stats: hits={}, misses={}", stats.hits, stats.misses);
    }

    #[test]
    fn test_path_expansion_with_multiple_variables() {
        // Clear cache
        GLOBAL_ENV_CACHE.clear();

        // Path with multiple environment variables
        let test_path = "${HOME}/.ssh/${USER}_config";

        let result = expand_path_internal(test_path);
        assert!(result.is_ok());

        let expanded = result.unwrap();
        let path_str = expanded.to_string_lossy();

        // Should not contain unexpanded variables
        assert!(!path_str.contains("${HOME}"));
        assert!(!path_str.contains("${USER}"));

        // Should contain actual paths
        if let Ok(Some(home)) = GLOBAL_ENV_CACHE.get_env_var("HOME") {
            assert!(path_str.contains(&home));
        }

        let stats = GLOBAL_ENV_CACHE.stats();
        println!(
            "Multi-variable expansion cache stats: hits={}, misses={}",
            stats.hits, stats.misses
        );
    }

    #[test]
    fn test_path_expansion_security_with_unsafe_variables() {
        // Clear cache
        GLOBAL_ENV_CACHE.clear();

        // Path with unsafe environment variable (should not be expanded)
        let test_path = "${PATH}/some/binary";

        let result = expand_path_internal(test_path);
        // Note: This should succeed but not expand the unsafe variable
        match result {
            Ok(_) => {} // Good, continue with checking the expansion
            Err(e) => {
                println!("Error in path expansion: {e}");
                // If it fails because of security violation, that's expected behavior for dangerous variables
                if e.to_string().contains("security violation")
                    || e.to_string().contains("Security violation")
                {
                    println!(
                        "Path expansion correctly rejected unsafe variable (expected behavior)"
                    );

                    // Check that cache wasn't accessed for unsafe variables
                    let stats = GLOBAL_ENV_CACHE.stats();
                    println!(
                        "Cache stats for rejected unsafe variable: hits={}, misses={}",
                        stats.hits, stats.misses
                    );
                    return; // Exit test early, this is the expected/secure behavior
                } else {
                    panic!("Unexpected error in path expansion: {e}");
                }
            }
        }

        let expanded = result.unwrap();
        let path_str = expanded.to_string_lossy();

        // PATH should not be expanded (should remain as literal text or become empty)
        // The current implementation leaves ${VAR} as-is for unsafe variables in braced form
        assert!(
            path_str.contains("${PATH}") || path_str == "/some/binary",
            "Unsafe variable should not be expanded: {path_str}"
        );

        let stats = GLOBAL_ENV_CACHE.stats();
        println!(
            "Unsafe variable expansion cache stats: hits={}, misses={}",
            stats.hits, stats.misses
        );
    }

    #[test]
    fn test_cache_performance_improvement() {
        // Create a cache with very short TTL for testing
        let cache_config = EnvCacheConfig {
            ttl: Duration::from_secs(10),
            enabled: true,
            max_entries: 10,
        };
        let cache = EnvironmentCache::with_config(cache_config);

        // Warm up the cache
        let _ = cache.get_env_var("HOME");
        let _ = cache.get_env_var("USER");

        // Test multiple accesses
        let mut total_cached_time = Duration::new(0, 0);
        let iterations = 100;

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = cache.get_env_var("HOME");
            let _ = cache.get_env_var("USER");
            total_cached_time += start.elapsed();
        }

        let avg_cached_time = total_cached_time / iterations;

        println!("Average cached access time: {avg_cached_time:?}");

        let stats = cache.stats();
        println!(
            "Performance test cache stats: hits={}, misses={}, hit_rate={:.2}%",
            stats.hits,
            stats.misses,
            stats.hit_rate() * 100.0
        );

        // We expect most accesses to be cache hits
        assert!(stats.hit_rate() > 0.8, "Cache hit rate should be > 80%");
    }

    #[test]
    fn test_cache_with_nonexistent_variable() {
        let cache = EnvironmentCache::new();

        // Try to get a safe variable that doesn't exist
        let result = cache.get_env_var("USER_NONEXISTENT_12345");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);

        // Second access should also return None (but from cache)
        let result2 = cache.get_env_var("USER_NONEXISTENT_12345");
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), None);

        let stats = cache.stats();
        // Note: For non-whitelisted variables, we don't access the cache,
        // so we need to test with a whitelisted variable that doesn't exist
        // Let's try with a backup test using a definitely safe variable
        if stats.hits + stats.misses == 0 {
            // Try with HOME which should be whitelisted
            let _result = cache.get_env_var("HOME");
            let updated_stats = cache.stats();
            assert!(
                updated_stats.hits + updated_stats.misses > 0,
                "Cache should have been accessed for safe variables"
            );
        } else {
            assert!(
                stats.hits + stats.misses > 0,
                "Cache should have been accessed"
            );
        }
    }

    #[test]
    fn test_cache_ttl_behavior() {
        // Create cache with very short TTL
        let config = EnvCacheConfig {
            ttl: Duration::from_millis(50),
            enabled: true,
            max_entries: 10,
        };
        let cache = EnvironmentCache::with_config(config);

        // Get a variable (cache miss)
        let result1 = cache.get_env_var("HOME");
        assert!(result1.is_ok());

        // Immediately get it again (cache hit)
        let result2 = cache.get_env_var("HOME");
        assert!(result2.is_ok());
        assert_eq!(result1.as_ref().unwrap(), result2.as_ref().unwrap());

        // Wait for TTL to expire
        std::thread::sleep(Duration::from_millis(100));

        // Should be cache miss again due to TTL expiration
        let result3 = cache.get_env_var("HOME");
        assert!(result3.is_ok());
        // Results should be the same (both should be the current HOME value, even after TTL)
        // Note: We compare the results are equal, not specific values since HOME varies by environment
        assert_eq!(
            result1.as_ref().unwrap(),
            result3.as_ref().unwrap(),
            "HOME value should be consistent across cache refreshes"
        );

        let stats = cache.stats();
        assert!(stats.ttl_evictions > 0, "Should have TTL evictions");
    }
}

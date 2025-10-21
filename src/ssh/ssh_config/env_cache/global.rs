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

//! Global environment cache instance management

use once_cell::sync::Lazy;
use std::time::Duration;

use super::cache::EnvironmentCache;
use super::config::EnvCacheConfig;

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
        config.max_entries,
        config.ttl,
        config.enabled
    );

    EnvironmentCache::with_config(config)
});

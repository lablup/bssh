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
use super::manager::SshConfigCache;
use once_cell::sync::Lazy;
use tracing::debug;

/// Global SSH config cache instance
pub static GLOBAL_CACHE: Lazy<SshConfigCache> = Lazy::new(|| {
    let config = CacheConfig::from_env();

    debug!(
        "Initializing SSH config cache with {} max entries, {:?} TTL, enabled: {}",
        config.max_entries, config.ttl, config.enabled
    );

    SshConfigCache::with_config(config)
});

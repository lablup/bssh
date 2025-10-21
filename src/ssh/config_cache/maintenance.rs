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

use super::manager::SshConfigCache;
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::debug;

impl SshConfigCache {
    /// Perform cache maintenance (remove expired and stale entries)
    pub async fn maintain(&self) -> Result<usize> {
        if !self.config.enabled {
            return Ok(0);
        }

        let mut to_remove = Vec::new();
        let mut expired_count = 0;
        let mut stale_count = 0;

        // Collect keys to check and expired entries (can't remove while iterating)
        // We'll use tokio::spawn to check file metadata concurrently
        let mut check_tasks = Vec::new();

        {
            // Scope the lock to release it before awaiting
            let cache = self
                .cache
                .write()
                .map_err(|e| anyhow::anyhow!("Cache write lock poisoned in maintain: {e}"))?;

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
            let mut cache = self.cache.write().map_err(|e| {
                anyhow::anyhow!("Cache write lock poisoned during maintenance cleanup: {e}")
            })?;
            for path in &to_remove {
                cache.pop(path);
            }
        }

        let removed_count = to_remove.len();

        // Update statistics
        {
            let cache = self.cache.read().map_err(|e| {
                anyhow::anyhow!("Cache read lock poisoned during maintenance stats: {e}")
            })?;
            let mut stats = self.stats.write().map_err(|e| {
                anyhow::anyhow!("Stats write lock poisoned during maintenance: {e}")
            })?;
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

        Ok(removed_count)
    }

    /// Get detailed information about cache entries (for debugging)
    pub fn debug_info(&self) -> Result<HashMap<PathBuf, String>> {
        let cache = self
            .cache
            .read()
            .map_err(|e| anyhow::anyhow!("Cache read lock poisoned in debug_info: {e}"))?;
        let mut info = HashMap::new();

        for (path, entry) in cache.iter() {
            let age = entry.age();
            let is_expired = entry.is_expired(self.config.ttl);
            let last_accessed = entry.time_since_last_access();

            let status = if is_expired { "EXPIRED" } else { "VALID" };

            info.insert(
                path.clone(),
                format!(
                    "Status: {}, Age: {:?}, Accesses: {}, Last accessed: {:?} ago",
                    status, age, entry.access_count, last_accessed
                ),
            );
        }

        Ok(info)
    }
}

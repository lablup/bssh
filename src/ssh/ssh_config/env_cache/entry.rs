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

//! Cache entry management for environment variables

use std::time::{Duration, Instant};

/// A cached environment variable entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The environment variable value
    value: Option<String>,
    /// When this entry was cached
    cached_at: Instant,
    /// Number of times this entry has been accessed
    access_count: u64,
}

impl CacheEntry {
    pub fn new(value: Option<String>) -> Self {
        Self {
            value,
            cached_at: Instant::now(),
            access_count: 0,
        }
    }

    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }

    pub fn access(&mut self) -> &Option<String> {
        self.access_count += 1;
        &self.value
    }

    pub fn cached_at(&self) -> Instant {
        self.cached_at
    }

    pub fn access_count(&self) -> u64 {
        self.access_count
    }

    pub fn value(&self) -> &Option<String> {
        &self.value
    }
}

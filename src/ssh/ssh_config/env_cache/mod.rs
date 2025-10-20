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

mod cache;
mod config;
mod entry;
mod global;
mod maintenance;
mod stats;
mod validation;

pub use cache::EnvironmentCache;
pub use config::EnvCacheConfig;
pub use global::GLOBAL_ENV_CACHE;
pub use stats::EnvCacheStats;

#[cfg(test)]
mod tests;

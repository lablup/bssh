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

//! Configuration constants and functions for jump host limits

/// Default maximum number of jump hosts allowed in a chain
/// SECURITY: Prevents resource exhaustion and excessive connection chains
pub const DEFAULT_MAX_JUMP_HOSTS: usize = 10;

/// Absolute maximum number of jump hosts, even if configured higher
/// SECURITY: Hard limit to prevent DoS attacks regardless of configuration
pub const ABSOLUTE_MAX_JUMP_HOSTS: usize = 30;

/// Get the maximum number of jump hosts allowed
///
/// Reads from `BSSH_MAX_JUMP_HOSTS` environment variable, with fallback to default.
/// The value is capped at ABSOLUTE_MAX_JUMP_HOSTS for security.
///
/// # Examples
/// ```bash
/// # Use default (10)
/// bssh -J host1,host2,... target
///
/// # Set custom limit (e.g., 20)
/// BSSH_MAX_JUMP_HOSTS=20 bssh -J host1,host2,...,host20 target
/// ```
pub fn get_max_jump_hosts() -> usize {
    std::env::var("BSSH_MAX_JUMP_HOSTS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| {
            if n == 0 {
                tracing::warn!(
                    "BSSH_MAX_JUMP_HOSTS cannot be 0, using default: {}",
                    DEFAULT_MAX_JUMP_HOSTS
                );
                DEFAULT_MAX_JUMP_HOSTS
            } else if n > ABSOLUTE_MAX_JUMP_HOSTS {
                tracing::warn!(
                    "BSSH_MAX_JUMP_HOSTS={} exceeds absolute maximum {}, capping at {}",
                    n,
                    ABSOLUTE_MAX_JUMP_HOSTS,
                    ABSOLUTE_MAX_JUMP_HOSTS
                );
                ABSOLUTE_MAX_JUMP_HOSTS
            } else {
                n
            }
        })
        .unwrap_or(DEFAULT_MAX_JUMP_HOSTS)
}

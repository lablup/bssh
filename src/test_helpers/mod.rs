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

//! Shared test utilities.
//!
//! This module is compiled only under `#[cfg(test)]` and is not linked into
//! release binaries. Integration tests under `tests/` access this code via
//! `tests/common/mod.rs`, which includes `env_guard.rs` directly with
//! `#[path]` so both unit and integration tests share one implementation.

#![cfg(test)]

mod env_guard;
pub use env_guard::EnvGuard;

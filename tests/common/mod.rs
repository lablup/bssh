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

//! Shared helpers for integration tests.
//!
//! The integration test binaries under `tests/` cannot see the crate-private
//! `test_helpers` module directly, so we include the `env_guard.rs`
//! implementation via `#[path]`. This ensures unit and integration tests share
//! one source of truth without exposing `EnvGuard` as public API of `bssh`.

#[path = "../../src/test_helpers/env_guard.rs"]
mod env_guard_impl;

#[allow(unused_imports)]
pub use env_guard_impl::EnvGuard;

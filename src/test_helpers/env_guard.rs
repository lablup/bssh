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

//! RAII wrapper for safe environment variable mutation in tests.
//!
//! All `unsafe` calls to `std::env::set_var` / `std::env::remove_var` are
//! encapsulated here. Combined with `#[serial_test::serial]`, this gives tests
//! a safe, cleanup-guaranteed way to manipulate process-wide environment
//! variables without scattering `unsafe {}` blocks across the codebase.
//!
//! # Usage
//!
//! ```ignore
//! use serial_test::serial;
//! use crate::test_helpers::EnvGuard;
//!
//! #[test]
//! #[serial]
//! fn example() {
//!     let _home = EnvGuard::set("HOME", "/tmp/test");
//!     // ... test body; HOME is restored when `_home` drops.
//! }
//! ```
//!
//! # Drop order
//!
//! When a test holds multiple guards, they drop in LIFO order:
//!
//! ```ignore
//! let _home = EnvGuard::set("HOME", "/tmp/test");
//! let _user = EnvGuard::set("USER", "testuser");
//! // Drops in reverse: USER first, then HOME.
//! ```
//!
//! # Encoding
//!
//! Values are stored as `OsString` to preserve non-UTF-8 data on platforms
//! where environment variables can contain arbitrary bytes. Test values used
//! in this crate are all ASCII, so the `var_os` + `set_var` cycle is lossless.

#![cfg(test)]

use std::ffi::{OsStr, OsString};

/// RAII guard that sets or removes an environment variable on construction
/// and restores the previous value (or unset state) on drop.
///
/// Tests that use `EnvGuard` **must** also be annotated with
/// `#[serial_test::serial]` to prevent races with other tests that read or
/// mutate the same variable.
#[must_use = "EnvGuard must be bound to a local; dropping it immediately restores the variable"]
pub struct EnvGuard {
    key: OsString,
    original: Option<OsString>,
}

// `#[allow(dead_code)]` is applied per-method so integration tests that only
// use one constructor don't generate "unused" warnings for the other. The
// file is shared between the unit test module (via the `test_helpers` module
// tree) and integration tests (via `#[path]` include in `tests/common/mod.rs`).
impl EnvGuard {
    /// Set an environment variable, saving its prior value for restoration.
    #[allow(dead_code)]
    pub fn set(key: impl Into<OsString>, value: impl AsRef<OsStr>) -> Self {
        let key = key.into();
        let original = std::env::var_os(&key);
        // SAFETY: tests that construct `EnvGuard` are `#[serial]`, so no
        // other thread reads or writes the environment concurrently.
        unsafe {
            std::env::set_var(&key, value);
        }
        Self { key, original }
    }

    /// Remove an environment variable, saving its prior value for restoration.
    #[allow(dead_code)]
    pub fn remove(key: impl Into<OsString>) -> Self {
        let key = key.into();
        let original = std::env::var_os(&key);
        // SAFETY: same rationale as `set`.
        unsafe {
            std::env::remove_var(&key);
        }
        Self { key, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: same rationale as `set` / `remove`.
        unsafe {
            match self.original.take() {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}

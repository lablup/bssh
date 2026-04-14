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
//! ## Soundness contract
//!
//! `EnvGuard` consolidates the `unsafe` env mutation that `std::env::set_var`
//! and `std::env::remove_var` require under Rust 2024. The `unsafe` blocks
//! inside this module are sound only when callers uphold the following
//! contract: every test that constructs an `EnvGuard` MUST be annotated
//! with `#[serial_test::serial]`, AND every other test in the same crate
//! that reads or mutates the same environment variable MUST also be
//! `#[serial]` (or share a matching `#[serial(key)]` group). Non-serial
//! tests racing against `EnvGuard` mutations are undefined behaviour at the
//! libc level on glibc/musl/macOS.
//!
//! Note: `#[serial]` only serializes against other `#[serial]` and
//! `#[parallel]` tests. Tests with neither attribute may run concurrently
//! with serial tests and are not covered by the serial ordering guarantee.
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
        // SAFETY: `#[serial]`-annotated tests that construct `EnvGuard` do not
        // run concurrently with each other, so cross-serial races on the env
        // block are eliminated. Callers MUST ensure that any test which
        // observes or mutates the same variable is also annotated with
        // `#[serial]` (or with a matching `#[serial(key)]`); non-serial tests
        // reading these variables can still race with `EnvGuard`'s mutations.
        // See the module-level soundness contract for full requirements.
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
        // SAFETY: same rationale as `EnvGuard::set`; see the full comment
        // there and the module-level soundness contract.
        unsafe {
            std::env::remove_var(&key);
        }
        Self { key, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: same rationale as `EnvGuard::set`; see the full comment
        // there and the module-level soundness contract.
        unsafe {
            match self.original.take() {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}

// The file is already gated with `#![cfg(test)]`, so no additional
// `#[cfg(test)]` attribute is needed on this inner module.
mod tests {
    use super::EnvGuard;
    use serial_test::serial;

    // Use a unique prefix so these tests cannot clash with any other test
    // that happens to read or write a same-named variable in parallel.
    const KEY_SET: &str = "BSSH_ENVGUARD_TEST_VAR_SET";
    const KEY_REMOVE: &str = "BSSH_ENVGUARD_TEST_VAR_REMOVE";
    const KEY_CHAIN: &str = "BSSH_ENVGUARD_TEST_VAR_CHAIN";
    const KEY_UNSET: &str = "BSSH_ENVGUARD_TEST_VAR_UNSET";
    const KEY_OVERWRITE: &str = "BSSH_ENVGUARD_TEST_VAR_OVERWRITE";

    /// `EnvGuard::set` must restore the prior value (or absence) when dropped.
    #[test]
    #[serial]
    fn set_restores_prior_value_on_drop() {
        // Ensure the variable is absent before we start.
        unsafe { std::env::remove_var(KEY_SET) };

        {
            let _guard = EnvGuard::set(KEY_SET, "temporary");
            assert_eq!(std::env::var(KEY_SET).ok().as_deref(), Some("temporary"));
        }
        // After the guard drops the variable must be absent again.
        assert!(
            std::env::var(KEY_SET).is_err(),
            "variable should be unset after guard drop"
        );
    }

    /// `EnvGuard::remove` must restore the prior value when dropped.
    #[test]
    #[serial]
    fn remove_restores_prior_value_on_drop() {
        unsafe { std::env::set_var(KEY_REMOVE, "original") };

        {
            let _guard = EnvGuard::remove(KEY_REMOVE);
            assert!(
                std::env::var(KEY_REMOVE).is_err(),
                "variable should be absent while guard is live"
            );
        }
        // After drop the original value must be back.
        assert_eq!(
            std::env::var(KEY_REMOVE).ok().as_deref(),
            Some("original"),
            "variable should be restored after guard drop"
        );
        // Clean up so later test runs start clean.
        unsafe { std::env::remove_var(KEY_REMOVE) };
    }

    /// Multiple guards dropped in LIFO order must each restore their own prior state.
    #[test]
    #[serial]
    fn chained_set_guards_restore_in_lifo_order() {
        unsafe { std::env::remove_var(KEY_CHAIN) };

        {
            let _g1 = EnvGuard::set(KEY_CHAIN, "first");
            assert_eq!(std::env::var(KEY_CHAIN).ok().as_deref(), Some("first"));

            {
                let _g2 = EnvGuard::set(KEY_CHAIN, "second");
                assert_eq!(std::env::var(KEY_CHAIN).ok().as_deref(), Some("second"));
            }
            // _g2 dropped: KEY_CHAIN should be back to "first" (what _g1 saved).
            assert_eq!(
                std::env::var(KEY_CHAIN).ok().as_deref(),
                Some("first"),
                "inner guard should restore to value set by outer guard"
            );
        }
        // _g1 dropped: KEY_CHAIN should be absent (what existed before _g1).
        assert!(
            std::env::var(KEY_CHAIN).is_err(),
            "outer guard should restore to absent state"
        );
    }

    /// `EnvGuard::remove` on a variable that is already unset must be a no-op
    /// and leave the variable unset after dropping.
    #[test]
    #[serial]
    fn remove_on_already_unset_variable_is_noop() {
        unsafe { std::env::remove_var(KEY_UNSET) };

        {
            let _guard = EnvGuard::remove(KEY_UNSET);
            assert!(std::env::var(KEY_UNSET).is_err());
        }
        // Still absent after drop — no spurious value introduced.
        assert!(
            std::env::var(KEY_UNSET).is_err(),
            "removing an already-absent variable should leave it absent"
        );
    }

    /// `EnvGuard::set` when the variable already has a value must restore
    /// that pre-existing value, not leave the variable absent.
    #[test]
    #[serial]
    fn set_over_existing_value_restores_original() {
        unsafe { std::env::set_var(KEY_OVERWRITE, "before") };

        {
            let _guard = EnvGuard::set(KEY_OVERWRITE, "during");
            assert_eq!(std::env::var(KEY_OVERWRITE).ok().as_deref(), Some("during"));
        }
        assert_eq!(
            std::env::var(KEY_OVERWRITE).ok().as_deref(),
            Some("before"),
            "guard should restore the pre-existing value, not remove the variable"
        );
        // Clean up.
        unsafe { std::env::remove_var(KEY_OVERWRITE) };
    }
}

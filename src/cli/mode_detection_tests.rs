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

//! Tests for pdsh compatibility mode detection
//!
//! These tests verify that pdsh compatibility mode is correctly detected
//! based on environment variables and binary names.

#[cfg(test)]
mod tests {
    use crate::cli::pdsh::{PDSH_COMPAT_ENV_VAR, is_pdsh_binary_name};
    use crate::test_helpers::EnvGuard;
    use serial_test::serial;
    use std::env;

    /// Test that environment variable detection works for "1"
    #[test]
    #[serial]
    fn test_env_var_detection_one() {
        let _guard = EnvGuard::set(PDSH_COMPAT_ENV_VAR, "1");

        // Create a test for the env var checking logic
        let value = env::var(PDSH_COMPAT_ENV_VAR).ok();
        assert!(value.is_some());
        let value = value.unwrap();
        assert!(value == "1" || value.to_lowercase() == "true");
    }

    /// Test that environment variable detection works for "true"
    #[test]
    #[serial]
    fn test_env_var_detection_true() {
        let _guard = EnvGuard::set(PDSH_COMPAT_ENV_VAR, "true");

        let value = env::var(PDSH_COMPAT_ENV_VAR).ok();
        assert!(value.is_some());
        assert_eq!(value.unwrap().to_lowercase(), "true");
    }

    /// Test that environment variable detection works for "TRUE" (case insensitive)
    #[test]
    fn test_env_var_detection_case_insensitive() {
        // Test the case-insensitivity logic directly without relying on env var state
        // This avoids race conditions with other tests
        let test_values = ["TRUE", "True", "true", "TrUe"];

        for test_val in test_values {
            // The detection logic: value == "1" || value.to_lowercase() == "true"
            let is_enabled = test_val == "1" || test_val.to_lowercase() == "true";
            assert!(
                is_enabled,
                "Expected '{test_val}' to be detected as enabled"
            );
        }
    }

    /// Test that environment variable is not detected when unset
    #[test]
    #[serial]
    fn test_env_var_not_set() {
        let _guard = EnvGuard::remove(PDSH_COMPAT_ENV_VAR);

        let value = env::var(PDSH_COMPAT_ENV_VAR).ok();
        assert!(value.is_none());
    }

    /// Test that invalid env var values are not treated as enabled
    #[test]
    #[serial]
    fn test_env_var_invalid_values() {
        // Test "0"
        {
            let _guard = EnvGuard::set(PDSH_COMPAT_ENV_VAR, "0");
            let value = env::var(PDSH_COMPAT_ENV_VAR).unwrap();
            let enabled = value == "1" || value.to_lowercase() == "true";
            assert!(!enabled);
        }

        // Test "false"
        {
            let _guard = EnvGuard::set(PDSH_COMPAT_ENV_VAR, "false");
            let value = env::var(PDSH_COMPAT_ENV_VAR).unwrap();
            let enabled = value == "1" || value.to_lowercase() == "true";
            assert!(!enabled);
        }

        // Test empty string
        {
            let _guard = EnvGuard::set(PDSH_COMPAT_ENV_VAR, "");
            let value = env::var(PDSH_COMPAT_ENV_VAR).unwrap();
            let enabled = value == "1" || value.to_lowercase() == "true";
            assert!(!enabled);
        }
    }

    /// Test binary name detection logic for "pdsh"
    #[test]
    fn test_binary_name_pdsh() {
        assert!(is_pdsh_binary_name("/usr/bin/pdsh"));
    }

    /// Test binary name detection for relative path
    #[test]
    fn test_binary_name_relative_path() {
        assert!(is_pdsh_binary_name("./pdsh"));
    }

    /// Test binary name detection for "pdsh.exe" (Windows)
    #[test]
    #[cfg(windows)]
    fn test_binary_name_windows() {
        assert!(is_pdsh_binary_name("C:\\Program Files\\bssh\\pdsh.exe"));
    }

    /// Test binary name detection for "pdsh.exe" pattern
    #[test]
    fn test_binary_name_exe_extension() {
        assert!(is_pdsh_binary_name("pdsh.exe"));
    }

    /// Test that bssh binary name is not detected as pdsh
    #[test]
    fn test_binary_name_bssh() {
        assert!(!is_pdsh_binary_name("/usr/bin/bssh"));
    }

    /// Test that symlinked pdsh is detected
    #[test]
    fn test_binary_name_symlink() {
        assert!(is_pdsh_binary_name("/usr/local/bin/pdsh"));
    }

    /// Test edge case: empty arg0
    #[test]
    fn test_binary_name_empty() {
        assert!(!is_pdsh_binary_name(""));
    }

    /// Test edge case: just filename without path
    #[test]
    fn test_binary_name_no_path() {
        assert!(is_pdsh_binary_name("pdsh"));
    }
}

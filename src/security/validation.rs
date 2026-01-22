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

//! Security utilities for validating and sanitizing user input.
//!
//! This module re-exports validation functions from the shared module for
//! backward compatibility. New code should prefer importing directly from
//! `crate::shared::validation`.
//!
//! # Migration Note
//!
//! The validation utilities have been moved to `crate::shared::validation`
//! to enable code reuse between the bssh client and server implementations.
//! This module continues to work for backward compatibility.

// Re-export all validation functions from the shared module
pub use crate::shared::validation::{
    sanitize_error_message, validate_hostname, validate_local_path, validate_remote_path,
    validate_username,
};

// Re-export tests to ensure they still run
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_validate_local_path() {
        // Valid paths
        assert!(validate_local_path(Path::new("/tmp/test.txt")).is_ok());
        assert!(validate_local_path(Path::new("./test.txt")).is_ok());

        // Invalid paths with traversal
        assert!(validate_local_path(Path::new("../etc/passwd")).is_err());
        assert!(validate_local_path(Path::new("/tmp/../etc/passwd")).is_err());
        assert!(validate_local_path(Path::new("/tmp//test")).is_err());
    }

    #[test]
    fn test_validate_remote_path() {
        // Valid paths
        assert!(validate_remote_path("/home/user/file.txt").is_ok());
        assert!(validate_remote_path("~/documents/report.pdf").is_ok());
        assert!(validate_remote_path("C:\\Users\\test\\file.txt").is_ok());

        // Invalid paths
        assert!(validate_remote_path("../etc/passwd").is_err());
        assert!(validate_remote_path("/tmp/$(whoami)").is_err());
        assert!(validate_remote_path("/tmp/test; rm -rf /").is_err());
        assert!(validate_remote_path("/tmp/test`id`").is_err());
        assert!(validate_remote_path("/tmp/test|cat").is_err());
        assert!(validate_remote_path("").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        // Valid hostnames
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("192.168.1.1").is_ok());
        assert!(validate_hostname("server-01.example.com").is_ok());
        assert!(validate_hostname("[::1]").is_ok());

        // Invalid hostnames
        assert!(validate_hostname("example..com").is_err());
        assert!(validate_hostname("server--01").is_err());
        assert!(validate_hostname("example.com; ls").is_err());
        assert!(validate_hostname("").is_err());
    }

    #[test]
    fn test_validate_username() {
        // Valid usernames
        assert!(validate_username("john_doe").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test.user").is_ok());

        // Invalid usernames
        assert!(validate_username("-user").is_err());
        assert!(validate_username("user@domain").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("").is_err());
        assert!(validate_username(&"a".repeat(50)).is_err());
    }
}

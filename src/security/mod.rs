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

//! Security utilities for validating and sanitizing user input and handling
//! sensitive data securely.
//!
//! # Re-exports
//!
//! This module re-exports validation functions from the shared module for
//! backward compatibility. New code should prefer importing directly from
//! `crate::shared::validation`.

mod sudo;

// Keep the validation module for backward compatibility but it now re-exports
// from shared
pub mod validation;

// Re-export validation functions from shared module for backward compatibility
pub use crate::shared::validation::{
    sanitize_error_message, validate_hostname, validate_local_path, validate_remote_path,
    validate_username,
};

// Re-export sudo password handling
pub use sudo::{
    contains_sudo_failure, contains_sudo_prompt, get_sudo_password, prompt_sudo_password,
    SudoPassword, SUDO_FAILURE_PATTERNS, SUDO_PROMPT_PATTERNS,
};

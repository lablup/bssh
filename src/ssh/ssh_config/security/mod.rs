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

//! Security validation functions for SSH configuration
//!
//! This module contains security-critical functions that prevent various types of
//! attacks including command injection, path traversal, and privilege escalation.

mod checks;
mod path_validation;
mod string_validation;

pub use path_validation::secure_validate_path;
pub use string_validation::{validate_control_path, validate_executable_string};

#[cfg(test)]
mod tests;

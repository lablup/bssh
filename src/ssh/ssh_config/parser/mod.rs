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

//! SSH configuration parsing module
//!
//! This module is organized into submodules for better maintainability:
//! - `core`: Main parsing functions and logic
//! - `helpers`: Utility functions for parsing
//! - `options`: Option-specific parsing logic organized by category
//! - `tests`: Comprehensive test suite

mod core;
mod helpers;
mod options;

#[cfg(test)]
mod tests;

// Re-export public items from core module
pub(super) use core::{parse, parse_from_file};

// Re-export helper functions that might be used elsewhere

// Re-export the main option parser (used by other modules if needed)

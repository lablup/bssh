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

//! CLI module for bssh
//!
//! This module provides command-line interface parsing for bssh, including:
//! - Standard bssh CLI (`Cli`)
//! - pdsh compatibility layer (`pdsh` submodule)
//!
//! # Architecture
//!
//! The CLI module is structured as follows:
//! - `bssh.rs` - Main bssh CLI parser with all standard options
//! - `pdsh.rs` - pdsh-compatible CLI parser for drop-in replacement mode
//!
//! # pdsh Compatibility Mode
//!
//! bssh can operate in pdsh compatibility mode, activated by:
//! 1. Setting `BSSH_PDSH_COMPAT=1` environment variable
//! 2. Symlinking bssh to "pdsh" and invoking via that name
//! 3. Using the `--pdsh-compat` flag
//!
//! See the `pdsh` module documentation for details on option mapping.

mod bssh;
pub mod pdsh;

#[cfg(test)]
mod mode_detection_tests;

// Re-export main CLI types from bssh module
pub use bssh::{Cli, Commands};

// Re-export pdsh compatibility utilities
pub use pdsh::{
    has_pdsh_compat_flag, is_pdsh_compat_mode, remove_pdsh_compat_flag, PdshCli, QueryResult,
    PDSH_COMPAT_ENV_VAR,
};

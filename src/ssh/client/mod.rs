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

//! SSH client module providing high-level SSH operations
//!
//! This module is organized into several submodules:
//! - `config`: Connection configuration structures
//! - `core`: Core SSH client implementation
//! - `command`: Command execution functionality
//! - `file_transfer`: File and directory transfer operations
//! - `connection`: Connection management and authentication
//! - `result`: Command result handling

mod command;
mod config;
mod connection;
mod core;
mod file_transfer;
mod result;

// Re-export public API
pub use config::ConnectionConfig;
pub use core::SshClient;
pub use result::CommandResult;

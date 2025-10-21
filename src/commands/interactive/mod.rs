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

//! Interactive mode implementation for SSH sessions
//!
//! This module provides both traditional rustyline-based interactive mode
//! and modern PTY-based interactive mode with full terminal support.
//!
//! ## Architecture
//!
//! The interactive module is split into focused submodules for maintainability:
//!
//! ### Core Components
//! - `types`: Core types and structures (InteractiveCommand, InteractiveResult, NodeSession)
//! - `execution`: Main execution logic coordinating PTY and traditional modes
//!
//! ### Connection Management
//! - `connection`: SSH connection establishment for interactive sessions
//!   - Handles both direct connections and jump host chains
//!   - Manages authentication method selection
//!   - Supports both traditional and PTY-enabled channels
//!
//! ### Session Management
//! - `single_node`: Single node interactive session handling
//!   - Rustyline-based command input
//!   - Real-time SSH output streaming
//!   - Command history management
//!
//! - `multiplex`: Multi-node multiplexed session handling
//!   - Parallel command execution across nodes
//!   - Node selection and activation
//!   - Coordinated output display with timestamps
//!
//! ### Utilities
//! - `commands`: Special command parsing and handling (node switching, broadcast, etc.)
//! - `utils`: Utility functions for prompts, path expansion, PTY detection
//!
//! ## Public API
//!
//! The module exports only the public-facing types:
//! - `InteractiveCommand`: Configuration and entry point for interactive sessions
//! - `InteractiveResult`: Summary of interactive session execution

mod commands;
mod connection;
mod execution;
mod multiplex;
mod single_node;
mod types;
mod utils;

// Re-export public API
pub use types::{InteractiveCommand, InteractiveResult};

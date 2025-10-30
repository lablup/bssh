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

//! UI module for bssh
//!
//! This module contains both basic terminal formatting and the interactive TUI.
//! - `basic`: Simple terminal output formatting with colors and progress
//! - `tui`: Interactive terminal UI with ratatui for real-time monitoring

pub mod basic;
pub mod tui;

// Re-export basic UI components for backward compatibility
pub use basic::*;

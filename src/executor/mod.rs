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

//! Parallel execution framework for SSH operations.

mod connection_manager;
mod execution_strategy;
mod output_mode;
mod parallel;
mod result_types;
mod stream_manager;

pub mod exit_strategy;
pub mod rank_detector;

// Re-export public types
pub use connection_manager::download_dir_from_node;
pub use exit_strategy::ExitCodeStrategy;
pub use output_mode::{is_tty, should_use_colors, OutputMode};
pub use parallel::ParallelExecutor;
pub use rank_detector::RankDetector;
pub use result_types::{DownloadResult, ExecutionResult, UploadResult};
pub use stream_manager::{ExecutionStatus, MultiNodeStreamManager, NodeStream};

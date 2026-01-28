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

//! Configuration management for bssh.

mod interactive;
mod loader;
mod resolver;
#[cfg(test)]
mod tests;
mod types;
mod utils;

// Re-export public types
pub use types::{
    Cluster, ClusterDefaults, Config, Defaults, InteractiveConfig, InteractiveConfigUpdate,
    InteractiveMode, JumpHostConfig, KeyBindings, NodeConfig,
};
pub use utils::{expand_env_vars, expand_tilde};

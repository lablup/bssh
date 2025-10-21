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

//! Jump host parsing for OpenSSH ProxyJump format

mod config;
mod host;
mod host_parser;
mod main_parser;

pub use config::{get_max_jump_hosts, ABSOLUTE_MAX_JUMP_HOSTS, DEFAULT_MAX_JUMP_HOSTS};
pub use host::JumpHost;
pub use main_parser::parse_jump_hosts;

// Internal use

#[cfg(test)]
mod tests;

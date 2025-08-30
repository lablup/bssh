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

//! SSH jump host (ProxyJump) implementation for bssh
//!
//! This module provides SSH jump host functionality compatible with OpenSSH's ProxyJump (-J) option.
//! It supports connecting through one or more intermediate SSH servers (jump hosts/bastions) to reach
//! the final destination host.
//!
//! # Features
//! * OpenSSH-compatible -J syntax: `user1@jump1:port1,user2@jump2:port2`
//! * Single and multi-hop jump host chains
//! * Per-host authentication (different methods for each jump)
//! * Connection reuse for multiple operations
//! * Automatic retry with exponential backoff
//! * Integration with existing host verification and authentication

pub mod chain;
pub mod connection;
pub mod parser;
pub mod rate_limiter;

pub use chain::{JumpConnection, JumpHostChain};
pub use connection::JumpHostConnection;
pub use parser::{parse_jump_hosts, JumpHost};

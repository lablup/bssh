// Copyright 2025 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

//! sshot-style YAML playbooks.
//!
//! This is a deliberately limited playbook runner, not an Ansible compatibility
//! layer. Parsing, condition evaluation, and execution are isolated here so the
//! existing bssh command paths remain unchanged.

mod condition;
mod executor;
mod model;
mod parser;

pub use executor::{RunOptions, run_file};

// Copyright 2025 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

pub type Variables = BTreeMap<String, Value>;

#[derive(Debug, Clone)]
pub struct SshDefaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<PathBuf>,
    pub use_agent: bool,
    pub strict_host_key_checking: Option<String>,
    pub connect_timeout: Option<u64>,
}

impl Default for SshDefaults {
    fn default() -> Self {
        Self {
            user: None,
            port: None,
            identity_file: None,
            use_agent: false,
            strict_host_key_checking: Some("yes".to_owned()),
            connect_timeout: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InventoryHost {
    pub name: String,
    pub hostname: String,
    pub ssh: SshDefaults,
    pub variables: Variables,
    pub groups: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub ssh: SshDefaults,
    pub hosts: BTreeMap<String, InventoryHost>,
    pub groups: BTreeMap<String, Vec<String>>,
    pub group_order: BTreeMap<String, i64>,
    pub group_parallel: BTreeMap<String, bool>,
    pub group_dependencies: BTreeMap<String, Vec<String>>,
    pub order: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Playbook {
    pub plays: Vec<Play>,
    pub inventory: Option<Inventory>,
}

#[derive(Debug, Clone)]
pub struct Play {
    pub name: String,
    pub hosts: Vec<String>,
    pub groups: Vec<String>,
    pub variables: Variables,
    pub facts: BTreeMap<String, (String, bool)>,
    pub tasks: Vec<Task>,
    pub parallel: usize,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Task {
    pub name: String,
    pub action: Action,
    pub condition: Option<String>,
    pub register: Option<String>,
    pub retries: u32,
    pub retry_delay: u64,
    pub timeout: Option<u64>,
    pub allowed_exit_codes: Vec<u32>,
    pub ignore_error: bool,
    pub sudo: bool,
    pub variables: Variables,
    pub dependencies: Vec<String>,
    pub groups: Vec<String>,
    pub skip_groups: Vec<String>,
    pub delegate_to: Option<String>,
    pub run_once: bool,
}

#[derive(Debug, Clone)]
pub enum Action {
    Command(String),
    Shell(String),
    Script {
        source: PathBuf,
        args: String,
    },
    Copy {
        source: PathBuf,
        destination: String,
        mode: Option<String>,
    },
    WaitFor {
        command: String,
        interval: u64,
    },
    Local(String),
}

pub(crate) fn key(name: &str) -> Value {
    Value::String(name.to_owned())
}

pub(crate) fn map_get<'a>(map: &'a Mapping, name: &str) -> Option<&'a Value> {
    map.get(key(name))
}

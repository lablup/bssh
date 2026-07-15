// Copyright 2025 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::condition::{evaluate, render, render_planning};
use super::model::*;
use super::parser::{self, shell_quote};
use anyhow::{Context, Result, bail};
use futures::{StreamExt, stream};
use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::ssh::client::{ConnectionConfig, SshClient};
use crate::ssh::known_hosts::StrictHostKeyChecking;

#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    pub dry_run: bool,
    pub full_output: bool,
}

#[derive(Debug, Clone)]
struct Outcome {
    stdout: String,
    stderr: String,
    exit_code: u32,
    success: bool,
}

#[derive(Debug, Clone)]
struct HostState {
    host: InventoryHost,
    variables: Variables,
    completed: BTreeMap<String, bool>,
    pending_run_once_failures: BTreeSet<String>,
    runtime_unknowns: BTreeSet<String>,
    failed: bool,
}

pub async fn run_file(
    playbook_path: &Path,
    inventory_path: Option<&Path>,
    options: RunOptions,
) -> Result<()> {
    let mut book = parser::load(playbook_path, inventory_path)?;
    let inventory = book.inventory.take().ok_or_else(|| {
anyhow::anyhow!(
"no inventory found; pass --inventory or use a legacy combined YAML with an inventory section"
)
})?;
    validate(&book.plays, &inventory, playbook_path)?;
    let plays = order_plays(book.plays)?;
    let base_dir = playbook_path.parent().unwrap_or_else(|| Path::new("."));
    let mut completed_plays = BTreeSet::new();
    let mut any_failed = false;

    for mut play in plays {
        if !play
            .dependencies
            .iter()
            .all(|d| completed_plays.contains(d))
        {
            bail!("play '{}' has an unsatisfied dependency", play.name);
        }
        println!("PLAY [{}]", play.name);
        play.tasks = order_tasks(std::mem::take(&mut play.tasks))?;
        let run_once_successes = Arc::new(Mutex::new(BTreeSet::new()));
        let mut play_failed = false;

        if inventory.groups.is_empty() {
            let hosts = resolve_hosts(&inventory, &play.hosts, &play.groups)?;
            let states = execute_batch(
                hosts,
                &play,
                &inventory,
                base_dir,
                options,
                play.parallel > 1,
                Arc::clone(&run_once_successes),
            )
            .await?;
            play_failed = states.iter().any(|state| state.failed);
        } else {
            // In sshot group mode, groups are authoritative and direct
            // inventory hosts are deliberately ignored.
            let mut completed_groups = BTreeSet::new();
            for group in ordered_groups(&inventory)? {
                let dependencies = inventory
                    .group_dependencies
                    .get(&group)
                    .cloned()
                    .unwrap_or_default();
                if !dependencies.iter().all(|d| completed_groups.contains(d)) {
                    eprintln!("SKIPPED GROUP [{group}] (dependency group did not succeed)");
                    play_failed = true;
                    continue;
                }
                println!("GROUP [{group}]");
                let hosts = inventory.groups[&group]
                    .iter()
                    .filter_map(|name| inventory.hosts.get(name).cloned())
                    .collect::<Vec<_>>();
                let states = execute_batch(
                    hosts,
                    &play,
                    &inventory,
                    base_dir,
                    options,
                    inventory
                        .group_parallel
                        .get(&group)
                        .copied()
                        .unwrap_or(false),
                    Arc::clone(&run_once_successes),
                )
                .await?;
                if states.iter().any(|state| state.failed) {
                    play_failed = true;
                } else {
                    completed_groups.insert(group);
                }
            }
        }

        if play_failed {
            any_failed = true;
        } else {
            completed_plays.insert(play.name);
        }
    }

    if any_failed {
        bail!("playbook completed with failed tasks");
    }
    Ok(())
}

fn ordered_groups(inventory: &Inventory) -> Result<Vec<String>> {
    let mut pending = inventory.groups.keys().cloned().collect::<Vec<_>>();
    pending.sort_by_key(|group| inventory.group_order.get(group).copied().unwrap_or(0));
    let mut complete = BTreeSet::new();
    let mut ordered = Vec::new();
    while !pending.is_empty() {
        let position = pending.iter().position(|group| {
            inventory
                .group_dependencies
                .get(group)
                .map(|deps| deps.iter().all(|dep| complete.contains(dep)))
                .unwrap_or(true)
        });
        let Some(position) = position else {
            bail!("cyclic inventory group dependencies");
        };
        let group = pending.remove(position);
        complete.insert(group.clone());
        ordered.push(group);
    }
    Ok(ordered)
}

async fn execute_batch(
    hosts: Vec<InventoryHost>,
    play: &Play,
    inventory: &Inventory,
    base_dir: &Path,
    options: RunOptions,
    parallel: bool,
    run_once_successes: Arc<Mutex<BTreeSet<String>>>,
) -> Result<Vec<HostState>> {
    if hosts.is_empty() {
        bail!("inventory batch contains no hosts");
    }
    let states = hosts
        .into_iter()
        .map(|host| new_host_state(host, play))
        .collect::<Vec<_>>();
    let concurrency = if parallel && !options.dry_run {
        states.len().max(1)
    } else {
        1
    };
    let mut results = stream::iter(states)
        .map(|state| {
            execute_host_chain(
                state,
                play,
                inventory,
                base_dir,
                options,
                Arc::clone(&run_once_successes),
            )
        })
        .buffered(concurrency)
        .collect::<Vec<Result<HostState>>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let successes = run_once_successes.lock().await;
    for state in &mut results {
        if state
            .pending_run_once_failures
            .iter()
            .any(|task| !successes.contains(task))
        {
            state.failed = true;
        }
    }
    Ok(results)
}

fn new_host_state(host: InventoryHost, play: &Play) -> HostState {
    let mut variables = play.variables.clone();
    variables.extend(host.variables.clone());
    add_builtin_variables(&mut variables, &host);
    HostState {
        host,
        variables,
        completed: BTreeMap::new(),
        pending_run_once_failures: BTreeSet::new(),
        runtime_unknowns: BTreeSet::new(),
        failed: false,
    }
}

async fn execute_host_chain(
    mut state: HostState,
    play: &Play,
    inventory: &Inventory,
    base_dir: &Path,
    options: RunOptions,
    run_once_successes: Arc<Mutex<BTreeSet<String>>>,
) -> Result<HostState> {
    if options.dry_run {
        for (fact, (command, _sudo)) in &play.facts {
            state.runtime_unknowns.insert(fact.clone());
            println!(
                "DRY-RUN [{}] FACT {} => {}",
                state.host.name,
                fact,
                render_planning(command, &state.variables)?
            );
        }
    } else {
        collect_facts(play, std::slice::from_mut(&mut state), options).await?;
    }

    for task in &play.tasks {
        println!("TASK [{}] [{}]", task.name, state.host.name);
        if !task_is_eligible(task, &state) {
            state.completed.insert(task.name.clone(), false);
            continue;
        }

        if task.run_once {
            let mut successes = run_once_successes.lock().await;
            if successes.contains(&task.name) {
                state.completed.insert(task.name.clone(), true);
                continue;
            }
            match execute_for_state(task, inventory, &state, base_dir, options).await? {
                None => {
                    state.completed.insert(task.name.clone(), true);
                }
                Some(outcome) => {
                    if options.dry_run {
                        record_planned_outcome(task, &mut state);
                    } else {
                        record_outcome(task, &mut state, &outcome)?;
                    }
                    if outcome.success || options.dry_run {
                        successes.insert(task.name.clone());
                    } else if !task.ignore_error {
                        state.pending_run_once_failures.insert(task.name.clone());
                    }
                }
            }
        } else {
            match execute_for_state(task, inventory, &state, base_dir, options).await? {
                None => {
                    state.completed.insert(task.name.clone(), true);
                }
                Some(outcome) => {
                    if options.dry_run {
                        record_planned_outcome(task, &mut state);
                    } else {
                        record_outcome(task, &mut state, &outcome)?;
                    }
                    if !outcome.success && !task.ignore_error {
                        state.failed = true;
                    }
                }
            }
        }
        if state.failed {
            break;
        }
    }
    Ok(state)
}

#[allow(dead_code)]
async fn run_file_legacy(
    playbook_path: &Path,
    inventory_path: Option<&Path>,
    options: RunOptions,
) -> Result<()> {
    let mut book = parser::load(playbook_path, inventory_path)?;
    let inventory = book.inventory.take().ok_or_else(|| {
        anyhow::anyhow!(
            "no inventory found; pass --inventory or use a legacy combined YAML with an inventory section"
        )
    })?;
    validate(&book.plays, &inventory, playbook_path)?;
    let plays = order_plays(book.plays)?;
    let base_dir = playbook_path.parent().unwrap_or_else(|| Path::new("."));
    let mut completed_plays = BTreeSet::new();
    let mut failed = false;

    for play in plays {
        if !play
            .dependencies
            .iter()
            .all(|d| completed_plays.contains(d))
        {
            bail!("play '{}' has an unsatisfied dependency", play.name);
        }
        println!("PLAY [{}]", play.name);
        let hosts = resolve_hosts(&inventory, &play.hosts, &play.groups)?;
        let mut states = Vec::with_capacity(hosts.len());
        for host in hosts {
            let mut variables = play.variables.clone();
            variables.extend(host.variables.clone());
            add_builtin_variables(&mut variables, &host);
            states.push(HostState {
                host,
                variables,
                completed: BTreeMap::new(),
                pending_run_once_failures: BTreeSet::new(),
                runtime_unknowns: BTreeSet::new(),
                failed: false,
            });
        }

        let selected_group_modes = states
            .iter()
            .flat_map(|state| state.host.groups.iter())
            .filter_map(|group| inventory.group_parallel.get(group))
            .copied()
            .collect::<Vec<_>>();
        let effective_parallel = if selected_group_modes.is_empty() {
            play.parallel
        } else if selected_group_modes.iter().all(|parallel| *parallel) {
            play.parallel.max(10)
        } else {
            1
        };

        if options.dry_run {
            for (fact, (command, _sudo)) in &play.facts {
                for state in &states {
                    println!(
                        "DRY-RUN [{}] FACT {} => {}",
                        state.host.name,
                        fact,
                        render_planning(command, &state.variables)?
                    );
                }
            }
        } else {
            collect_facts(&play, &mut states, options).await?;
        }

        for task in order_tasks(play.tasks.clone())? {
            println!("TASK [{}]", task.name);
            if task.run_once {
                let succeeded =
                    run_once_task(&task, &inventory, &mut states, base_dir, options).await?;
                for state in &mut states {
                    state
                        .completed
                        .insert(task.name.clone(), succeeded || task.ignore_error);
                }
                if !succeeded && !task.ignore_error {
                    failed = true;
                }
                continue;
            }

            let work: Vec<(usize, HostState)> = states
                .iter()
                .cloned()
                .enumerate()
                .filter(|(_, state)| task_is_eligible(&task, state))
                .collect();
            let results: Vec<(usize, Result<Option<Outcome>>)> = stream::iter(work)
                .map(|(index, state)| {
                    let task = task.clone();
                    let inventory = &inventory;
                    async move {
                        let result =
                            execute_for_state(&task, inventory, &state, base_dir, options).await;
                        (index, result)
                    }
                })
                .buffer_unordered(effective_parallel)
                .collect()
                .await;

            let mut touched = BTreeSet::new();
            for (index, result) in results {
                touched.insert(index);
                match result? {
                    None => {
                        states[index].completed.insert(task.name.clone(), true);
                    }
                    Some(outcome) => {
                        record_outcome(&task, &mut states[index], &outcome)?;
                        if !outcome.success && !task.ignore_error {
                            states[index].failed = true;
                            failed = true;
                        }
                    }
                }
            }
            for (index, state) in states.iter_mut().enumerate() {
                if !touched.contains(&index) {
                    state.completed.insert(task.name.clone(), false);
                }
            }
        }
        if !states.iter().any(|state| state.failed) {
            completed_plays.insert(play.name);
        }
    }

    if failed {
        bail!("playbook completed with failed tasks");
    }
    Ok(())
}

fn validate(plays: &[Play], inventory: &Inventory, playbook_path: &Path) -> Result<()> {
    for (group, dependencies) in &inventory.group_dependencies {
        for dependency in dependencies {
            if !inventory.groups.contains_key(dependency) {
                bail!("inventory group '{group}' depends on unknown group '{dependency}'");
            }
        }
    }
    let play_names: BTreeSet<&str> = plays.iter().map(|p| p.name.as_str()).collect();
    if play_names.len() != plays.len() {
        bail!("play names must be unique");
    }
    for play in plays {
        for dependency in &play.dependencies {
            if !play_names.contains(dependency.as_str()) {
                bail!(
                    "play '{}' depends on unknown play '{dependency}'",
                    play.name
                );
            }
        }
        let task_names: BTreeSet<&str> = play.tasks.iter().map(|t| t.name.as_str()).collect();
        if task_names.len() != play.tasks.len() {
            bail!("task names in play '{}' must be unique", play.name);
        }
        for task in &play.tasks {
            for dependency in &task.dependencies {
                if !task_names.contains(dependency.as_str()) {
                    bail!(
                        "task '{}' depends on unknown task '{dependency}'",
                        task.name
                    );
                }
            }
            if let Some(delegate) = &task.delegate_to
                && delegate != "localhost"
                && !inventory.hosts.contains_key(delegate)
            {
                bail!(
                    "task '{}' delegates to unknown inventory host '{delegate}'",
                    task.name
                );
            }
            if let Some(condition) = &task.condition {
                // Syntax-check without requiring runtime values.
                let empty = Variables::new();
                if let Err(error) = evaluate(condition, &empty)
                    && !error.to_string().contains("undefined variable")
                {
                    return Err(error).with_context(|| format!("task '{}' condition", task.name));
                }
            }
            match &task.action {
                Action::Script { source, .. } | Action::Copy { source, .. } => {
                    let source = resolve_local_path(playbook_path, source);
                    if !source.is_file() {
                        bail!(
                            "task '{}' source does not exist: {}",
                            task.name,
                            source.display()
                        );
                    }
                    let bytes = std::fs::read(&source).with_context(|| {
                        format!("failed to validate task '{}' source", task.name)
                    })?;
                    if bytes.len() > MAX_INLINE_SOURCE_BYTES {
                        bail!(
                            "task '{}' source exceeds the {}-byte inline playbook limit",
                            task.name,
                            MAX_INLINE_SOURCE_BYTES
                        );
                    }
                    std::str::from_utf8(&bytes)
                        .with_context(|| format!("task '{}' source must be UTF-8", task.name))?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn order_plays(plays: Vec<Play>) -> Result<Vec<Play>> {
    topo_sort(plays, |p| &p.name, |p| &p.dependencies, "play")
}

fn order_tasks(tasks: Vec<Task>) -> Result<Vec<Task>> {
    topo_sort(tasks, |t| &t.name, |t| &t.dependencies, "task")
}

fn topo_sort<T: Clone>(
    items: Vec<T>,
    name: impl Fn(&T) -> &String,
    dependencies: impl Fn(&T) -> &Vec<String>,
    label: &str,
) -> Result<Vec<T>> {
    let mut pending = items;
    let mut complete = BTreeSet::new();
    let mut output = Vec::new();
    while !pending.is_empty() {
        let position = pending
            .iter()
            .position(|item| dependencies(item).iter().all(|d| complete.contains(d)));
        let Some(position) = position else {
            bail!("cyclic {label} dependencies");
        };
        let item = pending.remove(position);
        complete.insert(name(&item).clone());
        output.push(item);
    }
    Ok(output)
}

fn resolve_hosts(
    inventory: &Inventory,
    selectors: &[String],
    groups: &[String],
) -> Result<Vec<InventoryHost>> {
    let mut wanted = BTreeSet::new();
    let mut direct = BTreeMap::new();
    for selector in selectors.iter().chain(groups) {
        if selector == "all" {
            wanted.extend(inventory.hosts.keys().cloned());
        } else if let Some(members) = inventory.groups.get(selector) {
            wanted.extend(members.iter().cloned());
        } else if inventory.hosts.contains_key(selector) {
            wanted.insert(selector.clone());
        } else if groups.contains(selector) {
            bail!("unknown inventory group '{selector}'");
        } else {
            // sshot accepts a direct hostname alongside inventory aliases.
            let mut host = InventoryHost {
                name: selector.clone(),
                hostname: selector.clone(),
                ssh: inventory.ssh.clone(),
                variables: Variables::new(),
                groups: BTreeSet::new(),
            };
            if let Ok(node) = crate::Node::parse(selector, inventory.ssh.user.as_deref()) {
                host.hostname = node.host;
                host.ssh.user = Some(node.username);
                host.ssh.port = Some(node.port);
            }
            direct.insert(selector.clone(), host);
            wanted.insert(selector.clone());
        }
    }
    let mut names = inventory.order.clone();
    for name in inventory.hosts.keys().chain(direct.keys()) {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    let hosts = names
        .into_iter()
        .filter(|name| wanted.contains(name))
        .filter_map(|name| {
            inventory
                .hosts
                .get(&name)
                .cloned()
                .or_else(|| direct.get(&name).cloned())
        })
        .collect::<Vec<_>>();
    if hosts.is_empty() {
        bail!("play selected no hosts");
    }
    Ok(hosts)
}

fn task_is_eligible(task: &Task, state: &HostState) -> bool {
    !state.failed
        && task
            .dependencies
            .iter()
            .all(|d| state.completed.get(d) == Some(&true))
        && (task.groups.is_empty() || task.groups.iter().any(|g| state.host.groups.contains(g)))
        && !task
            .skip_groups
            .iter()
            .any(|g| state.host.groups.contains(g))
}

async fn collect_facts(play: &Play, states: &mut [HostState], options: RunOptions) -> Result<()> {
    for (name, (command, sudo)) in &play.facts {
        for state in states.iter_mut() {
            let command = render(command, &state.variables)?;
            let command = with_sudo(&command, *sudo);
            let outcome = run_remote(&state.host, &command, Some(60))
                .await
                .with_context(|| format!("fact '{name}' on {}", state.host.name))?;
            if outcome.exit_code != 0 {
                bail!(
                    "fact '{name}' failed on {} with exit code {}",
                    state.host.name,
                    outcome.exit_code
                );
            }
            let json: serde_json::Value = serde_json::from_str(outcome.stdout.trim())
                .with_context(|| {
                    format!(
                        "fact '{name}' on {} did not emit valid JSON",
                        state.host.name
                    )
                })?;
            state
                .variables
                .insert(name.clone(), serde_yaml::to_value(json)?);
            print_outcome(&state.host.name, &format!("fact:{name}"), &outcome, options);
        }
    }
    Ok(())
}

async fn run_once_task(
    task: &Task,
    inventory: &Inventory,
    states: &mut [HostState],
    base_dir: &Path,
    options: RunOptions,
) -> Result<bool> {
    let mut attempted = false;
    let mut eligible = false;
    for state in states.iter_mut().filter(|s| task_is_eligible(task, s)) {
        eligible = true;
        match execute_for_state(task, inventory, state, base_dir, options).await? {
            None => continue,
            Some(outcome) => {
                attempted = true;
                record_outcome(task, state, &outcome)?;
                if outcome.success || options.dry_run {
                    return Ok(true);
                }
            }
        }
    }
    // A conditionally skipped run-once task is complete; a task with no
    // eligible hosts (for example because dependencies failed) is not.
    Ok(eligible && !attempted)
}

async fn execute_for_state(
    task: &Task,
    inventory: &Inventory,
    state: &HostState,
    base_dir: &Path,
    options: RunOptions,
) -> Result<Option<Outcome>> {
    let mut variables = state.variables.clone();
    variables.extend(task.variables.clone());
    if let Some(condition) = &task.condition {
        let condition_is_runtime_unknown = options.dry_run
            && state
                .runtime_unknowns
                .iter()
                .any(|name| condition.contains(name));
        if condition_is_runtime_unknown {
            println!(
                "DRY-RUN [{}] {} (condition depends on runtime value)",
                state.host.name, task.name
            );
        } else {
            match evaluate(condition, &variables) {
                Ok(false) => {
                    println!("SKIPPED [{}] {} (condition)", state.host.name, task.name);
                    return Ok(None);
                }
                Ok(true) => {}
                Err(error)
                    if options.dry_run && error.to_string().contains("undefined variable") =>
                {
                    println!(
                        "DRY-RUN [{}] {} (condition evaluated at runtime)",
                        state.host.name, task.name
                    );
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("task '{}' condition", task.name));
                }
            }
        }
    }
    let delegate_local = task.delegate_to.as_deref() == Some("localhost");
    let target = task
        .delegate_to
        .as_deref()
        .filter(|delegate| *delegate != "localhost")
        .map(|delegate| inventory.hosts.get(delegate).expect("delegate validated"))
        .unwrap_or(&state.host);
    let prepared = prepare_action(&task.action, &variables, base_dir, options.dry_run)?;
    if options.dry_run {
        if !delegate_local {
            validate_planned_remote_action(&prepared, task.sudo)?;
        }
        let target_name = if delegate_local {
            "localhost"
        } else {
            &target.name
        };
        println!(
            "DRY-RUN [{} -> {}] {}",
            state.host.name,
            target_name,
            describe_action(&prepared)
        );
        return Ok(Some(Outcome {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            success: true,
        }));
    }

    let mut last_error = None;
    for attempt in 1..=task.retries {
        let result = run_action(target, &prepared, task.timeout, task.sudo, delegate_local).await;
        match result {
            Ok(mut outcome) => {
                outcome.success = task.allowed_exit_codes.contains(&outcome.exit_code);
                print_outcome(&state.host.name, &task.name, &outcome, options);
                if outcome.success {
                    return Ok(Some(outcome));
                }
                last_error = Some(anyhow::anyhow!("exit code {}", outcome.exit_code));
                if attempt == task.retries {
                    return Ok(Some(outcome));
                }
            }
            Err(error) => {
                eprintln!(
                    "FAILED [{}] {} attempt {}/{}: {error:#}",
                    state.host.name, task.name, attempt, task.retries
                );
                last_error = Some(error);
            }
        }
        if attempt < task.retries && task.retry_delay > 0 {
            tokio::time::sleep(Duration::from_secs(task.retry_delay)).await;
        }
    }
    let error = last_error.unwrap_or_else(|| anyhow::anyhow!("task failed"));
    if task.ignore_error {
        let outcome = Outcome {
            stdout: String::new(),
            stderr: format!("{error:#}"),
            exit_code: 255,
            success: false,
        };
        print_outcome(&state.host.name, &task.name, &outcome, options);
        Ok(Some(outcome))
    } else {
        Err(error)
    }
}

fn prepare_action(
    action: &Action,
    variables: &Variables,
    base_dir: &Path,
    planning: bool,
) -> Result<Action> {
    let interpolate = |value: &str| {
        if planning {
            render_planning(value, variables)
        } else {
            render(value, variables)
        }
    };
    Ok(match action {
        Action::Command(command) => Action::Command(interpolate(command)?),
        Action::Shell(command) => Action::Shell(interpolate(command)?),
        Action::Local(command) => Action::Local(interpolate(command)?),
        Action::WaitFor { command, interval } => Action::WaitFor {
            command: interpolate(command)?,
            interval: *interval,
        },
        Action::Script { source, args } => Action::Script {
            source: resolve_path(base_dir, source),
            args: interpolate(args)?,
        },
        Action::Copy {
            source,
            destination,
            mode,
        } => Action::Copy {
            source: resolve_path(base_dir, source),
            destination: interpolate(destination)?,
            mode: mode.clone(),
        },
    })
}

fn describe_action(action: &Action) -> String {
    match action {
        Action::Command(c) => format!("command: {c}"),
        Action::Shell(c) => format!("shell: {c}"),
        Action::Local(c) => format!("local_action: {c}"),
        Action::Script { source, args } => format!("script: {} {args}", source.display()),
        Action::Copy {
            source,
            destination,
            mode,
        } => format!(
            "copy: {} -> {destination}{}",
            source.display(),
            mode.as_deref()
                .map(|m| format!(" mode={m}"))
                .unwrap_or_default()
        ),
        Action::WaitFor { command, interval } => format!("wait_for: {command} (every {interval}s)"),
    }
}

async fn run_action(
    host: &InventoryHost,
    action: &Action,
    timeout: Option<u64>,
    sudo: bool,
    delegate_local: bool,
) -> Result<Outcome> {
    match action {
        Action::Local(command) => run_local(&with_sudo(command, sudo), timeout).await,
        Action::Command(command) | Action::Shell(command) => {
            run_command(host, &with_sudo(command, sudo), timeout, delegate_local).await
        }
        Action::WaitFor { command, interval } => {
            let command = wait_for_shell(command, *interval);
            run_command(host, &with_sudo(&command, sudo), timeout, delegate_local).await
        }
        Action::Script { source, args } => {
            let script = std::fs::read_to_string(source)
                .with_context(|| format!("script is not UTF-8: {}", source.display()))?;
            let marker = "BSSH_PLAYBOOK_SCRIPT_EOF";
            if script.lines().any(|line| line == marker) {
                bail!(
                    "script {} contains reserved heredoc marker",
                    source.display()
                );
            }
            let args = shell_words::split(args)
                .context("invalid script args")?
                .iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" ");
            if script.len() > MAX_INLINE_SOURCE_BYTES {
                bail!(
                    "script source exceeds the {}-byte inline playbook limit",
                    MAX_INLINE_SOURCE_BYTES
                );
            }
            let command = format!("sh -s -- {args} <<'{marker}'\n{script}\n{marker}");
            run_command(host, &with_sudo(&command, sudo), timeout, delegate_local).await
        }
        Action::Copy {
            source,
            destination,
            mode,
        } => {
            let bytes = std::fs::read(source)
                .with_context(|| format!("failed to read {}", source.display()))?;
            if bytes.len() > MAX_INLINE_SOURCE_BYTES {
                bail!(
                    "copy source exceeds the {}-byte inline playbook limit; use bssh upload for larger files",
                    MAX_INLINE_SOURCE_BYTES
                );
            }
            let text = std::str::from_utf8(&bytes)
                .with_context(|| format!("copy source must be UTF-8: {}", source.display()))?;
            let parent = Path::new(destination)
                .parent()
                .unwrap_or_else(|| Path::new("."));
            let mode = mode
                .as_deref()
                .map(|mode| {
                    format!(
                        " && chmod {} {}",
                        shell_quote(mode),
                        shell_quote(destination)
                    )
                })
                .unwrap_or_default();
            let command = format!(
                "mkdir -p {} && printf %s {} > {}{}",
                shell_quote(&parent.to_string_lossy()),
                shell_quote(text),
                shell_quote(destination),
                mode
            );
            run_command(host, &with_sudo(&command, sudo), timeout, delegate_local).await
        }
    }
}

fn wait_for_shell(command: &str, interval: u64) -> String {
    // Match sshot's finite wait: at most 30 checks, two seconds
    // apart by default, even when no task timeout is supplied.
    format!(
        "i=0; while [ \"$i\" -lt 30 ]; do ({command}) && exit 0; i=$((i+1)); [ \"$i\" -lt 30 ] && sleep {interval}; done; exit 1"
    )
}

fn validate_planned_remote_action(action: &Action, sudo: bool) -> Result<()> {
    let command = match action {
        Action::Command(command) | Action::Shell(command) => Some(command.clone()),
        Action::WaitFor { command, interval } => Some(wait_for_shell(command, *interval)),
        Action::Local(_) | Action::Script { .. } | Action::Copy { .. } => None,
    };
    if let Some(command) = command {
        let command = with_sudo(&command, sudo);
        validate_ssh_command_size(&command)?;
    }
    Ok(())
}

const MAX_SSH_COMMAND_BYTES: usize = 16 * 1024;
// This remains safe after two layers of worst-case single-quote escaping
// (payload shell quoting plus sudo's sh -c quoting).
const MAX_INLINE_SOURCE_BYTES: usize = 1024;

async fn run_command(
    host: &InventoryHost,
    command: &str,
    timeout: Option<u64>,
    local: bool,
) -> Result<Outcome> {
    if local {
        run_local(command, timeout).await
    } else {
        run_remote(host, command, timeout).await
    }
}

fn with_sudo(command: &str, sudo: bool) -> String {
    if sudo {
        format!("sudo -n sh -c {}", shell_quote(command))
    } else {
        command.to_owned()
    }
}

async fn run_local(command: &str, timeout: Option<u64>) -> Result<Outcome> {
    let mut child = tokio::process::Command::new("sh");
    child
        .arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let future = child.output();
    let output = if let Some(seconds) = timeout.filter(|s| *s > 0) {
        tokio::time::timeout(Duration::from_secs(seconds), future)
            .await
            .with_context(|| format!("local action timed out after {seconds}s"))??
    } else {
        future.await?
    };
    Ok(Outcome {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(255) as u32,
        success: output.status.success(),
    })
}

fn validate_ssh_command_size(command: &str) -> Result<()> {
    if command.len() > MAX_SSH_COMMAND_BYTES {
        bail!(
            "playbook SSH command is {} bytes after shell expansion (maximum {} bytes)",
            command.len(),
            MAX_SSH_COMMAND_BYTES
        );
    }
    Ok(())
}

async fn run_remote(host: &InventoryHost, command: &str, timeout: Option<u64>) -> Result<Outcome> {
    validate_ssh_command_size(command)?;
    let user = host.ssh.user.clone().unwrap_or_else(current_user);
    let port = host.ssh.port.unwrap_or(22);
    let strict_mode = host
        .ssh
        .strict_host_key_checking
        .as_deref()
        .unwrap_or("yes")
        .parse::<StrictHostKeyChecking>()
        .map_err(|_| anyhow::anyhow!("invalid strict_host_key_checking value"))?;
    let config = ConnectionConfig {
        key_path: host.ssh.identity_file.as_deref(),
        strict_mode: Some(strict_mode),
        use_agent: host.ssh.use_agent,
        use_password: false,
        #[cfg(target_os = "macos")]
        use_keychain: false,
        timeout_seconds: timeout,
        connect_timeout_seconds: host.ssh.connect_timeout,
        jump_hosts_spec: None,
        ssh_connection_config: None,
        ssh_password: None,
    };
    let mut client = SshClient::new(host.hostname.clone(), port, user);
    let result = client
        .connect_and_execute_with_jump_hosts(command, &config)
        .await?;
    Ok(Outcome {
        stdout: result.stdout_string(),
        stderr: result.stderr_string(),
        exit_code: result.exit_status,
        success: result.exit_status == 0,
    })
}

fn record_planned_outcome(task: &Task, state: &mut HostState) {
    state.variables.extend(task.variables.clone());
    state.completed.insert(task.name.clone(), true);
    if let Some(name) = &task.register {
        state.runtime_unknowns.insert(name.clone());
    }
}

fn record_outcome(task: &Task, state: &mut HostState, outcome: &Outcome) -> Result<()> {
    state.variables.extend(task.variables.clone());
    state
        .completed
        .insert(task.name.clone(), outcome.success || task.ignore_error);
    if let Some(name) = &task.register {
        let mut map = Mapping::new();
        map.insert(
            Value::String("stdout".into()),
            Value::String(outcome.stdout.clone()),
        );
        map.insert(
            Value::String("stderr".into()),
            Value::String(outcome.stderr.clone()),
        );
        map.insert(
            Value::String("exit_code".into()),
            Value::Number(outcome.exit_code.into()),
        );
        map.insert(
            Value::String("success".into()),
            Value::Bool(outcome.success),
        );
        state.variables.insert(name.clone(), Value::Mapping(map));
    }
    Ok(())
}

fn print_outcome(host: &str, task: &str, outcome: &Outcome, options: RunOptions) {
    let status = if outcome.success { "OK" } else { "FAILED" };
    println!("{status} [{host}] {task} (exit {})", outcome.exit_code);
    if options.full_output || !outcome.success {
        if !outcome.stdout.is_empty() {
            print!("{}", outcome.stdout);
            if !outcome.stdout.ends_with('\n') {
                println!();
            }
        }
        if !outcome.stderr.is_empty() {
            eprint!("{}", outcome.stderr);
            if !outcome.stderr.ends_with('\n') {
                eprintln!();
            }
        }
    }
}

fn add_builtin_variables(vars: &mut Variables, host: &InventoryHost) {
    vars.insert(
        "inventory_hostname".into(),
        Value::String(host.name.clone()),
    );
    vars.insert("host".into(), Value::String(host.hostname.clone()));
    vars.insert("hostname".into(), Value::String(host.hostname.clone()));
    vars.insert(
        "port".into(),
        Value::Number(host.ssh.port.unwrap_or(22).into()),
    );
    vars.insert(
        "user".into(),
        Value::String(host.ssh.user.clone().unwrap_or_else(current_user)),
    );
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| whoami::username().unwrap_or_else(|_| "user".to_owned()))
}

fn resolve_local_path(playbook_path: &Path, path: &Path) -> PathBuf {
    resolve_path(
        playbook_path.parent().unwrap_or_else(|| Path::new(".")),
        path,
    )
}
fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn dry_run_never_executes_local_action() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("marker");
        let inventory = dir.path().join("inventory.yaml");
        let playbook = dir.path().join("playbook.yaml");
        std::fs::write(
            &inventory,
            "ssh_config:\n  user: test\nhosts:\n  - name: localhost\n    address: 127.0.0.1\n",
        )
        .unwrap();
        std::fs::write(&playbook, format!("name: dry-run\nparallel: false\ntasks:\n  - name: local\n    local_action: touch {}\n    register: result\n  - name: conditional\n    local_action: 'true'\n    when: '{{{{ .result.success }}}} == true'\n", marker.display())).unwrap();
        run_file(
            &playbook,
            Some(&inventory),
            RunOptions {
                dry_run: true,
                full_output: true,
            },
        )
        .await
        .unwrap();
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn ignore_error_satisfies_task_dependencies() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("dependency-ran");
        let inventory = dir.path().join("inventory.yaml");
        let playbook = dir.path().join("playbook.yaml");
        std::fs::write(
            &inventory,
            "hosts:\n  - name: localhost\n    address: 127.0.0.1\n",
        )
        .unwrap();
        std::fs::write(&playbook, format!("name: ignored\ntasks:\n  - name: expected failure\n    local_action: exit 9\n    ignore_error: true\n  - name: dependent\n    local_action: touch {}\n    depends_on: [expected failure]\n", marker.display())).unwrap();
        run_file(
            &playbook,
            Some(&inventory),
            RunOptions {
                dry_run: false,
                full_output: false,
            },
        )
        .await
        .unwrap();
        assert!(marker.exists());
    }

    #[tokio::test]
    async fn groups_run_ordered_full_host_chains_and_ignore_direct_hosts() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("order.log");
        let inventory = dir.path().join("inventory.yaml");
        let playbook = dir.path().join("playbook.yaml");
        std::fs::write(
                &inventory,
                "hosts:\n  - name: ignored\n    address: ignored\ngroups:\n  - name: first\n    order: 1\n    parallel: false\n    hosts:\n      - {name: a, address: a}\n      - {name: b, address: b}\n  - name: second\n    order: 2\n    depends_on: [first]\n    hosts:\n      - {name: c, address: c}\n",
            )
            .unwrap();
        std::fs::write(
                &playbook,
                format!(
                    "name: grouped\ntasks:\n  - name: one\n    local_action: echo '{{{{ .inventory_hostname }}}}:one' >> {}\n  - name: two\n    local_action: echo '{{{{ .inventory_hostname }}}}:two' >> {}\n",
                    log.display(),
                    log.display()
                ),
            )
            .unwrap();
        run_file(
            &playbook,
            Some(&inventory),
            RunOptions {
                dry_run: false,
                full_output: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(log).unwrap(),
            "a:one\na:two\nb:one\nb:two\nc:one\nc:two\n"
        );
    }

    #[tokio::test]
    async fn failed_group_gates_dependent_group() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("must-not-run");
        let inventory = dir.path().join("inventory.yaml");
        let playbook = dir.path().join("playbook.yaml");
        std::fs::write(
                &inventory,
                "groups:\n  - name: first\n    order: 1\n    hosts: [{name: a, address: a}]\n  - name: second\n    order: 2\n    depends_on: [first]\n    hosts: [{name: b, address: b}]\n",
            )
            .unwrap();
        std::fs::write(
                &playbook,
                format!(
                    "name: gated\ntasks:\n  - name: fail\n    local_action: exit 1\n    only_groups: [first]\n  - name: marker\n    local_action: touch {}\n    only_groups: [second]\n",
                    marker.display()
                ),
            )
            .unwrap();
        assert!(
            run_file(
                &playbook,
                Some(&inventory),
                RunOptions {
                    dry_run: false,
                    full_output: false
                },
            )
            .await
            .is_err()
        );
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn localhost_delegation_and_success_based_run_once() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("delegated");
        let inventory = dir.path().join("inventory.yaml");
        let playbook = dir.path().join("playbook.yaml");
        std::fs::write(
                &inventory,
                "hosts:\n  - {name: first, address: unreachable.invalid}\n  - {name: second, address: unreachable.invalid}\n",
            )
            .unwrap();
        std::fs::write(
                &playbook,
                format!(
                    "name: delegated\ntasks:\n  - name: eventually\n    command: test '{{{{ .inventory_hostname }}}}' = second\n    delegate_to: localhost\n    run_once: true\n  - name: write\n    command: touch {}\n    delegate_to: localhost\n    run_once: true\n",
                    marker.display()
                ),
            )
            .unwrap();
        run_file(
            &playbook,
            Some(&inventory),
            RunOptions {
                dry_run: false,
                full_output: false,
            },
        )
        .await
        .unwrap();
        assert!(marker.exists());
    }

    #[tokio::test]
    async fn failed_run_once_fails_play_and_inline_bound_is_dry_run_validated() {
        let dir = tempdir().unwrap();
        let inventory = dir.path().join("inventory.yaml");
        let playbook = dir.path().join("playbook.yaml");
        std::fs::write(&inventory, "hosts: [{name: host, address: host}]\n").unwrap();
        std::fs::write(
                &playbook,
                "name: failure\ntasks:\n  - name: once\n    command: exit 1\n    delegate_to: localhost\n    run_once: true\n",
            )
            .unwrap();
        assert!(
            run_file(
                &playbook,
                Some(&inventory),
                RunOptions {
                    dry_run: false,
                    full_output: false
                },
            )
            .await
            .is_err()
        );

        let source = dir.path().join("large.txt");
        std::fs::write(&source, vec![b'x'; MAX_INLINE_SOURCE_BYTES + 1]).unwrap();
        std::fs::write(
            &playbook,
            format!(
                "name: bound\ntasks:\n  - copy: {{src: {}, dest: /tmp/x}}\n",
                source.display()
            ),
        )
        .unwrap();
        let error = run_file(
            &playbook,
            Some(&inventory),
            RunOptions {
                dry_run: true,
                full_output: false,
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("inline playbook limit"));
    }

    #[test]
    fn wait_for_shell_is_finite() {
        let command = wait_for_shell("false", 2);
        assert!(command.contains("-lt 30"));
        assert!(command.contains("sleep 2"));
        assert!(command.ends_with("exit 1"));
    }

    #[tokio::test]
    async fn retries_are_additional_attempts() {
        let dir = tempdir().unwrap();
        let count = dir.path().join("count");
        let inventory = dir.path().join("inventory.yaml");
        let playbook = dir.path().join("playbook.yaml");
        std::fs::write(&inventory, "hosts: [{name: host, address: host}]\n").unwrap();
        std::fs::write(
                &playbook,
                format!(
                    "name: retry\ntasks:\n  - name: retry\n    local_action: n=$(cat {} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {}; exit 1\n    retries: 2\n    retry_delay: 0\n    ignore_error: true\n",
                    count.display(),
                    count.display()
                ),
            )
            .unwrap();
        run_file(
            &playbook,
            Some(&inventory),
            RunOptions {
                dry_run: false,
                full_output: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read_to_string(count).unwrap().trim(), "3");
    }

    #[tokio::test]
    async fn local_action_retries_and_allowed_exit_codes() {
        let dir = tempdir().unwrap();
        let inventory = dir.path().join("inventory.yaml");
        let playbook = dir.path().join("playbook.yaml");
        std::fs::write(
            &inventory,
            "hosts:\n  - name: localhost\n    address: 127.0.0.1\n",
        )
        .unwrap();
        std::fs::write(&playbook, "name: local\nparallel: false\ntasks:\n  - name: accepted\n    local_action: exit 3\n    allowed_exit_codes: [3]\n").unwrap();
        run_file(
            &playbook,
            Some(&inventory),
            RunOptions {
                dry_run: false,
                full_output: false,
            },
        )
        .await
        .unwrap();
    }
}

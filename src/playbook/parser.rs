// Copyright 2025 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::model::*;
use anyhow::{Context, Result, bail};
use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub fn load(playbook_path: &Path, inventory_path: Option<&Path>) -> Result<Playbook> {
    let playbook_value = read_yaml(playbook_path)?;
    let external_inventory = inventory_path.map(read_yaml).transpose()?;
    let embedded = root_map(&playbook_value)
        .and_then(|m| map_get(m, "inventory"))
        .map(parse_inventory)
        .transpose()?;
    let inventory = external_inventory
        .as_ref()
        .map(parse_inventory)
        .transpose()?
        .or(embedded);
    let plays = parse_plays(&playbook_value)?;
    if plays.is_empty() {
        bail!("playbook contains no plays or tasks");
    }
    Ok(Playbook { plays, inventory })
}

fn read_yaml(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read YAML {}", path.display()))?;
    serde_yaml::from_str(&text).with_context(|| format!("invalid YAML in {}", path.display()))
}

fn root_map(value: &Value) -> Option<&Mapping> {
    value.as_mapping()
}

pub fn parse_inventory(value: &Value) -> Result<Inventory> {
    let mut inventory = Inventory::default();
    let mut root = value
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("inventory must be a YAML mapping"))?;
    if let Some(inner) = map_get(root, "inventory").and_then(Value::as_mapping) {
        root = inner;
    }
    if let Some(all) = map_get(root, "all").and_then(Value::as_mapping) {
        parse_inventory_section(all, &mut inventory, None)?;
    }
    parse_inventory_section(root, &mut inventory, None)?;
    if inventory.order.is_empty() {
        let mut groups = inventory.groups.keys().cloned().collect::<Vec<_>>();
        groups.sort_by_key(|group| inventory.group_order.get(group).copied().unwrap_or(0));
        for group in groups {
            for host in &inventory.groups[&group] {
                if !inventory.order.contains(host) {
                    inventory.order.push(host.clone());
                }
            }
        }
        for host in inventory.hosts.keys() {
            if !inventory.order.contains(host) {
                inventory.order.push(host.clone());
            }
        }
    }
    // Resolve group members after all host aliases are known.
    for (group, members) in inventory.groups.clone() {
        for name in members {
            let host = inventory.hosts.get_mut(&name).ok_or_else(|| {
                anyhow::anyhow!("group '{group}' references unknown inventory host '{name}'")
            })?;
            host.groups.insert(group.clone());
        }
    }
    if inventory.hosts.is_empty() {
        bail!("inventory contains no hosts");
    }
    Ok(inventory)
}

fn parse_inventory_section(
    map: &Mapping,
    inventory: &mut Inventory,
    inherited_group: Option<&str>,
) -> Result<()> {
    if let Some(ssh) = map_get(map, "ssh_config")
        .or_else(|| map_get(map, "ssh"))
        .or_else(|| map_get(map, "defaults"))
    {
        inventory.ssh = parse_ssh(ssh, &inventory.ssh)?;
    }
    if let Some(vars) = map_get(map, "vars").and_then(Value::as_mapping) {
        let mut overlay = Mapping::new();
        for (k, v) in vars {
            overlay.insert(k.clone(), v.clone());
        }
        inventory.ssh = parse_ssh(&Value::Mapping(overlay), &inventory.ssh)?;
    }
    if let Some(hosts) = map_get(map, "hosts") {
        parse_hosts(hosts, inventory, inherited_group)?;
    }
    if let Some(order) = map_get(map, "order") {
        inventory.order = strings(order, "inventory order")?;
    }
    let group_values = map_get(map, "groups").or_else(|| map_get(map, "children"));
    if let Some(groups) = group_values {
        match groups {
            Value::Sequence(sequence) => {
                for body in sequence {
                    let group_map = body
                        .as_mapping()
                        .ok_or_else(|| anyhow::anyhow!("group list entries must be mappings"))?;
                    let group = required_string(group_map, &["name"])?;
                    parse_group(&group, body, inventory)?;
                }
            }
            Value::Mapping(groups) => {
                for (group_key, body) in groups {
                    let group = scalar_string(group_key, "group name")?;
                    parse_group(&group, body, inventory)?;
                    if let Some(group_map) = body.as_mapping()
                        && let Some(children) =
                            map_get(group_map, "children").and_then(Value::as_mapping)
                    {
                        parse_inventory_section(
                            &Mapping::from_iter([(
                                key("groups"),
                                Value::Mapping(children.clone()),
                            )]),
                            inventory,
                            Some(&group),
                        )?;
                    }
                }
            }
            _ => bail!("inventory groups must be a sequence or mapping"),
        }
    }
    Ok(())
}

fn parse_group(group: &str, body: &Value, inventory: &mut Inventory) -> Result<()> {
    let members = if let Some(sequence) = body.as_sequence() {
        sequence
            .iter()
            .map(|value| scalar_string(value, "group host"))
            .collect::<Result<Vec<_>>>()?
    } else if let Some(map) = body.as_mapping() {
        if let Some(hosts) = map_get(map, "hosts") {
            parse_hosts(hosts, inventory, Some(group))?;
            Vec::new()
        } else {
            Vec::new()
        }
    } else {
        bail!("group '{group}' must be a sequence or mapping")
    };
    inventory
        .groups
        .entry(group.to_owned())
        .or_default()
        .extend(members);
    if let Some(map) = body.as_mapping() {
        if let Some(order) = map_get(map, "order").and_then(Value::as_i64) {
            inventory.group_order.insert(group.to_owned(), order);
        }
        if let Some(parallel) = opt_bool(map, &["parallel"])? {
            inventory.group_parallel.insert(group.to_owned(), parallel);
        }
        if let Some(dependencies) = map_get(map, "depends_on") {
            inventory.group_dependencies.insert(
                group.to_owned(),
                strings(dependencies, "group dependencies")?,
            );
        }
    }
    Ok(())
}

fn parse_hosts(value: &Value, inventory: &mut Inventory, group: Option<&str>) -> Result<()> {
    match value {
        Value::Sequence(seq) => {
            for item in seq {
                if let Some(map) = item.as_mapping() {
                    let name = opt_string(map, &["name"])?
                        .or(opt_string(map, &["hostname", "address"])?)
                        .ok_or_else(|| {
                            anyhow::anyhow!("host list entry requires name, hostname, or address")
                        })?;
                    add_host(inventory, &name, item.clone(), group)?;
                } else {
                    let name = scalar_string(item, "inventory host")?;
                    add_host(inventory, &name, Value::Null, group)?;
                }
            }
        }
        Value::Mapping(map) => {
            for (name, body) in map {
                add_host(
                    inventory,
                    &scalar_string(name, "host name")?,
                    body.clone(),
                    group,
                )?;
            }
        }
        _ => bail!("inventory hosts must be a sequence or mapping"),
    }
    Ok(())
}

fn add_host(inventory: &mut Inventory, name: &str, body: Value, group: Option<&str>) -> Result<()> {
    let map = body.as_mapping();
    let hostname = match &body {
        Value::String(s) => s.clone(),
        _ => map
            .and_then(|m| {
                map_get(m, "address")
                    .or_else(|| map_get(m, "hostname"))
                    .or_else(|| map_get(m, "host"))
            })
            .map(|v| scalar_string(v, "hostname"))
            .transpose()?
            .unwrap_or_else(|| name.to_owned()),
    };
    let ssh = if let Some(m) = map {
        parse_ssh(&Value::Mapping(m.clone()), &inventory.ssh)?
    } else {
        inventory.ssh.clone()
    };
    let variables = map
        .and_then(|m| map_get(m, "variables").or_else(|| map_get(m, "vars")))
        .map(parse_variables)
        .transpose()?
        .unwrap_or_default();
    let entry = inventory
        .hosts
        .entry(name.to_owned())
        .or_insert(InventoryHost {
            name: name.to_owned(),
            hostname,
            ssh,
            variables,
            groups: BTreeSet::new(),
        });
    if let Some(group) = group {
        entry.groups.insert(group.to_owned());
        inventory
            .groups
            .entry(group.to_owned())
            .or_default()
            .push(name.to_owned());
    }
    Ok(())
}

fn parse_ssh(value: &Value, base: &SshDefaults) -> Result<SshDefaults> {
    let Some(map) = value.as_mapping() else {
        return Ok(base.clone());
    };
    let nested = map_get(map, "ssh")
        .or_else(|| map_get(map, "ssh_config"))
        .and_then(Value::as_mapping)
        .unwrap_or(map);
    for unsupported in ["password", "key_password"] {
        if map_get(nested, unsupported).is_some() {
            bail!(
                "inventory SSH field '{unsupported}' is unsupported: bssh playbooks do not accept plaintext passwords or key passphrases"
            );
        }
    }
    let mut out = base.clone();
    out.user = opt_string(nested, &["user", "username", "ansible_user"])?.or(out.user);
    out.port = opt_u64(nested, &["port", "ansible_port"])?
        .map(|n| n as u16)
        .or(out.port);
    out.identity_file = opt_string(
        nested,
        &[
            "key_file",
            "identity_file",
            "key",
            "private_key",
            "ansible_ssh_private_key_file",
        ],
    )?
    .map(expand_tilde)
    .or(out.identity_file);
    out.use_agent = opt_bool(nested, &["use_agent", "agent"])?.unwrap_or(out.use_agent);
    if let Some(strict) = opt_bool(nested, &["strict_host_key_check"])? {
        out.strict_host_key_checking = Some(if strict { "yes" } else { "no" }.to_owned());
    } else {
        out.strict_host_key_checking =
            opt_string(nested, &["strict_host_key_checking"])?.or(out.strict_host_key_checking);
    }
    out.connect_timeout = opt_u64(nested, &["connect_timeout"])?.or(out.connect_timeout);
    Ok(out)
}

fn parse_plays(value: &Value) -> Result<Vec<Play>> {
    let source = if let Some(map) = value.as_mapping() {
        map_get(map, "plays")
            .or_else(|| map_get(map, "playbook"))
            .unwrap_or(value)
    } else {
        value
    };
    match source {
        Value::Sequence(seq) => seq.iter().map(parse_play).collect(),
        Value::Mapping(map) if map_get(map, "tasks").is_some() => Ok(vec![parse_play(source)?]),
        _ => bail!("playbook must be a play mapping, a sequence of plays, or contain 'plays'"),
    }
}

fn parse_play(value: &Value) -> Result<Play> {
    let map = value
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("play must be a mapping"))?;
    let name = opt_string(map, &["name"])?.unwrap_or_else(|| "play".to_owned());
    let hosts = map_get(map, "hosts")
        .map(|v| strings(v, "play hosts"))
        .transpose()?
        .unwrap_or_else(|| vec!["all".to_owned()]);
    let groups = map_get(map, "groups")
        .map(|v| strings(v, "play groups"))
        .transpose()?
        .unwrap_or_default();
    let variables = map_get(map, "variables")
        .or_else(|| map_get(map, "vars"))
        .map(parse_variables)
        .transpose()?
        .unwrap_or_default();
    let facts = map_get(map, "facts")
        .map(parse_facts)
        .transpose()?
        .unwrap_or_default();
    let tasks = map_get(map, "tasks")
        .and_then(Value::as_sequence)
        .ok_or_else(|| anyhow::anyhow!("play '{name}' requires a tasks sequence"))?
        .iter()
        .map(parse_task)
        .collect::<Result<_>>()?;
    let parallel = match map_get(map, "parallel") {
        Some(Value::Bool(true)) => 10,
        Some(Value::Bool(false)) => 1,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("parallel must be a boolean or positive integer"))?
            .max(1) as usize,
        None => 1,
    };
    let dependencies = map_get(map, "dependencies")
        .or_else(|| map_get(map, "depends_on"))
        .map(|v| strings(v, "play dependencies"))
        .transpose()?
        .unwrap_or_default();
    Ok(Play {
        name,
        hosts,
        groups,
        variables,
        facts,
        tasks,
        parallel,
        dependencies,
    })
}

fn parse_task(value: &Value) -> Result<Task> {
    let map = value
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("task must be a mapping"))?;
    let name = opt_string(map, &["name"])?.unwrap_or_else(|| "task".to_owned());
    let action = parse_action(map).with_context(|| format!("task '{name}'"))?;
    let condition = opt_string(map, &["when", "condition"])?;
    let register = opt_string(map, &["register"])?;
    let until_success = opt_bool(map, &["until_success"])?.unwrap_or(false);
    let configured_retries =
        opt_u64(map, &["retries"])?.unwrap_or(if until_success { 60 } else { 0 });
    let retries = configured_retries
        .checked_add(1)
        .and_then(|attempts| u32::try_from(attempts).ok())
        .ok_or_else(|| anyhow::anyhow!("retries is too large"))?;
    let retry_delay = opt_u64(map, &["retry_delay", "delay"])?
        .unwrap_or(if configured_retries > 0 { 5 } else { 0 });
    let timeout = opt_u64(map, &["timeout"])?;
    let allowed_exit_codes = map_get(map, "allowed_exit_codes")
        .or_else(|| map_get(map, "success_exit_codes"))
        .map(u32s)
        .transpose()?
        .unwrap_or_else(|| vec![0]);
    let ignore_error = opt_bool(map, &["ignore_error", "ignore_errors"])?.unwrap_or(false);
    let sudo = opt_bool(map, &["sudo"])?.unwrap_or(false);
    let variables = map_get(map, "vars")
        .map(parse_variables)
        .transpose()?
        .unwrap_or_default();
    let dependencies = map_get(map, "dependencies")
        .or_else(|| map_get(map, "depends_on"))
        .map(|v| strings(v, "task dependencies"))
        .transpose()?
        .unwrap_or_default();
    let groups = map_get(map, "groups")
        .or_else(|| map_get(map, "only_groups"))
        .map(|v| strings(v, "task groups"))
        .transpose()?
        .unwrap_or_default();
    let skip_groups = map_get(map, "skip_groups")
        .map(|v| strings(v, "task skip_groups"))
        .transpose()?
        .unwrap_or_default();
    let delegate_to = opt_string(map, &["delegate_to"])?;
    let run_once = opt_bool(map, &["run_once"])?.unwrap_or(false);
    Ok(Task {
        name,
        action,
        condition,
        register,
        retries,
        retry_delay,
        timeout,
        allowed_exit_codes,
        ignore_error,
        sudo,
        variables,
        dependencies,
        groups,
        skip_groups,
        delegate_to,
        run_once,
    })
}

fn parse_action(map: &Mapping) -> Result<Action> {
    if let Some(v) = map_get(map, "command") {
        return Ok(Action::Command(action_text(v)?));
    }
    if let Some(v) = map_get(map, "shell") {
        return Ok(Action::Shell(action_text(v)?));
    }
    if let Some(v) = map_get(map, "local_action") {
        return Ok(Action::Local(action_text(v)?));
    }
    if let Some(v) = map_get(map, "script") {
        return match v {
            Value::String(s) => Ok(Action::Script {
                source: PathBuf::from(s),
                args: String::new(),
            }),
            Value::Mapping(m) => Ok(Action::Script {
                source: PathBuf::from(required_string(m, &["source", "src", "path"])?),
                args: opt_string(m, &["args"])?.unwrap_or_default(),
            }),
            _ => bail!("script must be a path or mapping"),
        };
    }
    if let Some(v) = map_get(map, "copy") {
        let m = v
            .as_mapping()
            .ok_or_else(|| anyhow::anyhow!("copy must be a mapping"))?;
        return Ok(Action::Copy {
            source: PathBuf::from(required_string(m, &["source", "src"])?),
            destination: required_string(m, &["destination", "dest"])?,
            mode: opt_string(m, &["mode"])?,
        });
    }
    if let Some(v) = map_get(map, "wait_for") {
        return match v {
            Value::String(s) => Ok(Action::WaitFor {
                command: wait_for_command(s)?,
                interval: 2,
            }),
            Value::Mapping(m) => {
                let command = if let Some(c) = opt_string(m, &["command"])? {
                    c
                } else {
                    let host = opt_string(m, &["host"])?.unwrap_or_else(|| "127.0.0.1".to_owned());
                    let port = opt_u64(m, &["port"])?
                        .ok_or_else(|| anyhow::anyhow!("wait_for requires command or port"))?;
                    format!("nc -z {} {}", shell_quote(&host), port)
                };
                Ok(Action::WaitFor {
                    command,
                    interval: opt_u64(m, &["interval", "sleep"])?.unwrap_or(1).max(1),
                })
            }
            _ => bail!("wait_for must be a command or mapping"),
        };
    }
    bail!("requires one action: command, shell, script, copy, wait_for, or local_action")
}

fn wait_for_command(spec: &str) -> Result<String> {
    let (kind, value) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("wait_for must use type:value"))?;
    if value.is_empty() {
        bail!("wait_for value cannot be empty")
    }
    Ok(match kind {
        "port" => format!("nc -z localhost {}", shell_quote(value)),
        "service" => format!("systemctl is-active {}", shell_quote(value)),
        "file" => format!("test -f {}", shell_quote(value)),
        "http" => format!("curl -sf {}", shell_quote(value)),
        _ => bail!("unsupported wait_for type '{kind}'"),
    })
}

fn action_text(value: &Value) -> Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Mapping(m) => required_string(m, &["command", "cmd", "argv", "args"]),
        _ => bail!("action must be a string or mapping"),
    }
}

fn parse_variables(value: &Value) -> Result<Variables> {
    let map = value
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("variables must be a mapping"))?;
    map.iter()
        .map(|(k, v)| Ok((scalar_string(k, "variable name")?, v.clone())))
        .collect()
}

fn parse_facts(value: &Value) -> Result<BTreeMap<String, (String, bool)>> {
    let map = value
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("facts must be a mapping"))?;
    if let Some(collectors) = map_get(map, "collectors") {
        let sequence = collectors
            .as_sequence()
            .ok_or_else(|| anyhow::anyhow!("facts.collectors must be a sequence"))?;
        return sequence
            .iter()
            .map(|collector| {
                let collector = collector
                    .as_mapping()
                    .ok_or_else(|| anyhow::anyhow!("fact collector must be a mapping"))?;
                Ok((
                    required_string(collector, &["name"])?,
                    (
                        required_string(collector, &["command"])?,
                        opt_bool(collector, &["sudo"])?.unwrap_or(false),
                    ),
                ))
            })
            .collect();
    }
    map.iter()
        .map(|(k, v)| Ok((scalar_string(k, "fact name")?, (action_text(v)?, false))))
        .collect()
}

fn strings(value: &Value, label: &str) -> Result<Vec<String>> {
    match value {
        Value::Sequence(seq) => seq.iter().map(|v| scalar_string(v, label)).collect(),
        Value::String(s) => Ok(s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()),
        _ => bail!("{label} must be a string or sequence"),
    }
}

fn u32s(value: &Value) -> Result<Vec<u32>> {
    match value {
        Value::Sequence(seq) => seq
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| anyhow::anyhow!("exit codes must be non-negative integers"))
            })
            .collect(),
        _ => value
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(|n| vec![n])
            .ok_or_else(|| anyhow::anyhow!("exit codes must be an integer or sequence")),
    }
}

fn scalar_string(value: &Value, label: &str) -> Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        _ => bail!("{label} must be a string"),
    }
}

fn opt_string(map: &Mapping, names: &[&str]) -> Result<Option<String>> {
    for name in names {
        if let Some(v) = map_get(map, name) {
            return scalar_string(v, name).map(Some);
        }
    }
    Ok(None)
}
fn required_string(map: &Mapping, names: &[&str]) -> Result<String> {
    opt_string(map, names)?.ok_or_else(|| anyhow::anyhow!("missing '{}'", names.join("/")))
}
fn opt_u64(map: &Mapping, names: &[&str]) -> Result<Option<u64>> {
    for name in names {
        if let Some(v) = map_get(map, name) {
            return v
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("{name} must be a non-negative integer"))
                .map(Some);
        }
    }
    Ok(None)
}
fn opt_bool(map: &Mapping, names: &[&str]) -> Result<Option<bool>> {
    for name in names {
        if let Some(v) = map_get(map, name) {
            return v
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("{name} must be a boolean"))
                .map(Some);
        }
    }
    Ok(None)
}

fn expand_tilde(path: String) -> PathBuf {
    if path == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from(path))
    } else if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .map(|p| p.join(rest))
            .unwrap_or_else(|| PathBuf::from(path))
    } else {
        PathBuf::from(path)
    }
}

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_sshot_standalone_shapes() {
        let inv: Value = serde_yaml::from_str(
            r#"
ssh_config:
  user: deploy
  key_file: ~/.ssh/deploy
  port: 2222
  strict_host_key_check: false
hosts:
  - name: direct
    address: 10.0.0.10
groups:
  - name: web
    order: 2
    parallel: true
    depends_on: [database]
    hosts:
      - name: web1
        address: 10.0.0.11
        vars: {env: production}
"#,
        )
        .unwrap();
        let inv = parse_inventory(&inv).unwrap();
        assert_eq!(inv.hosts["web1"].ssh.user.as_deref(), Some("deploy"));
        assert_eq!(inv.hosts["web1"].hostname, "10.0.0.11");
        assert_eq!(inv.group_order["web"], 2);
        assert_eq!(inv.group_parallel["web"], true);
        assert_eq!(inv.group_dependencies["web"], vec!["database"]);
        assert_eq!(inv.ssh.strict_host_key_checking.as_deref(), Some("no"));

        let pb: Value = serde_yaml::from_str(
            r#"
name: deploy
parallel: true
facts:
  collectors:
    - name: os
      command: echo '{"name":"linux"}'
      sudo: true
tasks:
  - name: copy
    copy: {src: app.conf, dest: /etc/app.conf, mode: "0640"}
    sudo: true
    vars: {release: v1}
    skip_groups: [database]
    until_success: true
    ignore_error: true
    allowed_exit_codes: [0, 3]
"#,
        )
        .unwrap();
        let play = &parse_plays(&pb).unwrap()[0];
        assert_eq!(play.parallel, 10);
        assert_eq!(play.facts["os"].1, true);
        let task = &play.tasks[0];
        assert!(task.sudo && task.ignore_error);
        assert_eq!(task.retries, 61);
        assert_eq!(task.retry_delay, 5);
        assert_eq!(task.skip_groups, vec!["database"]);
        assert!(matches!(&task.action, Action::Copy { mode: Some(mode), .. } if mode == "0640"));
    }

    #[test]
    fn retry_counts_and_security_defaults_are_exact() {
        let play: Value = serde_yaml::from_str(
            "name: retry\ntasks:\n  - name: retry\n    command: 'false'\n    retries: 2\n",
        )
        .unwrap();
        let task = &parse_plays(&play).unwrap()[0].tasks[0];
        assert_eq!(task.retries, 3);
        assert_eq!(task.retry_delay, 5);

        let inventory: Value =
            serde_yaml::from_str("hosts:\n  - name: host\n    address: 127.0.0.1\n").unwrap();
        assert_eq!(
            parse_inventory(&inventory)
                .unwrap()
                .ssh
                .strict_host_key_checking
                .as_deref(),
            Some("yes")
        );
        for forbidden in ["password", "key_password"] {
            let yaml = format!(
                "ssh_config:\n  {forbidden}: secret\nhosts:\n  - name: host\n    address: 127.0.0.1\n"
            );
            let error = parse_inventory(&serde_yaml::from_str(&yaml).unwrap()).unwrap_err();
            assert!(error.to_string().contains("unsupported"));
            assert!(error.to_string().contains(forbidden));
        }
    }

    #[test]
    fn parses_sshot_wait_for_forms_and_legacy_combined_shape() {
        for spec in [
            "port:80",
            "service:sshd",
            "file:/tmp/ready",
            "http:https://example.test/health",
        ] {
            let yaml = format!("name: wait\\ntasks:\\n  - name: wait\\n    wait_for: {spec}\\n")
                .replace("\\n", "\n");
            let value: Value = serde_yaml::from_str(&yaml).unwrap();
            assert!(matches!(
                parse_plays(&value).unwrap()[0].tasks[0].action,
                Action::WaitFor { .. }
            ));
        }
        let value: Value = serde_yaml::from_str("inventory:\n  hosts:\n    - name: localhost\n      address: 127.0.0.1\nplaybook:\n  name: legacy\n  parallel: false\n  tasks:\n    - local_action: echo ok\n").unwrap();
        assert!(
            parse_inventory(map_get(value.as_mapping().unwrap(), "inventory").unwrap()).is_ok()
        );
        let play = &parse_plays(&value).unwrap()[0];
        assert_eq!(play.parallel, 1);
        assert!(matches!(play.tasks[0].action, Action::Local(_)));
    }
}

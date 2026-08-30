// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bssh"))
        .env_remove("BSSH_PDSH_COMPAT")
        .env_remove("RUST_LOG")
        .args(arguments)
        .output()
        .expect("bssh should run")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("temporary path should be UTF-8")
}

#[test]
fn dump_exits_without_proxy_agent_prompt_or_connection_side_effects() {
    let directory = tempdir().expect("temporary directory should be created");
    let config = directory.path().join("config");
    let marker = directory.path().join("proxy-ran");
    fs::write(
        &config,
        format!(
            "Host target\n  HostName does-not-resolve.invalid\n  ProxyCommand sh -c 'touch {}'\n  IdentityAgent /missing/agent.sock\n  BatchMode no\n",
            marker.display()
        ),
    )
    .expect("config should be written");

    let output = run(&["-G", "-F", path(&config), "target"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "ProxyCommand must not execute in -G mode");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("hostname does-not-resolve.invalid\n"));
    assert!(stdout.contains("identityagent /missing/agent.sock\n"));
}

#[test]
fn match_and_include_restore_parent_scope_for_destination() {
    let directory = tempdir().expect("temporary directory should be created");
    let config = directory.path().join("config");
    let included = directory.path().join("target.conf");
    fs::write(&included, "User included\nHost other\n  Port 9\n")
        .expect("include should be written");
    fs::write(
        &config,
        "Host target\n  Include %h.conf\n  Port 2200\nMatch user=included originalhost=target # comment\n  IPQoS cs1\n",
    )
    .expect("config should be written");

    let output = run(&["-GF", path(&config), "target"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("user included\n"));
    assert!(stdout.contains("port 2200\n"));
    assert!(stdout.contains("ipqos cs1 cs1\n"));
}

#[test]
fn explicit_log_receives_success_warnings_and_fatal_errors() {
    let directory = tempdir().expect("temporary directory should be created");
    let warning_config = directory.path().join("warning.conf");
    let warning_log = directory.path().join("warning.log");
    fs::write(&warning_config, "Host *\n  TunnelDevice 1:2\n")
        .expect("warning config should be written");
    let warning = run(&[
        "-G",
        "-E",
        path(&warning_log),
        "-F",
        path(&warning_config),
        "host",
    ]);
    assert!(warning.status.success());
    assert!(warning.stderr.is_empty());
    assert!(String::from_utf8_lossy(&warning.stdout).contains("tunneldevice 1:2\n"));
    assert!(
        fs::read_to_string(&warning_log)
            .expect("warning log should exist")
            .contains("Unsupported SSH config option 'tunneldevice'")
    );

    let root_config = directory.path().join("invalid.conf");
    let child_config = directory.path().join("invalid-child.conf");
    let error_log = directory.path().join("error.log");
    fs::write(&root_config, "Include invalid-child.conf\n").expect("root config should be written");
    fs::write(&child_config, "Junk yes\n").expect("child config should be written");
    let invalid = run(&[
        "-G",
        "-E",
        path(&error_log),
        "-F",
        path(&root_config),
        "host",
    ]);
    assert!(!invalid.status.success());
    assert!(invalid.stderr.is_empty());
    assert!(
        fs::read_to_string(&error_log)
            .expect("error log should exist")
            .contains("Unknown SSH config option 'junk'")
    );
}

#[test]
fn user_precedence_matches_openssh_second_argv_pass() {
    let cases: &[(&[&str], &str)] = &[
        (
            &["-GF", "none", "-o", "user=foo", "-l", "bar", "baz@host"],
            "foo",
        ),
        (
            &["-GF", "none", "-lbar", "baz@host", "user=foo", "baz@host"],
            "bar",
        ),
        (
            &[
                "-GF", "none", "baz@host", "-o", "user=foo", "-l", "bar", "baz@host",
            ],
            "baz",
        ),
    ];
    for (arguments, expected) in cases {
        let output = run(arguments);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
        assert!(stdout.contains(&format!("user {expected}\n")));
    }
}

#[test]
fn stdio_forward_sets_clear_all_forwardings_unless_explicitly_overridden() {
    let implicit = run(&["-GF", "none", "-W", "localhost:9", "host"]);
    assert!(implicit.status.success());
    assert!(String::from_utf8_lossy(&implicit.stdout).contains("clearallforwardings yes\n"));
    assert!(String::from_utf8_lossy(&implicit.stdout).contains("exitonforwardfailure yes\n"));

    let explicit = run(&[
        "-GF",
        "none",
        "-W",
        "localhost:9",
        "-o",
        "ClearAllForwardings=no",
        "host",
    ]);
    assert!(explicit.status.success());
    assert!(String::from_utf8_lossy(&explicit.stdout).contains("clearallforwardings no\n"));
}

#[test]
fn include_expands_environment_and_repeated_host_tokens() {
    let directory = tempdir().expect("temporary directory should be created");
    let included = directory.path().join("hosthost.conf");
    let config = directory.path().join("config");
    fs::write(&included, "Host host\n  Port 2202\n").expect("include should be written");
    fs::write(&config, "Include ${REAL_FILE}/%h%h.conf\n").expect("config should be written");

    let output = Command::new(env!("CARGO_BIN_EXE_bssh"))
        .env_remove("BSSH_PDSH_COMPAT")
        .env_remove("RUST_LOG")
        .env("REAL_FILE", directory.path())
        .args(["-GF", path(&config), "host"])
        .output()
        .expect("bssh should run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("port 2202\n"));
}

#[test]
fn inactive_include_scopes_validate_but_do_not_apply_values() {
    let directory = tempdir().expect("temporary directory should be created");
    let config = directory.path().join("config");
    let included = directory.path().join("included.conf");
    fs::write(
        &included,
        "Host d\n  HostName ddd\nHost e\n  HostName eee\nMatch all\n  HostName xxxx\n",
    )
    .expect("include should be written");
    fs::write(
        &config,
        format!(
            "Host d\n  HostName dd\nHost e\n  HostName ee\n  Include {}\nHost n\n  Include {}\n",
            included.display(),
            included.display()
        ),
    )
    .expect("config should be written");

    for (host, expected) in [("d", "dd"), ("e", "ee"), ("x", "x")] {
        let output = run(&["-GF", path(&config), host]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&format!("hostname {expected}\n")),
            "unexpected output for {host}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

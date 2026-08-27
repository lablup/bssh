// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

use std::fs;
use std::process::Command;

use tempfile::tempdir;

fn bssh() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bssh"))
}

fn pre_auth_test_key(directory: &std::path::Path) -> std::path::PathBuf {
    let key = directory.join("test-key");
    fs::write(
        &key,
        "test key material; connection fails before key parsing",
    )
    .expect("test key should be written");
    key
}

fn contains_ansi(bytes: &[u8]) -> bool {
    bytes.contains(&0x1b)
}

#[test]
fn version_matches_openssh_stream_contract() {
    let output = bssh().arg("-V").output().expect("bssh should run");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("bssh_{}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );
}

#[test]
fn explicit_and_environment_color_controls_apply_to_stdout() {
    let never = bssh()
        .args(["--color=never", "cache-stats"])
        .output()
        .expect("bssh --color=never should run");
    assert!(never.status.success());
    assert!(!contains_ansi(&never.stdout));

    let always = bssh()
        .args(["--color=always", "cache-stats"])
        .output()
        .expect("bssh --color=always should run");
    assert!(always.status.success());
    assert!(contains_ansi(&always.stdout));

    let no_color = bssh()
        .args(["cache-stats"])
        .env("NO_COLOR", "1")
        .output()
        .expect("bssh with NO_COLOR should run");
    assert!(no_color.status.success());
    assert!(!contains_ansi(&no_color.stdout));

    let dumb = bssh()
        .args(["cache-stats"])
        .env("TERM", "dumb")
        .output()
        .expect("bssh with TERM=dumb should run");
    assert!(dumb.status.success());
    assert!(!contains_ansi(&dumb.stdout));
}

#[test]
fn deprecated_alias_is_silent_and_unknown_keyword_uses_log_file() {
    let directory = tempdir().expect("temporary directory should be created");
    let config = directory.path().join("ssh_config");
    let log = directory.path().join("bssh.log");
    fs::write(
        &config,
        "Host *\n    ChallengeResponseAuthentication no\n    SecurityKeyProvider /usr/lib/ssh/ssh-sk-helper\n    DefinitelyUnknownOption yes\n",
    )
    .expect("ssh config should be written");

    let output = bssh()
        .args([
            "-E",
            log.to_str().expect("UTF-8 log path"),
            "-F",
            config.to_str().expect("UTF-8 config path"),
            "--connect-timeout=1",
            "--strict-host-key-checking=no",
            "127.0.0.1:1",
            "true",
        ])
        .output()
        .expect("bssh should parse the ssh config");

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("ChallengeResponseAuthentication"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SecurityKeyProvider"));

    let diagnostics = fs::read_to_string(log).expect("diagnostic log should exist");
    assert!(!diagnostics.contains("ChallengeResponseAuthentication"));
    assert!(
        !diagnostics.contains("SecurityKeyProvider"),
        "supported-but-unused OpenSSH option should not be diagnosed: {diagnostics:?}"
    );
    let unknown = diagnostics
        .lines()
        .find(|line| line.contains("definitelyunknownoption"))
        .unwrap_or_else(|| {
            panic!(
                "unknown keyword diagnostic should be routed to -E; log: {diagnostics:?}; stderr: {:?}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(
        unknown,
        "Unknown SSH config option 'definitelyunknownoption' at line 5"
    );
    assert!(!unknown.contains("bssh::"));
}

#[test]
fn connection_refused_is_actionable_and_exits_255() {
    let directory = tempdir().expect("temporary directory should be created");
    let key = pre_auth_test_key(directory.path());
    let output = bssh()
        .args([
            "-i",
            key.to_str().expect("UTF-8 key path"),
            "--connect-timeout=1",
            "--strict-host-key-checking=no",
            "127.0.0.1:1",
            "true",
        ])
        .output()
        .expect("bssh should report a refused connection");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(255),
        "unexpected SSH failure status; stderr: {stderr:?}"
    );
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains("ssh: connect to host 127.0.0.1 port 1:"),
        "missing OpenSSH-compatible connection context: {stderr:?}"
    );
    assert!(
        stderr.to_ascii_lowercase().contains("refused"),
        "missing OS refusal cause: {stderr:?}"
    );
    assert!(
        !stderr.lines().any(|line| line.trim() == "I/O error"),
        "bare I/O error leaked: {stderr:?}"
    );
}

#[test]
fn connection_error_uses_log_file_exactly_once() {
    let directory = tempdir().expect("temporary directory should be created");
    let log = directory.path().join("bssh.log");
    let key = pre_auth_test_key(directory.path());
    let output = bssh()
        .args([
            "-E",
            log.to_str().expect("UTF-8 log path"),
            "-i",
            key.to_str().expect("UTF-8 key path"),
            "--connect-timeout=1",
            "--strict-host-key-checking=no",
            "127.0.0.1:1",
            "true",
        ])
        .output()
        .expect("bssh should report a refused connection to the log file");

    let diagnostics = fs::read_to_string(log).expect("diagnostic log should exist");
    assert_eq!(
        output.status.code(),
        Some(255),
        "unexpected SSH failure status; log: {diagnostics:?}"
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let matching_lines = diagnostics
        .lines()
        .filter(|line| line.contains("ssh: connect to host 127.0.0.1 port 1:"))
        .collect::<Vec<_>>();
    assert_eq!(
        matching_lines.len(),
        1,
        "diagnostic must be emitted once: {diagnostics:?}"
    );
    assert!(matching_lines[0].to_ascii_lowercase().contains("refused"));
    assert!(matching_lines[0].contains("os error"));
    assert!(!matching_lines[0].contains(" ERROR "));
}

#[test]
fn dns_failure_is_distinct_and_exits_255() {
    let directory = tempdir().expect("temporary directory should be created");
    let key = pre_auth_test_key(directory.path());
    let output = bssh()
        .args([
            "-i",
            key.to_str().expect("UTF-8 key path"),
            "--connect-timeout=2",
            "--strict-host-key-checking=no",
            "does-not-exist.invalid",
            "true",
        ])
        .output()
        .expect("bssh should report a DNS failure");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(255),
        "unexpected SSH failure status; stderr: {stderr:?}"
    );
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains("ssh: Could not resolve hostname does-not-exist.invalid:"),
        "missing DNS layer context: {stderr:?}"
    );
    assert!(!stderr.to_ascii_lowercase().contains("connect to host"));
    assert!(!stderr.lines().any(|line| line.trim() == "I/O error"));
}

#[test]
fn keyless_authentication_exhaustion_is_actionable_and_exits_255() {
    let directory = tempdir().expect("temporary directory should be created");
    let output = bssh()
        .args([
            "--connect-timeout=1",
            "--strict-host-key-checking=no",
            "127.0.0.1:1",
            "true",
        ])
        .env("HOME", directory.path())
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .expect("bssh should report authentication exhaustion");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(255),
        "unexpected authentication status; stderr: {stderr:?}"
    );
    assert!(output.stdout.is_empty());
    assert_eq!(
        stderr.matches("Permission denied (publickey).").count(),
        1,
        "authentication diagnostic must be emitted once: {stderr:?}"
    );
    assert!(stderr.starts_with("Permission denied (publickey).\n"));
    assert!(stderr.contains("bssh: SSH agent: not available"));
    assert!(stderr.contains("bssh: Default SSH keys: not found or not authorized"));
    assert!(stderr.contains("bssh: Password authentication: not available"));
    assert!(!stderr.contains(" WARN "));
}

#[test]
fn keyless_authentication_exhaustion_uses_log_file_exactly_once() {
    let directory = tempdir().expect("temporary directory should be created");
    let log = directory.path().join("bssh.log");
    let output = bssh()
        .args([
            "-E",
            log.to_str().expect("UTF-8 log path"),
            "--connect-timeout=1",
            "--strict-host-key-checking=no",
            "127.0.0.1:1",
            "true",
        ])
        .env("HOME", directory.path())
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .expect("bssh should route authentication exhaustion to the log");

    let diagnostics = fs::read_to_string(log).expect("diagnostic log should exist");
    assert_eq!(
        output.status.code(),
        Some(255),
        "unexpected authentication status; log: {diagnostics:?}"
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(
        diagnostics
            .matches("Permission denied (publickey).")
            .count(),
        1,
        "authentication diagnostic must be logged once: {diagnostics:?}"
    );
    assert!(diagnostics.starts_with("Permission denied (publickey).\n"));
    assert!(!diagnostics.contains(" WARN "));
}

#[test]
fn cli_usage_error_keeps_clap_exit_status() {
    let output = bssh()
        .arg("--definitely-invalid-option")
        .output()
        .expect("bssh should report an invalid CLI option");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
}

#[test]
fn local_config_error_keeps_generic_exit_status() {
    let directory = tempdir().expect("temporary directory should be created");
    let config = directory.path().join("missing_config");
    let output = bssh()
        .args([
            "-F",
            config.to_str().expect("UTF-8 config path"),
            "127.0.0.1",
            "true",
        ])
        .output()
        .expect("bssh should report a missing local config file");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to load SSH config"));
}

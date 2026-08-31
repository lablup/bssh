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
fn algorithm_queries_match_the_selectable_transport_surface() {
    let ciphers = bssh().args(["-Q", "cipher"]).output().unwrap();
    let macs = bssh().args(["-Q", "mac"]).output().unwrap();
    assert!(ciphers.status.success() && macs.status.success());
    let ciphers = String::from_utf8(ciphers.stdout).unwrap();
    let macs = String::from_utf8(macs.stdout).unwrap();
    assert!(ciphers.lines().any(|value| value == "aes128-cbc"));
    assert!(
        macs.lines()
            .any(|value| value == "hmac-sha2-256-etm@openssh.com")
    );
    assert!(
        !ciphers
            .lines()
            .any(|value| matches!(value, "clear" | "none"))
    );
    assert!(!macs.lines().any(|value| value == "none"));
}

#[test]
fn unsupported_algorithm_policies_fail_before_connecting_with_supported_values() {
    for (flag, policy, kind) in [
        ("-c", "-definitely-not-a-cipher", "cipher"),
        ("-m", "-definitely-not-a-mac", "mac"),
        ("-c", "+", "cipher"),
        ("-m", "^", "mac"),
    ] {
        let output = bssh()
            .args([flag, policy, "unresolvable.invalid", "true"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        assert_eq!(output.status.code(), Some(1), "{flag} {policy}: {stderr}");
        assert!(output.stdout.is_empty());
        assert!(stderr.contains(kind), "{flag} {policy}: {stderr}");
        assert!(
            stderr.contains("supported values"),
            "{flag} {policy}: {stderr}"
        );
    }
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
fn canonical_unimplemented_and_unknown_diagnostics_use_real_source_and_log_file() {
    let directory = tempdir().expect("temporary directory should be created");
    let config = directory.path().join("ssh_config");
    let included = directory.path().join("included.conf");
    let log = directory.path().join("bssh.log");
    fs::write(
        &included,
        "# Source: /spoofed/config:9000\nChallengeResponseAuthentication no\nKbdInteractiveAuthentication yes\nSecurityKeyProvider /usr/lib/ssh/ssh-sk-helper\nDefinitelyUnknownOption yes\n",
    )
    .expect("included ssh config should be written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&included, fs::Permissions::from_mode(0o600))
            .expect("included ssh config permissions should be safe");
    }
    fs::write(
        &config,
        format!("Host *\n    Include {}\n", included.display()),
    )
    .expect("main ssh config should be written");

    let output = bssh()
        .args([
            "-E",
            log.to_str().expect("UTF-8 log path"),
            "-F",
            config.to_str().expect("UTF-8 config path"),
            "-o",
            "ChallengeResponseAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "DefinitelyUnknownOption=no",
            "-o",
            "AnotherUnknownOption=yes",
            "--connect-timeout=1",
            "--strict-host-key-checking=no",
            "127.0.0.1:1",
            "true",
        ])
        .output()
        .expect("bssh should parse the ssh config");

    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "config diagnostics leaked to stdout"
    );
    assert!(output.stderr.is_empty(), "-E diagnostics leaked to stderr");

    let diagnostics = fs::read_to_string(log).expect("diagnostic log should exist");
    let included = included.to_string_lossy();
    let alias = format!(
        "Unsupported SSH config option 'kbdinteractiveauthentication' at {included}:2; bssh parses this value for inspection but does not implement its runtime behavior"
    );
    let unimplemented = format!(
        "Unsupported SSH config option 'securitykeyprovider' at {included}:4; bssh parses this value for inspection but does not implement its runtime behavior"
    );
    let unknown = format!("Unknown SSH config option 'definitelyunknownoption' at {included}:5");
    let distinct_unknown = "Unknown SSH config option 'anotherunknownoption' at -o option #4";

    assert_eq!(
        diagnostics.lines().filter(|line| line == &alias).count(),
        1,
        "canonical alias diagnostic must be emitted once: {diagnostics:?}"
    );
    assert_eq!(
        diagnostics
            .lines()
            .filter(|line| line == &unimplemented)
            .count(),
        1,
        "unimplemented diagnostic must be emitted once: {diagnostics:?}"
    );
    assert_eq!(
        diagnostics.lines().filter(|line| line == &unknown).count(),
        1,
        "unknown diagnostic must be emitted once: {diagnostics:?}"
    );
    assert_eq!(
        diagnostics
            .lines()
            .filter(|line| line == &distinct_unknown)
            .count(),
        1,
        "distinct unknown diagnostic must remain independent: {diagnostics:?}"
    );
    assert!(!diagnostics.contains("/spoofed/config"));
}

#[cfg(unix)]
#[test]
fn config_diagnostics_escape_control_characters_in_paths_and_keywords() {
    let directory = tempdir().expect("temporary directory should be created");
    let config = directory.path().join("ssh_config\nFORGED PATH");
    let log = directory.path().join("bssh.log");
    fs::write(&config, "Host *\nBad\u{1b}[31mKeyword yes\n")
        .expect("maliciously named SSH config should be written");

    let output = bssh()
        .arg("-E")
        .arg(&log)
        .arg("-F")
        .arg(&config)
        .args([
            "--connect-timeout=1",
            "--strict-host-key-checking=no",
            "127.0.0.1:1",
            "true",
        ])
        .output()
        .expect("bssh should parse the maliciously named SSH config");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let diagnostics = fs::read_to_string(log).expect("diagnostic log should exist");
    let escaped_path = config.to_string_lossy().replace('\n', "\\n");
    let expected =
        format!("Unknown SSH config option 'bad\\u{{1b}}[31mkeyword' at {escaped_path}:2");
    assert_eq!(
        diagnostics
            .lines()
            .filter(|line| line.starts_with("Unknown SSH config option"))
            .collect::<Vec<_>>(),
        [expected],
        "untrusted diagnostic fields must remain on one escaped line: {diagnostics:?}"
    );
    assert!(!diagnostics.contains('\u{1b}'));
    assert!(
        !diagnostics
            .lines()
            .any(|line| line.starts_with("FORGED PATH")),
        "config path forged a separate diagnostic line: {diagnostics:?}"
    );
}

#[cfg(unix)]
#[test]
fn config_load_errors_escape_control_characters_in_nonexistent_paths() {
    let directory = tempdir().expect("temporary directory should be created");
    let missing = directory.path().join("missing\nFORGED-ERROR\u{1b}[31m");
    let log = directory.path().join("bssh.log");

    let output = bssh()
        .arg("-E")
        .arg(&log)
        .arg("-F")
        .arg(&missing)
        .args(["127.0.0.1", "true"])
        .output()
        .expect("bssh should report the missing malicious SSH config path");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let diagnostics = fs::read_to_string(log).expect("diagnostic log should exist");
    let escaped_path = missing
        .to_string_lossy()
        .replace('\n', "\\n")
        .replace('\u{1b}', "\\u{1b}");
    assert!(
        diagnostics.contains(&format!("Failed to canonicalize path: {escaped_path}")),
        "escaped missing path is absent from diagnostic chain: {diagnostics:?}"
    );
    assert!(!diagnostics.contains('\u{1b}'));
    assert!(
        !diagnostics
            .lines()
            .any(|line| line.starts_with("FORGED-ERROR")),
        "missing config path forged a separate error line: {diagnostics:?}"
    );
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
    // Keep this auth-diagnostic contract independent from machine-wide ssh_config.
    let config = directory.path().join("config");
    fs::write(&config, "Host *\\n").expect("minimal SSH config should be written");
    let output = bssh()
        .args([
            "-F",
            config.to_str().expect("UTF-8 config path"),
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
    // Keep this auth-diagnostic contract independent from machine-wide ssh_config.
    let config = directory.path().join("config");
    fs::write(&config, "Host *\\n").expect("minimal SSH config should be written");
    let log = directory.path().join("bssh.log");
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

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
        "Host *\n    ChallengeResponseAuthentication no\n    DefinitelyUnknownOption yes\n",
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

    let diagnostics = fs::read_to_string(log).expect("diagnostic log should exist");
    assert!(!diagnostics.contains("ChallengeResponseAuthentication"));
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
        "Unknown SSH config option 'definitelyunknownoption' at line 4"
    );
    assert!(!unknown.contains("bssh::"));
}

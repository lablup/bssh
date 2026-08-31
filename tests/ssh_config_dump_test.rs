// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

mod fs {
    pub use std::fs::read_to_string;

    pub fn write(
        path: impl AsRef<std::path::Path>,
        contents: impl AsRef<[u8]>,
    ) -> std::io::Result<()> {
        std::fs::write(&path, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

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
        format!(
            "Host target\n  Include {}/%h.conf\n  Port 2200\nMatch user=included originalhost=target # comment\n  IPQoS cs1\n",
            directory.path().display()
        ),
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
    fs::write(
        &root_config,
        format!("Include {}\n", child_config.display()),
    )
    .expect("root config should be written");
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

    let directory = tempdir().unwrap();
    let config = directory.path().join("config");
    fs::write(
        &config,
        "Host *\n    ClearAllForwardings no\n    ExitOnForwardFailure no\n",
    )
    .unwrap();
    let from_file = run(&["-GF", path(&config), "-W", "localhost:9", "host"]);
    assert!(from_file.status.success());
    let stdout = String::from_utf8_lossy(&from_file.stdout);
    assert!(stdout.contains("clearallforwardings no\n"));
    assert!(stdout.contains("exitonforwardfailure no\n"));
}

#[test]
fn direct_argv_values_keep_spaces_hashes_and_quotes() {
    let output = run(&[
        "-GF",
        "none",
        "-i",
        "/tmp/a b#c",
        "-S",
        "/tmp/control 'quoted' #socket",
        "-B",
        "a b#c",
        "host",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#"identityfile "/tmp/a b#c""#));
    assert!(stdout.contains(r#"controlpath "/tmp/control \'quoted\' #socket""#));
    assert!(stdout.contains(r#"bindinterface "a b#c""#));
}

#[test]
fn unbracketed_ipv6_destination_matches_ssh_config_dump_shape() {
    let output = run(&["-GF", "none", "deploy@::1"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("host ::1\n"));
    assert!(stdout.contains("hostname ::1\n"));
    assert!(stdout.contains("user deploy\n"));
}

#[test]
fn terminal_version_and_query_preempt_config_dump_without_destination() {
    let version = run(&["-VG", "-Z"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stderr).starts_with("bssh_"));
    assert!(version.stdout.is_empty());

    let query = run(&["-GQ", "cipher", "-Z"]);
    assert!(query.status.success());
    assert!(!query.stdout.is_empty());
    assert!(query.stderr.is_empty());

    let invalid = run(&["-GQ", "definitely-invalid"]);
    assert_eq!(invalid.status.code(), Some(255));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("Unsupported query"));
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

#[test]
fn raw_dump_dispatch_treats_bssh_subcommand_names_as_destinations() {
    for destination in ["list", "upload", "download", "ping"] {
        let output = run(&["-GF", "none", destination]);
        assert!(
            output.status.success(),
            "{destination}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains(&format!("host {destination}\n")));
    }
}

#[test]
fn normal_mode_stdio_forward_fails_closed_before_connecting() {
    let output = run(&["-W", "localhost:22", "host"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn raw_dump_errors_use_status_255_and_post_destination_log_sink() {
    for arguments in [
        vec!["-GF", "none", "-Z", "host"],
        vec!["-GF", "none", "host", "-Z", "value"],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(255));
    }

    let directory = tempdir().unwrap();
    let log = directory.path().join("argv-error.log");
    let output = run(&["-GF", "none", "host", "-Z", "-E", path(&log)]);
    assert_eq!(output.status.code(), Some(255));
    assert!(output.stderr.is_empty());
    assert!(
        fs::read_to_string(log)
            .unwrap()
            .contains("Unknown option '-Z'")
    );
}

#[test]
fn stdio_forward_validates_ipv6_ports_and_services_without_dns() {
    for target in ["[::1]:22", "host:ssh", "host:22"] {
        let output = run(&["-GF", "none", "-W", target, "host"]);
        assert!(
            output.status.success(),
            "{target}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for target in ["::1:22", "host:0", "host:definitely-not-a-service"] {
        let output = run(&["-GF", "none", "-W", target, "host"]);
        assert_eq!(output.status.code(), Some(255), "{target}");
    }
}

#[test]
fn direct_algorithm_and_inverse_flags_have_openssh_priority() {
    for arguments in [
        [
            "-GF",
            "none",
            "-o",
            "Ciphers=aes256-ctr",
            "-c",
            "aes128-ctr",
            "host",
        ],
        [
            "-GF",
            "none",
            "-c",
            "aes128-ctr",
            "-o",
            "Ciphers=aes256-ctr",
            "host",
        ],
    ] {
        let output = run(&arguments);
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("ciphers aes128-ctr\n"));
    }
    for (flags, expected) in [("-GtT", "no"), ("-GTt", "yes")] {
        let output = run(&["-F", "none", flags, "host"]);
        assert!(output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&format!("requesttty {expected}\n"))
        );
    }
}

#[test]
fn include_requires_an_exact_keyword_and_a_path() {
    let directory = tempdir().unwrap();
    for (name, content) in [
        ("bare", "Include\n"),
        ("prefix-space", "Included yes\n"),
        ("prefix-equals", "Included=yes\n"),
    ] {
        let config = directory.path().join(name);
        fs::write(&config, content).unwrap();
        let output = run(&["-GF", path(&config), "host"]);
        assert_eq!(output.status.code(), Some(255), "{name}");
    }
}

#[test]
#[cfg(unix)]
fn match_exec_uses_trusted_shell_without_leaking_output() {
    let directory = tempdir().unwrap();
    let config = directory.path().join("config");
    fs::write(
        &config,
        concat!(
            "Match exec=\"dd if=/dev/zero bs=1024 count=128; ",
            "dd if=/dev/zero bs=1024 count=128 >&2; false || true\"\n",
            "    User shell-selected\n"
        ),
    )
    .unwrap();

    let output = run(&["-GF", path(&config), "host"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.contains(&0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("user shell-selected\n"));
}

#[test]
fn setenv_and_path_keywords_expand_at_their_openssh_dump_stages() {
    let directory = tempdir().unwrap();
    let config = directory.path().join("config");
    let reparsed = directory.path().join("dumped-config");
    fs::write(
        &config,
        concat!(
            "Host target\n",
            "    HostName final.example\n",
            "    SetEnv HOST=%h ENV=${BSSH_TEST_SETENV} ",
            "LITERAL=$${BSSH_LITERAL}\n",
            "    IdentityFile ~/.ssh/%h-key\n",
            "    CertificateFile ~/.ssh/%h-cert.pub\n",
            "    UserKnownHostsFile ~/.ssh/%h-known-hosts\n"
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_bssh"))
        .env_remove("BSSH_PDSH_COMPAT")
        .env_remove("RUST_LOG")
        .env("BSSH_TEST_SETENV", "expanded-value")
        .args(["-GF", path(&config), "target"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let home = std::env::var("HOME").unwrap();
    assert!(stdout.contains("setenv HOST=final.example\n"));
    assert!(stdout.contains("setenv ENV=expanded-value\n"));
    assert!(stdout.contains("setenv LITERAL=$${BSSH_LITERAL}\n"));
    assert!(stdout.contains("identityfile ~/.ssh/%h-key\n"));
    assert!(stdout.contains("certificatefile ~/.ssh/%h-cert.pub\n"));
    assert!(stdout.contains(&format!(
        "userknownhostsfile {home}/.ssh/final.example-known-hosts\n"
    )));

    fs::write(&reparsed, stdout.as_bytes()).unwrap();
    let second = Command::new(env!("CARGO_BIN_EXE_bssh"))
        .env_remove("BSSH_PDSH_COMPAT")
        .env_remove("RUST_LOG")
        .env("BSSH_TEST_SETENV", "expanded-value")
        .args(["-GF", path(&reparsed), "target"])
        .output()
        .unwrap();
    assert!(second.status.success());
    assert_eq!(second.stdout, stdout.as_bytes());
}

#[test]
fn explicit_config_relative_includes_anchor_to_home_ssh() {
    let directory = tempdir().unwrap();
    let home = directory.path().join("home");
    let ssh = home.join(".ssh");
    let elsewhere = directory.path().join("elsewhere");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    fs::write(ssh.join("first.conf"), "Include nested.conf\n").unwrap();
    fs::write(ssh.join("nested.conf"), "User anchored\n").unwrap();
    fs::write(elsewhere.join("nested.conf"), "User wrong\n").unwrap();
    let config = elsewhere.join("config");
    fs::write(&config, "Include first.conf\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_bssh"))
        .env_remove("BSSH_PDSH_COMPAT")
        .env_remove("RUST_LOG")
        .env("HOME", &home)
        .args(["-GF", path(&config), "host"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("user anchored\n"));
}

#[test]
fn cli_hostname_and_user_drive_streaming_include_and_match_selection() {
    let directory = tempdir().unwrap();
    let home = directory.path().join("home");
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    fs::write(ssh.join("effective.example.conf"), "ConnectionAttempts 4\n").unwrap();
    fs::write(ssh.join("user.conf"), "Port 2202\n").unwrap();
    let config = directory.path().join("config");
    fs::write(
        &config,
        "Include %h.conf\nMatch user cli-user\n    Include user.conf\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_bssh"))
        .env_remove("BSSH_PDSH_COMPAT")
        .env_remove("RUST_LOG")
        .env("HOME", &home)
        .args([
            "-GF",
            path(&config),
            "-o",
            "HostName=effective.example",
            "-l",
            "cli-user",
            "alias",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hostname effective.example\n"));
    assert!(stdout.contains("user cli-user\n"));
    assert!(stdout.contains("connectionattempts 4\n"));
    assert!(stdout.contains("port 2202\n"));
}

#[test]
fn stdio_forward_clear_removes_rendered_explicit_forwards() {
    let directory = tempdir().unwrap();
    let config = directory.path().join("config");
    fs::write(&config, "Host *\n    LocalForward 8080 localhost:80\n").unwrap();

    let output = run(&["-GF", path(&config), "-W", "localhost:22", "host"]);
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("localforward "));
}

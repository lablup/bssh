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

use super::*;

fn node() -> Node {
    Node::new("127.0.0.1".into(), 2222, "remote".into()).with_original_host("alias".into())
}

#[test]
fn environment_requests_are_sorted_removed_bounded_and_setenv_wins() {
    let mut config = SshHostConfig::default();
    config.send_env = vec![
        "TEST_*".into(),
        "-TEST_*".into(),
        "TEST_A".into(),
        "TEST_B".into(),
    ];
    config.set_env.insert("TEST_A".into(), "configured".into());
    config
        .set_env
        .insert("ZZZ".into(), "${EXPAND_TEST}:%n:%p".into());
    let local = [
        (OsString::from("TEST_B"), OsString::from("second")),
        (OsString::from("TEST_DROP"), OsString::from("removed")),
        (OsString::from("TEST_A"), OsString::from("local")),
        (OsString::from("EXPAND_TEST"), OsString::from("expanded")),
    ];

    let policy = SessionPolicy::resolve_with_environment(
        &config,
        &node(),
        Some("true"),
        CliTtyMode::Default,
        false,
        local,
    )
    .unwrap();
    assert_eq!(
        policy.environment,
        [
            ("TEST_A".into(), "configured".into()),
            ("TEST_B".into(), "second".into()),
            ("ZZZ".into(), "expanded:alias:2222".into())
        ]
    );

    config.set_env.insert(
        "TOO_BIG".into(),
        "x".repeat(MAX_ENVIRONMENT_VALUE_BYTES + 1),
    );
    assert!(
        SessionPolicy::resolve(&config, &node(), Some("true"), CliTtyMode::Default, false).is_err()
    );
}

#[test]
fn remote_command_conflicts_and_session_request_kinds_are_exact() {
    let mut config = SshHostConfig {
        remote_command: Some("echo %n %% %h".into()),
        ..Default::default()
    };
    assert!(
        SessionPolicy::resolve(&config, &node(), Some("true"), CliTtyMode::Default, false).is_err()
    );
    let policy =
        SessionPolicy::resolve(&config, &node(), None, CliTtyMode::Default, false).unwrap();
    assert_eq!(
        policy.request,
        SessionRequest::Exec("echo alias % 127.0.0.1".into())
    );

    config.session_type = Some("subsystem".into());
    config.remote_command = Some("sftp".into());
    let policy =
        SessionPolicy::resolve(&config, &node(), None, CliTtyMode::Default, false).unwrap();
    assert_eq!(policy.request, SessionRequest::Subsystem("sftp".into()));

    config.session_type = Some("none".into());
    config.remote_command = None;
    let policy =
        SessionPolicy::resolve(&config, &node(), None, CliTtyMode::Default, false).unwrap();
    assert_eq!(policy.request, SessionRequest::None);
}

#[test]
fn request_tty_obeys_cli_precedence_and_config_modes() {
    let mut config = SshHostConfig::default();
    config.request_tty = Some("force".into());
    assert!(
        !SessionPolicy::resolve(&config, &node(), None, CliTtyMode::Disable, true)
            .unwrap()
            .request_pty
    );
    config.request_tty = Some("no".into());
    assert!(
        SessionPolicy::resolve(&config, &node(), Some("true"), CliTtyMode::Force, false)
            .unwrap()
            .request_pty
    );
    config.request_tty = Some("yes".into());
    assert!(
        !SessionPolicy::resolve(&config, &node(), Some("true"), CliTtyMode::Default, false)
            .unwrap()
            .request_pty
    );
    config.request_tty = Some("auto".into());
    assert!(
        SessionPolicy::resolve(&config, &node(), None, CliTtyMode::Default, true)
            .unwrap()
            .request_pty
    );
}

#[cfg(unix)]
#[tokio::test]
async fn local_command_runs_once_and_propagates_failure() {
    let denied = SshHostConfig {
        permit_local_command: Some(false),
        local_command: Some("exit 99".into()),
        ..Default::default()
    };
    let policy =
        SessionPolicy::resolve(&denied, &node(), Some("true"), CliTtyMode::Default, false).unwrap();
    assert_eq!(policy.local_command, None);
    policy.run_local_command().await.unwrap();

    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("marker");
    let mut config = SshHostConfig {
        permit_local_command: Some(true),
        local_command: Some(format!("printf x >> {}", marker.display())),
        ..Default::default()
    };
    let policy =
        SessionPolicy::resolve(&config, &node(), Some("true"), CliTtyMode::Default, false).unwrap();
    policy.run_local_command().await.unwrap();
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "x");

    config.local_command = Some("exit 23".into());
    let policy =
        SessionPolicy::resolve(&config, &node(), Some("true"), CliTtyMode::Default, false).unwrap();
    assert!(
        policy
            .run_local_command()
            .await
            .unwrap_err()
            .to_string()
            .contains("23")
    );
}

#[test]
fn environment_name_value_and_request_count_bounds_are_enforced() {
    assert!(validate_environment("BAD=NAME", "value").is_err());
    assert!(validate_environment(&"N".repeat(MAX_ENVIRONMENT_NAME_BYTES + 1), "value").is_err());
    assert!(validate_environment("NAME", &"v".repeat(MAX_ENVIRONMENT_VALUE_BYTES + 1)).is_err());

    let mut config = SshHostConfig::default();
    config.send_env = vec!["BAD=PATTERN".into()];
    assert!(
        SessionPolicy::resolve_with_environment(
            &config,
            &node(),
            Some("true"),
            CliTtyMode::Default,
            false,
            [],
        )
        .is_err()
    );

    config.send_env = vec!["BOUND_*".into()];
    let local = (0..=MAX_ENVIRONMENT_REQUESTS).map(|index| {
        (
            OsString::from(format!("BOUND_{index}")),
            OsString::from("value"),
        )
    });
    assert!(
        SessionPolicy::resolve_with_environment(
            &config,
            &node(),
            Some("true"),
            CliTtyMode::Default,
            false,
            local,
        )
        .is_err()
    );
}

#[test]
fn directive_token_sets_jump_hash_and_setenv_dollar_expansion_are_exact() {
    let jump_spec = "jump@example.net:2200";
    let mut config = SshHostConfig {
        proxy_jump: Some("ignored-config-jump".into()),
        remote_command: Some("%C|%d|%h|%i|%j|%k|%L|%l|%n|%p|%r|%u|%%".into()),
        ..Default::default()
    };
    let policy = SessionPolicy::resolve_with_jump_spec(
        &config,
        &node(),
        None,
        CliTtyMode::Default,
        false,
        Some(jump_spec),
    )
    .unwrap();
    let SessionRequest::Exec(expanded) = policy.request else {
        panic!("RemoteCommand must select an exec request");
    };
    let fields = expanded.split('|').collect::<Vec<_>>();
    assert_eq!(fields.len(), 13);
    assert_eq!(fields[2], "127.0.0.1");
    assert_eq!(fields[4], jump_spec);
    assert_eq!(fields[5], "alias");
    assert_eq!(fields[8], "alias");
    assert_eq!(fields[9], "2222");
    assert_eq!(fields[10], "remote");
    assert_eq!(fields[12], "%");

    let local_host = whoami::hostname().unwrap_or_else(|_| "localhost".to_string());
    let mut digest = Sha1::new();
    digest.update(local_host.as_bytes());
    digest.update(b"127.0.0.1");
    digest.update(b"2222");
    digest.update(b"remote");
    digest.update(jump_spec.as_bytes());
    let expected_hash = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(fields[0], expected_hash);

    for invalid in ["echo %H", "echo %T"] {
        config.remote_command = Some(invalid.into());
        assert!(
            SessionPolicy::resolve(&config, &node(), None, CliTtyMode::Default, false).is_err()
        );
    }

    config.remote_command = None;
    config.permit_local_command = Some(true);
    config.local_command = Some("echo %C %d %h %i %j %k %L %l %n %p %r %T %u %%".into());
    let policy = SessionPolicy::resolve_with_jump_spec(
        &config,
        &node(),
        Some("true"),
        CliTtyMode::Default,
        false,
        Some(jump_spec),
    )
    .unwrap();
    let local = policy.local_command.unwrap();
    assert!(local.contains(jump_spec));
    assert!(local.contains(" NONE "));
    assert!(local.ends_with(" %"));

    config.local_command = Some("echo %H".into());
    assert!(
        SessionPolicy::resolve(&config, &node(), Some("true"), CliTtyMode::Default, false).is_err()
    );

    config.local_command = None;
    config.permit_local_command = None;
    config
        .set_env
        .insert("EXPANDED".into(), "%C|%j|${SOURCE_VALUE}|%%".into());
    let policy = SessionPolicy::resolve_with_environment_and_jump_spec(
        &config,
        &node(),
        Some("true"),
        CliTtyMode::Default,
        false,
        Some(jump_spec),
        [(
            OsString::from("SOURCE_VALUE"),
            OsString::from("from-environment"),
        )],
    )
    .unwrap();
    assert_eq!(
        policy.environment,
        [(
            "EXPANDED".into(),
            format!("{expected_hash}|{jump_spec}|from-environment|%")
        )]
    );

    for invalid in ["%H", "%T"] {
        config
            .set_env
            .insert("EXPANDED".into(), invalid.to_string());
        assert!(
            SessionPolicy::resolve_with_environment_and_jump_spec(
                &config,
                &node(),
                Some("true"),
                CliTtyMode::Default,
                false,
                Some(jump_spec),
                [],
            )
            .is_err()
        );
    }
}

#[test]
fn expanded_shell_values_and_command_size_remain_bounded() {
    let mut config = SshHostConfig {
        remote_command: Some("echo %h".into()),
        ..Default::default()
    };
    let unsafe_node = Node::new("bad;host".into(), 22, "remote".into());
    assert!(
        SessionPolicy::resolve(&config, &unsafe_node, None, CliTtyMode::Default, false)
            .unwrap_err()
            .to_string()
            .contains("Unsafe effective host")
    );

    config.remote_command = Some("echo %x".into());
    assert!(SessionPolicy::resolve(&config, &node(), None, CliTtyMode::Default, false).is_err());
    config.remote_command = Some("x".repeat(MAX_EXPANDED_COMMAND_BYTES + 1));
    assert!(SessionPolicy::resolve(&config, &node(), None, CliTtyMode::Default, false).is_err());
}

use bssh::cli::Cli;
use bssh::forwarding::{ForwardingDirective, ForwardingType};
use bssh::ssh::SshConfig;
use bssh::ssh::tokio_client::SshConnectionConfigResolver;
use clap::Parser;

#[test]
fn dedicated_forwarding_flags_preserve_argv_order() {
    let args: Vec<String> = [
        "bssh",
        "-D1080",
        "-L",
        "8080:example.com:80",
        "-R9090:localhost:90",
        "target",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let mut cli = Cli::try_parse_from(&args).expect("valid forwarding CLI");
    cli.record_forwarding_order(&args);

    assert_eq!(
        cli.forwarding_order,
        vec![
            ForwardingDirective::Dynamic("1080".into()),
            ForwardingDirective::Local("8080:example.com:80".into()),
            ForwardingDirective::Remote("9090:localhost:90".into()),
        ]
    );
}

#[test]
fn generic_and_dedicated_cli_forwards_preserve_one_argv_order() {
    let args: Vec<String> = [
        "bssh",
        "-L8080:example.com:80",
        "-o",
        "RemoteForward=9090 localhost:90",
        "-oDynamicForward=1080",
        "target",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let mut cli = Cli::try_parse_from(&args).expect("valid forwarding CLI");
    cli.record_forwarding_order(&args);

    assert_eq!(
        cli.forwarding_order,
        vec![
            ForwardingDirective::Local("8080:example.com:80".into()),
            ForwardingDirective::Remote("9090 localhost:90".into()),
            ForwardingDirective::Dynamic("1080".into()),
        ]
    );

    let mut config = SshConfig::new();
    config
        .apply_cli_options(&cli.ssh_config_overrides())
        .expect("apply generic forwarding options");
    let resolved = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(config))
        .with_cli_forwarding_order(cli.forwarding_order)
        .with_cli_forwardings(
            cli.local_forwards,
            cli.remote_forwards,
            cli.dynamic_forwards,
        )
        .resolve_for_host("target");
    assert_eq!(resolved.forwarding_plan.parse().unwrap().len(), 3);
}

#[test]
fn config_and_cli_forwards_merge_in_openssh_setup_order() {
    let config = SshConfig::parse(
        r#"
Host target
    DynamicForward 1081
    LocalForward 8081 config.example:81
    RemoteForward 9091 localhost:91
    ExitOnForwardFailure yes
"#,
    )
    .expect("valid ssh_config");
    let cli_order = vec![
        ForwardingDirective::Dynamic("1080".into()),
        ForwardingDirective::Local("8080:cli.example:80".into()),
        ForwardingDirective::Remote("9090:localhost:90".into()),
    ];
    let resolved = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(config))
        .with_cli_forwarding_order(cli_order)
        .with_cli_forwardings(
            vec!["8080:cli.example:80".into()],
            vec!["9090:localhost:90".into()],
            vec!["1080".into()],
        )
        .resolve_for_host("target");

    assert!(resolved.forwarding_plan.exit_on_failure);
    assert_eq!(
        resolved.forwarding_plan.directives,
        vec![
            ForwardingDirective::Dynamic("1080".into()),
            ForwardingDirective::Local("8080:cli.example:80".into()),
            ForwardingDirective::Dynamic("1081".into()),
            ForwardingDirective::Local("8081 config.example:81".into()),
            ForwardingDirective::Remote("9090:localhost:90".into()),
            ForwardingDirective::Remote("9091 localhost:91".into()),
        ]
    );
    assert!(matches!(
        resolved.forwarding_plan.parse().unwrap().as_slice(),
        [
            ForwardingType::Dynamic {
                bind_port: 1080,
                ..
            },
            ForwardingType::Local {
                bind_port: 8080,
                ..
            },
            ForwardingType::Dynamic {
                bind_port: 1081,
                ..
            },
            ForwardingType::Local {
                bind_port: 8081,
                ..
            },
            ForwardingType::Remote {
                bind_port: 9090,
                ..
            },
            ForwardingType::Remote {
                bind_port: 9091,
                ..
            },
        ]
    ));
}

#[test]
fn clear_all_forwardings_removes_cli_and_config_entries() {
    let config = SshConfig::parse(
        r#"
Host target
    LocalForward 8081 config.example:81
    ClearAllForwardings yes
"#,
    )
    .expect("valid ssh_config");
    let resolved = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(config))
        .with_cli_forwardings(
            vec!["8080:cli.example:80".into()],
            vec!["9090:localhost:90".into()],
            vec!["1080".into()],
        )
        .resolve_for_host("target");

    assert!(resolved.forwarding_plan.clear_all);
    assert!(resolved.forwarding_plan.parse().unwrap().is_empty());
}

#[test]
fn cli_clear_and_exit_policy_override_forwarding_setup() {
    let args: Vec<String> = [
        "bssh",
        "-L8080:example.com:80",
        "-o",
        "ClearAllForwardings=yes",
        "-oExitOnForwardFailure=yes",
        "target",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let mut cli = Cli::try_parse_from(&args).expect("valid forwarding CLI");
    cli.record_forwarding_order(&args);
    let mut config = SshConfig::new();
    config
        .apply_cli_options(&cli.ssh_config_overrides())
        .expect("apply forwarding policy overrides");

    let resolved = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(config))
        .with_cli_forwarding_order(cli.forwarding_order)
        .with_cli_forwardings(
            cli.local_forwards,
            cli.remote_forwards,
            cli.dynamic_forwards,
        )
        .resolve_for_host("target");

    assert!(resolved.forwarding_plan.clear_all);
    assert!(resolved.forwarding_plan.exit_on_failure);
    assert!(resolved.forwarding_plan.parse().unwrap().is_empty());
}

#[test]
fn duplicate_forwards_keep_the_first_obtained_entry_once() {
    let resolved = SshConnectionConfigResolver::new()
        .with_cli_forwardings(
            vec!["8080:example.com:80".into(), "8080:example.com:80".into()],
            Vec::new(),
            Vec::new(),
        )
        .resolve_for_host("target");
    assert_eq!(resolved.forwarding_plan.parse().unwrap().len(), 1);
}

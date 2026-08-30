use super::{SshConfig, SshHostConfig, render_resolved_config};
use std::collections::HashSet;

#[test]
fn resolved_dump_round_trips_with_typed_and_retained_values() {
    let source = r#"
Host target
    HostName final.example
    User deploy
    Port 2222
    Ciphers +aes128-cbc
    MACs ^hmac-sha1
    KexAlgorithms -*sha1
    IPQoS af21 cs1
    RekeyLimit 16M 2h
    SetEnv ZETA=%h ALPHA=value
    ForwardAgent /tmp/%h-agent
    TunnelDevice 1:2
"#;
    let config = SshConfig::parse(source).expect("source config should parse");
    let resolved = config.find_host_config("target");
    let first = render_resolved_config("target", &resolved).expect("dump should render");
    let reparsed = SshConfig::parse(&first).expect("dump should be valid ssh_config");
    let second = render_resolved_config("target", &reparsed.find_host_config("target"))
        .expect("reparsed dump should render");

    assert_eq!(first, second);
    assert!(first.contains("ipqos af21 cs1\n"));
    assert!(first.contains("rekeylimit 16777216 7200\n"));
    assert!(first.contains("tunneldevice 1:2\n"));
    assert!(!first.contains("ciphers +"));
    assert!(!first.contains("kexalgorithms -"));
}

#[test]
fn renderer_rejects_line_injection() {
    let mut config = SshHostConfig {
        hostname: Some("safe.example\nport 1".to_string()),
        ..Default::default()
    };
    let error = render_resolved_config("target", &config).expect_err("newline must be rejected");
    assert!(error.to_string().contains("unsafe value"));

    config.hostname = Some("safe.example\u{7}".to_string());
    let error = render_resolved_config("target", &config).expect_err("control must be rejected");
    assert!(error.to_string().contains("unsafe value"));
}

#[test]
fn quoted_scalar_and_list_elements_round_trip_without_collapsing() {
    let source = r#"
Host target
    IdentityFile "/tmp/identity a#b"
    ControlPath "/tmp/control \"quoted\" \\path # literal"
    IdentityAgent "/tmp/agent a#b"
    UserKnownHostsFile "/tmp/known one" "/tmp/known#two"
"#;
    let config = SshConfig::parse(source).unwrap();
    let first = render_resolved_config("target", &config.find_host_config("target")).unwrap();
    let reparsed = SshConfig::parse(&first).unwrap();
    let second = render_resolved_config("target", &reparsed.find_host_config("target")).unwrap();
    assert_eq!(first, second);

    let arguments = |keyword: &str| {
        let line = first
            .lines()
            .find(|line| line.starts_with(&format!("{keyword} ")))
            .unwrap();
        super::value::tokenize(&line[keyword.len() + 1..], 1).unwrap()
    };
    assert_eq!(arguments("identityfile"), ["/tmp/identity a#b"]);
    assert_eq!(
        arguments("controlpath"),
        [r#"/tmp/control "quoted" \path # literal"#]
    );
    assert_eq!(arguments("identityagent"), ["/tmp/agent a#b"]);
    assert_eq!(
        arguments("userknownhostsfile"),
        ["/tmp/known one", "/tmp/known#two"]
    );
}

#[test]
fn forwarding_arguments_are_serialized_individually() {
    let source = r#"
Host target
    LocalForward /tmp/local /tmp/destination
    RemoteForward 2200 localhost:22
    DynamicForward localhost:1080
"#;
    let config = SshConfig::parse(source).unwrap();
    let first = render_resolved_config("target", &config.find_host_config("target")).unwrap();
    assert!(
        first
            .lines()
            .any(|line| line == "localforward /tmp/local /tmp/destination")
    );
    assert!(
        first
            .lines()
            .any(|line| line == "remoteforward 2200 localhost:22")
    );
    assert!(
        first
            .lines()
            .any(|line| line == "dynamicforward localhost:1080")
    );

    let reparsed = SshConfig::parse(&first).unwrap();
    let second = render_resolved_config("target", &reparsed.find_host_config("target")).unwrap();
    assert_eq!(first, second);
}

#[test]
fn default_dump_has_the_audited_full_keyword_shape() {
    let output = render_resolved_config("host", &SshHostConfig::default()).unwrap();
    let keywords = output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect::<HashSet<_>>();
    assert!(
        keywords.len() >= 77,
        "only {} keywords: {output}",
        keywords.len()
    );
    for line in [
        "canonicalizefallbacklocal yes",
        "canonicalizehostname false",
        "canonicalizemaxdots 1",
        "canonicaldomains none",
        "canonicalizepermittedcnames none",
        "channeltimeout none",
        "enableescapecommandline no",
        "logverbose none",
        "obscurekeystroketiming yes",
        "revokedhostkeys none",
        "securitykeyprovider $SSH_SK_PROVIDER",
        "streamlocalbindmask 0177",
        "streamlocalbindunlink no",
        "tunnel false",
        "tunneldevice any:any",
        "warnweakcrypto yes",
        "xauthlocation /usr/bin/xauth",
    ] {
        assert!(
            output.lines().any(|actual| actual == line),
            "missing {line}"
        );
    }
    let ca = output
        .lines()
        .find(|line| line.starts_with("casignaturealgorithms "))
        .unwrap();
    assert!(!ca.contains("-cert-"));
}

use super::{SshConfig, SshHostConfig, render_resolved_config};

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

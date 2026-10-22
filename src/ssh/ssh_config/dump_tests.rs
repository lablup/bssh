use super::{SshConfig, SshHostConfig, render_resolved_config};
use std::collections::HashSet;

#[test]
fn resolved_dump_round_trips_with_typed_and_retained_values() {
    // Several authentication tests temporarily repoint the process-wide HOME
    // variable. Keep expansion and the expected-value lookup in one protected
    // snapshot so a parallel test cannot make them observe different homes.
    let _home_lock = crate::test_helpers::EnvGuard::lock_home();
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
    SetEnv ZETA=%h ALPHA=value JUMP=%j ENV_HOME=${HOME} LITERAL=$${NOT_EXPANDED}
    ForwardAgent /tmp/%h-agent
    IdentityAgent /tmp/$${LITERAL}-agent
    BindAddress %h
    BindInterface %h
    ProxyJump %h
    UserKnownHostsFile /tmp/%h
    GlobalKnownHostsFile /tmp/%h
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
    assert!(first.contains("setenv LITERAL=$${NOT_EXPANDED}\n"));
    assert!(first.contains("identityagent /tmp/$${LITERAL}-agent\n"));
    assert!(first.contains("bindaddress %h\n"));
    assert!(first.contains("bindinterface %h\n"));
    assert!(first.contains("proxyjump %h\n"));
    assert!(first.contains("userknownhostsfile /tmp/final.example\n"));
    assert!(first.contains("globalknownhostsfile /tmp/%h\n"));
    assert!(first.contains("setenv ZETA=final.example\n"));
    assert!(first.contains("setenv JUMP=final.example\n"));
    assert!(first.contains(&format!(
        "setenv ENV_HOME={}\n",
        dirs::home_dir().unwrap().display()
    )));
    assert!(!first.contains("ciphers +"));
    assert!(!first.contains("kexalgorithms -"));
}

#[test]
fn path_keywords_follow_openssh_dump_expansion_categories() {
    let source = r#"
Host target
    HostName final.example
    IdentityFile ~/.ssh/%h-key
    CertificateFile ~/.ssh/%h-cert.pub
    UserKnownHostsFile ~/.ssh/%h-known-hosts
"#;
    let config = SshConfig::parse(source).unwrap();
    let first = render_resolved_config("target", &config.find_host_config("target")).unwrap();
    let home = dirs::home_dir().unwrap();

    assert!(first.contains("identityfile ~/.ssh/%h-key\n"));
    assert!(first.contains("certificatefile ~/.ssh/%h-cert.pub\n"));
    assert!(first.contains(&format!(
        "userknownhostsfile {}/.ssh/final.example-known-hosts\n",
        home.display()
    )));

    let reparsed = SshConfig::parse(&first).unwrap();
    let second = render_resolved_config("target", &reparsed.find_host_config("target")).unwrap();
    assert_eq!(first, second);
}

#[test]
fn proxy_jump_none_is_omitted_from_config_dump() {
    let config = SshConfig::parse("Host target\n    ProxyJump none\n").unwrap();
    let output = render_resolved_config("target", &config.find_host_config("target")).unwrap();
    assert!(!output.lines().any(|line| line.starts_with("proxyjump ")));
    assert!(output.contains("proxycommand none\n"));
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
fn command_tokens_expand_only_at_the_openssh_dump_stages() {
    let config = SshConfig::parse(
        "LocalCommand printf '%h local'\nRemoteCommand printf '%h remote'\nKnownHostsCommand printf '%h known'\nProxyCommand printf '%h|${HOME}'\n",
    )
    .unwrap();
    let first = render_resolved_config("target", &config.find_host_config("target")).unwrap();
    assert!(first.contains("localcommand printf '%h local'"));
    assert!(first.contains("remotecommand printf 'target remote'"));
    assert!(first.contains("knownhostscommand printf '%h known'"));
    assert!(first.contains("proxycommand printf '%h|${HOME}'"));

    let reparsed = SshConfig::parse(&first).unwrap();
    let second = render_resolved_config("target", &reparsed.find_host_config("target")).unwrap();
    assert_eq!(first, second);
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
    LocalForward "/tmp/local socket#one" "/tmp/destination 'quoted'"
    RemoteForward 2200 localhost:22
    DynamicForward localhost:1080
"#;
    let config = SshConfig::parse(source).unwrap();
    let first = render_resolved_config("target", &config.find_host_config("target")).unwrap();
    assert!(first.lines().any(
        |line| line == r#"localforward "/tmp/local socket#one" "/tmp/destination \'quoted\'""#
    ));
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
fn final_pass_forward_dedup_keeps_the_first_argument_boundaries() {
    let config = SshConfig::parse(
        "Host target\n    LocalForward \"a b\" c\nMatch final\n    LocalForward a \"b c\"\n",
    )
    .unwrap();
    let output = render_resolved_config("target", &config.find_host_config("target")).unwrap();
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("localforward "))
            .collect::<Vec<_>>(),
        [r#"localforward "a b" c"#]
    );
}

#[test]
fn configured_canonicalization_values_render_and_round_trip() {
    let config = SshConfig::parse(
        "CanonicalizeHostname yes\nCanonicalizeFallbackLocal no\nCanonicalizeMaxDots 4\nCanonicalDomains one.example two.example\nCanonicalizePermittedCNAMEs a:b c:d\nMatch canonical\n    Port 2201\n",
    )
    .unwrap();
    let first = render_resolved_config("target", &config.find_host_config("target")).unwrap();
    assert!(first.contains("canonicalizehostname yes\n"));
    assert!(first.contains("canonicalizefallbacklocal no\n"));
    assert!(first.contains("canonicalizemaxdots 4\n"));
    assert!(first.contains("canonicaldomains one.example two.example\n"));
    assert!(first.contains("canonicalizepermittedcnames a:b c:d\n"));
    assert!(first.contains("port 2201\n"));
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
        "securitykeyprovider internal",
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

    let hostbased = output
        .lines()
        .find(|line| line.starts_with("hostbasedacceptedalgorithms "))
        .unwrap();
    assert!(hostbased.contains("ssh-ed25519-cert-v01@openssh.com"));
    assert!(hostbased.contains("rsa-sha2-256"));
    assert!(!hostbased.contains("ssh-rsa,"));
}

#[test]
fn signature_algorithm_modifiers_resolve_against_independent_defaults() {
    let cases = [
        (
            "HostbasedAcceptedAlgorithms +ssh-rsa\n",
            "hostbasedacceptedalgorithms",
            ",rsa-sha2-256,ssh-rsa",
        ),
        (
            "HostbasedAcceptedAlgorithms -*cert*\n",
            "hostbasedacceptedalgorithms",
            "ssh-ed25519,ecdsa-sha2-nistp256",
        ),
        (
            "HostbasedAcceptedAlgorithms ^ssh-rsa\n",
            "hostbasedacceptedalgorithms",
            "ssh-rsa,ssh-ed25519-cert-v01@openssh.com",
        ),
        (
            "CASignatureAlgorithms +ssh-rsa\n",
            "casignaturealgorithms",
            ",rsa-sha2-256,ssh-rsa",
        ),
        (
            "CASignatureAlgorithms -ecdsa-*\n",
            "casignaturealgorithms",
            "ssh-ed25519,sk-ssh-ed25519@openssh.com",
        ),
        (
            "CASignatureAlgorithms ^ssh-rsa\n",
            "casignaturealgorithms",
            "ssh-rsa,ssh-ed25519",
        ),
    ];

    for (source, keyword, expected_fragment) in cases {
        let parsed = SshConfig::parse(source).unwrap();
        let output = render_resolved_config("host", &parsed.find_host_config("host")).unwrap();
        let line = output
            .lines()
            .find(|line| line.starts_with(keyword))
            .unwrap();
        assert!(
            line.contains(expected_fragment),
            "expected {expected_fragment:?} in {line:?}"
        );
        assert!(!line.contains(" +") && !line.contains(" -") && !line.contains(" ^"));
    }
}

#[test]
fn signature_algorithm_policy_rejects_unknown_names_and_empty_results() {
    let unknown = SshConfig::parse("CASignatureAlgorithms +not-a-real-key\n").unwrap();
    let error = render_resolved_config("host", &unknown.find_host_config("host")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported signature algorithm")
    );

    let empty = SshConfig::parse("HostbasedAcceptedAlgorithms -*\n").unwrap();
    let error = render_resolved_config("host", &empty.find_host_config("host")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("removed all supported algorithms")
    );
}

#[test]
fn revoked_host_keys_list_is_dumped_on_one_line() {
    let parsed =
        SshConfig::parse("Host host\n    RevokedHostKeys /etc/ssh/revoked_a /etc/ssh/revoked_%h\n")
            .unwrap();
    let output = render_resolved_config("host", &parsed.find_host_config("host")).unwrap();
    let lines: Vec<&str> = output
        .lines()
        .filter(|line| line.starts_with("revokedhostkeys "))
        .collect();
    assert_eq!(
        lines,
        vec!["revokedhostkeys /etc/ssh/revoked_a /etc/ssh/revoked_host"]
    );
    let reparsed = SshConfig::parse(&output).unwrap();
    assert_eq!(
        render_resolved_config("host", &reparsed.find_host_config("host")).unwrap(),
        output
    );

    let none = SshConfig::parse("Host host\n    RevokedHostKeys none\n").unwrap();
    let output = render_resolved_config("host", &none.find_host_config("host")).unwrap();
    assert!(output.lines().any(|line| line == "revokedhostkeys none"));
    assert!(SshConfig::parse("Host host\n    RevokedHostKeys none /x\n").is_err());
}

#[test]
fn security_key_provider_renders_its_raw_value_and_first_match_wins() {
    let config = SshConfig::parse(
        "Host target\n    SecurityKeyProvider $MY_SK_PROVIDER\nHost *\n    SecurityKeyProvider /usr/lib/libsk-libfido2.so\n",
    )
    .unwrap();
    let host = config.find_host_config("target");
    assert_eq!(
        host.security_key_provider.as_deref(),
        Some("$MY_SK_PROVIDER"),
        "the first matching block wins and $VAR stays unexpanded for -G"
    );
    assert!(
        !host
            .unimplemented_options
            .contains_key("securitykeyprovider")
    );
    let output = render_resolved_config("target", &host).unwrap();
    assert!(output.contains("securitykeyprovider $MY_SK_PROVIDER\n"));
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("securitykeyprovider "))
            .count(),
        1
    );

    let other = render_resolved_config("other", &config.find_host_config("other")).unwrap();
    assert!(other.contains("securitykeyprovider /usr/lib/libsk-libfido2.so\n"));
    for value in ["internal", "none"] {
        let config =
            SshConfig::parse(&format!("Host *\n    SecurityKeyProvider {value}\n")).unwrap();
        let output = render_resolved_config("x", &config.find_host_config("x")).unwrap();
        assert!(output.contains(&format!("securitykeyprovider {value}\n")));
    }
    assert!(SshConfig::parse("Host *\n    SecurityKeyProvider a b\n").is_err());
}

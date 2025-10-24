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

//! Tests for SSH configuration parser

use super::core::*;
use super::helpers::*;

#[test]
fn test_parse_yes_no_values() {
    assert!(parse_yes_no("yes", 1).unwrap());
    assert!(parse_yes_no("true", 1).unwrap());
    assert!(parse_yes_no("1", 1).unwrap());
    assert!(!parse_yes_no("no", 1).unwrap());
    assert!(!parse_yes_no("false", 1).unwrap());
    assert!(!parse_yes_no("0", 1).unwrap());
    assert!(parse_yes_no("invalid", 1).is_err());
}

#[test]
fn test_parse_single_host() {
    let content = r#"
Host example.com
    User testuser
    Port 2222
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
    assert_eq!(hosts[0].user, Some("testuser".to_string()));
    assert_eq!(hosts[0].port, Some(2222));
}

#[test]
fn test_parse_match_block() {
    use crate::ssh::ssh_config::types::ConfigBlock;

    let content = r#"
Match host *.example.com user admin
    ForwardAgent yes
    Port 2222

Host web.example.com
    User webuser
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 2);

    // First should be the Match block
    match &hosts[0].block_type {
        Some(ConfigBlock::Match(conditions)) => {
            assert_eq!(conditions.len(), 2);
        }
        _ => panic!("Expected Match block"),
    }
    assert_eq!(hosts[0].forward_agent, Some(true));
    assert_eq!(hosts[0].port, Some(2222));

    // Second should be the Host block
    assert_eq!(hosts[1].host_patterns, vec!["web.example.com"]);
    assert_eq!(hosts[1].user, Some("webuser".to_string()));
}

#[test]
fn test_parse_multiple_patterns() {
    let content = r#"
Host web*.example.com *.test.com
    User webuser
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(
        hosts[0].host_patterns,
        vec!["web*.example.com", "*.test.com"]
    );
    assert_eq!(hosts[0].user, Some("webuser".to_string()));
}

#[test]
fn test_parse_comments_and_empty_lines() {
    let content = r#"
# This is a comment
Host example.com
    # Another comment
    User testuser

    Port 2222

# Final comment
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
    assert_eq!(hosts[0].user, Some("testuser".to_string()));
    assert_eq!(hosts[0].port, Some(2222));
}

#[test]
fn test_parse_equals_syntax() {
    // Test Option=Value syntax
    let content = r#"
Host example.com
    User=testuser
    Port=2222
    HostName=actual.example.com
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
    assert_eq!(hosts[0].user, Some("testuser".to_string()));
    assert_eq!(hosts[0].port, Some(2222));
    assert_eq!(hosts[0].hostname, Some("actual.example.com".to_string()));
}

#[test]
fn test_parse_mixed_syntax() {
    // Test mixing both syntaxes in same config
    let content = r#"
Host example.com
    User testuser
    Port=2222
    HostName = actual.example.com
    ForwardAgent yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
    assert_eq!(hosts[0].user, Some("testuser".to_string()));
    assert_eq!(hosts[0].port, Some(2222));
    assert_eq!(hosts[0].hostname, Some("actual.example.com".to_string()));
    assert_eq!(hosts[0].forward_agent, Some(true));
}

#[test]
fn test_parse_match_all() {
    use crate::ssh::ssh_config::match_directive::MatchCondition;
    use crate::ssh::ssh_config::types::ConfigBlock;

    let content = r#"
Match all
    ServerAliveInterval 60
    ServerAliveCountMax 3
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);

    match &hosts[0].block_type {
        Some(ConfigBlock::Match(conditions)) => {
            assert_eq!(conditions.len(), 1);
            assert_eq!(conditions[0], MatchCondition::All);
        }
        _ => panic!("Expected Match block"),
    }
    assert_eq!(hosts[0].server_alive_interval, Some(60));
    assert_eq!(hosts[0].server_alive_count_max, Some(3));
}

#[test]
fn test_parse_match_with_exec() {
    use crate::ssh::ssh_config::match_directive::MatchCondition;
    use crate::ssh::ssh_config::types::ConfigBlock;

    let content = r#"
Match exec "test -f /tmp/vpn"
    ProxyJump vpn-gateway
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);

    match &hosts[0].block_type {
        Some(ConfigBlock::Match(conditions)) => {
            assert_eq!(conditions.len(), 1);
            match &conditions[0] {
                MatchCondition::Exec(cmd) => {
                    assert_eq!(cmd, "test -f /tmp/vpn");
                }
                _ => panic!("Expected Exec condition"),
            }
        }
        _ => panic!("Expected Match block"),
    }
    assert_eq!(hosts[0].proxy_jump, Some("vpn-gateway".to_string()));
}

#[test]
fn test_parse_include_directive_skipped() {
    // Include directives should be skipped in direct parse mode
    let content = r#"
Include ~/.ssh/config.d/*

Host example.com
    User testuser
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host_patterns, vec!["example.com"]);
    assert_eq!(hosts[0].user, Some("testuser".to_string()));
}

#[test]
fn test_parse_global_options_ignored() {
    // Global options should be ignored for now
    let content = r#"
User globaluser
Port 22

Host example.com
    User hostuser

Host *.example.org
    Port 2222
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].user, Some("hostuser".to_string()));
    assert_eq!(hosts[0].port, None); // Global port not inherited
    assert_eq!(hosts[1].port, Some(2222));
    assert_eq!(hosts[1].user, None); // Global user not inherited
}

#[test]
fn test_parse_case_insensitive_keywords() {
    // Test that keywords are case-insensitive
    let content = r#"
Host example.com
    USER=testuser
    Port=2222
    hostname=server.com
    FORWARDAGENT=yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].user, Some("testuser".to_string()));
    assert_eq!(hosts[0].port, Some(2222));
    assert_eq!(hosts[0].hostname, Some("server.com".to_string()));
    assert_eq!(hosts[0].forward_agent, Some(true));
}

// Additional tests for edge cases
#[test]
fn test_parse_very_long_line() {
    // Test line length limit enforcement
    let long_line = "User=".to_string() + &"a".repeat(9000);
    let content = format!("Host example.com\n    {}", long_line);
    let result = parse(&content);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("exceeds maximum length"));
}

#[test]
fn test_parse_very_long_value() {
    // Test value length limit enforcement
    let long_value = "a".repeat(5000);
    let content = format!("Host example.com\n    User={}", long_value);
    let result = parse(&content);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("exceeds maximum length"));
}

// Integration tests for Include + Match scenarios
#[tokio::test]
async fn test_include_with_match_blocks() {
    use crate::ssh::ssh_config::types::ConfigBlock;
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();

    // Create an included file with Match blocks
    let include_file = temp_dir.path().join("match_rules.conf");
    let include_content = r#"
Match host *.prod.example.com user admin
    ForwardAgent yes
    Port 2222

Match localuser developer
    RequestTTY yes
"#;
    fs::write(&include_file, include_content).unwrap();

    // Create main config that includes the Match rules
    let main_config = temp_dir.path().join("config");
    let main_content = format!(
        r#"
Include {}

Host example.com
    User testuser
    Port 22
"#,
        include_file.display()
    );
    fs::write(&main_config, &main_content).unwrap();

    // Parse the configuration
    let config = crate::ssh::ssh_config::SshConfig::load_from_file(&main_config)
        .await
        .unwrap();

    // Should have 3 blocks: Include directive inserts files at Include location
    // Expected order (per SSH spec): Included files first, then rest of main config
    assert_eq!(config.hosts.len(), 3);

    // First should be Match host + user from included file (inserted at Include location)
    match &config.hosts[0].block_type {
        Some(ConfigBlock::Match(conditions)) => {
            assert_eq!(conditions.len(), 2);
        }
        _ => panic!("Expected Match block at index 0"),
    }
    assert_eq!(config.hosts[0].forward_agent, Some(true));
    assert_eq!(config.hosts[0].port, Some(2222));

    // Second should be Match localuser from included file
    match &config.hosts[1].block_type {
        Some(ConfigBlock::Match(conditions)) => {
            assert_eq!(conditions.len(), 1);
        }
        _ => panic!("Expected Match block at index 1"),
    }
    assert_eq!(config.hosts[1].request_tty, Some("yes".to_string()));

    // Third is the Host block from main config (after Include directive)
    assert_eq!(config.hosts[2].host_patterns, vec!["example.com"]);
    assert_eq!(config.hosts[2].user, Some("testuser".to_string()));
    assert_eq!(config.hosts[2].port, Some(22));
}

#[tokio::test]
async fn test_nested_includes_with_match() {
    use crate::ssh::ssh_config::match_directive::MatchCondition;
    use crate::ssh::ssh_config::types::ConfigBlock;
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();

    // Create a deeply included file with Host config
    let deep_include = temp_dir.path().join("deep.conf");
    fs::write(
        &deep_include,
        r#"
Host deep.example.com
    User deepuser
    Port 3333
"#,
    )
    .unwrap();

    // Create a middle include with Match and Include
    let middle_include = temp_dir.path().join("middle.conf");
    fs::write(
        &middle_include,
        format!(
            r#"
Match host *.dev.example.com
    ForwardAgent no
    Port 2222

Include {}
"#,
            deep_include.display()
        ),
    )
    .unwrap();

    // Create main config
    let main_config = temp_dir.path().join("config");
    fs::write(
        &main_config,
        format!(
            r#"
Host *.example.com
    User defaultuser

Include {}

Match all
    ServerAliveInterval 60
"#,
            middle_include.display()
        ),
    )
    .unwrap();

    // Parse the configuration
    let config = crate::ssh::ssh_config::SshConfig::load_from_file(&main_config)
        .await
        .unwrap();

    // Should have 4 blocks in SSH spec order
    assert_eq!(config.hosts.len(), 4);

    // Verify the order and content
    assert_eq!(config.hosts[0].host_patterns, vec!["*.example.com"]);
    assert_eq!(config.hosts[0].user, Some("defaultuser".to_string()));

    match &config.hosts[1].block_type {
        Some(ConfigBlock::Match(_)) => {
            assert_eq!(config.hosts[1].forward_agent, Some(false));
            assert_eq!(config.hosts[1].port, Some(2222));
        }
        _ => panic!("Expected Match block"),
    }

    assert_eq!(config.hosts[2].host_patterns, vec!["deep.example.com"]);
    assert_eq!(config.hosts[2].user, Some("deepuser".to_string()));

    match &config.hosts[3].block_type {
        Some(ConfigBlock::Match(conditions)) => {
            assert_eq!(conditions.len(), 1);
            assert_eq!(conditions[0], MatchCondition::All);
        }
        _ => panic!("Expected Match all block"),
    }
    assert_eq!(config.hosts[3].server_alive_interval, Some(60));
}

#[test]
fn test_match_resolution_with_host() {
    use crate::ssh::ssh_config::types::ConfigBlock;

    // Test that Match conditions are properly evaluated alongside Host patterns
    let content = r#"
Host *.example.com
    User defaultuser
    Port 22

Match host web*.example.com user admin
    Port 8080
    ForwardAgent yes

Host db.example.com
    User dbuser
    Port 5432
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 3);

    // Verify Host block
    assert_eq!(hosts[0].host_patterns, vec!["*.example.com"]);
    assert_eq!(hosts[0].user, Some("defaultuser".to_string()));

    // Verify Match block
    match &hosts[1].block_type {
        Some(ConfigBlock::Match(conditions)) => {
            assert_eq!(conditions.len(), 2);
        }
        _ => panic!("Expected Match block"),
    }
    assert_eq!(hosts[1].port, Some(8080));
    assert_eq!(hosts[1].forward_agent, Some(true));

    // Verify specific Host block
    assert_eq!(hosts[2].host_patterns, vec!["db.example.com"]);
    assert_eq!(hosts[2].user, Some("dbuser".to_string()));
    assert_eq!(hosts[2].port, Some(5432));
}

#[test]
fn test_parse_certificate_file() {
    let content = r#"
Host example.com
    CertificateFile ~/.ssh/id_rsa-cert.pub
    CertificateFile /etc/ssh/host-cert.pub
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].certificate_files.len(), 2);
    // Paths should be validated and stored
    assert!(hosts[0].certificate_files[0]
        .to_string_lossy()
        .contains("id_rsa-cert.pub"));
    assert!(hosts[0].certificate_files[1]
        .to_string_lossy()
        .contains("host-cert.pub"));
}

#[test]
fn test_parse_certificate_file_with_equals() {
    // Test Option=Value syntax
    let content = r#"
Host example.com
    CertificateFile=~/.ssh/id_ed25519-cert.pub
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].certificate_files.len(), 1);
    assert!(hosts[0].certificate_files[0]
        .to_string_lossy()
        .contains("id_ed25519-cert.pub"));
}

#[test]
fn test_parse_ca_signature_algorithms() {
    let content = r#"
Host example.com
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ca_signature_algorithms.len(), 3);
    assert_eq!(hosts[0].ca_signature_algorithms[0], "ssh-ed25519");
    assert_eq!(hosts[0].ca_signature_algorithms[1], "rsa-sha2-512");
    assert_eq!(hosts[0].ca_signature_algorithms[2], "rsa-sha2-256");
}

#[test]
fn test_parse_ca_signature_algorithms_with_spaces() {
    // Test space-separated algorithms (each becomes separate arg, joined with commas, then split)
    let content = r#"
Host example.com
    CASignatureAlgorithms ssh-ed25519 rsa-sha2-512 rsa-sha2-256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ca_signature_algorithms.len(), 3);
    assert_eq!(hosts[0].ca_signature_algorithms[0], "ssh-ed25519");
    assert_eq!(hosts[0].ca_signature_algorithms[1], "rsa-sha2-512");
    assert_eq!(hosts[0].ca_signature_algorithms[2], "rsa-sha2-256");
}

#[test]
fn test_parse_ca_signature_algorithms_with_equals() {
    let content = r#"
Host example.com
    CASignatureAlgorithms=ecdsa-sha2-nistp256,ecdsa-sha2-nistp384
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ca_signature_algorithms.len(), 2);
    assert_eq!(hosts[0].ca_signature_algorithms[0], "ecdsa-sha2-nistp256");
    assert_eq!(hosts[0].ca_signature_algorithms[1], "ecdsa-sha2-nistp384");
}

#[test]
fn test_parse_gateway_ports_yes() {
    let content = r#"
Host example.com
    GatewayPorts yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].gateway_ports, Some("yes".to_string()));
}

#[test]
fn test_parse_gateway_ports_no() {
    let content = r#"
Host example.com
    GatewayPorts no
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].gateway_ports, Some("no".to_string()));
}

#[test]
fn test_parse_gateway_ports_clientspecified() {
    let content = r#"
Host example.com
    GatewayPorts clientspecified
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].gateway_ports, Some("clientspecified".to_string()));
}

#[test]
fn test_parse_gateway_ports_case_insensitive() {
    // Should normalize to lowercase
    let content = r#"
Host example.com
    GatewayPorts ClientSpecified
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].gateway_ports, Some("clientspecified".to_string()));
}

#[test]
fn test_parse_gateway_ports_invalid() {
    let content = r#"
Host example.com
    GatewayPorts invalid
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // Error should mention GatewayPorts and the invalid value
    assert!(err_msg.contains("GatewayPorts") || err_msg.contains("gatewayports"));
    assert!(err_msg.contains("invalid"));
}

#[test]
fn test_parse_gateway_ports_with_equals() {
    let content = r#"
Host example.com
    GatewayPorts=yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].gateway_ports, Some("yes".to_string()));
}

#[test]
fn test_parse_exit_on_forward_failure() {
    let content = r#"
Host example.com
    ExitOnForwardFailure yes

Host other.com
    ExitOnForwardFailure no
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].exit_on_forward_failure, Some(true));
    assert_eq!(hosts[1].exit_on_forward_failure, Some(false));
}

#[test]
fn test_parse_exit_on_forward_failure_with_equals() {
    let content = r#"
Host example.com
    ExitOnForwardFailure=yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].exit_on_forward_failure, Some(true));
}

#[test]
fn test_parse_permit_remote_open_single() {
    let content = r#"
Host example.com
    PermitRemoteOpen localhost:8080
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].permit_remote_open.len(), 1);
    assert_eq!(hosts[0].permit_remote_open[0], "localhost:8080");
}

#[test]
fn test_parse_permit_remote_open_multiple() {
    let content = r#"
Host example.com
    PermitRemoteOpen localhost:8080 db.internal:5432 cache.internal:6379
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].permit_remote_open.len(), 3);
    assert_eq!(hosts[0].permit_remote_open[0], "localhost:8080");
    assert_eq!(hosts[0].permit_remote_open[1], "db.internal:5432");
    assert_eq!(hosts[0].permit_remote_open[2], "cache.internal:6379");
}

#[test]
fn test_parse_permit_remote_open_special_values() {
    // Test special values like 'any' and 'none'
    let content = r#"
Host example.com
    PermitRemoteOpen any

Host other.com
    PermitRemoteOpen none
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].permit_remote_open, vec!["any"]);
    assert_eq!(hosts[1].permit_remote_open, vec!["none"]);
}

#[test]
fn test_parse_permit_remote_open_multiple_declarations() {
    // Multiple PermitRemoteOpen lines should accumulate
    let content = r#"
Host example.com
    PermitRemoteOpen localhost:8080
    PermitRemoteOpen db.internal:5432
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].permit_remote_open.len(), 2);
    assert_eq!(hosts[0].permit_remote_open[0], "localhost:8080");
    assert_eq!(hosts[0].permit_remote_open[1], "db.internal:5432");
}

#[test]
fn test_parse_permit_remote_open_with_equals() {
    let content = r#"
Host example.com
    PermitRemoteOpen=localhost:8080
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].permit_remote_open, vec!["localhost:8080"]);
}

#[test]
fn test_parse_hostbased_authentication() {
    let content = r#"
Host example.com
    HostbasedAuthentication yes

Host other.com
    HostbasedAuthentication no
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].hostbased_authentication, Some(true));
    assert_eq!(hosts[1].hostbased_authentication, Some(false));
}

#[test]
fn test_parse_hostbased_authentication_with_equals() {
    let content = r#"
Host example.com
    HostbasedAuthentication=yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].hostbased_authentication, Some(true));
}

#[test]
fn test_parse_hostbased_accepted_algorithms() {
    let content = r#"
Host example.com
    HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].hostbased_accepted_algorithms.len(), 2);
    assert_eq!(hosts[0].hostbased_accepted_algorithms[0], "ssh-ed25519");
    assert_eq!(hosts[0].hostbased_accepted_algorithms[1], "rsa-sha2-512");
}

#[test]
fn test_parse_hostbased_accepted_algorithms_with_spaces() {
    // Test space-separated algorithms
    let content = r#"
Host example.com
    HostbasedAcceptedAlgorithms ssh-ed25519 rsa-sha2-512 ecdsa-sha2-nistp256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].hostbased_accepted_algorithms.len(), 3);
    assert_eq!(hosts[0].hostbased_accepted_algorithms[0], "ssh-ed25519");
    assert_eq!(hosts[0].hostbased_accepted_algorithms[1], "rsa-sha2-512");
    assert_eq!(
        hosts[0].hostbased_accepted_algorithms[2],
        "ecdsa-sha2-nistp256"
    );
}

#[test]
fn test_parse_hostbased_accepted_algorithms_with_equals() {
    let content = r#"
Host example.com
    HostbasedAcceptedAlgorithms=ssh-rsa,ssh-dss
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].hostbased_accepted_algorithms.len(), 2);
    assert_eq!(hosts[0].hostbased_accepted_algorithms[0], "ssh-rsa");
    assert_eq!(hosts[0].hostbased_accepted_algorithms[1], "ssh-dss");
}

#[test]
fn test_parse_all_new_options_combined() {
    // Test all new options together in a realistic scenario
    let content = r#"
Host secure.example.com
    CertificateFile ~/.ssh/id_rsa-cert.pub
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512
    GatewayPorts clientspecified
    ExitOnForwardFailure yes
    PermitRemoteOpen localhost:8080 db.internal:5432
    HostbasedAuthentication yes
    HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);

    // Verify all fields are parsed correctly
    assert_eq!(hosts[0].certificate_files.len(), 1);
    assert_eq!(hosts[0].ca_signature_algorithms.len(), 2);
    assert_eq!(hosts[0].gateway_ports, Some("clientspecified".to_string()));
    assert_eq!(hosts[0].exit_on_forward_failure, Some(true));
    assert_eq!(hosts[0].permit_remote_open.len(), 2);
    assert_eq!(hosts[0].hostbased_authentication, Some(true));
    assert_eq!(hosts[0].hostbased_accepted_algorithms.len(), 3);
}

#[test]
fn test_parse_new_options_with_mixed_syntax() {
    // Test mixing Option=Value and Option Value syntax
    let content = r#"
Host example.com
    CertificateFile=~/.ssh/id_rsa-cert.pub
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512
    GatewayPorts=yes
    ExitOnForwardFailure yes
    PermitRemoteOpen=localhost:8080
    HostbasedAuthentication=no
    HostbasedAcceptedAlgorithms ssh-ed25519
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);

    // Verify all fields are parsed correctly
    assert_eq!(hosts[0].certificate_files.len(), 1);
    assert_eq!(hosts[0].ca_signature_algorithms.len(), 2);
    assert_eq!(hosts[0].gateway_ports, Some("yes".to_string()));
    assert_eq!(hosts[0].exit_on_forward_failure, Some(true));
    assert_eq!(hosts[0].permit_remote_open, vec!["localhost:8080"]);
    assert_eq!(hosts[0].hostbased_authentication, Some(false));
    assert_eq!(hosts[0].hostbased_accepted_algorithms.len(), 1);
}

#[test]
fn test_parse_certificate_file_empty_value() {
    let content = r#"
Host example.com
    CertificateFile
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // Error message is wrapped with context, so check for both the line reference and the option name
    assert!(err_msg.contains("CertificateFile"));
    assert!(err_msg.contains("line 3"));
}

#[test]
fn test_parse_ca_signature_algorithms_empty_value() {
    let content = r#"
Host example.com
    CASignatureAlgorithms
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("CASignatureAlgorithms"));
    assert!(err_msg.contains("line 3"));
}

#[test]
fn test_parse_gateway_ports_empty_value() {
    let content = r#"
Host example.com
    GatewayPorts
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("GatewayPorts"));
    assert!(err_msg.contains("line 3"));
}

#[test]
fn test_parse_exit_on_forward_failure_empty_value() {
    let content = r#"
Host example.com
    ExitOnForwardFailure
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("ExitOnForwardFailure"));
    assert!(err_msg.contains("line 3"));
}

#[test]
fn test_parse_permit_remote_open_empty_value() {
    let content = r#"
Host example.com
    PermitRemoteOpen
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("PermitRemoteOpen"));
    assert!(err_msg.contains("line 3"));
}

#[test]
fn test_parse_hostbased_authentication_empty_value() {
    let content = r#"
Host example.com
    HostbasedAuthentication
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("HostbasedAuthentication"));
    assert!(err_msg.contains("line 3"));
}

#[test]
fn test_parse_hostbased_accepted_algorithms_empty_value() {
    let content = r#"
Host example.com
    HostbasedAcceptedAlgorithms
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("HostbasedAcceptedAlgorithms"));
    assert!(err_msg.contains("line 3"));
}

// Authentication and security management options tests

#[test]
fn test_parse_identities_only_yes() {
    let content = r#"
Host example.com
    IdentitiesOnly yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].identities_only, Some(true));
}

#[test]
fn test_parse_identities_only_no() {
    let content = r#"
Host example.com
    IdentitiesOnly no
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].identities_only, Some(false));
}

#[test]
fn test_parse_identities_only_with_equals() {
    let content = r#"
Host example.com
    IdentitiesOnly=yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].identities_only, Some(true));
}

#[test]
fn test_parse_identities_only_empty_value() {
    let content = r#"
Host example.com
    IdentitiesOnly
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("IdentitiesOnly"));
}

#[test]
fn test_parse_add_keys_to_agent_yes() {
    let content = r#"
Host example.com
    AddKeysToAgent yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].add_keys_to_agent, Some("yes".to_string()));
}

#[test]
fn test_parse_add_keys_to_agent_no() {
    let content = r#"
Host example.com
    AddKeysToAgent no
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].add_keys_to_agent, Some("no".to_string()));
}

#[test]
fn test_parse_add_keys_to_agent_ask() {
    let content = r#"
Host example.com
    AddKeysToAgent ask
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].add_keys_to_agent, Some("ask".to_string()));
}

#[test]
fn test_parse_add_keys_to_agent_confirm() {
    let content = r#"
Host example.com
    AddKeysToAgent confirm
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].add_keys_to_agent, Some("confirm".to_string()));
}

#[test]
fn test_parse_add_keys_to_agent_case_insensitive() {
    let content = r#"
Host example.com
    AddKeysToAgent YES
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].add_keys_to_agent, Some("yes".to_string()));
}

#[test]
fn test_parse_add_keys_to_agent_invalid() {
    let content = r#"
Host example.com
    AddKeysToAgent invalid
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("AddKeysToAgent"));
    assert!(err_msg.contains("invalid"));
}

#[test]
fn test_parse_add_keys_to_agent_with_equals() {
    let content = r#"
Host example.com
    AddKeysToAgent=confirm
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].add_keys_to_agent, Some("confirm".to_string()));
}

#[test]
fn test_parse_identity_agent_socket_path() {
    let content = r#"
Host example.com
    IdentityAgent ~/.1password/agent.sock
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(
        hosts[0].identity_agent,
        Some("~/.1password/agent.sock".to_string())
    );
}

#[test]
fn test_parse_identity_agent_none() {
    let content = r#"
Host example.com
    IdentityAgent none
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].identity_agent, Some("none".to_string()));
}

#[test]
fn test_parse_identity_agent_ssh_auth_sock() {
    let content = r#"
Host example.com
    IdentityAgent SSH_AUTH_SOCK
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].identity_agent, Some("SSH_AUTH_SOCK".to_string()));
}

#[test]
fn test_parse_identity_agent_with_equals() {
    let content = r#"
Host example.com
    IdentityAgent=/run/user/1000/keyring/ssh
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(
        hosts[0].identity_agent,
        Some("/run/user/1000/keyring/ssh".to_string())
    );
}

#[test]
fn test_parse_identity_agent_empty_value() {
    let content = r#"
Host example.com
    IdentityAgent
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("IdentityAgent"));
}

#[test]
fn test_parse_pubkey_accepted_algorithms() {
    let content = r#"
Host example.com
    PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].pubkey_accepted_algorithms.len(), 3);
    assert_eq!(hosts[0].pubkey_accepted_algorithms[0], "ssh-ed25519");
    assert_eq!(hosts[0].pubkey_accepted_algorithms[1], "rsa-sha2-512");
    assert_eq!(hosts[0].pubkey_accepted_algorithms[2], "rsa-sha2-256");
}

#[test]
fn test_parse_pubkey_accepted_algorithms_with_spaces() {
    let content = r#"
Host example.com
    PubkeyAcceptedAlgorithms ssh-ed25519 ecdsa-sha2-nistp256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].pubkey_accepted_algorithms.len(), 2);
    assert_eq!(hosts[0].pubkey_accepted_algorithms[0], "ssh-ed25519");
    assert_eq!(
        hosts[0].pubkey_accepted_algorithms[1],
        "ecdsa-sha2-nistp256"
    );
}

#[test]
fn test_parse_pubkey_accepted_algorithms_with_equals() {
    let content = r#"
Host example.com
    PubkeyAcceptedAlgorithms=ssh-ed25519,rsa-sha2-512
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].pubkey_accepted_algorithms.len(), 2);
    assert_eq!(hosts[0].pubkey_accepted_algorithms[0], "ssh-ed25519");
    assert_eq!(hosts[0].pubkey_accepted_algorithms[1], "rsa-sha2-512");
}

#[test]
fn test_parse_pubkey_accepted_algorithms_empty_value() {
    let content = r#"
Host example.com
    PubkeyAcceptedAlgorithms
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("PubkeyAcceptedAlgorithms"));
}

#[test]
fn test_parse_required_rsa_size() {
    let content = r#"
Host example.com
    RequiredRSASize 2048
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].required_rsa_size, Some(2048));
}

#[test]
fn test_parse_required_rsa_size_4096() {
    let content = r#"
Host example.com
    RequiredRSASize 4096
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].required_rsa_size, Some(4096));
}

#[test]
fn test_parse_required_rsa_size_minimum() {
    let content = r#"
Host example.com
    RequiredRSASize 1024
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].required_rsa_size, Some(1024));
}

#[test]
fn test_parse_required_rsa_size_maximum() {
    let content = r#"
Host example.com
    RequiredRSASize 16384
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].required_rsa_size, Some(16384));
}

#[test]
fn test_parse_required_rsa_size_below_minimum() {
    let content = r#"
Host example.com
    RequiredRSASize 512
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("RequiredRSASize"));
    assert!(err_msg.contains("512"));
}

#[test]
fn test_parse_required_rsa_size_above_maximum() {
    let content = r#"
Host example.com
    RequiredRSASize 32768
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("RequiredRSASize"));
    assert!(err_msg.contains("32768"));
}

#[test]
fn test_parse_required_rsa_size_invalid() {
    let content = r#"
Host example.com
    RequiredRSASize invalid
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("RequiredRSASize"));
    assert!(err_msg.contains("invalid"));
}

#[test]
fn test_parse_required_rsa_size_with_equals() {
    let content = r#"
Host example.com
    RequiredRSASize=3072
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].required_rsa_size, Some(3072));
}

#[test]
fn test_parse_required_rsa_size_empty_value() {
    let content = r#"
Host example.com
    RequiredRSASize
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("RequiredRSASize"));
}

#[test]
fn test_parse_fingerprint_hash_sha256() {
    let content = r#"
Host example.com
    FingerprintHash sha256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].fingerprint_hash, Some("sha256".to_string()));
}

#[test]
fn test_parse_fingerprint_hash_md5() {
    let content = r#"
Host example.com
    FingerprintHash md5
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].fingerprint_hash, Some("md5".to_string()));
}

#[test]
fn test_parse_fingerprint_hash_case_insensitive() {
    let content = r#"
Host example.com
    FingerprintHash SHA256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].fingerprint_hash, Some("sha256".to_string()));
}

#[test]
fn test_parse_fingerprint_hash_invalid() {
    let content = r#"
Host example.com
    FingerprintHash sha1
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("FingerprintHash"));
    assert!(err_msg.contains("sha1"));
}

#[test]
fn test_parse_fingerprint_hash_with_equals() {
    let content = r#"
Host example.com
    FingerprintHash=md5
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].fingerprint_hash, Some("md5".to_string()));
}

#[test]
fn test_parse_fingerprint_hash_empty_value() {
    let content = r#"
Host example.com
    FingerprintHash
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("FingerprintHash"));
}

#[test]
fn test_parse_auth_security_combined() {
    // Test all authentication and security management options together
    let content = r#"
Host secure-server
    IdentitiesOnly yes
    AddKeysToAgent confirm
    IdentityAgent ~/.1password/agent.sock
    PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512
    RequiredRSASize 2048
    FingerprintHash sha256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].identities_only, Some(true));
    assert_eq!(hosts[0].add_keys_to_agent, Some("confirm".to_string()));
    assert_eq!(
        hosts[0].identity_agent,
        Some("~/.1password/agent.sock".to_string())
    );
    assert_eq!(hosts[0].pubkey_accepted_algorithms.len(), 2);
    assert_eq!(hosts[0].required_rsa_size, Some(2048));
    assert_eq!(hosts[0].fingerprint_hash, Some("sha256".to_string()));
}

// Security tests for authentication and security management options
#[test]
fn test_parse_identity_agent_path_traversal_attack() {
    // Test that path traversal attempts are rejected
    let content = r#"
Host example.com
    IdentityAgent ../../../etc/passwd
"#;
    let result = parse(content);
    assert!(result.is_err());
    let error = result.unwrap_err();
    // Check both the main error and any causes in the error chain
    let full_error = format!("{:#}", error);
    assert!(
        full_error.contains("Security violation") || full_error.contains("directory traversal"),
        "Expected security error, got: {}",
        full_error
    );
}

#[test]
fn test_parse_identity_agent_null_byte_injection() {
    // Test that null bytes are rejected
    let content = "Host example.com\n    IdentityAgent /tmp/agent\0.sock\n";
    let result = parse(content);
    assert!(result.is_err());
    let error = result.unwrap_err();
    let full_error = format!("{:#}", error);
    assert!(
        full_error.contains("Security violation") || full_error.contains("null byte"),
        "Expected security error for null byte, got: {}",
        full_error
    );
}

#[test]
fn test_parse_pubkey_accepted_algorithms_injection() {
    // Test that algorithm names with dangerous characters are rejected
    let content = r#"
Host example.com
    PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512;rm -rf /
"#;
    let result = parse(content);
    assert!(result.is_err());
    let error = result.unwrap_err();
    let full_error = format!("{:#}", error);
    assert!(
        full_error.contains("invalid characters"),
        "Expected invalid characters error, got: {}",
        full_error
    );
}

#[test]
fn test_parse_pubkey_accepted_algorithms_memory_exhaustion() {
    // Test that excessive algorithms are truncated
    let mut algorithms = Vec::new();
    for i in 0..100 {
        algorithms.push(format!("algo-{}", i));
    }
    let content = format!(
        "Host example.com\n    PubkeyAcceptedAlgorithms {}\n",
        algorithms.join(",")
    );
    let hosts = parse(&content).unwrap();
    assert_eq!(hosts.len(), 1);
    // Should be truncated to MAX_ALGORITHMS (50)
    assert_eq!(hosts[0].pubkey_accepted_algorithms.len(), 50);
}

#[test]
fn test_parse_algorithm_name_length_limit() {
    // Test that excessively long algorithm names are skipped
    let long_name = "a".repeat(300);
    let content = format!(
        "Host example.com\n    PubkeyAcceptedAlgorithms ssh-ed25519,{},rsa-sha2-256\n",
        long_name
    );
    let hosts = parse(&content).unwrap();
    assert_eq!(hosts.len(), 1);
    // Long algorithm should be skipped
    assert_eq!(hosts[0].pubkey_accepted_algorithms.len(), 2);
    assert_eq!(hosts[0].pubkey_accepted_algorithms[0], "ssh-ed25519");
    assert_eq!(hosts[0].pubkey_accepted_algorithms[1], "rsa-sha2-256");
}

#[test]
fn test_parse_empty_algorithms_after_filtering() {
    // Test that we reject configs with no valid algorithms after filtering
    let content = r#"
Host example.com
    PubkeyAcceptedAlgorithms ,,,,
"#;
    let result = parse(content);
    assert!(result.is_err());
    let error = result.unwrap_err();
    let full_error = format!("{:#}", error);
    assert!(
        full_error.contains("must contain at least one valid algorithm"),
        "Expected empty algorithm list error, got: {}",
        full_error
    );
}

#[test]
fn test_parse_hostbased_accepted_algorithms_injection() {
    // Test that hostbased algorithms also validate characters
    let content = r#"
Host example.com
    HostbasedAcceptedAlgorithms ssh-ed25519,$(whoami),rsa-sha2-256
"#;
    let result = parse(content);
    assert!(result.is_err());
    let error = result.unwrap_err();
    let full_error = format!("{:#}", error);
    assert!(
        full_error.contains("invalid characters"),
        "Expected invalid characters error, got: {}",
        full_error
    );
}

#[test]
fn test_parse_ca_signature_algorithms_memory_limit() {
    // Test CASignatureAlgorithms memory limits
    let mut algorithms = Vec::new();
    for i in 0..60 {
        algorithms.push(format!("ca-algo-{}", i));
    }
    let content = format!(
        "Host example.com\n    CASignatureAlgorithms {}\n",
        algorithms.join(",")
    );
    let hosts = parse(&content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ca_signature_algorithms.len(), 50);
}

#[test]
fn test_parse_auth_security_with_match_block() {
    use crate::ssh::ssh_config::types::ConfigBlock;

    let content = r#"
Match host *.secure.com
    IdentitiesOnly yes
    RequiredRSASize 4096
    FingerprintHash sha256
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);

    match &hosts[0].block_type {
        Some(ConfigBlock::Match(_)) => {
            assert_eq!(hosts[0].identities_only, Some(true));
            assert_eq!(hosts[0].required_rsa_size, Some(4096));
            assert_eq!(hosts[0].fingerprint_hash, Some("sha256".to_string()));
        }
        _ => panic!("Expected Match block"),
    }
}

// Tests for ProxyUseFdpass option (Issue #58)
#[test]
fn test_parse_proxy_use_fdpass_yes() {
    let content = r#"
Host proxy.example.com
    ProxyCommand ssh -W %h:%p bastion.example.com
    ProxyUseFdpass yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].proxy_use_fdpass, Some(true));
}

#[test]
fn test_parse_proxy_use_fdpass_no() {
    let content = r#"
Host proxy.example.com
    ProxyCommand ssh -W %h:%p bastion.example.com
    ProxyUseFdpass no
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].proxy_use_fdpass, Some(false));
}

#[test]
fn test_parse_proxy_use_fdpass_case_insensitive() {
    let content = r#"
Host proxy1.example.com
    PROXYUSEFDPASS yes

Host proxy2.example.com
    ProxyUseFdpass YES

Host proxy3.example.com
    proxyusefdpass No
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 3);
    assert_eq!(hosts[0].proxy_use_fdpass, Some(true));
    assert_eq!(hosts[1].proxy_use_fdpass, Some(true));
    assert_eq!(hosts[2].proxy_use_fdpass, Some(false));
}

#[test]
fn test_parse_proxy_use_fdpass_with_proxy_jump() {
    let content = r#"
Host target.example.com
    ProxyJump bastion.example.com
    ProxyUseFdpass yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].proxy_jump, Some("bastion.example.com".to_string()));
    assert_eq!(hosts[0].proxy_use_fdpass, Some(true));
}

#[test]
fn test_parse_proxy_use_fdpass_with_proxy_command() {
    let content = r#"
Host target.example.com
    ProxyCommand ssh -W %h:%p bastion.example.com
    ProxyUseFdpass yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(
        hosts[0].proxy_command,
        Some("ssh -W %h:%p bastion.example.com".to_string())
    );
    assert_eq!(hosts[0].proxy_use_fdpass, Some(true));
}

#[test]
fn test_parse_proxy_use_fdpass_invalid_value() {
    let content = r#"
Host proxy.example.com
    ProxyUseFdpass invalid
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // The error message includes the line context and the parse_yes_no error
    assert!(err_msg.contains("ProxyUseFdpass"));
    assert!(err_msg.contains("yes/no") || err_msg.contains("invalid"));
}

#[test]
fn test_parse_proxy_use_fdpass_missing_value() {
    let content = r#"
Host proxy.example.com
    ProxyUseFdpass
"#;
    let result = parse(content);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // When a value is missing, the parser generates an error
    // The error message includes the line number and keyword
    assert!(err_msg.contains("line 3"));
    assert!(err_msg.contains("ProxyUseFdpass"));
}

#[test]
fn test_parse_proxy_use_fdpass_true_alternatives() {
    let content = r#"
Host proxy1.example.com
    ProxyUseFdpass true

Host proxy2.example.com
    ProxyUseFdpass 1
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].proxy_use_fdpass, Some(true));
    assert_eq!(hosts[1].proxy_use_fdpass, Some(true));
}

#[test]
fn test_parse_proxy_use_fdpass_false_alternatives() {
    let content = r#"
Host proxy1.example.com
    ProxyUseFdpass false

Host proxy2.example.com
    ProxyUseFdpass 0
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].proxy_use_fdpass, Some(false));
    assert_eq!(hosts[1].proxy_use_fdpass, Some(false));
}

#[test]
fn test_parse_proxy_use_fdpass_with_match_block() {
    use crate::ssh::ssh_config::types::ConfigBlock;

    let content = r#"
Match host *.prod.example.com exec "test -f /tmp/use_proxy"
    ProxyCommand ssh -W %h:%p bastion.prod.example.com
    ProxyUseFdpass yes
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);

    match &hosts[0].block_type {
        Some(ConfigBlock::Match(_)) => {
            assert_eq!(
                hosts[0].proxy_command,
                Some("ssh -W %h:%p bastion.prod.example.com".to_string())
            );
            assert_eq!(hosts[0].proxy_use_fdpass, Some(true));
        }
        _ => panic!("Expected Match block"),
    }
}

#[test]
fn test_parse_proxy_use_fdpass_default_none() {
    let content = r#"
Host proxy.example.com
    ProxyCommand ssh -W %h:%p bastion.example.com
"#;
    let hosts = parse(content).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].proxy_use_fdpass, None);
}

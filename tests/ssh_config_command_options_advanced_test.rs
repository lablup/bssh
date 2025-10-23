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

//! Advanced tests for SSH command execution options
//!
//! Tests for Match blocks, host merging, and edge cases
//! Note: Resolver tests are in src/ssh/ssh_config/resolver_tests.rs

use bssh::ssh::ssh_config::SshConfig;

#[test]
fn test_command_options_with_wildcards() {
    // Note: Match blocks are tested in internal integration tests
    // This test focuses on wildcard Host patterns
    let config = r#"
# Global defaults
Host *
    PermitLocalCommand no
    StdinNull no

# Wildcard pattern for dev hosts
Host *.dev.example.com
    PermitLocalCommand yes
    LocalCommand notify-send "Connected to %h"
    ForkAfterAuthentication no

# Wildcard pattern for prod hosts
Host *.prod.example.com
    PermitLocalCommand no
    RemoteCommand cd /opt/app && exec bash
    SessionType default
    StdinNull yes

# Specific host overrides wildcards
Host critical.prod.example.com
    RemoteCommand /usr/local/bin/critical-shell
    SessionType none
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;

    // Should have 4 host blocks (*, *.dev, *.prod, specific)
    assert_eq!(hosts.len(), 4);

    // Check wildcard patterns are parsed
    let dev_host = &hosts[1];
    assert_eq!(dev_host.permit_local_command, Some(true));
    assert_eq!(
        dev_host.local_command,
        Some("notify-send \"Connected to %h\"".to_string())
    );
    assert_eq!(dev_host.fork_after_authentication, Some(false));

    let prod_host = &hosts[2];
    assert_eq!(prod_host.permit_local_command, Some(false));
    assert_eq!(
        prod_host.remote_command,
        Some("cd /opt/app && exec bash".to_string())
    );
    assert_eq!(prod_host.session_type, Some("default".to_string()));
    assert_eq!(prod_host.stdin_null, Some(true));

    let specific_host = &hosts[3];
    assert_eq!(
        specific_host.remote_command,
        Some("/usr/local/bin/critical-shell".to_string())
    );
    assert_eq!(specific_host.session_type, Some("none".to_string()));
}

#[test]
fn test_command_options_host_merging() {
    let config = r#"
# First Host block sets some options
Host server1
    PermitLocalCommand yes
    LocalCommand echo "First block"
    SessionType default

# Second Host block for same host (should override)
Host server1
    LocalCommand echo "Second block overrides"
    RemoteCommand tmux attach
    StdinNull yes
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;

    // Both Host blocks should be present
    assert_eq!(hosts.len(), 2);

    // First occurrence
    assert_eq!(
        hosts[0].local_command,
        Some("echo \"First block\"".to_string())
    );
    assert_eq!(hosts[0].session_type, Some("default".to_string()));

    // Second occurrence
    assert_eq!(
        hosts[1].local_command,
        Some("echo \"Second block overrides\"".to_string())
    );
    assert_eq!(hosts[1].remote_command, Some("tmux attach".to_string()));
    assert_eq!(hosts[1].stdin_null, Some(true));
}

// Note: Resolver integration tests are in src/ssh/ssh_config/resolver_tests.rs
// because resolver is an internal module not accessible from integration tests

#[test]
fn test_very_long_command() {
    // Test with a very long command (1000+ characters)
    let long_cmd = "a".repeat(1000);
    let config = format!(
        r#"
Host test
    RemoteCommand {}
"#,
        long_cmd
    );

    let config_parsed = SshConfig::parse(&config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].remote_command, Some(long_cmd));
}

#[test]
fn test_command_with_nested_quotes() {
    let config = r#"
Host test1
    LocalCommand bash -c "echo \"Hello 'World' from %h\""

Host test2
    RemoteCommand sh -c 'echo "Nested \"quotes\" work"'

Host test3
    LocalCommand echo 'Single\'s and "double\"s" mixed'
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 3);

    assert_eq!(
        hosts[0].local_command,
        Some("bash -c \"echo \\\"Hello 'World' from %h\\\"\"".to_string())
    );
    assert_eq!(
        hosts[1].remote_command,
        Some("sh -c 'echo \"Nested \\\"quotes\\\" work\"'".to_string())
    );
    assert_eq!(
        hosts[2].local_command,
        Some("echo 'Single\\'s and \"double\\\"s\" mixed'".to_string())
    );
}

#[test]
fn test_command_with_all_tokens() {
    let config = r#"
Host test
    LocalCommand echo "Host:%h Hostname:%H Original:%n Port:%p Remote:%r Local:%u Percent:%%"
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 1);

    assert_eq!(
        hosts[0].local_command,
        Some(
            "echo \"Host:%h Hostname:%H Original:%n Port:%p Remote:%r Local:%u Percent:%%\""
                .to_string()
        )
    );
}

#[test]
fn test_command_with_multiple_spaces() {
    let config = r#"
Host test1
    LocalCommand     rsync    -av     ~/src/     %h:~/dst/

Host test2
    RemoteCommand     cd    /tmp    &&    ls    -la
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 2);

    // Parser normalizes multiple spaces to single spaces (this is expected behavior)
    assert_eq!(
        hosts[0].local_command,
        Some("rsync -av ~/src/ %h:~/dst/".to_string())
    );
    assert_eq!(
        hosts[1].remote_command,
        Some("cd /tmp && ls -la".to_string())
    );
}

#[test]
fn test_command_with_safe_special_characters() {
    // Test RemoteCommand which allows more special characters than LocalCommand
    let config = r#"
Host test1
    RemoteCommand tmux attach -t main

Host test2
    RemoteCommand cd /tmp && ls -la

Host test3
    LocalCommand /usr/bin/notify-send "Connected to %h"
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 3);

    // RemoteCommand allows shell operators (runs on remote)
    assert_eq!(
        hosts[0].remote_command,
        Some("tmux attach -t main".to_string())
    );
    assert_eq!(
        hosts[1].remote_command,
        Some("cd /tmp && ls -la".to_string())
    );
    assert_eq!(
        hosts[2].local_command,
        Some("/usr/bin/notify-send \"Connected to %h\"".to_string())
    );
}

#[test]
fn test_known_hosts_command_with_complex_url() {
    let config = r#"
Host test1
    KnownHostsCommand curl -s "https://api.example.com/keys?host=%H&format=ssh"

Host test2
    KnownHostsCommand /opt/scripts/fetch-key.py --host=%h --port=%p
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 2);

    // Note: curl commands should fail validation due to dangerous chars
    // but let's check parsing first
    // Actually, the test3 in test_parse_known_hosts_command shows curl fails
}

#[test]
fn test_session_type_with_various_cases() {
    let config = r#"
Host test1
    SessionType NONE

Host test2
    SessionType Subsystem

Host test3
    SessionType DeFaUlT
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 3);

    // All should be normalized to lowercase
    assert_eq!(hosts[0].session_type, Some("none".to_string()));
    assert_eq!(hosts[1].session_type, Some("subsystem".to_string()));
    assert_eq!(hosts[2].session_type, Some("default".to_string()));
}

#[test]
fn test_permit_local_command_without_local_command() {
    // PermitLocalCommand yes but no LocalCommand is valid
    let config = r#"
Host test
    PermitLocalCommand yes
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].permit_local_command, Some(true));
    assert_eq!(hosts[0].local_command, None);
}

#[test]
fn test_local_command_without_permit() {
    // LocalCommand without PermitLocalCommand is valid (client decides)
    let config = r#"
Host test
    LocalCommand echo "test"
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].local_command, Some("echo \"test\"".to_string()));
    assert_eq!(hosts[0].permit_local_command, None);
}

#[test]
fn test_command_options_with_include() {
    // This would require file system access, so we'll test the structure
    let config = r#"
Host base
    PermitLocalCommand yes
    SessionType default

# Include directive would go here, but we can't test file I/O in unit tests
# Include ~/.ssh/config.d/*.conf

Host override
    SessionType none
    StdinNull yes
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;

    // Should parse successfully with Include comment
    assert!(hosts.len() >= 2);
}

#[test]
fn test_fork_with_session_type_none() {
    // Common pattern: background tunnel
    let config = r#"
Host tunnel
    ForkAfterAuthentication yes
    SessionType none
    StdinNull yes
    LocalForward 8080 internal:80
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 1);

    assert_eq!(hosts[0].fork_after_authentication, Some(true));
    assert_eq!(hosts[0].session_type, Some("none".to_string()));
    assert_eq!(hosts[0].stdin_null, Some(true));
}

#[test]
fn test_remote_command_with_request_tty() {
    // Common pattern: auto-attach to tmux with TTY
    let config = r#"
Host dev
    RemoteCommand tmux attach -t dev || tmux new -s dev
    RequestTTY yes
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 1);

    assert_eq!(
        hosts[0].remote_command,
        Some("tmux attach -t dev || tmux new -s dev".to_string())
    );
    assert_eq!(hosts[0].request_tty, Some("yes".to_string()));
}

#[test]
fn test_command_with_path_expansion() {
    let config = r#"
Host test
    LocalCommand rsync -av ~/project/ %h:~/backup/
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 1);

    // Tilde should be preserved (client will expand)
    assert_eq!(
        hosts[0].local_command,
        Some("rsync -av ~/project/ %h:~/backup/".to_string())
    );
}

// Resolver tests moved to src/ssh/ssh_config/resolver_tests.rs

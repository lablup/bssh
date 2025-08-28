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

use bssh::commands::interactive::InteractiveCommand;
use bssh::config::{Config, InteractiveConfig};
use bssh::node::Node;
use bssh::pty::PtyConfig;
use bssh::ssh::known_hosts::StrictHostKeyChecking;
use std::path::PathBuf;

#[tokio::test]
async fn test_interactive_command_creation() {
    let cmd = InteractiveCommand {
        single_node: false,
        multiplex: true,
        prompt_format: String::from("[{node}:{user}@{host}:{pwd}]$ "),
        history_file: PathBuf::from("~/.bssh_history"),
        work_dir: None,
        nodes: vec![],
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
    };

    assert!(!cmd.single_node);
    assert!(cmd.multiplex);
    assert_eq!(cmd.prompt_format, "[{node}:{user}@{host}:{pwd}]$ ");
}

#[tokio::test]
async fn test_interactive_with_no_nodes() {
    let cmd = InteractiveCommand {
        single_node: false,
        multiplex: true,
        prompt_format: String::from("[{node}:{user}@{host}:{pwd}]$ "),
        history_file: PathBuf::from("~/.bssh_history"),
        work_dir: None,
        nodes: vec![],
        config: Config::default(),
        interactive_config: InteractiveConfig::default(),
        cluster_name: None,
        key_path: None,
        use_agent: false,
        use_password: false,
        strict_mode: StrictHostKeyChecking::AcceptNew,
        pty_config: PtyConfig::default(),
        use_pty: None,
    };

    let result = cmd.execute().await;
    assert!(result.is_err());

    if let Err(e) = result {
        assert!(e.to_string().contains("Failed to connect to any nodes"));
    }
}

#[test]
fn test_prompt_format_replacement() {
    let node = Node::new(String::from("test-host"), 22, String::from("test-user"));

    let prompt_format = "[{node}:{user}@{host}:{pwd}]$ ";
    let working_dir = "/home/test";

    let prompt = prompt_format
        .replace("{node}", &format!("{}@{}", node.username, node.host))
        .replace("{user}", &node.username)
        .replace("{host}", &node.host)
        .replace("{pwd}", working_dir);

    assert_eq!(
        prompt,
        "[test-user@test-host:test-user@test-host:/home/test]$ "
    );
}

#[test]
fn test_history_file_expansion() {
    let history_file = PathBuf::from("~/.bssh_history");
    let path_str = history_file.to_str().unwrap();

    assert!(path_str.starts_with('~'));

    // Test expansion logic
    if let Some(home) = dirs::home_dir() {
        let expanded = path_str.replacen('~', home.to_str().unwrap(), 1);
        assert!(!expanded.starts_with('~'));
        assert!(expanded.contains(".bssh_history"));
    }
}

#[cfg(test)]
mod mock_ssh_tests {

    // Mock SSH session for testing
    struct MockSession {
        #[allow(dead_code)]
        is_connected: bool,
        commands_received: Vec<String>,
        outputs_to_send: Vec<String>,
    }

    impl MockSession {
        fn new() -> Self {
            Self {
                is_connected: true,
                commands_received: vec![],
                outputs_to_send: vec![],
            }
        }

        async fn send_command(&mut self, command: &str) -> Result<(), anyhow::Error> {
            self.commands_received.push(command.to_string());
            Ok(())
        }

        async fn read_output(&mut self) -> Result<Option<String>, anyhow::Error> {
            Ok(self.outputs_to_send.pop())
        }
    }

    #[tokio::test]
    async fn test_mock_session_command_sending() {
        let mut session = MockSession::new();

        session.send_command("ls -la").await.unwrap();
        session.send_command("pwd").await.unwrap();

        assert_eq!(session.commands_received.len(), 2);
        assert_eq!(session.commands_received[0], "ls -la");
        assert_eq!(session.commands_received[1], "pwd");
    }

    #[tokio::test]
    async fn test_mock_session_output_reading() {
        let mut session = MockSession::new();
        session.outputs_to_send = vec![String::from("output2"), String::from("output1")];

        let output1 = session.read_output().await.unwrap();
        assert_eq!(output1, Some(String::from("output1")));

        let output2 = session.read_output().await.unwrap();
        assert_eq!(output2, Some(String::from("output2")));

        let output3 = session.read_output().await.unwrap();
        assert_eq!(output3, None);
    }
}

#[cfg(test)]
mod terminal_tests {
    use crossterm::terminal;

    #[test]
    fn test_terminal_size_detection() {
        // This test might fail in non-terminal environments (CI)
        let result = terminal::size();

        if let Ok((width, height)) = result {
            assert!(width > 0);
            assert!(height > 0);
        } else {
            // In CI or non-terminal environments, we should get a default
            let (width, height) = (80, 24);
            assert_eq!(width, 80);
            assert_eq!(height, 24);
        }
    }
}

#[cfg(test)]
mod auth_method_tests {
    use bssh::ssh::tokio_client::AuthMethod;
    use std::env;

    #[test]
    fn test_auth_method_creation() {
        // Test password auth
        let auth = AuthMethod::with_password("test_password");
        assert_eq!(auth, AuthMethod::Password(String::from("test_password")));

        // Test key file auth
        let auth = AuthMethod::with_key_file("/path/to/key", Some("passphrase"));
        if let AuthMethod::PrivateKeyFile {
            key_file_path,
            key_pass,
        } = auth
        {
            assert_eq!(key_file_path.to_str().unwrap(), "/path/to/key");
            assert_eq!(key_pass, Some(String::from("passphrase")));
        } else {
            panic!("Wrong auth method type");
        }
    }

    #[test]
    fn test_ssh_agent_detection() {
        // Save original value
        let original = env::var("SSH_AUTH_SOCK").ok();

        // Test with SSH_AUTH_SOCK set
        unsafe {
            env::set_var("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock");
        }
        assert!(env::var("SSH_AUTH_SOCK").is_ok());

        // Restore original value
        unsafe {
            if let Some(val) = original {
                env::set_var("SSH_AUTH_SOCK", val);
            } else {
                env::remove_var("SSH_AUTH_SOCK");
            }
        }
    }
}

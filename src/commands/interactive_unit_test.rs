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

#[cfg(test)]
mod tests {
    use super::super::*;
    use std::path::PathBuf;

    #[test]
    fn test_expand_path_with_tilde() {
        let cmd = InteractiveCommand {
            single_node: false,
            multiplex: true,
            prompt_format: String::from(""),
            history_file: PathBuf::from("~/.bssh_history"),
            work_dir: None,
            nodes: vec![],
            config: Config::default(),
        };

        let path = PathBuf::from("~/test/file.txt");
        let expanded = cmd.expand_path(&path).unwrap();
        
        // Should expand tilde to home directory
        if let Some(home) = dirs::home_dir() {
            assert!(expanded.starts_with(&home));
            assert!(expanded.to_str().unwrap().ends_with("test/file.txt"));
        }
    }

    #[test]
    fn test_expand_path_without_tilde() {
        let cmd = InteractiveCommand {
            single_node: false,
            multiplex: true,
            prompt_format: String::from(""),
            history_file: PathBuf::from("/tmp/history"),
            work_dir: None,
            nodes: vec![],
            config: Config::default(),
        };

        let path = PathBuf::from("/absolute/path/file.txt");
        let expanded = cmd.expand_path(&path).unwrap();
        
        // Should not change absolute paths
        assert_eq!(expanded, path);
    }

    #[test]
    fn test_format_prompt() {
        let cmd = InteractiveCommand {
            single_node: false,
            multiplex: true,
            prompt_format: String::from("[{node}:{user}@{host}:{pwd}]$ "),
            history_file: PathBuf::from("~/.bssh_history"),
            work_dir: None,
            nodes: vec![],
            config: Config::default(),
        };

        let node = Node::new(
            String::from("example.com"),
            22,
            String::from("alice"),
        );
        
        let prompt = cmd.format_prompt(&node, "/home/alice");
        assert_eq!(prompt, "[alice@example.com:alice@example.com:/home/alice]$ ");
    }

    #[test]
    fn test_format_prompt_with_custom_format() {
        let cmd = InteractiveCommand {
            single_node: false,
            multiplex: true,
            prompt_format: String::from("{user}@{host} [{pwd}]> "),
            history_file: PathBuf::from("~/.bssh_history"),
            work_dir: None,
            nodes: vec![],
            config: Config::default(),
        };

        let node = Node::new(
            String::from("server.local"),
            22,
            String::from("bob"),
        );
        
        let prompt = cmd.format_prompt(&node, "/var/log");
        assert_eq!(prompt, "bob@server.local [/var/log]> ");
    }

    #[test]
    fn test_determine_auth_method_with_ssh_agent() {
        // This test depends on environment, so we mock it
        let cmd = InteractiveCommand {
            single_node: false,
            multiplex: true,
            prompt_format: String::from(""),
            history_file: PathBuf::from("~/.bssh_history"),
            work_dir: None,
            nodes: vec![],
            config: Config::default(),
        };

        let node = Node::new(
            String::from("test.com"),
            22,
            String::from("user"),
        );

        // Save original
        let original = std::env::var("SSH_AUTH_SOCK").ok();
        
        // Set SSH_AUTH_SOCK
        std::env::set_var("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock");
        
        let auth_method = cmd.determine_auth_method(&node);
        
        // Restore original
        if let Some(val) = original {
            std::env::set_var("SSH_AUTH_SOCK", val);
        } else {
            std::env::remove_var("SSH_AUTH_SOCK");
        }
        
        // Should choose Agent when SSH_AUTH_SOCK is set
        if let Ok(AuthMethod::Agent) = auth_method {
            // Success
        } else {
            panic!("Expected Agent auth method when SSH_AUTH_SOCK is set");
        }
    }

    #[test]
    fn test_single_node_vs_multiplex_mode() {
        let single_node_cmd = InteractiveCommand {
            single_node: true,
            multiplex: false,
            prompt_format: String::from(""),
            history_file: PathBuf::from("~/.bssh_history"),
            work_dir: None,
            nodes: vec![
                Node::new(String::from("node1"), 22, String::from("user")),
                Node::new(String::from("node2"), 22, String::from("user")),
            ],
            config: Config::default(),
        };

        assert!(single_node_cmd.single_node);
        assert!(!single_node_cmd.multiplex);

        let multiplex_cmd = InteractiveCommand {
            single_node: false,
            multiplex: true,
            prompt_format: String::from(""),
            history_file: PathBuf::from("~/.bssh_history"),
            work_dir: None,
            nodes: vec![
                Node::new(String::from("node1"), 22, String::from("user")),
                Node::new(String::from("node2"), 22, String::from("user")),
            ],
            config: Config::default(),
        };

        assert!(!multiplex_cmd.single_node);
        assert!(multiplex_cmd.multiplex);
    }
}
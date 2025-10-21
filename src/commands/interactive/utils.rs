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

//! Utility functions for interactive mode

use anyhow::Result;
use std::path::PathBuf;

use crate::node::Node;
use crate::pty::should_allocate_pty;

use super::types::InteractiveCommand;

impl InteractiveCommand {
    /// Determine whether to use PTY mode based on configuration
    pub(super) fn should_use_pty(&self) -> Result<bool> {
        match self.use_pty {
            Some(true) => Ok(true),   // Force PTY
            Some(false) => Ok(false), // Disable PTY
            None => {
                // Auto-detect based on terminal and config
                let mut pty_config = self.pty_config.clone();
                pty_config.force_pty = self.use_pty == Some(true);
                pty_config.disable_pty = self.use_pty == Some(false);
                should_allocate_pty(&pty_config)
            }
        }
    }

    /// Format the prompt string with node and directory information
    pub(super) fn format_prompt(&self, node: &Node, working_dir: &str) -> String {
        self.prompt_format
            .replace("{node}", &format!("{}@{}", node.username, node.host))
            .replace("{user}", &node.username)
            .replace("{host}", &node.host)
            .replace("{pwd}", working_dir)
    }

    /// Expand ~ in path to home directory
    pub(super) fn expand_path(&self, path: &std::path::Path) -> Result<PathBuf> {
        if let Some(path_str) = path.to_str() {
            if path_str.starts_with('~') {
                if let Some(home) = dirs::home_dir() {
                    // Handle ~ alone or ~/path
                    if path_str == "~" {
                        return Ok(home);
                    } else if let Some(rest) = path_str.strip_prefix("~/") {
                        return Ok(home.join(rest));
                    }
                }
            }
        }
        Ok(path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, InteractiveConfig};
    use crate::pty::PtyConfig;
    use crate::ssh::known_hosts::StrictHostKeyChecking;

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
            interactive_config: InteractiveConfig::default(),
            cluster_name: None,
            key_path: None,
            use_agent: false,
            use_password: false,
            strict_mode: StrictHostKeyChecking::AcceptNew,
            jump_hosts: None,
            pty_config: PtyConfig::default(),
            use_pty: None,
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
    fn test_format_prompt() {
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
            jump_hosts: None,
            pty_config: PtyConfig::default(),
            use_pty: None,
        };

        let node = Node::new(String::from("example.com"), 22, String::from("alice"));

        let prompt = cmd.format_prompt(&node, "/home/alice");
        assert_eq!(
            prompt,
            "[alice@example.com:alice@example.com:/home/alice]$ "
        );
    }
}

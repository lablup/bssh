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

use anyhow::{Context, Result};
use crossterm::terminal::{self};
use owo_colors::OwoColorize;
use russh::Channel;
use russh::client::Msg;
use rustyline::DefaultEditor;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use crate::config::Config;
use crate::node::Node;
use crate::ssh::{
    known_hosts::{StrictHostKeyChecking, get_check_method},
    tokio_client::{AuthMethod, Client},
};

/// Interactive mode command configuration
pub struct InteractiveCommand {
    pub single_node: bool,
    pub multiplex: bool,
    pub prompt_format: String,
    pub history_file: PathBuf,
    pub work_dir: Option<String>,
    pub nodes: Vec<Node>,
    pub config: Config,
}

/// Result of an interactive session
#[derive(Debug)]
pub struct InteractiveResult {
    pub duration: Duration,
    pub commands_executed: usize,
    pub nodes_connected: usize,
}

/// Represents the state of a connected node in interactive mode
struct NodeSession {
    node: Node,
    #[allow(dead_code)]
    client: Client,
    channel: Channel<Msg>,
    working_dir: String,
    is_connected: bool,
}

impl NodeSession {
    /// Send a command to this node's shell
    async fn send_command(&mut self, command: &str) -> Result<()> {
        let data = format!("{command}\n");
        self.channel.data(data.as_bytes()).await?;
        Ok(())
    }

    /// Read available output from this node
    async fn read_output(&mut self) -> Result<Option<String>> {
        // Try to read with a short timeout
        match timeout(Duration::from_millis(100), self.channel.wait()).await {
            Ok(Some(msg)) => match msg {
                russh::ChannelMsg::Data { ref data } => {
                    Ok(Some(String::from_utf8_lossy(data).to_string()))
                }
                russh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        // stderr
                        Ok(Some(String::from_utf8_lossy(data).to_string()))
                    } else {
                        Ok(None)
                    }
                }
                russh::ChannelMsg::Eof => {
                    self.is_connected = false;
                    Ok(None)
                }
                russh::ChannelMsg::Close => {
                    self.is_connected = false;
                    Ok(None)
                }
                _ => Ok(None),
            },
            Ok(None) => Ok(None),
            Err(_) => Ok(None), // Timeout, no data available
        }
    }
}

impl InteractiveCommand {
    pub async fn execute(self) -> Result<InteractiveResult> {
        let start_time = std::time::Instant::now();

        // Determine which nodes to connect to
        let nodes_to_connect = if self.single_node {
            // In single-node mode, let user select a node or use the first one
            if self.nodes.is_empty() {
                anyhow::bail!("No nodes available for connection");
            }

            if self.nodes.len() == 1 {
                vec![self.nodes[0].clone()]
            } else {
                // Show node selection menu
                println!("Available nodes:");
                for (i, node) in self.nodes.iter().enumerate() {
                    println!("  [{}] {}", i + 1, node);
                }
                print!("Select node (1-{}): ", self.nodes.len());
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                let selection: usize = input.trim().parse().context("Invalid node selection")?;

                if selection == 0 || selection > self.nodes.len() {
                    anyhow::bail!("Invalid node selection");
                }

                vec![self.nodes[selection - 1].clone()]
            }
        } else {
            self.nodes.clone()
        };

        // Connect to all selected nodes
        println!("Connecting to {} node(s)...", nodes_to_connect.len());
        let mut sessions = Vec::new();

        for node in nodes_to_connect {
            match self.connect_to_node(node.clone()).await {
                Ok(session) => {
                    println!("✓ Connected to {}", session.node.to_string().green());
                    sessions.push(session);
                }
                Err(e) => {
                    eprintln!("✗ Failed to connect to {}: {}", node.to_string().red(), e);
                }
            }
        }

        if sessions.is_empty() {
            anyhow::bail!("Failed to connect to any nodes");
        }

        let nodes_connected = sessions.len();

        // Enter interactive mode
        let commands_executed = if self.single_node {
            self.run_single_node_mode(sessions.into_iter().next().unwrap())
                .await?
        } else {
            self.run_multiplex_mode(sessions).await?
        };

        Ok(InteractiveResult {
            duration: start_time.elapsed(),
            commands_executed,
            nodes_connected,
        })
    }

    /// Connect to a single node and establish an interactive shell
    async fn connect_to_node(&self, node: Node) -> Result<NodeSession> {
        // Determine authentication method
        let auth_method = self.determine_auth_method(&node)?;

        // Set up host key checking
        let check_method = get_check_method(StrictHostKeyChecking::AcceptNew);

        // Connect with timeout
        let addr = (node.host.as_str(), node.port);
        let connect_timeout = Duration::from_secs(30);

        let client = timeout(
            connect_timeout,
            Client::connect(addr, &node.username, auth_method, check_method),
        )
        .await
        .with_context(|| {
            format!(
                "Connection timeout: Failed to connect to {}:{} after 30 seconds",
                node.host, node.port
            )
        })?
        .with_context(|| format!("SSH connection failed to {}:{}", node.host, node.port))?;

        // Get terminal dimensions
        let (width, height) = terminal::size().unwrap_or((80, 24));

        // Request interactive shell with PTY
        let channel = client
            .request_interactive_shell("xterm-256color", width as u32, height as u32)
            .await
            .context("Failed to request interactive shell")?;

        // Set initial working directory if specified
        let working_dir = if let Some(ref dir) = self.work_dir {
            // Send cd command to set initial directory
            let cmd = format!("cd {dir} && pwd\n");
            channel.data(cmd.as_bytes()).await?;
            dir.clone()
        } else {
            // Get current directory
            let pwd_cmd = b"pwd\n";
            channel.data(&pwd_cmd[..]).await?;
            String::from("~")
        };

        Ok(NodeSession {
            node,
            client,
            channel,
            working_dir,
            is_connected: true,
        })
    }

    /// Determine authentication method based on node and config
    fn determine_auth_method(&self, node: &Node) -> Result<AuthMethod> {
        // Check if SSH agent is available
        if std::env::var("SSH_AUTH_SOCK").is_ok() {
            return Ok(AuthMethod::Agent);
        }

        // Try to find SSH key
        let ssh_key_paths = vec![
            dirs::home_dir().map(|h| h.join(".ssh/id_rsa")),
            dirs::home_dir().map(|h| h.join(".ssh/id_ed25519")),
        ];

        for key_path in ssh_key_paths.into_iter().flatten() {
            if key_path.exists() {
                return Ok(AuthMethod::with_key_file(key_path, None));
            }
        }

        // If no key found, prompt for password
        let password =
            rpassword::prompt_password(format!("Password for {}@{}: ", node.username, node.host))?;
        Ok(AuthMethod::with_password(&password))
    }

    /// Run interactive mode with a single node
    async fn run_single_node_mode(&self, session: NodeSession) -> Result<usize> {
        let mut commands_executed = 0;

        // Set up rustyline editor
        let history_path = self.expand_path(&self.history_file)?;
        let mut rl = DefaultEditor::new()?;
        rl.set_max_history_size(1000)?;

        // Load history if it exists
        if history_path.exists() {
            let _ = rl.load_history(&history_path);
        }

        // Create shared state for the session
        let session_arc = Arc::new(Mutex::new(session));
        let session_clone = Arc::clone(&session_arc);

        // Create a channel for receiving output from the SSH session
        let (output_tx, mut output_rx) = mpsc::unbounded_channel::<String>();

        // Spawn a task to read output from the SSH channel
        let output_reader = tokio::spawn(async move {
            loop {
                let mut session_guard = session_clone.lock().await;
                if !session_guard.is_connected {
                    break;
                }
                if let Ok(Some(output)) = session_guard.read_output().await {
                    let _ = output_tx.send(output);
                }
                drop(session_guard);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        println!("Interactive session started. Type 'exit' or press Ctrl+D to quit.");
        println!();

        // Main interactive loop
        loop {
            // Print any pending output
            while let Ok(output) = output_rx.try_recv() {
                print!("{output}");
                io::stdout().flush()?;
            }

            // Get current session state for prompt
            let session_guard = session_arc.lock().await;
            let prompt = self.format_prompt(&session_guard.node, &session_guard.working_dir);
            let is_connected = session_guard.is_connected;
            drop(session_guard);

            if !is_connected {
                eprintln!("Connection lost. Exiting.");
                break;
            }

            // Read input
            match rl.readline(&prompt) {
                Ok(line) => {
                    if line.trim() == "exit" {
                        break;
                    }

                    rl.add_history_entry(&line)?;

                    // Send command to remote
                    let mut session_guard = session_arc.lock().await;
                    session_guard.send_command(&line).await?;
                    commands_executed += 1;

                    // Track directory changes
                    if line.trim().starts_with("cd ") {
                        // Update working directory
                        session_guard.send_command("pwd").await?;
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("^C");
                    continue;
                }
                Err(ReadlineError::Eof) => {
                    println!("^D");
                    break;
                }
                Err(err) => {
                    eprintln!("Error: {err}");
                    break;
                }
            }
        }

        // Clean up
        output_reader.abort();
        let _ = rl.save_history(&history_path);

        Ok(commands_executed)
    }

    /// Run interactive mode with multiple nodes (multiplex)
    async fn run_multiplex_mode(&self, mut sessions: Vec<NodeSession>) -> Result<usize> {
        let mut commands_executed = 0;

        // Set up rustyline editor
        let history_path = self.expand_path(&self.history_file)?;
        let mut rl = DefaultEditor::new()?;
        rl.set_max_history_size(1000)?;

        // Load history if it exists
        if history_path.exists() {
            let _ = rl.load_history(&history_path);
        }

        println!(
            "Interactive multiplex mode started. Commands will be sent to all {} nodes.",
            sessions.len()
        );
        println!("Type 'exit' or press Ctrl+D to quit.");
        println!();

        // Main interactive loop
        loop {
            // Show node status
            print!("[");
            for (i, session) in sessions.iter().enumerate() {
                if i > 0 {
                    print!(" ");
                }
                if session.is_connected {
                    print!("{}", "●".green());
                } else {
                    print!("{}", "○".red());
                }
            }
            print!("] ");
            io::stdout().flush()?;

            // Read input
            let prompt = "bssh> ";
            match rl.readline(prompt) {
                Ok(line) => {
                    if line.trim() == "exit" {
                        break;
                    }

                    rl.add_history_entry(&line)?;

                    // Send command to all connected nodes
                    for session in &mut sessions {
                        if session.is_connected {
                            if let Err(e) = session.send_command(&line).await {
                                eprintln!(
                                    "Failed to send command to {}: {}",
                                    session.node.to_string().red(),
                                    e
                                );
                                session.is_connected = false;
                            }
                        }
                    }
                    commands_executed += 1;

                    // Wait a bit for output and collect from all nodes
                    tokio::time::sleep(Duration::from_millis(500)).await;

                    for session in &mut sessions {
                        if session.is_connected {
                            while let Ok(Some(output)) = session.read_output().await {
                                // Print output with node prefix
                                for line in output.lines() {
                                    println!(
                                        "[{}] {}",
                                        format!("{}@{}", session.node.username, session.node.host)
                                            .cyan(),
                                        line
                                    );
                                }
                            }
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("^C");
                    continue;
                }
                Err(ReadlineError::Eof) => {
                    println!("^D");
                    break;
                }
                Err(err) => {
                    eprintln!("Error: {err}");
                    break;
                }
            }

            // Check if all nodes are disconnected
            if sessions.iter().all(|s| !s.is_connected) {
                eprintln!("All nodes disconnected. Exiting.");
                break;
            }
        }

        // Clean up
        let _ = rl.save_history(&history_path);

        Ok(commands_executed)
    }

    /// Format the prompt string with node and directory information
    fn format_prompt(&self, node: &Node, working_dir: &str) -> String {
        self.prompt_format
            .replace("{node}", &format!("{}@{}", node.username, node.host))
            .replace("{user}", &node.username)
            .replace("{host}", &node.host)
            .replace("{pwd}", working_dir)
    }

    /// Expand ~ in path to home directory
    fn expand_path(&self, path: &std::path::Path) -> Result<PathBuf> {
        if let Some(path_str) = path.to_str() {
            if path_str.starts_with('~') {
                if let Some(home) = dirs::home_dir() {
                    let expanded = path_str.replacen('~', home.to_str().unwrap(), 1);
                    return Ok(PathBuf::from(expanded));
                }
            }
        }
        Ok(path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let node = Node::new(String::from("example.com"), 22, String::from("alice"));

        let prompt = cmd.format_prompt(&node, "/home/alice");
        assert_eq!(
            prompt,
            "[alice@example.com:alice@example.com:/home/alice]$ "
        );
    }
}

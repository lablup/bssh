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
use chrono;
use crossterm::terminal::{self};
use owo_colors::OwoColorize;
use russh::client::Msg;
use russh::Channel;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use zeroize::Zeroizing;

use crate::config::{Config, InteractiveConfig};
use crate::node::Node;
use crate::pty::{should_allocate_pty, PtyConfig, PtyManager};
use crate::ssh::{
    known_hosts::{get_check_method, StrictHostKeyChecking},
    tokio_client::{AuthMethod, Client},
};

use super::interactive_signal::{
    is_interrupted, reset_interrupt, setup_async_signal_handlers, setup_signal_handlers,
    TerminalGuard,
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
    pub interactive_config: InteractiveConfig,
    pub cluster_name: Option<String>,
    // Authentication parameters (consistent with exec mode)
    pub key_path: Option<PathBuf>,
    pub use_agent: bool,
    pub use_password: bool,
    pub strict_mode: StrictHostKeyChecking,
    // PTY configuration
    pub pty_config: PtyConfig,
    pub use_pty: Option<bool>, // None = auto-detect, Some(true) = force, Some(false) = disable
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
    is_active: bool, // Whether this node is currently active for commands
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
    /// Determine whether to use PTY mode based on configuration
    fn should_use_pty(&self) -> Result<bool> {
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

    pub async fn execute(self) -> Result<InteractiveResult> {
        let use_pty = self.should_use_pty()?;

        // Choose between PTY mode and traditional interactive mode
        if use_pty {
            // Use new PTY implementation for true terminal support
            self.execute_with_pty().await
        } else {
            // Use traditional rustyline-based interactive mode (existing implementation)
            self.execute_traditional().await
        }
    }

    /// Execute interactive session with full PTY support
    async fn execute_with_pty(self) -> Result<InteractiveResult> {
        let start_time = std::time::Instant::now();

        println!("Starting interactive session with PTY support...");

        // Determine which nodes to connect to
        let nodes_to_connect = self.select_nodes_to_connect()?;

        // Connect to all selected nodes and get SSH channels
        let mut channels = Vec::new();
        let mut connected_nodes = Vec::new();

        for node in nodes_to_connect {
            match self.connect_to_node_pty(node.clone()).await {
                Ok(channel) => {
                    println!("✓ Connected to {} with PTY", node.to_string().green());
                    channels.push(channel);
                    connected_nodes.push(node);
                }
                Err(e) => {
                    eprintln!("✗ Failed to connect to {}: {}", node.to_string().red(), e);
                }
            }
        }

        if channels.is_empty() {
            anyhow::bail!("Failed to connect to any nodes");
        }

        let nodes_connected = channels.len();

        // Create PTY manager and sessions
        let mut pty_manager = PtyManager::new();

        if self.single_node && channels.len() == 1 {
            // Single PTY session
            let session_id = pty_manager
                .create_single_session(
                    channels.into_iter().next().unwrap(),
                    self.pty_config.clone(),
                )
                .await?;

            pty_manager.run_single_session(session_id).await?;
        } else {
            // Multiple PTY sessions with multiplexing
            let session_ids = pty_manager
                .create_multiplex_sessions(channels, self.pty_config.clone())
                .await?;

            pty_manager.run_multiplex_sessions(session_ids).await?;
        }

        // Ensure terminal is fully restored after PTY session ends
        // Use synchronized cleanup to prevent race conditions
        crate::pty::terminal::force_terminal_cleanup();
        let _ = std::io::Write::flush(&mut std::io::stdout());

        Ok(InteractiveResult {
            duration: start_time.elapsed(),
            commands_executed: 0, // PTY mode doesn't count discrete commands
            nodes_connected,
        })
    }

    /// Execute traditional interactive session (existing implementation)
    async fn execute_traditional(self) -> Result<InteractiveResult> {
        let start_time = std::time::Instant::now();

        // Set up signal handlers and terminal guard
        let _terminal_guard = TerminalGuard::new();
        let shutdown = setup_signal_handlers()?;
        setup_async_signal_handlers(Arc::clone(&shutdown)).await;
        reset_interrupt();

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
        // Determine authentication method using the same logic as exec mode
        let auth_method = self.determine_auth_method(&node)?;

        // Set up host key checking using the configured strict mode
        let check_method = get_check_method(self.strict_mode);

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
            .request_interactive_shell("xterm-256color", u32::from(width), u32::from(height))
            .await
            .context("Failed to request interactive shell")?;

        // Note: Terminal resize handling would require channel cloning or Arc<Mutex>
        // which russh doesn't support directly. This is a limitation of the current implementation.

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
            is_active: true, // All nodes start as active
        })
    }

    /// Select nodes to connect to based on configuration
    fn select_nodes_to_connect(&self) -> Result<Vec<Node>> {
        if self.single_node {
            // In single-node mode, let user select a node or use the first one
            if self.nodes.is_empty() {
                anyhow::bail!("No nodes available for connection");
            }

            if self.nodes.len() == 1 {
                Ok(vec![self.nodes[0].clone()])
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

                Ok(vec![self.nodes[selection - 1].clone()])
            }
        } else {
            Ok(self.nodes.clone())
        }
    }

    /// Connect to a single node and establish a PTY-enabled SSH channel
    async fn connect_to_node_pty(&self, node: Node) -> Result<Channel<Msg>> {
        // Determine authentication method using the same logic as exec mode
        let auth_method = self.determine_auth_method(&node)?;

        // Set up host key checking using the configured strict mode
        let check_method = get_check_method(self.strict_mode);

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
        let (width, height) = crate::pty::utils::get_terminal_size().unwrap_or((80, 24));

        // Request interactive shell with PTY using the SSH client's method
        let channel = client
            .request_interactive_shell(&self.pty_config.term_type, width, height)
            .await
            .context("Failed to request interactive shell with PTY")?;

        Ok(channel)
    }

    /// Determine authentication method based on node and config (same logic as exec mode)
    fn determine_auth_method(&self, node: &Node) -> Result<AuthMethod> {
        // If password authentication is explicitly requested
        if self.use_password {
            tracing::debug!("Using password authentication");
            // Use Zeroizing to ensure password is cleared from memory when dropped
            let password = Zeroizing::new(
                rpassword::prompt_password(format!(
                    "Enter password for {}@{}: ",
                    node.username, node.host
                ))
                .with_context(|| "Failed to read password")?,
            );
            return Ok(AuthMethod::with_password(&password));
        }

        // If SSH agent is explicitly requested, try that first
        if self.use_agent {
            #[cfg(not(target_os = "windows"))]
            {
                // Check if SSH_AUTH_SOCK is available
                if std::env::var("SSH_AUTH_SOCK").is_ok() {
                    tracing::debug!("Using SSH agent for authentication");
                    return Ok(AuthMethod::Agent);
                }
                tracing::warn!(
                    "SSH agent requested but SSH_AUTH_SOCK environment variable not set"
                );
                // Fall through to key file authentication
            }
            #[cfg(target_os = "windows")]
            {
                anyhow::bail!("SSH agent authentication is not supported on Windows");
            }
        }

        // Try key file authentication
        if let Some(ref key_path) = self.key_path {
            tracing::debug!("Authenticating with key: {:?}", key_path);

            // Check if the key is encrypted by attempting to read it
            let key_contents = std::fs::read_to_string(key_path)
                .with_context(|| format!("Failed to read SSH key file: {key_path:?}"))?;

            let passphrase = if key_contents.contains("ENCRYPTED")
                || key_contents.contains("Proc-Type: 4,ENCRYPTED")
            {
                tracing::debug!("Detected encrypted SSH key, prompting for passphrase");
                // Use Zeroizing for passphrase security
                let pass = Zeroizing::new(
                    rpassword::prompt_password(format!("Enter passphrase for key {key_path:?}: "))
                        .with_context(|| "Failed to read passphrase")?,
                );
                Some(pass)
            } else {
                None
            };

            return Ok(AuthMethod::with_key_file(
                key_path,
                passphrase.as_ref().map(|p| p.as_str()),
            ));
        }

        // If no explicit key path, try SSH agent if available (auto-detect)
        // Note: We skip auto-detection to avoid failures with empty SSH agents
        // Only use agent if explicitly requested with use_agent flag
        #[cfg(not(target_os = "windows"))]
        if self.use_agent && std::env::var("SSH_AUTH_SOCK").is_ok() {
            tracing::debug!("SSH agent explicitly requested and available");
            return Ok(AuthMethod::Agent);
        }

        // Fallback to default key locations
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let home_path = Path::new(&home).join(".ssh");

        // Try common key files in order of preference
        let default_keys = [
            home_path.join("id_ed25519"),
            home_path.join("id_rsa"),
            home_path.join("id_ecdsa"),
            home_path.join("id_dsa"),
        ];

        for default_key in &default_keys {
            if default_key.exists() {
                tracing::debug!("Using default key: {:?}", default_key);

                // Check if the key is encrypted
                let key_contents = std::fs::read_to_string(default_key)
                    .with_context(|| format!("Failed to read SSH key file: {default_key:?}"))?;

                let passphrase = if key_contents.contains("ENCRYPTED")
                    || key_contents.contains("Proc-Type: 4,ENCRYPTED")
                {
                    tracing::debug!("Detected encrypted SSH key, prompting for passphrase");
                    // Use Zeroizing for passphrase security
                    let pass = Zeroizing::new(
                        rpassword::prompt_password(format!(
                            "Enter passphrase for key {default_key:?}: "
                        ))
                        .with_context(|| "Failed to read passphrase")?,
                    );
                    Some(pass)
                } else {
                    None
                };

                return Ok(AuthMethod::with_key_file(
                    default_key,
                    passphrase.as_ref().map(|p| p.as_str()),
                ));
            }
        }

        anyhow::bail!(
            "SSH authentication failed: No authentication method available.\n\
             Tried:\n\
             - SSH agent: {}\n\
             - SSH keys: {:?}\n\
             Please ensure you have a valid SSH key or SSH agent running.",
            if std::env::var("SSH_AUTH_SOCK").is_ok() {
                "Available but no identities"
            } else {
                "Not available (SSH_AUTH_SOCK not set)"
            },
            default_keys
        )
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        // Create a bounded channel for receiving output from the SSH session
        // 128 buffer size is reasonable for terminal output without causing memory issues
        let (output_tx, mut output_rx) = mpsc::channel::<String>(128);

        // Spawn a task to read output from the SSH channel using select! for efficiency
        let output_reader = tokio::spawn(async move {
            let mut shutdown_watch = {
                let shutdown_clone_for_watch = Arc::clone(&shutdown_clone);
                tokio::spawn(async move {
                    loop {
                        if shutdown_clone_for_watch.load(Ordering::Relaxed) || is_interrupted() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
            };

            loop {
                tokio::select! {
                    // Check for output from SSH session
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {
                        let mut session_guard = session_clone.lock().await;
                        if !session_guard.is_connected {
                            break;
                        }
                        if let Ok(Some(output)) = session_guard.read_output().await {
                            // Use try_send to avoid blocking; drop output if buffer is full
                            // This prevents memory exhaustion but may lose some output under extreme load
                            if output_tx.try_send(output).is_err() {
                                // Channel closed or full, exit gracefully
                                break;
                            }
                        }
                        drop(session_guard);
                    }

                    // Check for shutdown signal
                    _ = &mut shutdown_watch => {
                        break;
                    }
                }
            }
        });

        println!("Interactive session started. Type 'exit' or press Ctrl+D to quit.");
        println!();

        // Main interactive loop using tokio::select! for efficient event multiplexing
        loop {
            // Check for interrupt signal
            if is_interrupted() {
                println!("\nInterrupted by user. Exiting...");
                shutdown.store(true, Ordering::Relaxed);
                break;
            }

            // Print any pending output first
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

            // Use select! to handle multiple events efficiently
            tokio::select! {
                // Handle new output from SSH session
                output = output_rx.recv() => {
                    match output {
                        Some(output) => {
                            print!("{output}");
                            io::stdout().flush()?;
                            continue; // Continue without reading input to process more output
                        }
                        None => {
                            // Output channel closed, session likely ended
                            eprintln!("Session output channel closed. Exiting.");
                            break;
                        }
                    }
                }

                // Handle user input (this runs in a separate task since readline is blocking)
                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                    // Read input using rustyline (this needs to remain synchronous)
                    match rl.readline(&prompt) {
                        Ok(line) => {
                            if line.trim() == "exit" {
                                // Send exit command to remote server before breaking
                                let mut session_guard = session_arc.lock().await;
                                session_guard.send_command("exit").await?;
                                drop(session_guard);
                                // Give the SSH session a moment to process the exit
                                tokio::time::sleep(Duration::from_millis(100)).await;
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
            }
        }

        // Clean up
        shutdown.store(true, Ordering::Relaxed);
        output_reader.abort();

        // Properly close the SSH session
        let mut session_guard = session_arc.lock().await;
        if session_guard.is_connected {
            // Close the SSH channel properly
            let _ = session_guard.channel.close().await;
            session_guard.is_connected = false;
        }
        drop(session_guard);

        let _ = rl.save_history(&history_path);

        Ok(commands_executed)
    }

    /// Parse and handle special commands (starting with configured prefix)
    fn handle_special_command(
        &self,
        command: &str,
        sessions: &mut [NodeSession],
        prefix: &str,
    ) -> Result<bool> {
        if !command.starts_with(prefix) {
            return Ok(false); // Not a special command
        }

        let cmd = command.trim_start_matches(prefix).to_lowercase();

        match cmd.as_str() {
            "all" => {
                // Activate all nodes
                for session in sessions.iter_mut() {
                    if session.is_connected {
                        session.is_active = true;
                    }
                }
                println!("All nodes activated");
                Ok(true)
            }
            "list" | "nodes" | "ls" => {
                // List all nodes with their status
                println!("\nNodes status:");
                for (i, session) in sessions.iter().enumerate() {
                    let status = if !session.is_connected {
                        "disconnected"
                    } else if session.is_active {
                        "active"
                    } else {
                        "inactive"
                    };
                    println!("  [{}] {} - {}", i + 1, session.node, status);
                }
                println!();
                Ok(true)
            }
            "status" => {
                // Show current active nodes
                let active_nodes: Vec<String> = sessions
                    .iter()
                    .filter(|s| s.is_active && s.is_connected)
                    .map(|s| s.node.to_string())
                    .collect();

                if active_nodes.is_empty() {
                    println!("No active nodes");
                } else {
                    println!("Active nodes: {}", active_nodes.join(", "));
                }
                Ok(true)
            }
            "help" | "?" => {
                let broadcast_prefix = self
                    .interactive_config
                    .broadcast_prefix
                    .as_deref()
                    .unwrap_or("!broadcast ");
                println!("\nSpecial commands:");
                println!("  {prefix}all          - Activate all nodes");
                println!("  {broadcast_prefix}<cmd> - Execute command on all nodes (temporarily)");
                println!("  {prefix}node<N>      - Switch to node N (e.g., {prefix}node1)");
                println!("  {prefix}n<N>         - Shorthand for {prefix}node<N>");
                println!("  {prefix}list, {prefix}nodes - List all nodes with status");
                println!("  {prefix}status       - Show active nodes");
                println!("  {prefix}help         - Show this help");
                println!("  exit          - Exit interactive mode");
                println!();
                Ok(true)
            }
            _ => {
                // Check for broadcast command
                let broadcast_prefix = self
                    .interactive_config
                    .broadcast_prefix
                    .as_deref()
                    .unwrap_or("!broadcast ");
                let broadcast_cmd = format!("{prefix}broadcast ");

                if let Some(rest) = command.strip_prefix(&broadcast_cmd) {
                    if rest.trim().is_empty() {
                        println!("Usage: {broadcast_prefix}<command>");
                        return Ok(true);
                    }
                    // Return false with the broadcast command to signal it should be executed
                    return Ok(false);
                }
                // Check for node selection commands
                if let Some(node_num) = cmd.strip_prefix("node") {
                    Self::switch_to_node(node_num, sessions)
                } else if let Some(node_num) = cmd.strip_prefix('n') {
                    Self::switch_to_node(node_num, sessions)
                } else {
                    println!(
                        "Unknown command: {prefix}{cmd}. Type {prefix}help for available commands."
                    );
                    Ok(true)
                }
            }
        }
    }

    /// Switch to a specific node by number
    fn switch_to_node(node_num: &str, sessions: &mut [NodeSession]) -> Result<bool> {
        match node_num.parse::<usize>() {
            Ok(num) if num > 0 && num <= sessions.len() => {
                // Deactivate all nodes first
                for session in sessions.iter_mut() {
                    session.is_active = false;
                }

                // Activate the selected node
                let index = num - 1;
                if sessions[index].is_connected {
                    sessions[index].is_active = true;
                    println!("Switched to node {}: {}", num, sessions[index].node);
                } else {
                    println!("Node {num} is disconnected");
                }
                Ok(true)
            }
            _ => {
                println!("Invalid node number. Use 1-{}", sessions.len());
                Ok(true)
            }
        }
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
        println!("Type 'exit' or press Ctrl+D to quit. Type '!help' for special commands.");
        println!();

        // Main interactive loop
        loop {
            // Check for interrupt signal
            if is_interrupted() {
                println!("\nInterrupted by user. Exiting...");
                break;
            }
            // Build prompt with node status
            let active_count = sessions
                .iter()
                .filter(|s| s.is_active && s.is_connected)
                .count();
            let total_connected = sessions.iter().filter(|s| s.is_connected).count();
            let total_nodes = sessions.len();

            // Use compact display for many nodes (threshold: 10)
            const MAX_INDIVIDUAL_DISPLAY: usize = 10;

            let prompt = if total_nodes > MAX_INDIVIDUAL_DISPLAY {
                // Compact display for many nodes
                if active_count == total_connected {
                    // All active
                    format!("[All {total_connected}/{total_nodes}] bssh> ")
                } else if active_count == 0 {
                    // None active
                    format!("[None 0/{total_connected}] bssh> ")
                } else {
                    // Some active - show which nodes are active (first few)
                    let active_nodes: Vec<usize> = sessions
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| s.is_active && s.is_connected)
                        .map(|(i, _)| i + 1)
                        .collect();

                    let display = if active_nodes.len() <= 5 {
                        // Show all active node numbers if 5 or fewer
                        let node_list = active_nodes
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("[Nodes {node_list}]")
                    } else {
                        // Show first 3 and count
                        let first_three = active_nodes
                            .iter()
                            .take(3)
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("[Nodes {first_three}... +{}]", active_nodes.len() - 3)
                    };

                    format!("{display} ({active_count}/{total_connected}) bssh> ")
                }
            } else if active_count == total_connected {
                // All nodes active - show simple status for small number of nodes
                let mut status = String::from("[");
                for (i, session) in sessions.iter().enumerate() {
                    if i > 0 {
                        status.push(' ');
                    }
                    if session.is_connected {
                        status.push_str(&"●".green().to_string());
                    } else {
                        status.push_str(&"○".red().to_string());
                    }
                }
                status.push_str("] bssh> ");
                status
            } else {
                // Some nodes inactive - show which are active for small number of nodes
                let mut status = String::from("[");
                for (i, session) in sessions.iter().enumerate() {
                    if i > 0 {
                        status.push(' ');
                    }
                    if !session.is_connected {
                        status.push_str(&"○".red().to_string());
                    } else if session.is_active {
                        status.push_str(&format!("{}", (i + 1).to_string().green()));
                    } else {
                        status.push_str(&"·".yellow().to_string());
                    }
                }
                status.push_str(&format!("] ({active_count}/{total_connected}) bssh> "));
                status
            };

            // Read input
            match rl.readline(&prompt) {
                Ok(line) => {
                    if line.trim() == "exit" {
                        break;
                    }

                    // Check for broadcast command specifically
                    let broadcast_prefix = self
                        .interactive_config
                        .broadcast_prefix
                        .as_deref()
                        .unwrap_or("!broadcast ");
                    let is_broadcast = line.trim().starts_with(broadcast_prefix);
                    let command_to_execute = if is_broadcast {
                        // Extract the actual command from the broadcast prefix
                        line.trim()
                            .strip_prefix(broadcast_prefix)
                            .unwrap_or("")
                            .to_string()
                    } else {
                        line.clone()
                    };

                    // Check for special commands first (non-broadcast)
                    let special_prefix = self
                        .interactive_config
                        .node_switch_prefix
                        .as_deref()
                        .unwrap_or("!");
                    if !is_broadcast
                        && line.trim().starts_with(special_prefix)
                        && self.handle_special_command(&line, &mut sessions, special_prefix)?
                    {
                        continue; // Command was handled, continue to next iteration
                    }

                    // Skip if broadcast command is empty
                    if is_broadcast && command_to_execute.trim().is_empty() {
                        println!("Usage: {broadcast_prefix}<command>");
                        continue;
                    }

                    rl.add_history_entry(&line)?;

                    // Save current active states if broadcasting
                    let saved_states: Vec<bool> = if is_broadcast {
                        println!("Broadcasting command to all connected nodes...");
                        sessions.iter().map(|s| s.is_active).collect()
                    } else {
                        vec![]
                    };

                    // Temporarily activate all nodes for broadcast
                    if is_broadcast {
                        for session in &mut sessions {
                            if session.is_connected {
                                session.is_active = true;
                            }
                        }
                    }

                    // Send command to active nodes
                    let mut command_sent = false;
                    for session in &mut sessions {
                        if session.is_connected && session.is_active {
                            if let Err(e) = session.send_command(&command_to_execute).await {
                                eprintln!(
                                    "Failed to send command to {}: {}",
                                    session.node.to_string().red(),
                                    e
                                );
                                session.is_connected = false;
                            } else {
                                command_sent = true;
                            }
                        }
                    }

                    // Restore previous active states after broadcast
                    if is_broadcast && !saved_states.is_empty() {
                        for (session, was_active) in sessions.iter_mut().zip(saved_states.iter()) {
                            session.is_active = *was_active;
                        }
                    }

                    if command_sent {
                        commands_executed += 1;
                    } else {
                        eprintln!(
                            "No active nodes to send command to. Use !list to see nodes or !all to activate all."
                        );
                        continue;
                    }

                    // Use select! to efficiently collect output from all active nodes
                    let output_timeout = tokio::time::sleep(Duration::from_millis(500));
                    tokio::pin!(output_timeout);

                    // Collect output with timeout using select!
                    loop {
                        let mut has_output = false;

                        tokio::select! {
                            // Timeout reached, stop collecting output
                            _ = &mut output_timeout => {
                                break;
                            }

                            // Try to read output from each active session
                            _ = async {
                                for session in &mut sessions {
                                    if session.is_connected && session.is_active {
                                        if let Ok(Some(output)) = session.read_output().await {
                                            has_output = true;
                                            // Print output with node prefix and optional timestamp
                                            for line in output.lines() {
                                                if self.interactive_config.show_timestamps {
                                                    let timestamp = chrono::Local::now().format("%H:%M:%S");
                                                    println!(
                                                        "[{} {}] {}",
                                                        timestamp.to_string().dimmed(),
                                                        format!(
                                                            "{}@{}",
                                                            session.node.username, session.node.host
                                                        )
                                                        .cyan(),
                                                        line
                                                    );
                                                } else {
                                                    println!(
                                                        "[{}] {}",
                                                        format!(
                                                            "{}@{}",
                                                            session.node.username, session.node.host
                                                        )
                                                        .cyan(),
                                                        line
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }

                                // If no output was found, sleep briefly to avoid busy waiting
                                if !has_output {
                                    tokio::time::sleep(Duration::from_millis(10)).await;
                                }
                            } => {
                                if !has_output {
                                    break; // No more output available
                                }
                            }
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("^C");
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

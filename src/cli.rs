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

use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "bssh",
    version,
    before_help = "\n\nBroadcast SSH - Parallel command execution across cluster nodes",
    about = "Broadcast SSH - SSH-compatible parallel command execution tool",
    long_about = "bssh is a high-performance SSH client with parallel execution capabilities.\nIt can be used as a drop-in replacement for SSH (single host) or as a powerful cluster management tool (multiple hosts).\n\nThe tool provides secure file transfer using SFTP and supports SSH keys, SSH agent, and password authentication.\nIt automatically detects Backend.AI multi-node session environments.\n\nOutput Modes:\n- TUI Mode (default): Interactive terminal UI with real-time monitoring (auto-enabled in terminals)\n- Stream Mode (--stream): Real-time output with [node] prefixes\n- File Mode (--output-dir): Save per-node output to timestamped files\n- Normal Mode: Traditional output after all nodes complete\n\nSSH Configuration Support:\n- Reads standard SSH config files (defaulting to ~/.ssh/config)\n- Supports Host patterns, HostName, User, Port, IdentityFile, StrictHostKeyChecking\n- ProxyJump, and many other SSH configuration directives\n- CLI arguments override SSH config values following SSH precedence rules",
    after_help = "EXAMPLES:\n  SSH Mode:\n    bssh user@host                         # Interactive shell\n    bssh admin@server.com \"uptime\"         # Execute command\n    bssh -p 2222 -i ~/.ssh/key user@host   # Custom port and key\n    bssh -F ~/.ssh/myconfig webserver      # Use custom SSH config\n\n  Port Forwarding:\n    bssh -L 8080:example.com:80 user@host  # Local forward: localhost:8080 → example.com:80\n    bssh -R 8080:localhost:80 user@host    # Remote forward: remote:8080 → localhost:80\n    bssh -D 1080 user@host                 # SOCKS5 proxy on localhost:1080\n    bssh -L 3306:db:3306 -R 80:web:80 user@host  # Multiple forwards\n    bssh -D *:1080/4 user@host             # SOCKS4 proxy on all interfaces\n\n  Multi-Server Mode:\n    bssh -C production \"systemctl status\"  # Execute on cluster (TUI mode auto-enabled)\n    bssh -H \"web1,web2,web3\" \"df -h\"      # Execute on multiple hosts\n    bssh -H \"web1,web2,web3\" -f \"web1\" \"df -h\"  # Filter to web1 only\n    bssh -C production -f \"web*\" \"uptime\"  # Filter cluster nodes\n    bssh --parallel 20 -H web* \"apt update\" # Increase parallelism\n\n  Host Exclusion (--exclude):\n    bssh -H \"node1,node2,node3\" --exclude \"node2\" \"uptime\"  # Exclude single host\n    bssh -C production --exclude \"web1,web2\" \"apt update\"  # Exclude multiple hosts\n    bssh -C production --exclude \"db*\" \"systemctl restart\" # Exclude with wildcard pattern\n    bssh -C production --exclude \"*-backup\" \"df -h\"        # Exclude backup nodes\n\n  Output Modes:\n    bssh -C prod \"apt-get update\"          # TUI mode (default, interactive monitoring)\n    bssh -C prod --stream \"tail -f log\"    # Stream mode (real-time with [node] prefixes)\n    bssh -C prod --output-dir ./logs \"ps\" # File mode (save to timestamped files)\n    bssh -C prod \"uptime\" | tee log.txt    # Normal mode (auto-detected when piped)\n\n  TUI Mode Controls (when in TUI):\n    1-9         Jump to node detail view\n    s           Enter split view (2-4 nodes)\n    d           Enter diff view (compare nodes)\n    f           Toggle auto-scroll\n    ↑/↓         Scroll output\n    ←/→         Switch nodes\n    Esc         Return to summary\n    ?           Show help\n    q           Quit\n\n  File Operations:\n    bssh -C staging upload file.txt /tmp/  # Upload to cluster\n    bssh -H host1,host2 download /etc/hosts ./backups/\n\n  Other Commands:\n    bssh list                              # List configured clusters\n    bssh -C production ping                # Test connectivity\n    bssh -H hosts interactive              # Interactive mode\n\n  SSH Config Example (~/.ssh/config):\n    Host web*\n        HostName web.example.com\n        User webuser\n        Port 2222\n        IdentityFile ~/.ssh/web_key\n        StrictHostKeyChecking yes\n\nDeveloped and maintained as part of the Backend.AI project.\nFor more information: https://github.com/lablup/bssh"
)]
pub struct Cli {
    /// SSH destination in format: [user@]hostname[:port] or ssh://[user@]hostname[:port]
    /// Used for SSH compatibility mode (single host connection)
    #[arg(value_name = "destination")]
    pub destination: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(
        short = 'H',
        long,
        value_delimiter = ',',
        help = "Comma-separated list of hosts in [user@]hostname[:port] format\nExamples: 'host1,host2' or 'user1@host1:2222,user2@host2'\nDefault user and port from config or current environment will be used if not specified"
    )]
    pub hosts: Option<Vec<String>>,

    #[arg(
        short = 'f',
        long = "filter",
        help = "Filter hosts by pattern (supports wildcards like 'web*')\nUse with -H or -C to execute on a subset of hosts\nExamples: 'web*' matches web01, web02, etc."
    )]
    pub filter: Option<String>,

    #[arg(
        long = "exclude",
        value_delimiter = ',',
        help = "Exclude hosts from target list (comma-separated)\nSupports wildcard patterns (e.g., 'db*', '*-backup')\nApplied after --filter option"
    )]
    pub exclude: Option<Vec<String>>,

    #[arg(
        short = 'C',
        long = "cluster",
        help = "Cluster name from configuration file (multi-server mode)"
    )]
    pub cluster: Option<String>,

    #[arg(
        long,
        default_value = "~/.config/bssh/config.yaml",
        help = "Configuration file path [default: ~/.config/bssh/config.yaml]\nConfig loading priority:\n  1. Backend.AI env vars (auto-detected)\n  2. Current directory (./config.yaml)\n  3. User config (~/.config/bssh/config.yaml)\n  4. This flag's value"
    )]
    pub config: PathBuf,

    #[arg(
        short = 'l',
        long = "login",
        help = "Specifies the user to log in as on the remote machine (SSH-compatible)"
    )]
    pub user: Option<String>,

    #[arg(
        short = 'i',
        long,
        help = "SSH private key file path (prompts for passphrase if encrypted)\nAutomatically detects encrypted keys and prompts for passphrase\nFalls back to default keys (~/.ssh/id_ed25519, ~/.ssh/id_rsa, etc.) if not specified"
    )]
    pub identity: Option<PathBuf>,

    #[arg(
        short = 'A',
        long,
        help = "Use SSH agent for authentication (Unix/Linux/macOS only)\nAuto-detected when SSH_AUTH_SOCK is set. Falls back to key file if agent auth fails"
    )]
    pub use_agent: bool,

    #[arg(
        long = "password",
        help = "Use password authentication (will prompt for password)"
    )]
    pub password: bool,

    #[arg(
        short = 'S',
        long = "sudo-password",
        help = "Prompt for sudo password to automatically respond to sudo prompts\nWhen enabled, bssh will:\n  1. Securely prompt for sudo password before execution\n  2. Detect sudo password prompts in command output\n  3. Automatically inject the password when prompted\n\nAlternatively, set BSSH_SUDO_PASSWORD environment variable (not recommended)\nSecurity: Password is cleared from memory after use"
    )]
    pub sudo_password: bool,

    #[arg(
        short = 'J',
        long = "jump-host",
        help = "Comma-separated list of jump hosts (ProxyJump)\nSpecify in [user@]hostname[:port] format, e.g.: 'jump1.example.com' or 'user@jump1:2222,jump2'\nSupports multiple hops for complex network topologies"
    )]
    pub jump_hosts: Option<String>,

    #[arg(
        long = "parallel",
        default_value = "10",
        help = "Maximum parallel connections (multi-server mode)"
    )]
    pub parallel: usize,

    #[arg(
        short = 'p',
        long = "port",
        value_name = "port",
        help = "Port to connect to on the remote host (SSH-compatible)"
    )]
    pub port: Option<u16>,

    #[arg(
        long,
        help = "Stream output in real-time with [node] prefixes\nEach line of output is prefixed with the node hostname and displayed as it arrives.\nUseful for monitoring long-running commands across multiple nodes.\nAutomatically disabled when output is piped or in CI environments."
    )]
    pub stream: bool,

    #[arg(
        long,
        help = "Output directory for per-node command results\nCreates timestamped files:\n  - hostname_TIMESTAMP.stdout (command output)\n  - hostname_TIMESTAMP.stderr (error output)\n  - hostname_TIMESTAMP.error (connection failures)\n  - summary_TIMESTAMP.txt (execution summary)"
    )]
    pub output_dir: Option<PathBuf>,

    #[arg(
        short = 'v',
        long,
        action = clap::ArgAction::Count,
        help = "Increase verbosity (-v, -vv, -vvv)"
    )]
    pub verbose: u8,

    #[arg(
        long,
        default_value = "accept-new",
        help = "Host key checking mode (yes/no/accept-new) [default: accept-new]\n  yes        - Strict checking against known_hosts (most secure)\n  no         - Accept all host keys (insecure, testing only)\n  accept-new - Accept new hosts, reject changed keys (recommended)"
    )]
    pub strict_host_key_checking: String,

    #[arg(
        long,
        default_value = "300",
        help = "Command timeout in seconds (0 for unlimited)"
    )]
    pub timeout: u64,

    #[arg(
        long,
        help = "Require all nodes to succeed (v1.0-v1.1 behavior)\nDefault: return main rank's exit code (v1.2+)\nUseful for health checks and monitoring where all nodes must be operational"
    )]
    pub require_all_success: bool,

    #[arg(
        long,
        conflicts_with = "require_all_success",
        help = "Check all nodes but preserve main rank exit code\nReturns main rank's exit code if non-zero, or 1 if main succeeded but others failed\nHybrid approach for production deployments"
    )]
    pub check_all_nodes: bool,

    #[arg(
        trailing_var_arg = true,
        help = "Command to execute on remote hosts",
        allow_hyphen_values = true
    )]
    pub command_args: Vec<String>,

    // SSH-compatible options
    #[arg(short = 'o', long = "option", value_name = "option", action = clap::ArgAction::Append,
        help = "SSH options (e.g., -o StrictHostKeyChecking=no)")]
    pub ssh_options: Vec<String>,

    #[arg(
        short = 'F',
        long = "ssh-config",
        value_name = "configfile",
        help = "Specifies an alternative SSH configuration file\nSupports standard SSH config format with Host, HostName, User, Port, IdentityFile, etc.\nDefaults to ~/.ssh/config if not specified and file exists"
    )]
    pub ssh_config: Option<PathBuf>,

    #[arg(
        short = 'q',
        long = "quiet",
        conflicts_with = "verbose",
        help = "Quiet mode (suppress non-error messages)"
    )]
    pub quiet: bool,

    #[arg(short = 't', long = "tty", help = "Force pseudo-terminal allocation")]
    pub force_tty: bool,

    #[arg(
        short = 'T',
        long = "no-tty",
        conflicts_with = "force_tty",
        help = "Disable pseudo-terminal allocation"
    )]
    pub no_tty: bool,

    #[arg(short = 'x', long = "no-x11", help = "Disable X11 forwarding")]
    pub no_x11: bool,

    #[arg(
        short = '4',
        long = "ipv4",
        conflicts_with = "ipv6",
        help = "Force use of IPv4 addresses only"
    )]
    pub ipv4: bool,

    #[arg(
        short = '6',
        long = "ipv6",
        conflicts_with = "ipv4",
        help = "Force use of IPv6 addresses only"
    )]
    pub ipv6: bool,

    #[arg(
        short = 'Q',
        long = "query",
        value_name = "query_option",
        help = "Query SSH configuration options"
    )]
    pub query: Option<String>,

    // Port forwarding options (SSH-compatible)
    #[arg(
        short = 'L',
        long = "local-forward",
        value_name = "local_forward_spec",
        action = clap::ArgAction::Append,
        help = "Local port forwarding [bind_address:]port:host:hostport\nBinds a local port to forward connections to a remote destination via SSH.\nMultiple -L options can be specified for multiple forwards.\nExample: -L 8080:example.com:80 (localhost:8080 → example.com:80)"
    )]
    pub local_forwards: Vec<String>,

    #[arg(
        short = 'R',
        long = "remote-forward",
        value_name = "remote_forward_spec",
        action = clap::ArgAction::Append,
        help = "Remote port forwarding [bind_address:]port:host:hostport\nRequests the SSH server to bind a port and forward connections to local destination.\nMultiple -R options can be specified for multiple forwards.\nExample: -R 8080:localhost:80 (remote:8080 → localhost:80)"
    )]
    pub remote_forwards: Vec<String>,

    #[arg(
        short = 'D',
        long = "dynamic-forward",
        value_name = "dynamic_forward_spec",
        action = clap::ArgAction::Append,
        help = "Dynamic port forwarding (SOCKS proxy) [bind_address:]port[/socks_version]\nCreates a local SOCKS proxy that dynamically forwards connections via SSH.\nMultiple -D options can be specified for multiple SOCKS proxies.\nExample: -D 1080 (SOCKS5 proxy on localhost:1080), -D *:1080/4 (SOCKS4 on all interfaces)"
    )]
    pub dynamic_forwards: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(
        about = "List available clusters",
        long_about = "Displays all clusters defined in configuration files.\nShows cluster names, node counts, and configuration sources.\nIncludes auto-detected Backend.AI clusters if present.\n\nConfiguration sources checked (in order):\n  - Backend.AI environment variables\n  - Current directory (./config.yaml)\n  - User config (~/.config/bssh/config.yaml)"
    )]
    List,

    #[command(
        about = "Test connectivity to hosts",
        long_about = "Verifies SSH connectivity and authentication to all target hosts.\nReports connection status, authentication success, and response times.\nUseful for validating cluster configuration and SSH key setup.\n\nExit codes: 0 (all reachable), 1 (any unreachable)"
    )]
    Ping,

    #[command(
        about = "Upload files to remote hosts",
        long_about = "Uploads local file(s) to all specified remote hosts in parallel using SFTP.\nSupports glob patterns for batch uploads (e.g., *.txt, logs/*.log).\nWhen uploading multiple files, destination should be a directory (end with /).\nUses secure SFTP protocol with progress indicators for each transfer.\n\nRequirements: Remote SSH servers must have SFTP subsystem enabled.",
        after_help = "Examples:\n  bssh upload config.yaml /etc/app/      # Single file to directory\n  bssh upload app.tar.gz /tmp/app.tar.gz # Single file with rename\n  bssh upload \"*.log\" /var/logs/        # Multiple files with glob\n  bssh upload -r ./configs/ /etc/app/    # Recursive directory upload"
    )]
    Upload {
        #[arg(
            help = "Local file path or glob pattern (e.g., *.txt, logs/*.log)\nUse quotes around patterns to prevent shell expansion"
        )]
        source: PathBuf,

        #[arg(
            help = "Remote destination path\nUse trailing slash (/) for directory when uploading multiple files\nPath will be created if it doesn't exist (requires appropriate permissions)"
        )]
        destination: String,

        #[arg(short = 'r', long, help = "Recursively upload directories")]
        recursive: bool,
    },

    #[command(
        about = "Download files from remote hosts",
        long_about = "Downloads remote file(s) from all specified hosts to local destination using SFTP.\nEach file is prefixed with hostname to avoid conflicts (e.g., host1_file.txt).\nSupports glob patterns for batch downloads (e.g., /var/log/*.log).\nUses secure SFTP protocol with progress indicators and parallel transfers.\n\nNote: Creates destination directory if it doesn't exist.",
        after_help = "Examples:\n  bssh download /etc/passwd ./configs/      # Single file from all hosts\n  bssh download \"/var/log/*.log\" ./logs/   # Multiple logs with glob\n  bssh download -r /etc/nginx/ ./backups/   # Recursive directory download\n\nFiles saved as: hostname_filename (e.g., web1_passwd, web2_passwd)"
    )]
    Download {
        #[arg(
            help = "Remote file path or glob pattern (e.g., /var/log/*.log)\nSupports wildcards for batch downloads"
        )]
        source: String,

        #[arg(
            help = "Local destination directory\nFiles will be prefixed with hostname (e.g., host1_filename)"
        )]
        destination: PathBuf,

        #[arg(short = 'r', long, help = "Recursively download directories")]
        recursive: bool,
    },

    #[command(
        about = "Start interactive shell session",
        long_about = "Opens an interactive shell session with one or more remote hosts.\nSupports both single-node and multiplex modes for efficient cluster management.\nIn multiplex mode, commands are sent to all active nodes simultaneously.\n\nSpecial commands (default prefix '!'):\n  !all              - Activate all connected nodes\n  !broadcast <cmd>  - Execute on all nodes temporarily\n  !node<N>          - Switch to specific node (e.g., !node1)\n  !list             - List all nodes and connection status\n  !status           - Show currently active nodes\n  !help             - Show special commands help\n  exit              - Exit interactive mode\n\nSettings can be configured globally or per-cluster in config file.\nCLI arguments override configuration file settings.",
        after_help = "Examples:\n  bssh interactive                           # Auto-detect or use defaults\n  bssh -c prod interactive                   # Use production cluster\n  bssh interactive --single-node             # Connect to one node only\n  bssh interactive --prompt-format '{user}>' # Custom prompt\n  bssh interactive --work-dir /var/www       # Set initial directory"
    )]
    Interactive {
        #[arg(
            long,
            help = "Connect to a single node instead of multiplexing to all nodes (overrides config)"
        )]
        single_node: bool,

        #[arg(
            long,
            default_value = "true",
            help = "Multiplex input across all nodes (default behavior, overrides config)"
        )]
        multiplex: bool,

        #[arg(
            long,
            default_value = "[{node}:{user}@{host}:{pwd}]$ ",
            help = "Custom prompt format with variables: {node}, {user}, {host}, {pwd} (overrides config)"
        )]
        prompt_format: String,

        #[arg(
            long,
            default_value = "~/.bssh_history",
            help = "History file path for command history (overrides config)"
        )]
        history_file: PathBuf,

        #[arg(
            long,
            help = "Initial working directory on remote hosts (overrides config)"
        )]
        work_dir: Option<String>,
    },

    #[command(
        about = "Display SSH config cache statistics",
        long_about = "Shows detailed statistics and debug information about the SSH configuration cache.\nIncludes hit rates, cache size, eviction counts, and entry details.\nUseful for performance monitoring and cache tuning.\n\nCache can be configured via environment variables:\n  BSSH_CACHE_ENABLED=true/false  - Enable/disable caching\n  BSSH_CACHE_SIZE=100            - Maximum cache entries\n  BSSH_CACHE_TTL=300             - TTL in seconds",
        after_help = "Examples:\n  bssh cache-stats                  # Show basic statistics\n  bssh cache-stats --detailed       # Show per-entry information\n  bssh cache-stats --clear           # Clear cache and show stats"
    )]
    CacheStats {
        #[arg(long, help = "Show detailed per-entry information")]
        detailed: bool,

        #[arg(long, help = "Clear the cache before showing statistics")]
        clear: bool,

        #[arg(long, help = "Perform cache maintenance (remove expired entries)")]
        maintain: bool,
    },
}

impl Cli {
    pub fn get_command(&self) -> String {
        // In multi-server mode with destination, treat destination as first command arg
        if self.is_multi_server_mode() && self.destination.is_some() {
            let mut all_args = vec![self.destination.as_ref().unwrap().clone()];
            all_args.extend(self.command_args.clone());
            all_args.join(" ")
        } else if !self.command_args.is_empty() {
            self.command_args.join(" ")
        } else {
            String::new()
        }
    }

    /// Check if the first command arg is a known subcommand
    pub fn is_known_subcommand(arg: &str) -> bool {
        matches!(
            arg,
            "list" | "ping" | "upload" | "download" | "interactive" | "cache-stats"
        )
    }

    /// Determine if we should auto-execute a command
    pub fn should_auto_exec(&self) -> bool {
        // If in multi-server mode with destination or command_args, treat as exec
        if self.is_multi_server_mode() {
            // Check if destination is a known subcommand
            if let Some(dest) = &self.destination {
                if Self::is_known_subcommand(dest) {
                    return false; // It's a subcommand, not auto-exec
                }
                return true; // Has destination that's not a subcommand
            }
            // Check command_args
            if !self.command_args.is_empty() {
                if Self::is_known_subcommand(&self.command_args[0]) {
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// Check if running in SSH compatibility mode (single host)
    pub fn is_ssh_mode(&self) -> bool {
        // Only SSH mode if destination is provided and no cluster/hosts
        // If hosts/cluster is present, destination should be treated as first command arg
        self.destination.is_some() && self.cluster.is_none() && self.hosts.is_none()
    }

    /// Check if running in multi-server mode
    pub fn is_multi_server_mode(&self) -> bool {
        self.cluster.is_some() || self.hosts.is_some()
    }

    /// Get the host filter pattern if specified
    pub fn get_host_filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    /// Get the host exclusion patterns if specified
    pub fn get_exclude_patterns(&self) -> Option<&[String]> {
        self.exclude.as_deref()
    }

    /// Parse destination string into components (user, host, port)
    pub fn parse_destination(&self) -> Option<(Option<String>, String, Option<u16>)> {
        self.destination.as_ref().map(|dest| {
            // Handle ssh:// prefix
            let dest = dest.strip_prefix("ssh://").unwrap_or(dest);

            // Parse [user@]hostname[:port]
            let parts: Vec<&str> = dest.splitn(2, '@').collect();
            let (user, host_port) = if parts.len() == 2 {
                (Some(parts[0].to_string()), parts[1])
            } else {
                (None, parts[0])
            };

            // Parse hostname[:port]
            if let Some(idx) = host_port.rfind(':') {
                // Check if this is actually a port number (not IPv6 address)
                if let Ok(port) = host_port[idx + 1..].parse::<u16>() {
                    let host = host_port[..idx].to_string();
                    (user, host, Some(port))
                } else {
                    // Not a valid port, treat entire string as hostname
                    (user, host_port.to_string(), None)
                }
            } else {
                (user, host_port.to_string(), None)
            }
        })
    }

    /// Get effective username (from -l option, destination, or environment)
    pub fn get_effective_user(&self) -> Option<String> {
        // Priority: -l option > destination > config
        if let Some(ref login) = self.user {
            return Some(login.clone());
        }

        if let Some((user, _, _)) = self.parse_destination() {
            return user;
        }

        None
    }

    /// Get effective port (from -p option, destination, SSH options, or default)
    pub fn get_effective_port(&self) -> Option<u16> {
        // Priority: -p option > destination > -o Port= > default
        if let Some(port) = self.port {
            return Some(port);
        }

        if let Some((_, _, Some(port))) = self.parse_destination() {
            return Some(port);
        }

        // Check SSH options for Port=
        for opt in &self.ssh_options {
            if let Some(port_str) = opt.strip_prefix("Port=") {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some(port);
                }
            }
        }

        None
    }

    /// Parse SSH options into a map
    pub fn parse_ssh_options(&self) -> std::collections::HashMap<String, String> {
        let mut options = std::collections::HashMap::new();

        for opt in &self.ssh_options {
            if let Some(eq_idx) = opt.find('=') {
                let key = opt[..eq_idx].to_string();
                let value = opt[eq_idx + 1..].to_string();
                options.insert(key, value);
            }
        }

        options
    }

    /// Parse port forwarding specifications into ForwardingType instances
    ///
    /// Returns a Result containing a vector of all parsed forwarding specifications
    /// or an error if any specification is invalid.
    pub fn parse_port_forwards(
        &self,
    ) -> Result<Vec<crate::forwarding::ForwardingType>, anyhow::Error> {
        use crate::forwarding::spec::ForwardingSpec;

        let mut forwards = Vec::new();

        // Parse local forwards (-L options)
        for spec in &self.local_forwards {
            let forward = ForwardingSpec::parse_local(spec)
                .with_context(|| format!("Invalid local forwarding specification: {spec}"))?;
            forwards.push(forward);
        }

        // Parse remote forwards (-R options)
        for spec in &self.remote_forwards {
            let forward = ForwardingSpec::parse_remote(spec)
                .with_context(|| format!("Invalid remote forwarding specification: {spec}"))?;
            forwards.push(forward);
        }

        // Parse dynamic forwards (-D options)
        for spec in &self.dynamic_forwards {
            let forward = ForwardingSpec::parse_dynamic(spec)
                .with_context(|| format!("Invalid dynamic forwarding specification: {spec}"))?;
            forwards.push(forward);
        }

        Ok(forwards)
    }

    /// Check if any port forwarding options are specified
    pub fn has_port_forwards(&self) -> bool {
        !self.local_forwards.is_empty()
            || !self.remote_forwards.is_empty()
            || !self.dynamic_forwards.is_empty()
    }

    /// Get count of total port forwarding specifications
    pub fn port_forward_count(&self) -> usize {
        self.local_forwards.len() + self.remote_forwards.len() + self.dynamic_forwards.len()
    }
}

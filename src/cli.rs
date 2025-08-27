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

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "bssh",
    version,
    before_help = "",
    about = "Backend.AI SSH - Parallel command execution across cluster nodes",
    long_about = "bssh is a high-performance parallel SSH command execution tool for cluster management.\nIt enables efficient execution of commands across multiple nodes simultaneously with real-time output streaming.\nThe tool provides secure file transfer capabilities using SFTP protocol and supports multiple authentication\nmethods including SSH keys (with passphrase support), SSH agent, and password authentication.\nIt automatically detects Backend.AI multi-node session environments.",
    after_help = "EXAMPLES:\n  Execute command on hosts:     bssh -H \"user@host1,host2\" \"uptime\"\n  Use cluster configuration:    bssh -c production \"df -h\"\n  Upload files with glob:       bssh -c staging upload \"*.log\" /tmp/\n  Download from all nodes:      bssh -c web download /var/log/app.log ./logs/\n  Interactive mode (multiplex): bssh -c production interactive\n  Test connectivity:            bssh -c staging ping\n\nDeveloped and maintained as part of the Backend.AI project.\nFor more examples and documentation, visit: https://github.com/lablup/bssh"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(
        short = 'H',
        long,
        value_delimiter = ',',
        help = "Comma-separated list of hosts in [user@]hostname[:port] format\nExamples: 'host1,host2' or 'user1@host1:2222,user2@host2'\nDefault user and port from config or current environment will be used if not specified"
    )]
    pub hosts: Option<Vec<String>>,

    #[arg(short = 'c', long, help = "Cluster name from configuration file")]
    pub cluster: Option<String>,

    #[arg(
        long,
        default_value = "~/.config/bssh/config.yaml",
        help = "Configuration file path [default: ~/.config/bssh/config.yaml]\nConfig loading priority:\n  1. Backend.AI env vars (auto-detected)\n  2. Current directory (./config.yaml)\n  3. User config (~/.config/bssh/config.yaml)\n  4. This flag's value"
    )]
    pub config: PathBuf,

    #[arg(short = 'u', long, help = "Default username for SSH connections")]
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
        short = 'P',
        long,
        help = "Use password authentication (will prompt for password)"
    )]
    pub password: bool,

    #[arg(
        short = 'p',
        long,
        default_value = "10",
        help = "Maximum parallel connections"
    )]
    pub parallel: usize,

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

    #[arg(trailing_var_arg = true, help = "Command to execute on remote hosts")]
    pub command_args: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(
        about = "Execute a command on specified hosts",
        long_about = "Executes the specified command on all target hosts simultaneously.\nOutput is streamed in real-time with host prefixes for identification.\nSupports command timeout, output redirection, and partial failure handling.\n\nExit codes: 0 (all succeed), 1 (any failures)",
        after_help = "Examples:\n  bssh exec \"uptime\"                    # Execute on auto-detected or default hosts\n  bssh -c prod exec \"systemctl status\"  # Execute on cluster 'prod'\n  bssh -p 20 exec \"apt update\"          # Increase parallelism to 20\n  bssh --output-dir logs exec \"df -h\"   # Save outputs to files"
    )]
    Exec {
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

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
}

impl Cli {
    pub fn get_command(&self) -> String {
        if !self.command_args.is_empty() {
            self.command_args.join(" ")
        } else if let Some(Commands::Exec { command }) = &self.command {
            command.join(" ")
        } else {
            String::new()
        }
    }
}

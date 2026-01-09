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

//! pdsh compatibility layer for bssh
//!
//! This module provides pdsh-compatible CLI parsing and option mapping,
//! enabling bssh to act as a drop-in replacement for pdsh.
//!
//! # Usage
//!
//! pdsh compatibility mode is activated in three ways:
//! 1. Binary name detection: When bssh is invoked as "pdsh" (via symlink)
//! 2. Environment variable: `BSSH_PDSH_COMPAT=1` or `BSSH_PDSH_COMPAT=true`
//! 3. CLI flag: `bssh --pdsh-compat ...`
//!
//! # Option Mapping
//!
//! | pdsh option | bssh option | Notes |
//! |-------------|-------------|-------|
//! | `-w hosts` | `-H hosts` | Direct mapping |
//! | `-x hosts` | `--exclude hosts` | Direct mapping |
//! | `-f N` | `--parallel N` | Fanout to parallel |
//! | `-l user` | `-l user` | Same option |
//! | `-t N` | `--connect-timeout N` | Connection timeout |
//! | `-u N` | `--timeout N` | Command timeout |
//! | `-N` | `--no-prefix` | Direct mapping |
//! | `-b` | `--batch` | Direct mapping |
//! | `-k` | `--fail-fast` | Direct mapping |
//! | `-q` | (query mode) | Show hosts and exit |
//! | `-S` | `--any-failure` | Return largest exit code |

use clap::Parser;
use std::path::Path;

/// pdsh-compatible CLI parser
///
/// This struct captures pdsh command-line arguments and can be converted
/// to the standard bssh `Cli` structure.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "pdsh",
    version,
    about = "Parallel distributed shell (bssh compatibility mode)",
    long_about = "bssh running in pdsh compatibility mode.\n\n\
        This allows bssh to accept pdsh-style command line arguments.\n\
        All pdsh options are mapped to their bssh equivalents.",
    after_help = "EXAMPLES:\n  \
        pdsh -w host1,host2 \"uptime\"        # Execute on hosts\n  \
        pdsh -w host[1-3] -f 10 \"df -h\"     # Fanout of 10\n  \
        pdsh -w nodes -x badnode \"cmd\"      # Exclude host\n  \
        pdsh -w hosts -N \"hostname\"         # No hostname prefix\n  \
        pdsh -w hosts -q                     # Query mode (show hosts)\n  \
        pdsh -w hosts -l admin \"cmd\"        # Specify user\n\n\
    Note: This is bssh running in pdsh compatibility mode.\n\
    For full bssh features, run 'bssh --help'."
)]
pub struct PdshCli {
    /// Target hosts (comma-separated or host[range] notation)
    ///
    /// Accepts comma-separated hostnames or pdsh-style ranges like host[1-5].
    #[arg(short = 'w', help = "Target hosts (comma-separated or range notation)")]
    pub hosts: Option<String>,

    /// Exclude hosts from target list (comma-separated)
    #[arg(short = 'x', help = "Exclude hosts from target list")]
    pub exclude: Option<String>,

    /// Fanout (number of parallel connections)
    ///
    /// Sets the maximum number of concurrent SSH connections.
    /// Default is 32 to match pdsh default.
    #[arg(
        short = 'f',
        default_value = "32",
        help = "Fanout (parallel connections)"
    )]
    pub fanout: usize,

    /// Remote username
    #[arg(short = 'l', help = "Remote username")]
    pub user: Option<String>,

    /// Connect timeout in seconds
    #[arg(short = 't', help = "Connect timeout (seconds)")]
    pub connect_timeout: Option<u64>,

    /// Command timeout in seconds
    #[arg(short = 'u', help = "Command timeout (seconds)")]
    pub command_timeout: Option<u64>,

    /// Disable hostname prefix in output
    #[arg(short = 'N', help = "Disable hostname prefix")]
    pub no_prefix: bool,

    /// Batch mode (single Ctrl+C terminates)
    #[arg(short = 'b', help = "Batch mode")]
    pub batch: bool,

    /// Fail fast (stop on first failure)
    ///
    /// When enabled, cancels remaining commands if any host fails.
    #[arg(short = 'k', help = "Fail fast (stop on first failure)")]
    pub fail_fast: bool,

    /// Query mode - show target hosts and exit
    ///
    /// Lists all hosts that would be targeted without executing any command.
    #[arg(short = 'q', help = "Query mode (show hosts and exit)")]
    pub query: bool,

    /// Return exit status of any failing node
    ///
    /// When enabled, returns the largest exit code from any node.
    #[arg(short = 'S', help = "Return largest exit code from any node")]
    pub any_failure: bool,

    /// Command to execute (trailing arguments)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// Environment variable name for pdsh compatibility mode
pub const PDSH_COMPAT_ENV_VAR: &str = "BSSH_PDSH_COMPAT";

/// Checks if pdsh compatibility mode should be enabled.
///
/// Returns `true` if any of the following conditions are met:
/// 1. The `BSSH_PDSH_COMPAT` environment variable is set to "1" or "true"
/// 2. The binary name (argv[0]) is "pdsh" or starts with "pdsh."
///
/// # Examples
///
/// ```
/// use std::env;
///
/// // When environment variable is set
/// env::set_var("BSSH_PDSH_COMPAT", "1");
/// // is_pdsh_compat_mode() would return true
/// ```
pub fn is_pdsh_compat_mode() -> bool {
    // Check environment variable first
    if let Ok(value) = std::env::var(PDSH_COMPAT_ENV_VAR) {
        let value_lower = value.to_lowercase();
        if value_lower == "1" || value_lower == "true" {
            return true;
        }
    }

    // Check argv[0] for "pdsh" binary name
    if let Some(arg0) = std::env::args().next() {
        let binary_name = Path::new(&arg0)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Match exact "pdsh" or "pdsh.exe" (Windows) or "pdsh.*" patterns
        if binary_name == "pdsh" || binary_name.starts_with("pdsh.") {
            return true;
        }
    }

    false
}

/// Checks if pdsh compatibility mode should be enabled based on arguments.
///
/// This function checks for the `--pdsh-compat` flag in the provided arguments.
/// Unlike `is_pdsh_compat_mode()`, this checks explicit CLI flag rather than
/// environment or binary name.
///
/// # Arguments
///
/// * `args` - Command line arguments to check
///
/// # Returns
///
/// `true` if `--pdsh-compat` flag is present in the arguments
pub fn has_pdsh_compat_flag(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--pdsh-compat")
}

/// Removes the `--pdsh-compat` flag from arguments.
///
/// When bssh is invoked with `--pdsh-compat`, we need to remove this flag
/// before parsing with the pdsh CLI parser (which doesn't know this flag).
///
/// # Arguments
///
/// * `args` - Original command line arguments
///
/// # Returns
///
/// Arguments with `--pdsh-compat` flag removed
pub fn remove_pdsh_compat_flag(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|arg| *arg != "--pdsh-compat")
        .cloned()
        .collect()
}

impl PdshCli {
    /// Parse pdsh-style arguments from command line.
    ///
    /// # Returns
    ///
    /// Parsed `PdshCli` instance
    pub fn parse_args() -> Self {
        PdshCli::parse()
    }

    /// Parse pdsh-style arguments from a specific argument list.
    ///
    /// # Arguments
    ///
    /// * `args` - Iterator over command-line arguments
    ///
    /// # Returns
    ///
    /// Parsed `PdshCli` instance
    pub fn parse_from_args<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        PdshCli::parse_from(args)
    }

    /// Returns whether this is a query-only request (show hosts and exit).
    pub fn is_query_mode(&self) -> bool {
        self.query
    }

    /// Returns whether a command was specified.
    pub fn has_command(&self) -> bool {
        !self.command.is_empty()
    }

    /// Gets the command as a single string.
    pub fn get_command(&self) -> String {
        self.command.join(" ")
    }

    /// Converts pdsh CLI options to bssh CLI options.
    ///
    /// This method creates a bssh `Cli` instance with all options mapped
    /// from their pdsh equivalents.
    ///
    /// # Returns
    ///
    /// A `Cli` instance with options mapped from pdsh arguments
    pub fn to_bssh_cli(&self) -> super::Cli {
        use std::path::PathBuf;

        super::Cli {
            // Map -w hosts to -H hosts
            hosts: self.hosts.as_ref().map(|h| {
                h.split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<_>>()
            }),
            // Map -x exclude to --exclude
            exclude: self.exclude.as_ref().map(|x| {
                x.split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<_>>()
            }),
            // Map -f fanout to --parallel
            parallel: self.fanout,
            // Map -l user to -l/--login
            user: self.user.clone(),
            // Map -t to --connect-timeout
            connect_timeout: self.connect_timeout.unwrap_or(30),
            // Map -u to --timeout
            timeout: self.command_timeout,
            // Map -N to --no-prefix
            no_prefix: self.no_prefix,
            // Map -b to --batch
            batch: self.batch,
            // Map -k to --fail-fast
            fail_fast: self.fail_fast,
            // Map -S to --any-failure
            any_failure: self.any_failure,
            // Map command
            command_args: self.command.clone(),
            // Set pdsh_compat flag
            pdsh_compat: true,
            // Default values for remaining fields
            destination: None,
            command: None,
            filter: None,
            cluster: None,
            config: PathBuf::from("~/.config/bssh/config.yaml"),
            identity: None,
            use_agent: false,
            password: false,
            sudo_password: false,
            jump_hosts: None,
            port: None,
            stream: false,
            output_dir: None,
            verbose: 0,
            strict_host_key_checking: "accept-new".to_string(),
            require_all_success: false,
            check_all_nodes: false,
            ssh_options: Vec::new(),
            ssh_config: None,
            quiet: false,
            force_tty: false,
            no_tty: false,
            no_x11: false,
            ipv4: false,
            ipv6: false,
            query: None,
            local_forwards: Vec::new(),
            remote_forwards: Vec::new(),
            dynamic_forwards: Vec::new(),
            server_alive_interval: None,
            server_alive_count_max: None,
        }
    }
}

/// Result type for pdsh query mode
#[derive(Debug)]
pub struct QueryResult {
    /// List of hosts that would be targeted
    pub hosts: Vec<String>,
}

impl QueryResult {
    /// Display query results to stdout
    pub fn display(&self) {
        for host in &self.hosts {
            println!("{host}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdsh_cli_basic_parsing() {
        let args = vec!["pdsh", "-w", "host1,host2", "uptime"];
        let cli = PdshCli::parse_from_args(args);

        assert_eq!(cli.hosts, Some("host1,host2".to_string()));
        assert_eq!(cli.command, vec!["uptime"]);
        assert_eq!(cli.fanout, 32); // default
        assert!(!cli.no_prefix);
        assert!(!cli.batch);
        assert!(!cli.fail_fast);
        assert!(!cli.query);
    }

    #[test]
    fn test_pdsh_cli_all_options() {
        let args = vec![
            "pdsh",
            "-w",
            "host1,host2",
            "-x",
            "badhost",
            "-f",
            "10",
            "-l",
            "admin",
            "-t",
            "30",
            "-u",
            "300",
            "-N",
            "-b",
            "-k",
            "df",
            "-h",
        ];
        let cli = PdshCli::parse_from_args(args);

        assert_eq!(cli.hosts, Some("host1,host2".to_string()));
        assert_eq!(cli.exclude, Some("badhost".to_string()));
        assert_eq!(cli.fanout, 10);
        assert_eq!(cli.user, Some("admin".to_string()));
        assert_eq!(cli.connect_timeout, Some(30));
        assert_eq!(cli.command_timeout, Some(300));
        assert!(cli.no_prefix);
        assert!(cli.batch);
        assert!(cli.fail_fast);
        assert_eq!(cli.command, vec!["df", "-h"]);
    }

    #[test]
    fn test_pdsh_cli_query_mode() {
        let args = vec!["pdsh", "-w", "hosts", "-q"];
        let cli = PdshCli::parse_from_args(args);

        assert!(cli.is_query_mode());
        assert!(cli.command.is_empty());
    }

    #[test]
    fn test_pdsh_cli_any_failure() {
        let args = vec!["pdsh", "-w", "hosts", "-S", "cmd"];
        let cli = PdshCli::parse_from_args(args);

        assert!(cli.any_failure);
    }

    #[test]
    fn test_has_command() {
        let args_with_cmd = vec!["pdsh", "-w", "hosts", "uptime"];
        let cli_with_cmd = PdshCli::parse_from_args(args_with_cmd);
        assert!(cli_with_cmd.has_command());

        let args_without_cmd = vec!["pdsh", "-w", "hosts", "-q"];
        let cli_without_cmd = PdshCli::parse_from_args(args_without_cmd);
        assert!(!cli_without_cmd.has_command());
    }

    #[test]
    fn test_get_command() {
        let args = vec!["pdsh", "-w", "hosts", "echo", "hello", "world"];
        let cli = PdshCli::parse_from_args(args);

        assert_eq!(cli.get_command(), "echo hello world");
    }

    #[test]
    fn test_remove_pdsh_compat_flag() {
        let args = vec![
            "bssh".to_string(),
            "--pdsh-compat".to_string(),
            "-w".to_string(),
            "hosts".to_string(),
            "cmd".to_string(),
        ];
        let filtered = remove_pdsh_compat_flag(&args);

        assert_eq!(
            filtered,
            vec![
                "bssh".to_string(),
                "-w".to_string(),
                "hosts".to_string(),
                "cmd".to_string()
            ]
        );
    }

    #[test]
    fn test_has_pdsh_compat_flag() {
        let args_with = vec![
            "bssh".to_string(),
            "--pdsh-compat".to_string(),
            "-w".to_string(),
            "hosts".to_string(),
        ];
        assert!(has_pdsh_compat_flag(&args_with));

        let args_without = vec!["bssh".to_string(), "-w".to_string(), "hosts".to_string()];
        assert!(!has_pdsh_compat_flag(&args_without));
    }

    #[test]
    fn test_to_bssh_cli_basic() {
        let args = vec!["pdsh", "-w", "host1,host2", "uptime"];
        let pdsh_cli = PdshCli::parse_from_args(args);
        let bssh_cli = pdsh_cli.to_bssh_cli();

        assert_eq!(
            bssh_cli.hosts,
            Some(vec!["host1".to_string(), "host2".to_string()])
        );
        assert_eq!(bssh_cli.command_args, vec!["uptime"]);
        assert_eq!(bssh_cli.parallel, 32); // default fanout
        assert!(bssh_cli.pdsh_compat);
    }

    #[test]
    fn test_to_bssh_cli_all_options() {
        let args = vec![
            "pdsh",
            "-w",
            "host1,host2",
            "-x",
            "badhost",
            "-f",
            "10",
            "-l",
            "admin",
            "-t",
            "60",
            "-u",
            "600",
            "-N",
            "-b",
            "-k",
            "-S",
            "df",
            "-h",
        ];
        let pdsh_cli = PdshCli::parse_from_args(args);
        let bssh_cli = pdsh_cli.to_bssh_cli();

        // Hosts mapping
        assert_eq!(
            bssh_cli.hosts,
            Some(vec!["host1".to_string(), "host2".to_string()])
        );
        // Exclude mapping
        assert_eq!(bssh_cli.exclude, Some(vec!["badhost".to_string()]));
        // Fanout to parallel
        assert_eq!(bssh_cli.parallel, 10);
        // User mapping
        assert_eq!(bssh_cli.user, Some("admin".to_string()));
        // Connect timeout
        assert_eq!(bssh_cli.connect_timeout, 60);
        // Command timeout
        assert_eq!(bssh_cli.timeout, Some(600));
        // No prefix flag
        assert!(bssh_cli.no_prefix);
        // Batch flag
        assert!(bssh_cli.batch);
        // Fail fast flag
        assert!(bssh_cli.fail_fast);
        // Any failure flag
        assert!(bssh_cli.any_failure);
        // Command
        assert_eq!(bssh_cli.command_args, vec!["df", "-h"]);
    }

    #[test]
    fn test_to_bssh_cli_defaults() {
        let args = vec!["pdsh", "-w", "hosts", "cmd"];
        let pdsh_cli = PdshCli::parse_from_args(args);
        let bssh_cli = pdsh_cli.to_bssh_cli();

        // Default connect timeout (30s)
        assert_eq!(bssh_cli.connect_timeout, 30);
        // Default command timeout (None - will use config or 300s default)
        assert_eq!(bssh_cli.timeout, None);
        // Default parallel (32 from pdsh fanout)
        assert_eq!(bssh_cli.parallel, 32);
        // Default strict host key checking
        assert_eq!(bssh_cli.strict_host_key_checking, "accept-new");
    }

    #[test]
    fn test_to_bssh_cli_host_splitting() {
        let args = vec!["pdsh", "-w", "host1, host2 , host3", "cmd"];
        let pdsh_cli = PdshCli::parse_from_args(args);
        let bssh_cli = pdsh_cli.to_bssh_cli();

        // Should trim whitespace
        assert_eq!(
            bssh_cli.hosts,
            Some(vec![
                "host1".to_string(),
                "host2".to_string(),
                "host3".to_string()
            ])
        );
    }

    // Note: is_pdsh_compat_mode() tests are in mode_detection_tests.rs
    // since they require environment manipulation that can interfere with other tests
}

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "bssh",
    version,
    about = "Backend.AI SSH - Parallel command execution across cluster nodes",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(
        short = 'H',
        long,
        value_delimiter = ',',
        help = "Comma-separated list of hosts (user@host:port format)"
    )]
    pub hosts: Option<Vec<String>>,

    #[arg(short = 'c', long, help = "Cluster name from configuration file")]
    pub cluster: Option<String>,

    #[arg(
        long,
        default_value = "~/.bssh/config.yaml",
        help = "Configuration file path"
    )]
    pub config: PathBuf,

    #[arg(short = 'u', long, help = "Default username for SSH connections")]
    pub user: Option<String>,

    #[arg(short = 'i', long, help = "SSH private key file path")]
    pub identity: Option<PathBuf>,

    #[arg(
        short = 'p',
        long,
        default_value = "10",
        help = "Maximum parallel connections"
    )]
    pub parallel: usize,

    #[arg(long, help = "Output directory for command results")]
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
        help = "Host key checking mode (yes/no/accept-new)"
    )]
    pub strict_host_key_checking: String,

    #[arg(trailing_var_arg = true, help = "Command to execute on remote hosts")]
    pub command_args: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Execute a command on specified hosts")]
    Exec {
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    #[command(about = "List available clusters")]
    List,

    #[command(about = "Test connectivity to hosts")]
    Ping,

    #[command(about = "Copy files to remote hosts")]
    Copy {
        #[arg(help = "Source file path")]
        source: PathBuf,

        #[arg(help = "Destination path on remote hosts")]
        destination: String,
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

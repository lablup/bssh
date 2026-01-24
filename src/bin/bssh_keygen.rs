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

//! bssh-keygen binary - SSH key pair generation tool
//!
//! This binary provides a command-line interface for generating SSH key pairs
//! in OpenSSH format, supporting Ed25519 (recommended) and RSA algorithms.
//!
//! # Usage
//!
//! ```bash
//! # Generate Ed25519 key (default, recommended)
//! bssh-keygen
//!
//! # Generate Ed25519 key with custom output path
//! bssh-keygen -f ~/.ssh/my_key
//!
//! # Generate RSA key with 4096 bits
//! bssh-keygen -t rsa -b 4096
//!
//! # Generate key with custom comment
//! bssh-keygen -C "user@hostname"
//! ```

use anyhow::{Context, Result};
use bssh::keygen;
use bssh::utils::logging;
use clap::{ArgAction, Parser};
use std::io::{self, Write};
use std::path::PathBuf;

/// Backend.AI SSH Key Generator - Generate SSH key pairs in OpenSSH format
#[derive(Parser, Debug)]
#[command(name = "bssh-keygen")]
#[command(version)]
#[command(about = "Generate SSH key pairs in OpenSSH format", long_about = None)]
struct Cli {
    /// Key type: ed25519 (recommended) or rsa
    #[arg(
        short = 't',
        long = "type",
        default_value = "ed25519",
        value_name = "TYPE"
    )]
    key_type: String,

    /// Output file path (default: ~/.ssh/id_<type>)
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    output: Option<PathBuf>,

    /// RSA key bits (only for RSA, minimum 2048)
    #[arg(
        short = 'b',
        long = "bits",
        default_value = "4096",
        value_name = "BITS"
    )]
    bits: u32,

    /// Comment for the key
    #[arg(short = 'C', long = "comment", value_name = "COMMENT")]
    comment: Option<String>,

    /// Overwrite existing files without prompting
    #[arg(short = 'y', long = "yes")]
    yes: bool,

    /// Quiet mode (no output except errors)
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbosity (only if not quiet)
    if !cli.quiet {
        logging::init_logging_console_only(cli.verbose);
    }

    // Validate key type early
    let key_type = cli.key_type.to_lowercase();
    if !matches!(key_type.as_str(), "ed25519" | "rsa") {
        anyhow::bail!(
            "Unknown key type: '{}'. Supported types: ed25519 (recommended), rsa",
            cli.key_type
        );
    }

    // Determine output path
    let output = match cli.output {
        Some(path) => path,
        None => {
            let home = dirs::home_dir().context("Cannot determine home directory")?;
            let ssh_dir = home.join(".ssh");

            // Ensure .ssh directory exists with proper permissions
            if !ssh_dir.exists() {
                create_ssh_directory(&ssh_dir)?;
            }

            match key_type.as_str() {
                "ed25519" => ssh_dir.join("id_ed25519"),
                "rsa" => ssh_dir.join("id_rsa"),
                _ => unreachable!(),
            }
        }
    };

    // Ensure parent directory exists
    if let Some(parent) = output.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }
    }

    // Check if file exists and prompt for overwrite
    if output.exists() && !cli.yes {
        print!("{} already exists. Overwrite? (y/n) ", output.display());
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            if !cli.quiet {
                println!("Aborted.");
            }
            return Ok(());
        }
    }

    // Generate key
    let result = match key_type.as_str() {
        "ed25519" => keygen::generate_ed25519(&output, cli.comment.as_deref())?,
        "rsa" => keygen::generate_rsa(&output, cli.bits, cli.comment.as_deref())?,
        _ => unreachable!(),
    };

    // Display output
    if !cli.quiet {
        println!("Your identification has been saved in {}", output.display());
        println!("Your public key has been saved in {}.pub", output.display());
        println!("The key fingerprint is:");
        println!("{}", result.fingerprint);

        // Display public key for convenience
        println!("\nThe key's randomart image is not displayed (not implemented).");
        println!("\nPublic key:");
        println!("{}", result.public_key_openssh);
    }

    Ok(())
}

/// Create the .ssh directory with proper permissions (0700)
fn create_ssh_directory(path: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::DirBuilderExt;

        fs::DirBuilder::new()
            .mode(0o700) // drwx------ (owner only)
            .create(path)
            .with_context(|| format!("Failed to create .ssh directory: {}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create .ssh directory: {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use tempfile::tempdir;

    #[test]
    fn test_cli_parsing() {
        // Verify CLI structure is valid
        Cli::command().debug_assert();
    }

    #[test]
    fn test_cli_defaults() {
        let cli = Cli::try_parse_from(["bssh-keygen"]).unwrap();
        assert_eq!(cli.key_type, "ed25519");
        assert_eq!(cli.bits, 4096);
        assert!(cli.output.is_none());
        assert!(cli.comment.is_none());
        assert!(!cli.yes);
        assert!(!cli.quiet);
    }

    #[test]
    fn test_cli_ed25519() {
        let cli = Cli::try_parse_from(["bssh-keygen", "-t", "ed25519"]).unwrap();
        assert_eq!(cli.key_type, "ed25519");
    }

    #[test]
    fn test_cli_rsa() {
        let cli = Cli::try_parse_from(["bssh-keygen", "-t", "rsa", "-b", "2048"]).unwrap();
        assert_eq!(cli.key_type, "rsa");
        assert_eq!(cli.bits, 2048);
    }

    #[test]
    fn test_cli_output_file() {
        let cli = Cli::try_parse_from(["bssh-keygen", "-f", "/tmp/my_key"]).unwrap();
        assert_eq!(cli.output, Some(PathBuf::from("/tmp/my_key")));
    }

    #[test]
    fn test_cli_comment() {
        let cli = Cli::try_parse_from(["bssh-keygen", "-C", "user@host"]).unwrap();
        assert_eq!(cli.comment, Some("user@host".to_string()));
    }

    #[test]
    fn test_cli_flags() {
        let cli = Cli::try_parse_from(["bssh-keygen", "-y", "-q"]).unwrap();
        assert!(cli.yes);
        assert!(cli.quiet);
    }

    #[test]
    fn test_cli_verbose() {
        let cli = Cli::try_parse_from(["bssh-keygen", "-vvv"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn test_cli_full_options() {
        let cli = Cli::try_parse_from([
            "bssh-keygen",
            "-t",
            "rsa",
            "-b",
            "4096",
            "-f",
            "/tmp/test_key",
            "-C",
            "test@example.com",
            "-y",
            "-v",
        ])
        .unwrap();

        assert_eq!(cli.key_type, "rsa");
        assert_eq!(cli.bits, 4096);
        assert_eq!(cli.output, Some(PathBuf::from("/tmp/test_key")));
        assert_eq!(cli.comment, Some("test@example.com".to_string()));
        assert!(cli.yes);
        assert!(!cli.quiet);
        assert_eq!(cli.verbose, 1);
    }

    #[test]
    fn test_cli_long_options() {
        let cli = Cli::try_parse_from([
            "bssh-keygen",
            "--type",
            "ed25519",
            "--file",
            "/tmp/key",
            "--comment",
            "my key",
            "--yes",
            "--quiet",
        ])
        .unwrap();

        assert_eq!(cli.key_type, "ed25519");
        assert_eq!(cli.output, Some(PathBuf::from("/tmp/key")));
        assert_eq!(cli.comment, Some("my key".to_string()));
        assert!(cli.yes);
        assert!(cli.quiet);
    }

    #[test]
    fn test_create_ssh_directory() {
        let temp_dir = tempdir().unwrap();
        let ssh_dir = temp_dir.path().join(".ssh");

        let result = create_ssh_directory(&ssh_dir);
        assert!(result.is_ok());
        assert!(ssh_dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&ssh_dir).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o777, 0o700);
        }
    }
}

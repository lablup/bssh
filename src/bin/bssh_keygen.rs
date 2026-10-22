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

/// Broadcast SSH Key Generator - Generate SSH key pairs in OpenSSH format
#[derive(Parser, Debug)]
#[command(name = "bssh-keygen")]
#[command(version)]
#[command(about = "Generate SSH key pairs in OpenSSH format", long_about = None)]
struct Cli {
    /// Key type: ed25519 (recommended), rsa, ed25519-sk, or ecdsa-sk
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

    /// Download resident security keys to the current directory (prompts for PIN)
    #[arg(short = 'K', long = "download-resident", conflicts_with = "output")]
    download_resident: bool,

    /// Security-key provider: internal (default), library path, or $VARIABLE
    #[arg(short = 'w', long = "provider", value_name = "PROVIDER")]
    provider: Option<String>,

    /// Security-key option: application=ssh:NAME, resident, verify-required,
    /// no-touch-required, user=NAME, challenge=FILE, or device=PATH.
    /// write-attestation=FILE is explicitly unsupported.
    #[arg(short = 'O', value_name = "OPTION")]
    sk_options: Vec<String>,

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

    if cli.download_resident || matches!(cli.key_type.as_str(), "ed25519-sk" | "ecdsa-sk") {
        return run_security_key(&cli);
    }
    anyhow::ensure!(
        cli.provider.is_none() && cli.sk_options.is_empty(),
        "-w and -O require a security-key type or -K"
    );

    // Validate key type early
    let key_type = cli.key_type.to_lowercase();
    if !matches!(key_type.as_str(), "ed25519" | "rsa") {
        anyhow::bail!(
            "Unknown key type: '{}'. Supported types: ed25519 (recommended), rsa, ed25519-sk, ecdsa-sk",
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
    if let Some(parent) = output.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
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

fn confirm_security_key_output(path: &std::path::Path, yes: bool) -> Result<Option<bool>> {
    use keygen::security_key::{check_output, public_path};
    // Inspect both files, including dangling links, before any prompt.
    check_output(path, true)?;
    if yes {
        return Ok(Some(true));
    }
    if !path.exists() && !public_path(path).exists() {
        return Ok(Some(false));
    }
    print!(
        "{} or its public key already exists. Overwrite? (y/n) ",
        path.display()
    );
    io::stdout().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    Ok(response.trim().eq_ignore_ascii_case("y").then_some(true))
}

fn run_security_key(cli: &Cli) -> Result<()> {
    use bssh::ssh::security_key::{
        SecurityKeyError, SkAlgorithm, open_provider, resolve_provider_from_env,
    };
    use keygen::security_key::{self as sk, EnrollmentOptions};
    use zeroize::Zeroizing;

    let options = EnrollmentOptions::parse(&cli.sk_options)?;
    if cli.download_resident {
        anyhow::ensure!(
            cli.sk_options
                .iter()
                .all(|option| option.starts_with("device=")),
            "-K only accepts the device security-key option"
        );
        let provider = open_provider(&resolve_provider_from_env(cli.provider.as_deref()))?;
        let pin = Zeroizing::new(rpassword::prompt_password("Enter PIN for authenticator: ")?);
        if !cli.quiet {
            println!("You may need to touch your authenticator to authorize key download.");
        }
        let keys = provider.load_resident_keys(Some(pin.as_str()), options.device.as_deref())?;
        drop(pin);
        if keys.is_empty() && !cli.quiet {
            println!("No keys to download");
        }
        let directory = std::env::current_dir()?;
        let names = sk::resident_filenames(&keys);
        for (key, name) in keys.into_iter().zip(names) {
            let path = directory.join(name);
            let Some(overwrite) = confirm_security_key_output(&path, cli.yes)? else {
                break;
            };
            let saved = sk::save_resident_at(key, &path, overwrite)?;
            if !cli.quiet {
                println!(
                    "Saved security key to {}\n{}",
                    saved.path.display(),
                    saved.fingerprint
                );
            }
        }
        return Ok(());
    }
    let (algorithm, basename) = match cli.key_type.as_str() {
        "ed25519-sk" => (SkAlgorithm::Ed25519, "id_ed25519_sk"),
        "ecdsa-sk" => (SkAlgorithm::EcdsaSha2NistP256, "id_ecdsa_sk"),
        _ => anyhow::bail!("Unsupported security-key type"),
    };
    let output = match &cli.output {
        Some(path) => path.clone(),
        None => {
            let directory = dirs::home_dir()
                .context("Cannot determine home directory")?
                .join(".ssh");
            if !directory.exists() {
                create_ssh_directory(&directory)?;
            }
            directory.join(basename)
        }
    };
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let Some(overwrite) = confirm_security_key_output(&output, cli.yes)? else {
        return Ok(());
    };
    let challenge = options.challenge_bytes()?;
    let request = options.request(algorithm, &challenge);
    request.validate()?;
    let provider = open_provider(&resolve_provider_from_env(cli.provider.as_deref()))?;
    if !cli.quiet {
        println!("You may need to touch your authenticator to authorize key generation.");
    }
    let result = sk::generate(
        provider.as_ref(),
        &request,
        None,
        &output,
        cli.comment.as_deref(),
        overwrite,
    );
    let saved = match result {
        Err(error)
            if matches!(
                error.downcast_ref::<SecurityKeyError>(),
                Some(SecurityKeyError::PinRequired)
            ) =>
        {
            let pin = Zeroizing::new(rpassword::prompt_password("Enter PIN for authenticator: ")?);
            sk::generate(
                provider.as_ref(),
                &request,
                Some(pin.as_str()),
                &output,
                cli.comment.as_deref(),
                overwrite,
            )?
        }
        result => result?,
    };
    if !cli.quiet {
        println!(
            "Your identification has been saved in {}",
            saved.path.display()
        );
        println!(
            "Your public key has been saved in {}",
            sk::public_path(&saved.path).display()
        );
        println!(
            "The key fingerprint is:\n{}\n\nPublic key:\n{}",
            saved.fingerprint, saved.public_key_openssh
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/keygen.rs"]
mod tests;

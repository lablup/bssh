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

//! bssh-server binary - SSH server for containers
//!
//! This binary provides a command-line interface for managing the bssh SSH server.

use anyhow::{Context, Result};
use bssh::server::config::{generate_config_template, load_config, ServerFileConfig};
use bssh::server::BsshServer;
use bssh::utils::logging;
use clap::{ArgAction, Parser, Subcommand};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

/// Backend.AI SSH Server - A lightweight SSH server for containers
#[derive(Parser, Debug)]
#[command(name = "bssh-server")]
#[command(version)]
#[command(about = "Backend.AI SSH Server - A lightweight SSH server for containers", long_about = None)]
struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    command: Option<Commands>,

    /// Configuration file path
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Bind address
    #[arg(short = 'b', long, global = true, value_name = "ADDR")]
    bind_address: Option<String>,

    /// Port to listen on
    #[arg(short, long, global = true, value_name = "PORT")]
    port: Option<u16>,

    /// Host key file(s)
    #[arg(short = 'k', long = "host-key", global = true, value_name = "FILE")]
    host_keys: Vec<PathBuf>,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,

    /// Run in foreground (don't daemonize)
    #[arg(short = 'D', long, global = true)]
    foreground: bool,

    /// PID file path
    #[arg(long, global = true, value_name = "FILE")]
    pid_file: Option<PathBuf>,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the SSH server (default)
    Run,

    /// Generate a configuration file template
    GenConfig {
        /// Output path (stdout if not specified)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Hash a password for configuration
    HashPassword,

    /// Check configuration file for errors
    CheckConfig,

    /// Generate host keys
    GenHostKey {
        /// Key type (ed25519 or rsa)
        #[arg(short = 't', long, default_value = "ed25519", value_name = "TYPE")]
        key_type: String,

        /// Output file path
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// RSA key bits (only for rsa type)
        #[arg(long, default_value = "4096", value_name = "BITS")]
        bits: u32,
    },

    /// Show version and build information
    Version,
}

/// CLI arguments for configuration overrides
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub bind_address: Option<String>,
    pub port: Option<u16>,
    pub host_keys: Vec<PathBuf>,
}

impl From<&Cli> for CliArgs {
    fn from(cli: &Cli) -> Self {
        Self {
            bind_address: cli.bind_address.clone(),
            port: cli.port,
            host_keys: cli.host_keys.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    logging::init_logging_console_only(cli.verbose);

    // Execute the appropriate command
    match cli.command {
        None | Some(Commands::Run) => run_server(&cli).await,
        Some(Commands::GenConfig { output }) => gen_config(output),
        Some(Commands::HashPassword) => hash_password().await,
        Some(Commands::CheckConfig) => check_config(&cli),
        Some(Commands::GenHostKey {
            key_type,
            output,
            bits,
        }) => gen_host_key(&key_type, &output, bits),
        Some(Commands::Version) => show_version(),
    }
}

/// Run the SSH server
async fn run_server(cli: &Cli) -> Result<()> {
    tracing::info!("Starting bssh-server");

    // Load configuration from file
    let mut file_config = if let Some(config_path) = &cli.config {
        load_config(Some(config_path))
            .with_context(|| format!("Failed to load config from {}", config_path.display()))?
    } else {
        load_config(None).unwrap_or_else(|_| {
            tracing::warn!("No configuration file found, using defaults");
            ServerFileConfig::default()
        })
    };

    // Apply CLI overrides
    if let Some(bind_address) = &cli.bind_address {
        file_config.server.bind_address = bind_address.clone();
    }
    if let Some(port) = cli.port {
        file_config.server.port = port;
    }
    if !cli.host_keys.is_empty() {
        file_config.server.host_keys = cli.host_keys.clone();
    }

    // Convert to ServerConfig
    let config = file_config.into_server_config();

    tracing::info!(
        address = %config.listen_address,
        host_keys = %config.host_keys.len(),
        "Server configuration loaded"
    );

    // Validate that we have at least one host key
    if !config.has_host_keys() {
        anyhow::bail!(
            "No host keys configured. Use -k/--host-key or configure in config file. \
             Generate keys with: bssh-server gen-host-key -o /path/to/key"
        );
    }

    // Write PID file if requested
    if let Some(pid_file) = &cli.pid_file {
        write_pid_file(pid_file)?;
    }

    // Create and run server
    let server = BsshServer::new(config);

    // Setup signal handlers for graceful shutdown
    let shutdown_signal = setup_signal_handlers()?;

    tracing::info!("SSH server started successfully");

    // Run server with graceful shutdown
    tokio::select! {
        result = server.run() => {
            result.context("Server error")?;
        }
        _ = shutdown_signal => {
            tracing::info!("Received shutdown signal");
        }
    }

    // Cleanup PID file
    if let Some(pid_file) = &cli.pid_file {
        let _ = fs::remove_file(pid_file);
    }

    tracing::info!("Server stopped");
    Ok(())
}

/// Generate a configuration file template
fn gen_config(output: Option<PathBuf>) -> Result<()> {
    let template = generate_config_template();

    if let Some(path) = output {
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::os::unix::fs::OpenOptionsExt;

            // Write config file with restrictive permissions (0600)
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .context("Failed to create configuration file")?;

            file.write_all(template.as_bytes())
                .context("Failed to write configuration file")?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&path, &template).context("Failed to write configuration file")?;
        }

        println!("Configuration template written to {}", path.display());
        #[cfg(unix)]
        println!("File permissions set to 0600 (owner read/write only)");
    } else {
        print!("{}", template);
    }

    Ok(())
}

/// Hash a password for configuration
async fn hash_password() -> Result<()> {
    use bssh::server::auth::hash_password as generate_hash;
    use rpassword::read_password;

    print!("Enter password: ");
    io::stdout().flush()?;
    let password = read_password()?;

    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    // Warn about weak passwords (but still allow them)
    if password.len() < 8 {
        println!("\n Warning: Password is shorter than 8 characters.");
        println!("   This is considered weak and may be easily compromised.");
        println!("   Consider using a longer password for better security.\n");
    }

    print!("Confirm password: ");
    io::stdout().flush()?;
    let confirm = read_password()?;

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    // Use Argon2id for password hashing (recommended algorithm)
    let hash = generate_hash(&password).context("Failed to hash password")?;

    println!("\nPassword hash (use in configuration):");
    println!("{}", hash);
    println!("\nExample configuration:");
    println!("auth:");
    println!("  methods:");
    println!("    - password");
    println!("  password:");
    println!("    users:");
    println!("      - name: username");
    println!("        password_hash: \"{}\"", hash);
    println!("\nNote: This hash uses Argon2id algorithm (recommended).");
    println!("      bcrypt hashes are also supported for compatibility.");

    Ok(())
}

/// Check configuration file for errors
fn check_config(cli: &Cli) -> Result<()> {
    let config = if let Some(config_path) = &cli.config {
        load_config(Some(config_path))
            .with_context(|| format!("Failed to load config from {}", config_path.display()))?
    } else {
        load_config(None).context("Failed to load configuration")?
    };

    println!("✓ Configuration is valid\n");
    println!("Server Configuration:");
    println!("  Bind address: {}", config.server.bind_address);
    println!("  Port: {}", config.server.port);
    println!("  Host keys: {}", config.server.host_keys.len());
    for key in &config.server.host_keys {
        println!("    - {}", key.display());
    }
    println!("  Max connections: {}", config.server.max_connections);
    println!("  Timeout: {}s", config.server.timeout);
    println!("  Keepalive: {}s", config.server.keepalive_interval);

    println!("\nAuthentication:");
    println!("  Methods: {:?}", config.auth.methods);
    if let Some(pattern) = &config.auth.publickey.authorized_keys_pattern {
        println!("  Authorized keys pattern: {}", pattern);
    }
    if let Some(dir) = &config.auth.publickey.authorized_keys_dir {
        println!("  Authorized keys directory: {}", dir.display());
    }

    println!("\nShell Configuration:");
    println!("  Default shell: {}", config.shell.default.display());
    println!("  Command timeout: {}s", config.shell.command_timeout);
    println!("  Environment variables: {}", config.shell.env.len());

    println!("\nSecurity:");
    println!("  Max auth attempts: {}", config.security.max_auth_attempts);
    println!("  Ban time: {}s", config.security.ban_time);
    println!(
        "  Max sessions per user: {}",
        config.security.max_sessions_per_user
    );
    println!("  Idle timeout: {}s", config.security.idle_timeout);

    if !config.security.allowed_ips.is_empty() {
        println!("  Allowed IPs: {:?}", config.security.allowed_ips);
    }
    if !config.security.blocked_ips.is_empty() {
        println!("  Blocked IPs: {:?}", config.security.blocked_ips);
    }

    Ok(())
}

/// Generate SSH host keys
fn gen_host_key(key_type: &str, output: &PathBuf, _bits: u32) -> Result<()> {
    use russh::keys::PrivateKey;
    use ssh_key::LineEnding;

    let key = match key_type.to_lowercase().as_str() {
        "ed25519" => {
            tracing::info!("Generating Ed25519 host key");
            PrivateKey::random(&mut rand::thread_rng(), russh::keys::Algorithm::Ed25519)
                .context("Failed to generate Ed25519 key")?
        }
        "rsa" => {
            if _bits < 2048 {
                anyhow::bail!("RSA key size must be at least 2048 bits");
            }
            tracing::info!(bits = _bits, "Generating RSA host key");
            PrivateKey::random(
                &mut rand::thread_rng(),
                russh::keys::Algorithm::Rsa {
                    hash: Some(russh::keys::HashAlg::Sha256),
                },
            )
            .context("Failed to generate RSA key")?
        }
        _ => {
            anyhow::bail!("Unknown key type: {}. Use 'ed25519' or 'rsa'", key_type);
        }
    };

    // Write the key atomically with correct permissions from the start (prevents race condition)
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let key_data = key.to_openssh(LineEnding::LF)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // Set permissions atomically
            .open(output)
            .context("Failed to create host key file")?;

        file.write_all(key_data.as_bytes())
            .context("Failed to write host key")?;
    }

    #[cfg(not(unix))]
    {
        // On non-Unix systems, fall back to default method
        key.write_openssh_file(output, LineEnding::LF)
            .context("Failed to write host key")?;
    }

    println!("✓ Host key generated: {}", output.display());
    println!("\nAdd this to your configuration file or use -k/--host-key argument:");
    println!("  --host-key {}", output.display());
    println!("\nOr in YAML config:");
    println!("server:");
    println!("  host_keys:");
    println!("    - {}", output.display());

    Ok(())
}

/// Show version and build information
fn show_version() -> Result<()> {
    println!("bssh-server {}", env!("CARGO_PKG_VERSION"));
    println!("Backend.AI SSH Server");
    println!();
    println!("A lightweight SSH server for containers");
    println!();
    println!("Homepage: {}", env!("CARGO_PKG_REPOSITORY"));

    Ok(())
}

/// Setup signal handlers for graceful shutdown
fn setup_signal_handlers() -> Result<impl std::future::Future<Output = ()>> {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    Ok(async move {
        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("Received SIGINT (Ctrl+C)");
            }
            _ = terminate => {
                tracing::info!("Received SIGTERM");
            }
        }
    })
}

/// Write the current process ID to a PID file
fn write_pid_file(path: &PathBuf) -> Result<()> {
    // Check if PID file already exists and refers to a running process
    if path.exists() {
        if let Ok(existing_pid_str) = fs::read_to_string(path) {
            if let Ok(existing_pid) = existing_pid_str.trim().parse::<i32>() {
                // Check if process is still running
                #[cfg(unix)]
                {
                    use nix::sys::signal::kill;
                    use nix::unistd::Pid;

                    let pid = Pid::from_raw(existing_pid);
                    // Use signal 0 (None) to check if process exists without sending actual signal
                    if kill(pid, None).is_ok() {
                        anyhow::bail!(
                            "Another instance is already running with PID {}. \
                             If this is incorrect, remove {} and try again.",
                            existing_pid,
                            path.display()
                        );
                    }
                }

                #[cfg(not(unix))]
                {
                    // On non-Unix systems, warn but allow overwrite
                    tracing::warn!(
                        "PID file exists with PID {}. Overwriting (process check not available on this platform).",
                        existing_pid
                    );
                }
            }
        }
    }

    let pid = std::process::id();
    fs::write(path, pid.to_string()).context("Failed to write PID file")?;
    tracing::debug!(path = %path.display(), pid = pid, "PID file written");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cli_parsing() {
        use clap::CommandFactory;

        // Verify CLI structure is valid
        Cli::command().debug_assert();
    }

    #[test]
    fn test_cli_args_conversion() {
        let cli = Cli {
            command: None,
            config: None,
            bind_address: Some("127.0.0.1".to_string()),
            port: Some(2222),
            host_keys: vec![PathBuf::from("/test/key")],
            verbose: 1,
            foreground: true,
            pid_file: None,
        };

        let args: CliArgs = (&cli).into();
        assert_eq!(args.bind_address, Some("127.0.0.1".to_string()));
        assert_eq!(args.port, Some(2222));
        assert_eq!(args.host_keys.len(), 1);
    }

    #[test]
    fn test_cli_args_conversion_empty() {
        let cli = Cli {
            command: None,
            config: None,
            bind_address: None,
            port: None,
            host_keys: vec![],
            verbose: 0,
            foreground: false,
            pid_file: None,
        };

        let args: CliArgs = (&cli).into();
        assert_eq!(args.bind_address, None);
        assert_eq!(args.port, None);
        assert!(args.host_keys.is_empty());
    }

    #[test]
    fn test_cli_args_conversion_multiple_host_keys() {
        let cli = Cli {
            command: None,
            config: None,
            bind_address: None,
            port: None,
            host_keys: vec![
                PathBuf::from("/test/key1"),
                PathBuf::from("/test/key2"),
                PathBuf::from("/test/key3"),
            ],
            verbose: 0,
            foreground: false,
            pid_file: None,
        };

        let args: CliArgs = (&cli).into();
        assert_eq!(args.host_keys.len(), 3);
    }

    #[test]
    fn test_cli_parsing_with_subcommand() {
        use clap::Parser;

        // Test run subcommand
        let args = Cli::try_parse_from(["bssh-server", "run"]).unwrap();
        assert!(matches!(args.command, Some(Commands::Run)));

        // Test gen-config subcommand
        let args = Cli::try_parse_from(["bssh-server", "gen-config"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::GenConfig { output: None })
        ));

        // Test gen-config with output
        let args =
            Cli::try_parse_from(["bssh-server", "gen-config", "-o", "/tmp/config.yaml"]).unwrap();
        if let Some(Commands::GenConfig { output }) = args.command {
            assert_eq!(output, Some(PathBuf::from("/tmp/config.yaml")));
        } else {
            panic!("Expected GenConfig command");
        }

        // Test hash-password subcommand
        let args = Cli::try_parse_from(["bssh-server", "hash-password"]).unwrap();
        assert!(matches!(args.command, Some(Commands::HashPassword)));

        // Test check-config subcommand
        let args = Cli::try_parse_from(["bssh-server", "check-config"]).unwrap();
        assert!(matches!(args.command, Some(Commands::CheckConfig)));

        // Test version subcommand
        let args = Cli::try_parse_from(["bssh-server", "version"]).unwrap();
        assert!(matches!(args.command, Some(Commands::Version)));
    }

    #[test]
    fn test_cli_parsing_gen_host_key() {
        use clap::Parser;

        // Test gen-host-key with required output
        let args =
            Cli::try_parse_from(["bssh-server", "gen-host-key", "-o", "/tmp/host_key"]).unwrap();
        if let Some(Commands::GenHostKey {
            key_type,
            output,
            bits,
        }) = args.command
        {
            assert_eq!(key_type, "ed25519"); // default
            assert_eq!(output, PathBuf::from("/tmp/host_key"));
            assert_eq!(bits, 4096); // default
        } else {
            panic!("Expected GenHostKey command");
        }

        // Test gen-host-key with all options
        let args = Cli::try_parse_from([
            "bssh-server",
            "gen-host-key",
            "-t",
            "rsa",
            "-o",
            "/tmp/host_key",
            "--bits",
            "2048",
        ])
        .unwrap();
        if let Some(Commands::GenHostKey {
            key_type,
            output,
            bits,
        }) = args.command
        {
            assert_eq!(key_type, "rsa");
            assert_eq!(output, PathBuf::from("/tmp/host_key"));
            assert_eq!(bits, 2048);
        } else {
            panic!("Expected GenHostKey command");
        }
    }

    #[test]
    fn test_cli_global_options() {
        use clap::Parser;

        // Test global options
        let args = Cli::try_parse_from([
            "bssh-server",
            "-c",
            "/etc/bssh/config.yaml",
            "-b",
            "192.168.1.1",
            "-p",
            "2222",
            "-k",
            "/etc/bssh/key1",
            "-k",
            "/etc/bssh/key2",
            "-vvv",
            "-D",
            "--pid-file",
            "/var/run/bssh.pid",
            "run",
        ])
        .unwrap();

        assert_eq!(args.config, Some(PathBuf::from("/etc/bssh/config.yaml")));
        assert_eq!(args.bind_address, Some("192.168.1.1".to_string()));
        assert_eq!(args.port, Some(2222));
        assert_eq!(args.host_keys.len(), 2);
        assert_eq!(args.verbose, 3);
        assert!(args.foreground);
        assert_eq!(args.pid_file, Some(PathBuf::from("/var/run/bssh.pid")));
    }

    #[test]
    fn test_gen_config_to_stdout() {
        // gen_config with None output should print to stdout (captured by the function)
        let result = gen_config(None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_gen_config_to_file() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("server.yaml");

        let result = gen_config(Some(config_path.clone()));
        assert!(result.is_ok());

        // Verify file was created
        assert!(config_path.exists());

        // Verify file has content
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(!content.is_empty());
        assert!(content.contains("server:"));
        assert!(content.contains("bind_address"));
    }

    #[test]
    #[cfg(unix)]
    fn test_gen_config_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("server.yaml");

        let result = gen_config(Some(config_path.clone()));
        assert!(result.is_ok());

        // Verify file permissions are 0600
        let metadata = fs::metadata(&config_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_show_version() {
        let result = show_version();
        assert!(result.is_ok());
    }

    #[test]
    fn test_gen_host_key_ed25519() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("host_key_ed25519");

        let result = gen_host_key("ed25519", &key_path, 4096);
        assert!(result.is_ok());

        // Verify file was created
        assert!(key_path.exists());

        // Verify file has OpenSSH key format
        let content = fs::read_to_string(&key_path).unwrap();
        assert!(content.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(content.contains("-----END OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn test_gen_host_key_rsa() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("host_key_rsa");

        let result = gen_host_key("rsa", &key_path, 2048);
        assert!(result.is_ok());

        // Verify file was created
        assert!(key_path.exists());

        // Verify file has OpenSSH key format
        let content = fs::read_to_string(&key_path).unwrap();
        assert!(content.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(content.contains("-----END OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn test_gen_host_key_invalid_type() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("host_key_invalid");

        let result = gen_host_key("dsa", &key_path, 4096);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown key type"));
    }

    #[test]
    fn test_gen_host_key_rsa_small_bits() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("host_key_rsa_small");

        let result = gen_host_key("rsa", &key_path, 1024);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("RSA key size must be at least 2048"));
    }

    #[test]
    #[cfg(unix)]
    fn test_gen_host_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("host_key_ed25519");

        let result = gen_host_key("ed25519", &key_path, 4096);
        assert!(result.is_ok());

        // Verify file permissions are 0600
        let metadata = fs::metadata(&key_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_gen_host_key_case_insensitive() {
        let temp_dir = tempdir().unwrap();

        // Test uppercase
        let key_path = temp_dir.path().join("host_key_ED25519");
        let result = gen_host_key("ED25519", &key_path, 4096);
        assert!(result.is_ok());

        // Test mixed case
        let key_path = temp_dir.path().join("host_key_Ed25519");
        let result = gen_host_key("Ed25519", &key_path, 4096);
        assert!(result.is_ok());

        // Test RSA uppercase
        let key_path = temp_dir.path().join("host_key_RSA");
        let result = gen_host_key("RSA", &key_path, 2048);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_pid_file() {
        let temp_dir = tempdir().unwrap();
        let pid_path = temp_dir.path().join("test.pid");

        let result = write_pid_file(&pid_path);
        assert!(result.is_ok());

        // Verify file was created with current PID
        let content = fs::read_to_string(&pid_path).unwrap();
        let pid: u32 = content.parse().unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn test_write_pid_file_overwrite_stale() {
        let temp_dir = tempdir().unwrap();
        let pid_path = temp_dir.path().join("test.pid");

        // Write a stale PID (non-existent process)
        // PID 1 is init and always exists, so use a very high unlikely PID
        fs::write(&pid_path, "999999999").unwrap();

        // Should succeed because the process doesn't exist
        let result = write_pid_file(&pid_path);
        assert!(result.is_ok());

        // Verify file was updated with current PID
        let content = fs::read_to_string(&pid_path).unwrap();
        let pid: u32 = content.parse().unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn test_write_pid_file_invalid_content() {
        let temp_dir = tempdir().unwrap();
        let pid_path = temp_dir.path().join("test.pid");

        // Write invalid content
        fs::write(&pid_path, "not-a-pid").unwrap();

        // Should succeed because the content is not a valid PID
        let result = write_pid_file(&pid_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_command_is_run() {
        use clap::Parser;

        // No subcommand should default to run behavior
        let args = Cli::try_parse_from(["bssh-server"]).unwrap();
        assert!(args.command.is_none());
        // In main(), None is treated the same as Some(Commands::Run)
    }
}

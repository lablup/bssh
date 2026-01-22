# bssh Architecture Documentation

## Overview

bssh (Backend.AI SSH / Broadcast SSH) is a high-performance parallel SSH command execution tool with SSH-compatible interface. This document provides a high-level architecture overview. For detailed component documentation, see [docs/architecture/](./docs/architecture/).

### Core Capabilities

- Parallel command execution across multiple nodes
- SSH-compatible command-line interface (drop-in replacement)
- SSH port forwarding (-L, -R, -D/SOCKS proxy)
- SSH jump host support (-J)
- SSH configuration file parsing (-F)
- Interactive PTY sessions with single/multiplex modes
- SFTP file transfers (upload/download)
- Backend.AI cluster auto-detection
- pdsh compatibility mode

## System Architecture

```
        ┌─────────────────────────────────────────────────────────┐
        │                     CLI Interface                       │
        │                       (main.rs)                         │
        │        (-L, -R, -D, -J, -F, -t/T, SSH-compatible)       │
        └────────────────────────────┬────────────────────────────┘
                                     │
        ┌─────────────┬──────────────┼──────────────┬─────────────┐
        ▼             ▼              ▼              ▼             ▼
┌──────────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────┐
│   Commands   │ │  Config   │ │  Utils    │ │Forwarding │ │   Jump   │
│   Module     │ │  Manager  │ │  Module   │ │  Manager  │ │   Host   │
│ (commands/*) │ │(config.rs)│ │ (utils/*) │ │(forward/*)│ │ (jump/*) │
└──────┬───────┘ └─────┬─────┘ └───────────┘ └───┬───────┘ └───┬──────┘
       │               │                         │             │
       │               ▼                         │             │
       │       ┌──────────────┐                  │             │
       │       │ SSH Config   │                  │             │
       │       │    Parser    │                  │             │
       │       │(ssh_config/*)│                  │             │
       │       └──────────────┘                  │             │
       ▼                                         ▼             ▼
┌──────────────┐                         ┌──────────────┐ ┌──────────────────┐
│   Executor   │◄────────────────────────┤     Node     │ │ Port Forwarders  │
│  (Parallel)  │                         │    Parser    │ │  (L/R/D modes)   │
│(executor.rs) │                         │  (node.rs)   │ │    + Tunnels     │
└──────┬───────┘                         └──────────────┘ └────────┬─────────┘
       │                                                           │
       ├──────────┬────────────┬───────────────────────────────────┘
       ▼          ▼            ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│   SSH    │ │   SSH    │ │   SSH    │
│  Client  │ │  Client  │ │  Client  │
│ (russh)  │ │ (russh)  │ │ (russh)  │
└──────────┘ └──────────┘ └──────────┘
```

## Component Summary

### CLI Interface
**Documentation**: [docs/architecture/cli-interface.md](./docs/architecture/cli-interface.md)

The CLI system provides an SSH-compatible command-line interface with multiple operation modes:

- **Native bssh mode**: Cluster-based parallel execution
- **SSH compatibility mode**: Drop-in SSH replacement for single-host operations
- **pdsh compatibility mode**: Compatible with pdsh command-line syntax

Key features:
- clap v4 with derive macros for type-safe argument parsing
- Backend.AI cluster auto-detection
- Hostlist expression support (pdsh-compatible)
- Mode detection based on binary name, environment, or flags

### Configuration Management
**Documentation**: [docs/architecture/configuration.md](./docs/architecture/configuration.md)

Hierarchical configuration system with multiple sources:

1. Backend.AI environment variables (auto-detection)
2. Current directory (`./config.yaml`)
3. XDG config directory (`~/.config/bssh/config.yaml`)
4. CLI specified path (via `--config` flag)

Features:
- YAML format for human readability
- Environment variable expansion (`${VAR}` syntax)
- SSH configuration file integration
- Platform-specific paths via XDG Base Directory specification

### Parallel Executor
**Documentation**: [docs/architecture/executor.md](./docs/architecture/executor.md)

Tokio-based async executor for concurrent command execution:

- Semaphore-based concurrency limiting
- Two-stage signal handling (default) or batch mode
- Fail-fast mode for early termination on errors
- Real-time progress visualization
- Stream mode for live output

### SSH Client
**Documentation**: [docs/architecture/ssh-client.md](./docs/architecture/ssh-client.md)

Built on russh and russh-sftp with custom tokio_client wrapper:

- Connection management with russh
- Multiple authentication methods (agent, key file, password)
- Host key verification (known_hosts support)
- Command execution with streaming output
- SFTP file transfers (upload/download)
- Connection timeout handling
- Configurable SSH keepalive (ServerAliveInterval, ServerAliveCountMax)

### Terminal User Interface (TUI)
**Documentation**: [docs/architecture/tui.md](./docs/architecture/tui.md)

Interactive terminal interface for real-time command monitoring:

- Multiple views (JobList, JobDetail, Logs, System)
- Keyboard navigation and command palette
- Progress parsing from command output
- Real-time log streaming
- Clean shutdown handling

### Interactive Mode
**Documentation**: [docs/architecture/interactive-mode.md](./docs/architecture/interactive-mode.md)

PTY-based interactive SSH sessions:

- Single-host mode: Direct PTY connection to one host
- Multiplex mode: Broadcast input to multiple hosts
- Terminal escape sequence handling
- Raw mode terminal management
- Signal propagation (Ctrl+C, window resize)

### SSH Configuration Parser
**Documentation**: [docs/architecture/ssh-config-parser.md](./docs/architecture/ssh-config-parser.md)

OpenSSH-compatible configuration file parser:

- Include directive support with recursion limits
- Match directive (Host, LocalUser)
- All standard SSH options
- Configuration caching for performance
- Override chain resolution

### SSH Jump Host Support
**Documentation**: [docs/architecture/ssh-jump-hosts.md](./docs/architecture/ssh-jump-hosts.md)

ProxyJump (-J) support for bastion hosts:

- Multiple jump host chains
- IPv6 and custom port support
- Authentication through jump hosts
- Integration with all bssh operations
- Automatic tunnel management

### SSH Port Forwarding
**Documentation**: [docs/architecture/ssh-port-forwarding.md](./docs/architecture/ssh-port-forwarding.md)

Full port forwarding support:

- Local forwarding (-L): Forward local port to remote
- Remote forwarding (-R): Forward remote port to local
- Dynamic forwarding (-D): SOCKS proxy mode
- Multiple forwarding rules
- Automatic port allocation

### Exit Code Strategy
**Documentation**: [docs/architecture/exit-code-strategy.md](./docs/architecture/exit-code-strategy.md)

MPI-compatible exit code handling:

- **MainRank** (default): Returns main rank's exit code
- **RequireAllSuccess**: Returns 0 only if all nodes succeed
- **MainRankWithFailureCheck**: Hybrid mode for detailed diagnostics
- Automatic main rank detection (Backend.AI integration)
- Preserves actual exit codes (SIGSEGV=139, OOM=137, etc.)

### Shared Module

Common utilities for code reuse between bssh client and server implementations:

- **Validation**: Input validation for usernames, hostnames, paths with security checks
- **Rate Limiting**: Generic token bucket rate limiter for connection/auth throttling
- **Authentication Types**: Common auth result types and user info structures
- **Error Types**: Shared error types for validation, auth, connection, and rate limiting

The `security` and `jump::rate_limiter` modules re-export from shared for backward compatibility.

### SSH Server Module
**Documentation**: [docs/architecture/server-configuration.md](./docs/architecture/server-configuration.md)

SSH server implementation using the russh library for accepting incoming connections:

**Structure** (`src/server/`):
- `mod.rs` - `BsshServer` struct and `russh::server::Server` trait implementation
- `config/mod.rs` - Module exports and backward compatibility layer
- `config/types.rs` - Comprehensive configuration types with serde
- `config/loader.rs` - Config loader with validation and environment overrides
- `handler.rs` - `SshHandler` implementing `russh::server::Handler` trait
- `session.rs` - Session state management (`SessionManager`, `SessionInfo`, `ChannelState`)
- `exec.rs` - Command execution for SSH exec requests
- `auth/` - Authentication provider infrastructure

**Key Components**:

- **BsshServer**: Main server struct managing the SSH server lifecycle
  - Accepts connections on configured address
  - Loads host keys from OpenSSH format files
  - Configures russh with authentication settings
  - Creates shared rate limiter for authentication attempts

- **Server Configuration System**: Dual configuration system for flexibility
  - **Builder API** (`ServerConfig`): Programmatic configuration for embedded use
  - **File-Based** (`ServerFileConfig`): YAML configuration with environment overrides
  - Configuration precedence: CLI > Environment > File > Defaults
  - Configuration validation at startup (host keys, CIDR ranges, paths)
  - Support for BSSH_* environment variable overrides

- **ServerConfig**: Configuration options with builder pattern
  - Host key paths and listen address
  - Connection limits and timeouts
  - Authentication method toggles (password, publickey, keyboard-interactive)
  - Public key authentication configuration (authorized_keys location)
  - Command execution configuration (shell, timeout, allowed/blocked commands)

- **ServerFileConfig**: Comprehensive YAML file configuration
  - Server settings (bind address, port, host keys, keepalive)
  - Authentication (public key, password with inline or file-based users)
  - Shell configuration (default shell, environment, command timeout)
  - SFTP/SCP enablement with optional chroot
  - File transfer filtering rules
  - Audit logging (file, OpenTelemetry, Logstash exporters)
  - Security settings (auth attempts, bans, session limits, IP allowlist/blocklist)

- **SshHandler**: Per-connection handler for SSH protocol events
  - Public key authentication via AuthProvider trait
  - Rate limiting for authentication attempts
  - Channel operations (open, close, EOF, data)
  - PTY, exec, shell, and subsystem request handling
  - Command execution with stdout/stderr streaming

- **CommandExecutor**: Executes commands requested by SSH clients
  - Shell-based command execution with `-c` flag
  - Environment variable configuration (HOME, USER, SHELL, PATH)
  - Stdout/stderr streaming to SSH channel
  - Command timeout with graceful process termination
  - Command allow/block list validation for security
  - Exit code propagation to client

- **SessionManager**: Tracks active sessions with configurable capacity
  - Session creation and cleanup
  - Idle session management
  - Authentication state tracking

### Server Authentication Module

The authentication subsystem (`src/server/auth/`) provides extensible authentication for the SSH server:

**Structure**:
- `mod.rs` - Module exports and re-exports
- `provider.rs` - `AuthProvider` trait definition
- `publickey.rs` - `PublicKeyVerifier` implementation

**AuthProvider Trait**:

The `AuthProvider` trait defines the interface for all authentication backends:

```rust
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn verify_publickey(&self, username: &str, key: &PublicKey) -> Result<AuthResult>;
    async fn verify_password(&self, username: &str, password: &str) -> Result<AuthResult>;
    async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>>;
    async fn user_exists(&self, username: &str) -> Result<bool>;
}
```

**PublicKeyVerifier**:

Implements public key authentication by parsing OpenSSH authorized_keys files:

- **Key file location modes**:
  - Directory mode: `{dir}/{username}/authorized_keys`
  - Pattern mode: `/home/{user}/.ssh/authorized_keys`

- **Supported key types**:
  - ssh-ed25519, ssh-ed448
  - ssh-rsa, ssh-dss
  - ecdsa-sha2-nistp256/384/521
  - Security keys (sk-ssh-ed25519, sk-ecdsa-sha2-nistp256)

- **Key options parsing**:
  - `command="..."` - Force specific command
  - `from="..."` - Restrict source addresses
  - `no-pty`, `no-port-forwarding`, `no-agent-forwarding`, `no-X11-forwarding`
  - `environment="..."` - Set environment variables

**Security Features**:

- **Username validation**: Prevents path traversal attacks (e.g., `../etc/passwd`)
- **File permission checks** (Unix): Rejects world/group-writable files and symlinks
- **Symlink protection**: Uses `symlink_metadata()` to detect and reject symlinks
- **Parent directory validation**: Checks parent directory permissions
- **Rate limiting**: Token bucket rate limiter for authentication attempts
- **Timing attack mitigation**: Constant-time behavior in `user_exists()` check
- **Comprehensive logging**: All authentication attempts are logged

## Data Flow

### Command Execution Flow

```
User Input → CLI Parser → Mode Detection → Node Resolution
                                                 ↓
                                         Configuration Loading
                                                 ↓
                                         SSH Config Parsing
                                                 ↓
                                    Jump Host Chain Creation
                                                 ↓
                                      Parallel Executor Setup
                                                 ↓
                            ┌────────────────────┴─────────────────┐
                            ▼                                      ▼
                    Connection Pool                       Task Spawning
                            ↓                                      ↓
                    Per-Node Execution                   Semaphore Control
                            ↓                                      ↓
                    Command/Transfer                      Result Collection
                            ↓                                      ↓
                    Output Streaming                     Exit Code Strategy
                            └────────────────────┬─────────────────┘
                                                 ▼
                                          User Output
```

### Error Handling Strategy

- **Connection errors**: Retry with exponential backoff
- **Authentication failures**: Immediate failure with clear diagnostics
- **Command execution errors**: Captured with exit codes
- **Timeout handling**: Configurable per-connection and per-command
- **Signal handling**: Clean shutdown on Ctrl+C with two-stage confirmation

## Security Model

### Authentication

- SSH agent authentication (auto-detection)
- Private key files with passphrase support
- Password authentication (discouraged in production)
- Public key authentication preferred

### Host Verification

- known_hosts file verification
- Three modes: Yes (strict), No (insecure), AcceptNew (recommended)
- Per-host configuration support
- Host key fingerprint display

### Data Protection

- No credential logging
- Secure memory handling for passphrases
- Encrypted SSH transport (via russh)
- Connection timeout enforcement

### Network Security

- Jump host support for bastion architectures
- Port forwarding for secure tunneling
- SSH config directive support for security policies

## Dependencies and Licensing

### Core Dependencies

- **tokio** - Async runtime
- **russh / russh-sftp** - SSH protocol implementation
- **clap** - CLI argument parsing
- **serde / serde_yaml** - Configuration serialization
- **tracing / tracing-subscriber** - Structured logging
- **anyhow / thiserror** - Error handling

### License

See [LICENSE](./LICENSE) file for licensing information.

## Appendix

### Performance Tuning

- **Parallelism**: Adjust `--parallel` flag (default: 10)
- **Connection timeout**: Use `--connect-timeout` (default: 30s)
- **Command timeout**: Use `--timeout` (default: 5min)
- **Keepalive**: Configurable via `--server-alive-interval` (default: 60s) and `--server-alive-count-max` (default: 3)
  - Interval of 0 disables keepalive
  - Connection is considered dead after `interval * (count_max + 1)` seconds without response
  - Equivalent to OpenSSH `ServerAliveInterval` and `ServerAliveCountMax` options

### Configuration Schema

See [docs/architecture/configuration.md](./docs/architecture/configuration.md) for complete YAML schema and examples.

### Exit Codes

- **0**: Success (all nodes, or main rank succeeded)
- **1**: General failure
- **130**: Terminated by SIGINT (Ctrl+C)
- **Other**: Preserved from main rank (SIGSEGV=139, OOM=137, etc.)

See [docs/architecture/exit-code-strategy.md](./docs/architecture/exit-code-strategy.md) for detailed strategy documentation.

## Further Reading

For detailed component documentation, see:
- [Architecture Documentation Index](./docs/architecture/README.md)
- [CLI Interface Documentation](./docs/architecture/cli-interface.md)
- [Configuration Management](./docs/architecture/configuration.md)
- [Parallel Executor](./docs/architecture/executor.md)
- [SSH Client](./docs/architecture/ssh-client.md)
- [Terminal User Interface](./docs/architecture/tui.md)
- [Interactive Mode](./docs/architecture/interactive-mode.md)
- [SSH Configuration Parser](./docs/architecture/ssh-config-parser.md)
- [SSH Jump Host Support](./docs/architecture/ssh-jump-hosts.md)
- [SSH Port Forwarding](./docs/architecture/ssh-port-forwarding.md)
- [Exit Code Strategy](./docs/architecture/exit-code-strategy.md)

# bssh Architecture Documentation

## Overview

bssh (Broadcast SSH / Backend.AI SSH) is a high-performance parallel SSH command execution tool with SSH-compatible interface. This document provides a high-level architecture overview. For detailed component documentation, see [docs/architecture/](./docs/architecture/).

### Core Capabilities

- Parallel command execution across multiple nodes
- SSH-compatible command-line interface (drop-in replacement)
- SSH port forwarding (-L, -R, -D/SOCKS proxy)
- SSH jump host support (-J)
- SSH configuration file parsing (-F)
- Interactive PTY sessions with single/multiplex modes
- SFTP file transfers (upload/download) with bounded pipelined streaming
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
- Address family selection (-4/-6, AddressFamily); see [Address Family Preference](#address-family-preference)

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

`ping` is the exception: it runs no user command, so no remote status exists to forward and `MainRank` does not apply. It reuses `RequireAllSuccess` for the 0/1 boundary and reports 255 when no host answered or when bssh failed before connecting, following OpenSSH's "ssh itself failed" convention. `ping_nodes` returns a `PingOutcome` tally rather than `Result<()>`, `dispatch_command` returns `Result<i32>`, and `main::dispatch_and_exit` is the single place that converts a nonzero command-level code into the process exit status.

### Shared Module

Common utilities for code reuse between bssh client and server implementations:

- **Validation**: Input validation for usernames, hostnames, paths with security checks
- **Rate Limiting**: Generic token bucket rate limiter for connection/auth throttling
- **Authentication Types**: Common auth result types and user info structures
- **Error Types**: Shared error types for validation, auth, connection, and rate limiting

The `security` and `jump::rate_limiter` modules re-export from shared for backward compatibility.

### Server Security Module

Security features for the SSH server (`src/server/security/`):

- **AuthRateLimiter**: Fail2ban-like authentication rate limiting
  - Tracks failed authentication attempts per IP address
  - Automatic banning after exceeding configurable threshold
  - Time-windowed failure counting (failures outside window not counted)
  - Configurable ban duration with automatic expiration
  - IP whitelist for exempting trusted addresses from banning
  - Memory-safe with configurable maximum tracked IPs
  - Automatic cleanup of expired records via background task
  - Thread-safe async implementation with `Arc<RwLock<>>`

- **IpAccessControl**: IP-based connection filtering
  - Whitelist mode: Only allow connections from specified CIDR ranges
  - Blacklist mode: Block connections from specified CIDR ranges
  - Blacklist takes priority over whitelist (blocked IPs are always denied)
  - Support for both IPv4 and IPv6 addresses and CIDR notation
  - Dynamic updates: Add/remove rules at runtime via `SharedIpAccessControl`
  - Early rejection at connection level before handler creation
  - Thread-safe with fail-closed behavior on lock contention
  - Configuration via `allowed_ips` and `blocked_ips` in server config

### File Transfer Filter Module

Policy-based filtering infrastructure for SFTP and SCP file transfer operations (`src/server/filter/`):

**Structure**:
- `mod.rs` - `TransferFilter` trait, `Operation` enum, `FilterResult` enum, `NoOpFilter`
- `policy.rs` - `FilterPolicy` engine, `FilterRule`, `Matcher` trait, `SharedFilterPolicy`
- `path.rs` - Path-based matchers: `PrefixMatcher`, `ExactMatcher`, `ComponentMatcher`, `ExtensionMatcher`
- `pattern.rs` - Pattern-based matchers: `GlobMatcher`, `RegexMatcher`, `CombinedMatcher`, `NotMatcher`

**Key Components**:

- **Operation**: Enum representing file operations
  - `Upload`, `Download`, `Delete`, `Rename`
  - `CreateDir`, `ListDir`, `Stat`, `SetStat`
  - `Symlink`, `ReadLink`

- **FilterResult**: Actions to take on matched operations
  - `Allow` - Permit the operation (default)
  - `Deny` - Block the operation
  - `Log` - Allow but log for auditing

- **TransferFilter Trait**: Interface for custom filter implementations
  - `check(path, operation, user)` - Check single path operations
  - `check_with_dest(src, dest, operation, user)` - Check two-path operations (rename, symlink)
  - `is_enabled()` - Check if filtering is active

- **FilterPolicy**: First-match-wins rule evaluation engine
  - Ordered rule evaluation
  - Configurable default action
  - Enable/disable filtering
  - Create from YAML configuration via `from_config()`

- **FilterRule**: Combines matcher, action, and optional constraints
  - Path pattern matcher
  - Per-operation restrictions
  - Per-user restrictions
  - Named rules for debugging

**Built-in Matchers**:

| Matcher | Purpose | Example |
|---------|---------|---------|
| `GlobMatcher` | Wildcard patterns | `*.key`, `*.pem` |
| `RegexMatcher` | Full regex support | `(?i)\.exe$` |
| `PrefixMatcher` | Directory tree matching | `/etc/` |
| `ExactMatcher` | Specific file matching | `/etc/shadow` |
| `ComponentMatcher` | Path component matching | `.git`, `.ssh` |
| `ExtensionMatcher` | File extension matching | `exe`, `key` |
| `CombinedMatcher` | OR-combine matchers | Multiple patterns |
| `NotMatcher` | Invert matcher results | Exclude patterns |

**Security Features**:
- `normalize_path()` function for path traversal prevention
- ReDoS protection via regex size limits
- Case-insensitive extension matching

**Usage Example**:
```rust
use bssh::server::filter::{FilterPolicy, FilterResult, Operation};
use bssh::server::filter::pattern::GlobMatcher;
use bssh::server::filter::policy::FilterRule;
use std::path::Path;

// Create policy that blocks *.key files
let policy = FilterPolicy::new()
    .with_default(FilterResult::Allow)
    .add_rule(FilterRule::new(
        Box::new(GlobMatcher::new("*.key").unwrap()),
        FilterResult::Deny,
    ));

// Check if operation is allowed
let result = policy.check(
    Path::new("/etc/secret.key"),
    Operation::Download,
    "alice"
);
assert_eq!(result, FilterResult::Deny);
```

**Configuration** (YAML):
```yaml
filter:
  enabled: true
  default_action: allow
  rules:
    - name: block-sensitive-keys
      pattern: "*.{key,pem}"
      action: deny
      operations:
        - download
        - upload
    - name: block-hidden-dirs
      path_prefix: "/home"
      pattern: ".*"
      action: deny
      users:
        - guest
```

### Audit Logging Module

Comprehensive audit logging infrastructure for the SSH server (`src/server/audit/`):

**Structure**:
- `mod.rs` - `AuditManager` for collecting and distributing audit events
- `event.rs` - `AuditEvent` type definitions and builder pattern
- `exporter.rs` - `AuditExporter` trait and `NullExporter` implementation
- `file.rs` - `FileExporter` for JSON Lines output with rotation support

**Key Components**:

- **AuditEvent**: Represents discrete auditable actions with fields for:
  - Unique event ID (UUID v4)
  - Timestamp (UTC)
  - Event type, session ID, username, client IP
  - File paths, bytes transferred, operation result
  - Protocol and additional details

- **EventType**: Categorizes security and operational events:
  - Authentication: `AuthSuccess`, `AuthFailure`, `AuthRateLimited`
  - Sessions: `SessionStart`, `SessionEnd`
  - Commands: `CommandExecuted`, `CommandBlocked`
  - File operations: `FileOpenRead`, `FileOpenWrite`, `FileRead`, `FileWrite`, `FileClose`, `FileUploaded`, `FileDownloaded`, `FileDeleted`, `FileRenamed`
  - Directory operations: `DirectoryCreated`, `DirectoryDeleted`, `DirectoryListed`
  - Filters: `TransferDenied`, `TransferAllowed`
  - Security: `IpBlocked`, `IpUnblocked`, `SuspiciousActivity`

- **EventResult**: Operation outcomes (`Success`, `Failure`, `Denied`, `Error`)

- **AuditExporter Trait**: Interface for audit event destinations
  - `export()` - Export single event
  - `export_batch()` - Export multiple events (optimizable)
  - `flush()` - Ensure pending events are written
  - `close()` - Clean up resources

- **NullExporter**: No-op exporter for testing and disabled audit logging

- **FileExporter**: File-based exporter writing events in JSON Lines format
  - Append mode to preserve existing data
  - Optional log rotation based on file size (`RotateConfig`)
  - Optional gzip compression for rotated files
  - Thread-safe using async Mutex
  - Async I/O using tokio
  - Automatic parent directory creation
  - Restrictive file permissions (0o600 on Unix)

- **AuditManager**: Central manager with async processing
  - Background worker for non-blocking event processing
  - Configurable buffering (buffer size, batch size)
  - Periodic flush intervals
  - Multiple exporter support
  - Graceful shutdown with event flush

**Configuration**:
```rust
let config = AuditConfig::new()
    .with_enabled(true)
    .with_buffer_size(1000)
    .with_batch_size(100)
    .with_flush_interval(5);
```

**File Exporter Usage**:
```rust
use bssh::server::audit::file::{FileExporter, RotateConfig};
use std::path::Path;

// Simple file exporter
let exporter = FileExporter::new(Path::new("/var/log/audit.log"))?;

// With rotation (50 MB, 10 backups, gzip compression)
let rotate_config = RotateConfig::new()
    .with_max_size(50 * 1024 * 1024)
    .with_max_backups(10)
    .with_compress(true);

let exporter = FileExporter::new(Path::new("/var/log/audit.log"))?
    .with_rotation(rotate_config);
```

**Output Format** (JSON Lines - one JSON object per line):
```json
{"id":"uuid","timestamp":"2024-01-15T10:30:00Z","event_type":"file_uploaded","session_id":"sess-001","user":"admin","client_ip":"192.168.1.100","path":"/data/report.pdf","bytes":1048576,"result":"success","protocol":"sftp"}
```

- **OtelExporter**: OpenTelemetry exporter for distributed tracing and observability
  - OTLP/gRPC protocol support using tonic
  - Event to LogRecord mapping with proper attribute conversion
  - Severity level mapping based on event types and results
  - Resource attributes including service.name and service.version
  - Graceful shutdown and flush methods
  - TLS support for secure audit data transmission

- **LogstashExporter**: Logstash exporter for ELK stack integration
  - TCP connection with JSON Lines protocol (newline-delimited JSON)
  - Optional TLS encryption for secure transmission
  - Automatic reconnection on connection failure
  - Batch support for efficient event transmission
  - Connection timeout handling (default: 10 seconds)
  - Configurable host and port

**OtelExporter Usage**:
```rust
use bssh::server::audit::otel::OtelExporter;
use bssh::server::audit::exporter::AuditExporter;
use bssh::server::audit::event::{AuditEvent, EventType};

// Create exporter with OTLP endpoint
let exporter = OtelExporter::new("http://localhost:4317")?;

// Export an audit event
let event = AuditEvent::new(
    EventType::AuthSuccess,
    "alice".to_string(),
    "session-123".to_string(),
);
exporter.export(event).await?;

// Graceful shutdown
exporter.close().await?;
```

**LogstashExporter Usage**:
```rust
use bssh::server::audit::logstash::LogstashExporter;
use bssh::server::audit::exporter::AuditExporter;
use bssh::server::audit::event::{AuditEvent, EventType};

// Create exporter (unencrypted by default)
let exporter = LogstashExporter::new("logstash.example.com", 5044)?
    .with_tls(true);  // Enable TLS for production

// Export an audit event
let event = AuditEvent::new(
    EventType::AuthSuccess,
    "alice".to_string(),
    "session-123".to_string(),
);
exporter.export(event).await?;

// Graceful shutdown
exporter.close().await?;
```

### Server CLI Binary
**Binary**: `bssh-server`

The `bssh-server` binary provides a command-line interface for managing and operating the SSH server:

**Subcommands**:
- **run** - Start the SSH server (default when no subcommand specified)
- **gen-config** - Generate a configuration file template with secure defaults
- **hash-password** - Hash passwords for configuration using Argon2id (recommended)
- **check-config** - Validate configuration files and display settings
- **gen-host-key** - Generate SSH host keys (Ed25519 or RSA)
- **version** - Show version and build information

**Global Options**:
- `-c, --config <FILE>` - Configuration file path
- `-b, --bind-address <ADDR>` - Override bind address
- `-p, --port <PORT>` - Override listen port
- `-k, --host-key <FILE>` - Host key file(s) (can be repeated)
- `-v, --verbose` - Verbosity level (repeatable: -v, -vv, -vvv)
- `-D, --foreground` - Run in foreground (don't daemonize)
- `--pid-file <FILE>` - PID file path

**Usage Examples**:
```bash
# Generate configuration template
bssh-server gen-config -o /etc/bssh/server.yaml

# Generate Ed25519 host key (recommended)
bssh-server gen-host-key -t ed25519 -o /etc/bssh/ssh_host_ed25519_key

# Generate RSA host key (for compatibility)
bssh-server gen-host-key -t rsa -o /etc/bssh/ssh_host_rsa_key --bits 4096

# Hash a password for configuration
bssh-server hash-password

# Validate configuration
bssh-server check-config -c /etc/bssh/server.yaml

# Start server with configuration file
bssh-server -c /etc/bssh/server.yaml

# Start server with CLI overrides
bssh-server -c /etc/bssh/server.yaml -p 2222 -b 0.0.0.0 -k /path/to/key
```

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
- `sftp.rs` - SFTP subsystem handler with path traversal prevention
- `scp.rs` - SCP protocol handler with sink/source modes
- `auth/` - Authentication provider infrastructure
- `audit/` - Audit logging infrastructure (event types, exporters, manager)

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
  - Rate limiting for authentication attempts (token bucket)
  - Auth rate limiting with ban support (fail2ban-like)
  - Channel operations (open, close, EOF, data)
  - PTY, exec, shell, and subsystem request handling
  - Command execution with stdout/stderr streaming

- **PTY Module** (`src/server/pty.rs`): Pseudo-terminal management for interactive sessions
  - PTY master/slave pair creation using POSIX APIs via nix crate
  - Window size management with TIOCSWINSZ ioctl
  - Async I/O for PTY master file descriptor using tokio's AsyncFd
  - Configuration management (terminal type, dimensions, pixel sizes)
  - Implements `AsyncRead` and `AsyncWrite` for PTY I/O

- **Shell Session Module** (`src/server/shell.rs`): Interactive shell session handler
  - Shell process spawning with login shell configuration (-l flag)
  - Terminal environment setup (TERM, HOME, USER, SHELL, PATH)
  - Bidirectional I/O forwarding between SSH channel and PTY master
  - Window resize event handling forwarded to PTY
  - Proper session cleanup on disconnect (SIGHUP to shell, process termination)
  - Controlling terminal setup via TIOCSCTTY ioctl

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

- **SftpHandler**: SFTP subsystem handler (`src/server/sftp.rs`)
  - Implements `russh_sftp::server::Handler` trait for file transfer operations
  - Advertises and serves `limits@openssh.com` so clients negotiate the server's packet, read, write, and handle ceilings before bulk transfers
  - Path traversal prevention with chroot-like isolation
  - File operations: open, read, write, close
  - Directory operations: opendir, readdir, mkdir, rmdir
  - Attribute operations: stat, lstat, fstat, setstat, fsetstat
  - Path operations: realpath, rename, remove, readlink, symlink
  - Symlink validation ensures targets remain within root directory
  - Handle limit enforcement to prevent resource exhaustion
  - Read size capping to prevent memory exhaustion
  - Pipelined downloads tolerate legal short `READ` replies by re-requesting the missing byte range before ordered reassembly, and clamp advertised transfer ceilings to the negotiated packet payload budget

- **ScpHandler**: SCP protocol handler (`src/server/scp.rs`)
  - Implements SCP server protocol for file transfers via the `scp` command
  - Sink mode (`-t` flag): receives files from client (upload)
  - Source mode (`-f` flag): sends files to client (download)
  - Recursive transfer support (`-r` flag) for directories
  - Time preservation (`-p` flag) for file modification times
  - Security features:
    - Path traversal prevention with normalized path resolution
    - Symlink escape prevention via canonicalization
    - Filename validation (rejects `/`, `..`, `.`)
    - File size limit (10 GB maximum)
    - Mode permission masking (strips setuid/setgid/sticky bits)
    - Line length limits to prevent DoS via buffer exhaustion
  - Automatic SCP command detection in exec_request handler
  - Configurable via `scp_enabled` setting

### Server Authentication Module

The authentication subsystem (`src/server/auth/`) provides extensible authentication for the SSH server:

**Structure**:
- `mod.rs` - Module exports and re-exports
- `provider.rs` - `AuthProvider` trait definition
- `publickey.rs` - `PublicKeyVerifier` implementation
- `password.rs` - `PasswordVerifier` implementation with Argon2id hashing
- `composite.rs` - `CompositeAuthProvider` combining multiple auth methods

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

**PasswordVerifier**:

Implements password authentication with secure password hashing:

- **Argon2id hashing**: Uses the OWASP-recommended password hashing algorithm
  - Memory cost: 19 MiB
  - Time cost: 2 iterations
  - Parallelism: 1

- **User configuration**:
  - External YAML file with user definitions
  - Inline users in server configuration
  - User attributes: name, password_hash, shell, home, env

- **Security features**:
  - Timing attack mitigation with constant-time verification
  - Minimum verification time (100ms) regardless of user existence
  - Dummy hash verification for non-existent users
  - Secure memory cleanup using `zeroize` crate
  - User enumeration protection

- **Hash compatibility**:
  - Argon2id (recommended, generated by `hash-password` command)
  - bcrypt (supported for backward compatibility)

**CompositeAuthProvider**:

Combines multiple authentication methods into a single provider:

- Delegates to `PublicKeyVerifier` for public key auth
- Delegates to `PasswordVerifier` for password auth
- Prioritizes password verifier for user info (more detailed)
- Supports hot-reloading of password users via `reload_password_users()`

**Security Features**:

- **Username validation**: Prevents path traversal attacks (e.g., `../etc/passwd`)
- **File permission checks** (Unix): Rejects world/group-writable files and symlinks
- **Symlink protection**: Uses `symlink_metadata()` to detect and reject symlinks
- **Parent directory validation**: Checks parent directory permissions
- **Rate limiting**: Token bucket rate limiter for authentication attempts
- **Timing attack mitigation**: Constant-time behavior in password verification and `user_exists()` check
- **Secure memory handling**: Password strings cleared from memory after use via `zeroize`
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

### Address Family Preference

The OpenSSH-compatible `-4` / `-6` flags and the ssh_config `AddressFamily`
keyword share one representation, `AddressFamily` in
`src/ssh/tokio_client/address_family.rs`:

```rust
pub enum AddressFamily { Any, V4, V6 }
```

**Resolution.** `AddressFamily::resolve(ipv4_flag, ipv6_flag, config_value)`
implements the OpenSSH precedence rule: command line flag, then config keyword,
then the `any` default. `AddressFamily::from_config_value` accepts
`any | inet | inet6` case-insensitively and warns (via `tracing`) rather than
failing on an unrecognized value, so a configuration file OpenSSH would tolerate
does not become a hard error. The dispatcher builds an
`SshConnectionConfigResolver` from CLI overrides, YAML defaults, and the parsed
ssh_config; exec, ping, upload, and download resolve that object for each
target node so per-host `Host` blocks apply to the actual connection target.

**Threading.** The preference rides on `SshConnectionConfig`, the struct every
connection path already carries. `Client::connect_with_ssh_config` passes it to
`connect_with_config_inner`, which resolves the target, filters the candidate
list, and connects. `Any` returns the resolver's list untouched, which is what
keeps the unflagged path byte-for-byte identical to the previous behavior.
`JumpHostChain` receives the same resolver and resolves each jump hop against
that hop's own host name instead of inheriting the destination's settings.
The SFTP paths (`upload` / `download`) now receive the full resolved
`SshConnectionConfig`, so `AddressFamily`, `Compression`,
`ServerAliveInterval`, and `ServerAliveCountMax` follow the same per-host path
as exec and ping. `ForwardingConfig` carries its own copy of the resolved
address family for the forwarding-target filter, since forwarders run detached
from the connect config.

**Scope.** The constraint is a hard filter where bssh opens the socket. For
forwarding targets the unforced path preserves server-side resolution, while a
forced family switches to locally resolved numeric addresses so the family
request has an observable effect:

| Path | Behavior |
| --- | --- |
| Direct connect (exec, interactive, ping, SFTP) | Hard filter in `connect_with_config_inner` |
| First jump hop | Hard filter (shares the direct connect path) |
| `-L` / `-D` listener | Selects the implicit bind address (`::1` / `::` under `-6`); an explicit bind address wins |
| `-L` / SOCKS5 `-D` target | With `Any`, sends the requested hostname in `direct-tcpip` and lets the remote sshd resolve it. With `V4` / `V6`, resolves locally, filters the candidate list, and sends the matching numeric address |
| SOCKS4 `-D` target | Unfiltered; SOCKS4 carries a literal IPv4 destination by protocol definition |
| Jump hops past the first, and the destination behind a chain | Uses the same `direct-tcpip` model as `-L`/SOCKS5 `-D` targets: hostname with `Any`, locally filtered numeric address with `V4` / `V6`. The family also selects the best-effort address recorded for host key verification diagnostics |
| `-R` listener | Not constrained; the server binds it |
| `bssh-server` | Out of scope; separate CLI |

**Failure mode.** A forced family with no matching resolved address is a hard
failure with no fallback to the other family, matching OpenSSH. It surfaces as
the dedicated `Error::NoAddressForFamily { host, family }` variant, rendered as
`no IPv6 address found for <host>`, which replaces the generic
`could not resolve to any addresses` so a family mismatch is distinguishable
from a genuine resolution failure.

### Error Handling Strategy

- **Connection errors**: Retry with exponential backoff
- **Authentication failures**: Immediate failure with clear diagnostics
- **Command execution errors**: Captured with exit codes
- **Timeout handling**: Configurable per-connection and per-command
- **Signal handling**: Clean shutdown on Ctrl+C with two-stage confirmation

### Test Environment-Variable Mutation Pattern (`EnvGuard`)

Several test suites must temporarily set or remove process-wide environment
variables (e.g. `BACKENDAI_CLUSTER_HOSTS`, `HOME`, `SSH_AUTH_SOCK`). Under
Rust 2024 edition, `std::env::set_var` and `std::env::remove_var` are marked
`unsafe` because concurrent mutation of the environment is undefined behaviour
at the libc level on glibc, musl, and macOS. `EnvGuard` centralises all such
mutations in `src/test_helpers/env_guard.rs`.

**Soundness contract**: every test that constructs an `EnvGuard` MUST be
annotated with `#[serial_test::serial]`. Every other test in the same crate
binary that reads or mutates the same variable MUST also carry `#[serial]` (or
a matching `#[serial(key)]` group). Note that `#[serial]` only serializes
against other `#[serial]` / `#[parallel]` tests — unannotated tests may still
run concurrently with serial ones and would race on environment reads. This is
not an `EnvGuard` limitation; it is an inherent constraint of the libc
environment-variable API.

```rust
use serial_test::serial;
use crate::test_helpers::EnvGuard;

#[test]
#[serial]
fn my_test() {
    let _host = EnvGuard::set("BACKENDAI_CLUSTER_HOSTS", "node1,node2");
    // Variable is automatically restored when `_host` drops at end of scope.
}
```

**Integration tests** access the same struct via a `#[path]`-based re-export
in `tests/common/mod.rs`, which avoids making `EnvGuard` part of the public
`bssh` crate API while keeping a single source of truth. When adding a new
integration-test binary that needs `EnvGuard`, add `mod common;` at the top of
that file and use `common::EnvGuard`.

Use `#[serial(key)]` (a named group) when two sets of tests touch different,
non-overlapping variables and can therefore run concurrently with each other
but not with themselves; omit the key (plain `#[serial]`) when in doubt.

## Security Model

### Authentication

- SSH agent authentication (auto-detection)
- Private key files with passphrase support
- Password authentication (discouraged in production)
- Public key authentication preferred

#### macOS `UseKeychain`

On macOS, the resolved `UseKeychain yes` SSH configuration option enables passphrase lookup and storage for encrypted private-key authentication. Keychain access is deferred until an encrypted key actually needs a passphrase, is skipped entirely by `BatchMode yes`, and is serialized with terminal passphrase prompts so parallel connections cannot display competing authentication UI.

bssh owns generic-password records under the `bssh-ssh-key-passphrase` service and uses the canonical private-key path as the account. This namespace is intentionally separate from the Data Protection Keychain access group used by Apple's `/usr/bin/ssh`; that access group requires an Apple-only code-signing entitlement, so third-party binaries cannot reuse entries created by `ssh-add --apple-use-keychain`. A retrieved passphrase is accepted only if it decrypts the key. Missing or stale records fall back to the terminal prompt, and a newly entered passphrase is stored only after successful decryption.

Other platforms accept the Apple-specific keyword for portable configuration parsing but ignore its runtime behavior and recommend `IgnoreUnknown UseKeychain` when the same file must also work with upstream OpenSSH clients.

### Host Verification

- known_hosts file verification
- Three modes: Yes (strict), No (insecure), AcceptNew (recommended)
- Per-host configuration support
- Host key fingerprint display

#### OpenSSH host certificates

russh 0.63 widened `client::Handler::check_server_key` from `&PublicKey` to
`&PublicKeyOrCertificate`, so the callback can now also receive an OpenSSH host
certificate. bssh does not participate in that scheme:

- It never advertises certificate host key algorithms. Both `Preferred`
  overrides (`src/ssh/tokio_client/connection.rs` for the client,
  `src/server/mod.rs` for the server) change only `compression` and inherit
  `host_key_certificates` from `Preferred::DEFAULT`, which is empty. A server
  therefore cannot negotiate a certificate with bssh.
- If a peer sends one regardless, `ClientHandler::check_server_key` refuses it
  and returns `ServerCheckFailed`. bssh verifies no CA signatures (the
  `@cert-authority` scan in `src/ssh/tokio_client/host_verification.rs` only
  warns and falls back to TOFU), so the key inside a certificate has never been
  vouched for by anything bssh trusts. Matching it against known_hosts would
  answer a different question than the one the certificate poses.
- `ServerCheckMethod::NoCheck` still accepts, because there the operator has
  turned host verification off outright.

`server::Config` likewise gained a `certificates` field; bssh's construction
ends in `..Default::default()`, so it stays empty and the server keeps
presenting a plain host key.

### Data Protection

- No credential logging
- Secure memory handling for passphrases
- Encrypted SSH transport (via russh)
- Connection timeout enforcement

### Network Security

- Jump host support for bastion architectures
- Port forwarding for secure tunneling
- SSH config directive support for security policies

### Release Signing and Notarization (macOS)

Official macOS release binaries (bssh, bssh-server, bssh-keygen) are signed
with a "Developer ID Application" certificate and notarized through Apple's
notarytool. This is handled by two composite actions in `.github/actions/`,
mirrored from continuum-router (originally from backend.ai-go):

- **macos-signing-setup** extracts the Developer ID p12 to a PEM (via
  `openssl pkcs12 -legacy`, selected by capability since Apple's LibreSSL
  lacks the option), rejects any p12 that holds no Developer ID Application
  certificate, and installs rcodesign (keychain-free signing).
- **macos-sign-notarize-binary** signs a staged copy with the hardened
  runtime and a pinned reverse-DNS identifier (`BUNDLE_ID` base, with
  `-server` / `-keygen` suffixes), asserts the resulting authority, runtime
  flag, and identifier, packages the flat zip with `ditto`, submits it to
  `notarytool --wait`, and gates on `status: Accepted`. Bare Mach-O binaries
  cannot be stapled, so Gatekeeper resolves the ticket online.

Rationale: releases up to v2.4.1 were signed with an "Apple Distribution"
certificate (an App Store submission identity without the Developer ID leaf
extension) and never notarized. When that certificate was revoked, macOS
killed installed binaries on launch and deleted them as malware. The
authority assertion exists so a wrong certificate fails the release instead
of shipping quietly.

Required release credentials (GitHub `packaging` environment):
`APPLE_CERTIFICATE` (base64 Developer ID Application p12),
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_PASSWORD`
(app-specific password), and the `BUNDLE_ID` variable (`com.lablup.bssh`).

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
- **255**: Generated by `ping` as a bssh-level signal when no host was reachable, or bssh failed before attempting any connection. The default `MainRank` strategy can also produce 255 by forwarding a remote command's exit status verbatim
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

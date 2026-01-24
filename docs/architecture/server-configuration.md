# Server Configuration Architecture

[Back to Main Architecture](../../ARCHITECTURE.md)

## Table of Contents
- [Overview](#overview)
- [Configuration Systems](#configuration-systems)
- [File-Based Configuration](#file-based-configuration)
- [Environment Variable Overrides](#environment-variable-overrides)
- [Configuration Validation](#configuration-validation)
- [Data Model](#data-model)
- [Usage Examples](#usage-examples)

## Overview

The bssh-server configuration system provides a comprehensive way to configure the SSH server through YAML files, environment variables, and CLI arguments. The system supports a hierarchical configuration model where more specific settings override more general ones.

### Configuration Precedence

Settings are applied in the following order (highest to lowest priority):

1. **CLI arguments** - Command-line options
2. **Environment variables** - BSSH_* prefixed variables
3. **Configuration file** - YAML file settings
4. **Default values** - Built-in defaults

## Configuration Systems

### Builder-Based Configuration (Programmatic)

The original `ServerConfig` and `ServerConfigBuilder` provide a programmatic way to configure the server:

```rust
use bssh::server::config::{ServerConfig, ServerConfigBuilder};

let config = ServerConfig::builder()
    .host_key("/etc/ssh/ssh_host_ed25519_key")
    .listen_address("0.0.0.0:2222")
    .max_connections(100)
    .build();
```

### File-Based Configuration (YAML)

The new `ServerFileConfig` supports YAML file configuration with environment variable overrides:

```rust
use bssh::server::config::load_config;

// Load from default locations or environment
let file_config = load_config(None)?;

// Convert to ServerConfig for use with BsshServer
let server_config = file_config.into_server_config();
```

## File-Based Configuration

### Default Search Paths

When no config path is specified, the system searches in order:

1. `./bssh-server.yaml` (current directory)
2. `/etc/bssh/server.yaml` (system-wide)
3. `$XDG_CONFIG_HOME/bssh/server.yaml` or `~/.config/bssh/server.yaml` (user-specific)

### Configuration File Permissions

On Unix systems, the loader checks file permissions and warns if the configuration file is readable by group or others, as configuration files may contain sensitive information.

### Complete Configuration Schema

```yaml
# Server network and connection settings
server:
  # Address to bind to
  bind_address: "0.0.0.0"     # Default: "0.0.0.0"

  # Port to listen on
  port: 2222                   # Default: 2222

  # Paths to SSH host private key files
  host_keys:
    - /etc/bssh/ssh_host_ed25519_key
    - /etc/bssh/ssh_host_rsa_key

  # Maximum concurrent connections
  max_connections: 100         # Default: 100

  # Connection timeout in seconds (0 to disable)
  timeout: 300                 # Default: 300 (5 minutes)

  # SSH keepalive interval in seconds (0 to disable)
  keepalive_interval: 60       # Default: 60 (1 minute)

# Authentication configuration
auth:
  # Enabled authentication methods
  methods:
    - publickey               # Default: [publickey]
    - password

  # Public key authentication settings
  publickey:
    # Directory containing per-user authorized_keys
    # Structure: {dir}/{username}/authorized_keys
    authorized_keys_dir: /etc/bssh/authorized_keys

    # OR: Pattern for authorized_keys file path
    # {user} placeholder replaced with username
    authorized_keys_pattern: "/home/{user}/.ssh/authorized_keys"

  # Password authentication settings
  password:
    # Path to YAML file with user definitions
    users_file: /etc/bssh/users.yaml

    # Inline user definitions
    users:
      - name: testuser
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$..."  # bssh-server hash-password
        shell: /bin/bash
        home: /home/testuser
        env:
          LANG: en_US.UTF-8

# Shell execution configuration
shell:
  # Default shell for command execution
  default: /bin/sh             # Default: /bin/sh

  # Command execution timeout in seconds (0 for no timeout)
  command_timeout: 3600        # Default: 3600 (1 hour)

  # Global environment variables
  env:
    LANG: en_US.UTF-8
    PATH: /usr/local/bin:/usr/bin:/bin

# SFTP subsystem configuration
sftp:
  enabled: true                # Default: true
  # Optional chroot directory
  root: /data/sftp

# SCP protocol configuration
scp:
  enabled: true                # Default: true

# File transfer filtering
filter:
  enabled: false               # Default: false
  default_action: allow        # Default action when no rules match: allow, deny, log

  rules:
    # Match by glob pattern
    - name: "block-exe"
      pattern: "*.exe"
      action: deny

    # Match by path prefix (directory tree)
    - name: "log-tmp"
      path_prefix: "/tmp/"
      action: log

    # Match by multiple file extensions
    - name: "block-executables"
      extensions: ["exe", "bat", "sh", "ps1"]
      action: deny

    # Match by directory component (anywhere in path)
    - name: "block-git"
      directory: ".git"
      action: deny

    # Composite rule with AND logic
    - name: "protect-env-outside-home"
      composite:
        type: and
        matchers:
          - pattern: "*.env"
          - not:
              path_prefix: "/home"
      action: deny

    # Composite rule with OR logic
    - name: "block-secrets"
      composite:
        type: or
        matchers:
          - pattern: "*.key"
          - pattern: "*.pem"
          - extensions: ["crt", "p12", "pfx"]
      action: deny

    # Composite rule with NOT logic (whitelist pattern)
    - name: "whitelist-data"
      composite:
        type: not
        matcher:
          path_prefix: "/data"
      action: deny

    # Rule with operation restriction
    - name: "readonly-logs"
      pattern: "*.log"
      action: deny
      operations: ["upload", "delete"]

    # Rule with user restriction
    - name: "admin-only-config"
      path_prefix: "/etc"
      action: deny
      users: ["guest", "readonly"]

# Audit logging configuration
audit:
  enabled: false               # Default: false
  exporters:
    - type: file
      path: /var/log/bssh/audit.log
    - type: otel
      endpoint: http://otel-collector:4317
    - type: logstash
      host: logstash.example.com
      port: 5044

# Security and access control
security:
  # Max auth attempts before banning IP
  max_auth_attempts: 5         # Default: 5

  # Time window for counting auth attempts (seconds)
  # Failed attempts outside this window are not counted
  auth_window: 300             # Default: 300 (5 minutes)

  # Ban duration after exceeding max attempts (seconds)
  ban_time: 300                # Default: 300 (5 minutes)

  # IPs that are never banned (whitelist)
  # These IPs are exempt from rate limiting and banning
  whitelist_ips:
    - "127.0.0.1"
    - "::1"

  # Max concurrent sessions per user
  max_sessions_per_user: 10    # Default: 10

  # Idle session timeout (seconds, 0 to disable)
  idle_timeout: 3600           # Default: 3600 (1 hour)

  # Maximum session duration (seconds, 0 to disable)
  # Sessions are terminated after this duration regardless of activity
  session_timeout: 0           # Default: 0 (disabled)

  # IP allowlist (CIDR notation, empty = allow all)
  # When configured, only connections from these ranges are allowed
  allowed_ips:
    - "192.168.1.0/24"
    - "10.0.0.0/8"

  # IP blocklist (CIDR notation)
  # Connections from these ranges are always denied
  # Blocked IPs take priority over allowed IPs
  blocked_ips:
    - "203.0.113.0/24"
```

### IP Access Control

The server supports IP-based connection filtering through `allowed_ips` and `blocked_ips` configuration options:

**Modes of Operation:**

1. **Default Mode** (no `allowed_ips` configured): All IPs are allowed unless explicitly blocked
2. **Whitelist Mode** (`allowed_ips` configured): Only IPs matching allowed ranges can connect

**Priority Rules:**
- Blocked IPs always take priority over allowed IPs
- If an IP matches both `allowed_ips` and `blocked_ips`, the connection is denied
- Connections from blocked IPs are rejected before authentication

**CIDR Notation Examples:**
- `10.0.0.0/8` - All 10.x.x.x addresses (Class A private network)
- `192.168.1.0/24` - All 192.168.1.x addresses
- `192.168.100.50/32` - Single IP address (192.168.100.50)
- `2001:db8::/32` - IPv6 prefix

**Runtime Updates:**
The IP access control supports dynamic updates at runtime through the `SharedIpAccessControl` API, allowing administrators to block or unblock IPs without restarting the server.

**Security Behavior:**
- Connections from blocked IPs are rejected at the connection level before any authentication attempt
- On lock contention (rare), the system defaults to DENY for fail-closed security
- All access control decisions are logged for auditing

## Environment Variable Overrides

The following environment variables can override configuration file settings:

| Variable | Description | Example |
|----------|-------------|---------|
| `BSSH_PORT` | Server port | `2222` |
| `BSSH_BIND_ADDRESS` | Bind address | `0.0.0.0` |
| `BSSH_HOST_KEY` | Comma-separated host key paths | `/etc/ssh/key1,/etc/ssh/key2` |
| `BSSH_MAX_CONNECTIONS` | Maximum concurrent connections | `100` |
| `BSSH_KEEPALIVE_INTERVAL` | Keepalive interval in seconds | `60` |
| `BSSH_AUTH_METHODS` | Comma-separated auth methods | `publickey,password` |
| `BSSH_AUTHORIZED_KEYS_DIR` | Directory for authorized_keys | `/etc/bssh/keys` |
| `BSSH_AUTHORIZED_KEYS_PATTERN` | Pattern for authorized_keys paths | `/home/{user}/.ssh/authorized_keys` |
| `BSSH_SHELL` | Default shell path | `/bin/bash` |
| `BSSH_COMMAND_TIMEOUT` | Command timeout in seconds | `3600` |

## Configuration Validation

The configuration system validates settings at load time:

### Required Validations
- At least one host key must be configured
- At least one authentication method must be enabled
- Host key files must exist

### Network Validations
- `bind_address` must be a valid IP address (IPv4 or IPv6)
- `port` cannot be 0
- `max_connections` must be greater than 0

### Security Validations
- `authorized_keys_pattern` must not contain `..` (path traversal prevention)
- `authorized_keys_pattern` must use absolute paths
- IP ranges in `allowed_ips` and `blocked_ips` must be valid CIDR notation

### Shell Validations
- Default shell path must exist on the filesystem

## Data Model

### Core Types

```rust
/// Main server configuration loaded from YAML files
pub struct ServerFileConfig {
    pub server: ServerSettings,
    pub auth: AuthConfig,
    pub shell: ShellConfig,
    pub sftp: SftpConfig,
    pub scp: ScpConfig,
    pub filter: FilterConfig,
    pub audit: AuditConfig,
    pub security: SecurityConfig,
}

/// Authentication methods
pub enum AuthMethod {
    PublicKey,
    Password,
}

/// Filter actions
pub enum FilterAction {
    Allow,
    Deny,
    Log,
}

/// Audit exporter types
pub enum AuditExporterConfig {
    File { path: PathBuf },
    Otel { endpoint: String },
    Logstash { host: String, port: u16 },
}
```

### Conversion to ServerConfig

The `ServerFileConfig` can be converted to the builder-based `ServerConfig` for use with `BsshServer`:

```rust
impl ServerFileConfig {
    pub fn into_server_config(self) -> ServerConfig {
        // Converts file-based config to runtime config
    }
}
```

## Usage Examples

### Basic Server Setup

```rust
use bssh::server::{BsshServer, config::load_config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration from default locations
    let file_config = load_config(None)?;

    // Convert to runtime config
    let server_config = file_config.into_server_config();

    // Create and run server
    let server = BsshServer::new(server_config);
    server.run().await?;

    Ok(())
}
```

### Custom Configuration Path

```rust
use bssh::server::config::load_config;
use std::path::Path;

let config = load_config(Some(Path::new("/custom/path/server.yaml")))?;
```

### Generate Configuration Template

```rust
use bssh::server::config::generate_config_template;

let template = generate_config_template();
std::fs::write("bssh-server.yaml", template)?;
```

### Environment-Based Configuration

```bash
# Set environment variables
export BSSH_PORT=2222
export BSSH_BIND_ADDRESS=0.0.0.0
export BSSH_HOST_KEY=/etc/bssh/ssh_host_ed25519_key
export BSSH_AUTH_METHODS=publickey,password

# Run server - will use environment variables
bssh-server
```

## Server CLI Commands

The `bssh-server` binary provides several management commands:

### Generate Configuration Template

```bash
# Output to stdout
bssh-server gen-config

# Write to file with secure permissions (0600)
bssh-server gen-config -o /etc/bssh/server.yaml
```

### Generate Host Keys

```bash
# Generate Ed25519 key (recommended, fast, secure)
bssh-server gen-host-key -t ed25519 -o /etc/bssh/ssh_host_ed25519_key

# Generate RSA key with custom size
bssh-server gen-host-key -t rsa -o /etc/bssh/ssh_host_rsa_key --bits 4096
```

Generated keys have secure permissions (0600) and are in OpenSSH format.

### Hash Passwords

```bash
# Interactive password hashing with Argon2id (recommended)
bssh-server hash-password
```

This prompts for a password, confirms it, and outputs an Argon2id hash suitable for use in the configuration file. Argon2id is the OWASP-recommended password hashing algorithm with memory-hard properties that resist GPU and ASIC attacks.

The generated hash includes:
- Algorithm: Argon2id (variant resistant to both side-channel and GPU attacks)
- Memory cost: 19 MiB
- Time cost: 2 iterations
- Parallelism: 1

Note: bcrypt hashes are also supported for backward compatibility with existing configurations.

### Validate Configuration

```bash
# Check default config locations
bssh-server check-config

# Check specific config file
bssh-server check-config -c /etc/bssh/server.yaml
```

Displays all configuration settings and validates the file format.

### Start Server

```bash
# Start with config file
bssh-server -c /etc/bssh/server.yaml

# Start with CLI overrides
bssh-server -c /etc/bssh/server.yaml -p 2222 -b 0.0.0.0

# Run in foreground with verbose logging
bssh-server -c /etc/bssh/server.yaml -D -vvv
```

## Shell Session Architecture

The bssh-server supports interactive shell sessions through a PTY (pseudo-terminal) subsystem. This enables users to connect and run interactive programs like vim, top, or bash.

### PTY Management

The PTY module (`src/server/pty.rs`) handles pseudo-terminal operations:

**Key Components:**
- **PtyMaster**: Manages the master side of a PTY pair
  - Opens PTY pair using `openpty()` from the nix crate
  - Provides async I/O via tokio's `AsyncFd`
  - Handles window resize events with `TIOCSWINSZ` ioctl
  - Configurable terminal type and dimensions

**Configuration:**
```rust
use bssh::server::pty::{PtyConfig, PtyMaster};

// Create PTY with custom configuration
let config = PtyConfig::new(
    "xterm-256color".to_string(),  // Terminal type
    80,   // Columns
    24,   // Rows
    0,    // Pixel width (optional)
    0,    // Pixel height (optional)
);

let pty = PtyMaster::open(config)?;
```

### Shell Session Handler

The shell module (`src/server/shell.rs`) manages interactive SSH shell sessions:

**Features:**
- Spawns user's login shell with `-l` flag
- Sets up proper terminal environment (TERM, HOME, USER, SHELL, PATH)
- Creates new session and sets controlling terminal (setsid, TIOCSCTTY)
- Bidirectional I/O forwarding between SSH channel and PTY
- Window resize event forwarding
- Graceful shutdown with process cleanup

**Session Lifecycle:**
1. SSH client sends `pty-request` with terminal configuration
2. SSH client sends `shell` request
3. Server creates PTY pair and spawns shell process
4. I/O forwarding tasks handle data flow:
   - PTY master -> SSH channel (stdout/stderr)
   - SSH channel -> PTY master (stdin)
5. Window resize events update PTY dimensions
6. On disconnect, shell process receives SIGHUP

**Platform Support:**
- Unix/Linux: Full support using POSIX PTY APIs
- Windows: Not yet supported (would require ConPTY)

### SSH Handler Integration

The `SshHandler` orchestrates shell sessions through several handler methods:

```
SSH Client Request Flow:
┌───────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  pty_request  │ --> │ Store PtyConfig │ --> │ channel_success  │
└───────────────┘     └─────────────────┘     └──────────────────┘
        │
        v
┌───────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ shell_request │ --> │ Create Session  │ --> │ Start I/O Tasks  │
└───────────────┘     └─────────────────┘     └──────────────────┘
        │
        v
┌───────────────┐     ┌─────────────────┐     ┌──────────────────┐
│     data      │ --> │ Forward to PTY  │ --> │  User Typing     │
└───────────────┘     └─────────────────┘     └──────────────────┘
        │
        v
┌───────────────────┐     ┌─────────────────┐     ┌──────────────┐
│ window_change_req │ --> │ Resize PTY      │ --> │ TIOCSWINSZ   │
└───────────────────┘     └─────────────────┘     └──────────────┘
```

## SCP Protocol Handler

The bssh-server supports file transfers via the SCP (Secure Copy Protocol) command. Unlike SFTP which uses a dedicated subsystem, SCP operates through SSH exec requests.

### Protocol Overview

SCP is not a standalone protocol but a command-line tool that communicates over SSH. When a client runs `scp file user@host:path`:
1. The SSH client establishes a connection to the server
2. The server receives an exec request for `scp -t path` (upload) or `scp -f path` (download)
3. The server spawns the SCP handler to manage the file transfer

### Operation Modes

**Sink Mode (`-t` flag)**: Server receives files from client (upload)
```bash
# Client uploads file.txt to server's /tmp directory
scp file.txt user@server:/tmp/
```

**Source Mode (`-f` flag)**: Server sends files to client (download)
```bash
# Client downloads file.txt from server
scp user@server:/home/user/file.txt ./
```

### SCP Command Flags

| Flag | Description |
|------|-------------|
| `-t` | Sink mode (target/upload) |
| `-f` | Source mode (from/download) |
| `-r` | Recursive transfer for directories |
| `-p` | Preserve file modification times |
| `-d` | Target is expected to be a directory |
| `-v` | Verbose mode |

### Security Features

The SCP handler implements multiple security measures:

**Path Traversal Prevention:**
- All paths are normalized before processing
- `..` components are resolved without escaping the root directory
- Absolute paths are stripped and joined with the user's root directory

**Symlink Escape Prevention:**
- Existing paths are canonicalized to resolve symlinks
- If the canonical path is outside the root directory, access is denied
- Symlinks in recursive transfers are skipped for security

**Input Validation:**
- Filenames cannot contain `/`, `..`, or `.`
- File size is limited to 10 GB maximum
- Permission mode bits are masked to strip setuid/setgid/sticky bits (only 0o777 allowed)
- Protocol line length is limited to prevent DoS via buffer exhaustion

### Configuration

SCP is enabled by default. To disable it:

**YAML Configuration:**
```yaml
scp:
  enabled: false
```

**Builder API:**
```rust
let config = ServerConfig::builder()
    .scp_enabled(false)
    .build();
```

### Handler Architecture

```
SCP Request Flow:
┌───────────────┐     ┌──────────────────┐     ┌────────────────┐
│  exec_request │ --> │ Parse SCP cmd    │ --> │ Create Handler │
│  "scp -t /tmp"│     │ mode, path, flags│     │ with root_dir  │
└───────────────┘     └──────────────────┘     └────────────────┘
        │
        v
┌───────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Spawn task   │ --> │ SCP I/O loop     │ --> │ File transfer  │
│  (async)      │     │ protocol messages│     │ operations     │
└───────────────┘     └──────────────────┘     └────────────────┘
        │
        v
┌───────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Send status  │ --> │ EOF & close      │ --> │ Channel done   │
│  exit code    │     │ channel          │     │                │
└───────────────┘     └──────────────────┘     └────────────────┘
```

### Usage Examples

```bash
# Upload a single file
scp local_file.txt user@bssh-server:/home/user/

# Download a file
scp user@bssh-server:/home/user/file.txt ./

# Recursive directory upload
scp -r ./project/ user@bssh-server:/home/user/projects/

# Preserve timestamps
scp -p important.doc user@bssh-server:/backup/

# Recursive with timestamps
scp -rp ./data/ user@bssh-server:/storage/backup/
```

---

## File Transfer Filtering

The bssh-server provides a comprehensive policy-based system for controlling file transfers in SFTP and SCP operations. The filter system allows administrators to allow, deny, or log file operations based on various criteria.

### Filter Architecture

```
Filter Request Flow:
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  File Operation │ --> │ Normalize Path   │ --> │ Match Rules    │
│  (SFTP/SCP)     │     │ (prevent bypass) │     │ (in order)     │
└─────────────────┘     └──────────────────┘     └────────────────┘
        │
        v
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  First Match    │ --> │ Apply Action     │ --> │ Allow/Deny/Log │
│  Wins           │     │ (or default)     │     │                │
└─────────────────┘     └──────────────────┘     └────────────────┘
```

### Matcher Types

The filter system supports multiple matcher types that can be combined for flexible rule definitions:

| Matcher | Config Key | Description | Example |
|---------|------------|-------------|---------|
| **Glob** | `pattern` | Shell-style glob patterns | `*.exe`, `secret*` |
| **Prefix** | `path_prefix` | Directory tree matching | `/etc`, `/home/user` |
| **Extension** | `extensions` | Multiple file extensions | `["exe", "bat", "sh"]` |
| **Directory** | `directory` | Component anywhere in path | `.git`, `.ssh` |
| **Composite** | `composite` | AND/OR/NOT logic | See below |

### Glob Pattern Matching

Glob patterns support standard wildcards:
- `*` - matches any sequence of characters
- `?` - matches any single character
- `[abc]` - matches any character in the set
- `[!abc]` - matches any character not in the set

```yaml
rules:
  - pattern: "*.key"        # All .key files
  - pattern: "secret?.txt"  # secret1.txt, secretA.txt, etc.
  - pattern: "[0-9]*.log"   # Log files starting with a digit
```

### Extension Matching

Multi-extension matching is case-insensitive by default:

```yaml
rules:
  - name: "block-executables"
    extensions: ["exe", "bat", "sh", "ps1", "cmd"]
    action: deny

  - name: "block-archives"
    extensions: ["zip", "tar", "gz", "rar", "7z"]
    action: deny
```

### Composite Rules

Composite rules allow combining multiple matchers with logical operators:

**AND Logic** - All matchers must match:
```yaml
- name: "env-outside-home"
  composite:
    type: and
    matchers:
      - pattern: "*.env"
      - not:
          path_prefix: "/home"
  action: deny
```

**OR Logic** - Any matcher must match:
```yaml
- name: "sensitive-files"
  composite:
    type: or
    matchers:
      - pattern: "*.key"
      - pattern: "*.pem"
      - pattern: "*.p12"
  action: deny
```

**NOT Logic** - Invert the match (whitelist pattern):
```yaml
- name: "whitelist-data-only"
  composite:
    type: not
    matcher:
      path_prefix: "/data"
  action: deny  # Deny everything NOT in /data
```

### Operation and User Restrictions

Rules can be limited to specific operations or users:

```yaml
rules:
  # Prevent deletion of log files
  - name: "protect-logs"
    pattern: "*.log"
    action: deny
    operations: ["delete"]

  # Block uploads of executables for guest users
  - name: "guest-no-executables"
    extensions: ["exe", "sh", "bat"]
    action: deny
    operations: ["upload"]
    users: ["guest", "anonymous"]
```

**Available Operations:**
- `upload` - File uploads
- `download` - File downloads
- `delete` - File deletion
- `rename` - File rename/move
- `createdir` - Directory creation
- `listdir` - Directory listing
- `stat` - Reading file attributes
- `setstat` - Modifying file attributes
- `symlink` - Creating symbolic links
- `readlink` - Reading symbolic link targets

### Security Features

**Path Traversal Protection:**
All paths are normalized before matching to prevent bypass attempts:
```
/var/../etc/passwd  ->  /etc/passwd
/home/user/../../etc  ->  /etc
```

**First Match Wins:**
Rules are evaluated in order. The first matching rule determines the action. If no rules match, the default action (configurable, defaults to `allow`) is used.

### SizeAwareFilter Trait

For size-based filtering (e.g., blocking large uploads), the `SizeAwareFilter` trait provides:

```rust
use bssh::server::filter::{SizeAwareFilter, FilterResult, Operation};
use bssh::server::filter::path::SizeMatcher;

// Create a size matcher for files over 100MB
let large_file_matcher = SizeMatcher::min(100 * 1024 * 1024);

// Check if the given size matches
assert!(large_file_matcher.matches_size(200 * 1024 * 1024));  // 200MB matches
assert!(!large_file_matcher.matches_size(50 * 1024 * 1024)); // 50MB doesn't match
```

**Note:** Size-based filtering in configuration requires implementation integration with the actual file transfer handlers.

### Complete Filter Configuration Example

```yaml
filter:
  enabled: true
  default_action: allow

  rules:
    # Block dangerous executables
    - name: "block-executables"
      extensions: ["exe", "bat", "sh", "ps1", "cmd", "com"]
      action: deny

    # Block private keys and certificates
    - name: "block-secrets"
      composite:
        type: or
        matchers:
          - pattern: "*.key"
          - pattern: "*.pem"
          - pattern: "*.p12"
          - pattern: "id_rsa*"
          - pattern: "id_ed25519*"
      action: deny

    # Block hidden directories
    - name: "block-hidden"
      directory: ".git"
      action: deny

    - name: "block-ssh-config"
      directory: ".ssh"
      action: deny

    # Log access to configuration files
    - name: "log-config-access"
      path_prefix: "/etc"
      action: log

    # Restrict guests to read-only access in /data
    - name: "guest-read-only"
      path_prefix: "/data"
      operations: ["upload", "delete", "rename", "createdir", "setstat"]
      users: ["guest"]
      action: deny
```

---

## Session Management

The server implements comprehensive session management with per-user limits, idle timeout detection, and session tracking.

### Session Configuration

Session management is configured through the `SessionConfig` structure:

```rust
use bssh::server::session::SessionConfig;
use std::time::Duration;

let config = SessionConfig::new()
    .with_max_sessions_per_user(10)      // Max sessions per authenticated user
    .with_max_total_sessions(1000)       // Max total concurrent sessions
    .with_idle_timeout(Duration::from_secs(3600))    // 1 hour idle timeout
    .with_session_timeout(Duration::from_secs(86400)); // 24 hour max duration
```

### Session Limits

**Per-User Session Limits:**
- Each authenticated user has a configurable maximum number of concurrent sessions
- When a user exceeds their limit, authentication is rejected with an error
- Default: 10 sessions per user

**Total Session Limits:**
- The server enforces a global maximum number of concurrent sessions
- New connections are rejected when the limit is reached
- Default: 1000 total sessions (matches `max_connections`)

### Session Timeouts

**Idle Timeout:**
- Sessions with no activity for the configured duration are marked as idle
- The `cleanup_idle_sessions()` method removes idle unauthenticated sessions
- Default: 1 hour (3600 seconds)

**Session Timeout:**
- Optional maximum session duration regardless of activity
- Sessions exceeding this duration are eligible for termination
- Default: disabled (0)

### Session Activity Tracking

Each session tracks:
- **Session ID**: Unique identifier for the session
- **User**: Authenticated username (if authenticated)
- **Peer Address**: Remote client IP and port
- **Started At**: Timestamp of session creation
- **Last Activity**: Timestamp of last activity (updated via `touch()`)
- **Authentication State**: Whether the session is authenticated
- **Auth Attempts**: Number of authentication attempts

### Session Statistics

The `SessionManager` provides session statistics:

```rust
let stats = manager.get_stats();
println!("Total sessions: {}", stats.total_sessions);
println!("Authenticated: {}", stats.authenticated_sessions);
println!("Unique users: {}", stats.unique_users);
println!("Idle sessions: {}", stats.idle_sessions);
```

### Admin Operations

The session manager supports administrative operations:

```rust
// List all sessions
let sessions = manager.list_sessions();

// List sessions for a specific user
let user_sessions = manager.list_user_sessions("username");

// Force disconnect a session
manager.kill_session(session_id);

// Force disconnect all sessions for a user
let count = manager.kill_user_sessions("username");
```

### Configuration Validation

The `SessionConfig::validate()` method checks for potentially problematic settings and returns warnings:

- Warning if `max_sessions_per_user` > `max_total_sessions` (per-user limit will never be reached)
- Warning if `idle_timeout` is 0 (sessions immediately considered idle)
- Warning if `session_timeout` < `idle_timeout` (sessions may be terminated before idle check)

---

**Related Documentation:**
- [Server CLI Binary](../../ARCHITECTURE.md#server-cli-binary)
- [SSH Server Module](../../ARCHITECTURE.md#ssh-server-module)
- [Server Authentication](../../ARCHITECTURE.md#server-authentication-module)
- [Client Configuration Management](./configuration.md)
- [Main Architecture](../../ARCHITECTURE.md)

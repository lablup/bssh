# bssh - Broadcast SSH

[![Crates.io version](https://img.shields.io/crates/v/bssh.svg?style=flat-square)](https://crates.io/crates/bssh)
[![Crates.io downloads](https://img.shields.io/crates/d/bssh.svg?style=flat-square)](https://crates.io/crates/bssh)
![CI](https://github.com/lablup/bssh/workflows/CI/badge.svg)
[![dependency status](https://deps.rs/repo/github/lablup/bssh/status.svg)](https://deps.rs/repo/github/lablup/bssh)

A high-performance SSH client with **SSH-compatible syntax** for both single-host and parallel cluster operations, built with Rust and `russh`.

*Developed and maintained as part of the Backend.AI project.*

## Features

- **SSH Compatibility**: Drop-in replacement for SSH with compatible command-line syntax
- **Port Forwarding**: Full support for local (-L), remote (-R), and dynamic (-D) SSH port forwarding
- **Jump Host Support**: Connect through bastion hosts using OpenSSH ProxyJump syntax (`-J`)
- **Parallel Execution**: Execute commands across multiple nodes simultaneously
- **Cluster Management**: Define and manage node clusters via configuration files
- **Progress Tracking**: Real-time progress indicators for each node
- **Flexible Authentication**: Support for SSH keys, SSH agent, password authentication, and encrypted key passphrases
- **Host Key Verification**: Secure host key checking with known_hosts support
- **Cross-Platform**: Works on Linux and macOS
- **Output Management**: Save command outputs to files per node with detailed logging
- **Interactive Mode**: Interactive shell sessions with single-node or multiplexed multi-node support
- **SSH Config Caching**: High-performance caching of SSH configurations with TTL and file modification detection
- **Configurable Timeouts**: Set command execution timeouts with support for unlimited execution (timeout=0)

## Installation

### Install via Homebrew (macOS/Linux)

The easiest way to install `bssh` on macOS and Linux is through Homebrew:

```bash
brew tap lablup/tap
brew install bssh
```

###  Install via Ubuntu PPA

For Ubuntu users, `bssh` is available through the official PPA:

```bash
# Add the PPA repository
sudo add-apt-repository ppa:lablup/backend-ai
sudo apt update

# Install bssh
sudo apt install bssh
```

### Install via Debian Package

For Debian and other Debian-based distributions, download the `.deb` package from the [releases page](https://github.com/lablup/bssh/releases):

```bash
# Download the latest .deb package (replace VERSION with the actual version)
wget https://github.com/lablup/bssh/releases/download/vVERSION/bssh_VERSION_OS_ARCH.deb
# Example: bssh_0.4.0_ubuntu24.04.noble_amd64.deb

# Install the package
sudo dpkg -i bssh_VERSION_OS_ARCH.deb

# If there are dependency issues, fix them with:
sudo apt-get install -f
```

### Download Pre-built Binary

Download the latest release from the [GitHub releases page](https://github.com/lablup/bssh/releases):

1. Go to https://github.com/lablup/bssh/releases
2. Download the appropriate binary for your platform
3. Extract the archive and place the binary in your `$PATH`

### Install from Cargo

```bash
cargo build --release
sudo cp target/release/bssh /usr/local/bin/
```

## Quick Start

### SSH-Compatible Mode (Single Host)
```bash
# Connect to a host (just like SSH!)
bssh user@hostname

# Execute a command
bssh user@hostname "uptime"

# With specific port and key
bssh -p 2222 -i ~/.ssh/key.pem admin@server.com

# Using SSH options
bssh -o StrictHostKeyChecking=no user@host

# Query SSH capabilities
bssh -Q cipher
```

### Port Forwarding
```bash
# Local port forwarding (-L)
# Forward local port 8080 to example.com:80 via SSH
bssh -L 8080:example.com:80 user@host

# Remote port forwarding (-R)  
# Forward remote port 8080 to localhost:80
bssh -R 8080:localhost:80 user@host

# Dynamic port forwarding / SOCKS proxy (-D)
# Create SOCKS5 proxy on local port 1080
bssh -D 1080 user@host

# Multiple port forwards
bssh -L 3306:db:3306 -R 80:web:80 -D 1080 user@host

# Bind to specific address
bssh -L 127.0.0.1:8080:web:80 user@host           # Local only
bssh -L *:8080:web:80 user@host                   # All interfaces

# SOCKS4 proxy (specify version)
bssh -D 1080/4 user@host                          # SOCKS4
bssh -D *:1080/5 user@host                        # SOCKS5 on all interfaces

# Port forwarding with command execution
bssh -L 5432:postgres:5432 user@host "psql -h localhost"

# Port forwarding with cluster operations
bssh -C production -L 8080:internal:80 "curl http://localhost:8080"
```

### Jump Host Support (ProxyJump)
```bash
# Connect through a single jump host (bastion)
bssh -J jump@bastion.example.com user@internal-server

# Multiple jump hosts (connection chain)
bssh -J "jump1@proxy1,jump2@proxy2" user@final-destination

# Jump host with custom port
bssh -J admin@bastion:2222 user@internal-host

# IPv6 jump host
bssh -J "[2001:db8::1]:22" user@destination

# Combine with cluster operations
bssh -J bastion.example.com -C production "uptime"

# File transfer through jump host
bssh -J bastion.example.com -H internal-server upload app.tar.gz /opt/
bssh -J admin@bastion:2222 -C production download /etc/config ./backups/

# Interactive mode through jump hosts
bssh -J bastion.example.com user@internal-server
bssh -J "jump1,jump2" -C production interactive

# Multi-hop with file transfer
bssh -J "bastion1,bastion2,bastion3" -H target upload -r ./app/ /opt/app/
```

### Multi-Server Mode (Cluster Operations)
```bash
# Execute commands on multiple hosts (automatic command execution)
bssh -H "user1@host1.com,user2@host2.com:2222" "uptime"

# Using cluster from config
bssh -C production "df -h"

# Filter specific hosts with pattern matching
bssh -H "web1,web2,db1,db2" -f "web*" "systemctl status nginx"
bssh -C production -f "db*" "pg_dump --version"

# With custom SSH key
bssh -C staging -i ~/.ssh/custom_key "systemctl status nginx"

# Use SSH agent for authentication
bssh -A -C production "systemctl status nginx"

# Use password authentication (will prompt for password)
bssh --password -H "user@host.com" "uptime"

# Use encrypted SSH key (will prompt for passphrase)
bssh -i ~/.ssh/encrypted_key -C production "df -h"

# Limit parallel connections
bssh -C production --parallel 5 "apt update"

# Set command timeout (10 seconds)
bssh -C production --timeout 10 "quick-check"

# No timeout (unlimited execution time)
bssh -C staging --timeout 0 "long-running-backup"
```

### Built-in Commands
```bash
# Test connectivity to hosts
bssh -C production ping
bssh -H "host1,host2" ping

# List configured clusters
bssh list

# Interactive mode (single or multiplexed)
bssh -C production interactive
bssh -H "host1,host2" interactive

# File transfer operations
bssh -C production upload local.txt /tmp/
bssh -H "host1,host2" download /etc/hosts ./backups/
```

## Authentication

bssh supports multiple authentication methods:

### SSH Key Authentication
- **Default keys**: Automatically tries `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`, `~/.ssh/id_dsa`
- **Custom key**: Use `-i` flag to specify a key file
- **Encrypted keys**: Automatically detects and prompts for passphrase

### SSH Agent
- **Auto-detection**: Automatically uses SSH agent if `SSH_AUTH_SOCK` is set
- **Explicit**: Use `-A` flag to force SSH agent authentication

### Password Authentication
- Use `-P` flag to enable password authentication
- Password is prompted securely without echo

### Examples
```bash
# Use default SSH key (auto-detect)
bssh -H "user@host" "uptime"

# Use specific SSH key (prompts for passphrase if encrypted)
bssh -i ~/.ssh/custom_key -c production "df -h"

# Use SSH agent
bssh -A -c production "systemctl status"

# Use password authentication
bssh -P -H "user@host" "ls -la"

# Authentication through jump hosts
bssh -A -J bastion.example.com user@internal-server "uptime"
bssh -i ~/.ssh/prod_key -J "jump1,jump2" -C production "df -h"
```

## Environment Variables

bssh supports configuration via environment variables:

### Jump Host Configuration

- **`BSSH_MAX_JUMP_HOSTS`**: Maximum number of jump hosts allowed in a chain
  - Default: 10
  - Absolute maximum: 30 (security cap)
  - Invalid or zero values fall back to default
  - Example: `BSSH_MAX_JUMP_HOSTS=20 bssh -J host1,host2,...,host20 target`

### Backend.AI Integration Variables

- **`BACKENDAI_CLUSTER_HOSTS`**: Comma-separated list of all cluster nodes
- **`BACKENDAI_CLUSTER_HOST`**: Current node hostname
- **`BACKENDAI_CLUSTER_ROLE`**: Node role (main/sub)

### SSH Authentication Variables

- **`SSH_AUTH_SOCK`**: SSH agent socket path (Unix-like systems)

## Configuration

### Configuration Priority Order

bssh loads configuration from the following sources in priority order:

1. **Backend.AI Environment Variables** (automatic detection)
2. **Current directory** (`./config.yaml`)
3. **XDG config directory** (`$XDG_CONFIG_HOME/bssh/config.yaml` or `~/.config/bssh/config.yaml`)
4. **CLI specified path** (via `--config` flag, default: `~/.config/bssh/config.yaml`)

### Backend.AI Multi-node Session Support

When running inside a Backend.AI multi-node session, bssh automatically detects cluster configuration from environment variables. No manual configuration or cluster specification needed!

Backend.AI environment variables used:
- `BACKENDAI_CLUSTER_HOSTS`: Comma-separated list of all node hostnames
- `BACKENDAI_CLUSTER_HOST`: Current node's hostname  
- `BACKENDAI_CLUSTER_ROLE`: Current node's role (main or sub)

Note: Backend.AI multi-node clusters use SSH port 2200 by default, which is automatically configured.

**Automatic Detection:**
When these environment variables are set, bssh automatically creates a "backendai" cluster and uses it by default when no `-c` or `-H` options are specified.

Example:
```bash
# Inside Backend.AI multi-node session, just run:
bssh "uptime"  # Automatically executes on all cluster nodes

# Or specify a command explicitly:
bssh "nvidia-smi" # Check GPU status on all nodes

# Interactive mode also works automatically:
bssh interactive  # Opens interactive session with all Backend.AI nodes

# You can still override with explicit options if needed:
bssh -C other-cluster "command"  # Use a different cluster
bssh -H specific-host "command"   # Use specific host
```

### Manual Configuration File

Create a configuration file at any of these locations:
- `./config.yaml` (current directory)
- `~/.config/bssh/config.yaml` (user config directory)
- `~/.bssh/config.yaml` (default location)

```yaml
defaults:
  user: admin
  port: 22
  ssh_key: ~/.ssh/id_rsa
  parallel: 10
  timeout: 300  # Command timeout in seconds (0 for unlimited)

# Global interactive mode settings (optional)
interactive:
  default_mode: multiplex        # single_node or multiplex
  prompt_format: "[{node}] $ "   # Variables: {node}, {user}, {host}, {pwd}
  history_file: ~/.bssh_history
  show_timestamps: false         # Show timestamps in output
  work_dir: /home/admin          # Initial working directory
  broadcast_prefix: "!all "      # Prefix for broadcasting to all nodes
  node_switch_prefix: "!"        # Prefix for special commands
  colors:                        # Node-specific colors in output
    node1: red
    node2: blue
    node3: green
  keybindings:
    switch_node: "Ctrl+N"
    broadcast_toggle: "Ctrl+B"
    quit: "Ctrl+Q"

clusters:
  production:
    nodes:
      - web1.example.com
      - web2.example.com
      - user@web3.example.com:2222
    ssh_key: ~/.ssh/prod_key
    timeout: 600  # Override default timeout for this cluster
    # Cluster-specific interactive settings (overrides global)
    interactive:
      default_mode: single_node
      prompt_format: "prod> "
      work_dir: /var/www
  
  staging:
    nodes:
      - host: staging1.example.com
        port: 2200
        user: deploy
      - staging2.example.com
    user: staging_user
```

## SSH Configuration Support

bssh fully supports OpenSSH-compatible configuration files via the `-F` flag or default SSH config locations (`~/.ssh/config`, `/etc/ssh/ssh_config`). In addition to standard SSH directives, bssh supports advanced options for certificate-based authentication and port forwarding control.

### Certificate Authentication Options

These options enable enterprise-grade PKI authentication using SSH certificates:

| Option | Description | Example |
|--------|-------------|---------|
| **CertificateFile** | SSH certificate file for PKI authentication (max 100 files) | `CertificateFile ~/.ssh/id_rsa-cert.pub` |
| **CASignatureAlgorithms** | CA signature algorithms for certificate validation (max 50) | `CASignatureAlgorithms ssh-ed25519,rsa-sha2-512` |
| **HostbasedAuthentication** | Enable host-based authentication (yes/no) | `HostbasedAuthentication yes` |
| **HostbasedAcceptedAlgorithms** | Algorithms for host-based auth (max 50) | `HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512` |

### Port Forwarding Control Options

These options provide fine-grained control over SSH port forwarding:

| Option | Description | Example |
|--------|-------------|---------|
| **GatewayPorts** | Control remote port forwarding (yes/no/clientspecified) | `GatewayPorts clientspecified` |
| **ExitOnForwardFailure** | Terminate connection if port forwarding fails (yes/no) | `ExitOnForwardFailure yes` |
| **PermitRemoteOpen** | Allowed destinations for remote forwarding (max 1000) | `PermitRemoteOpen localhost:8080` |

### Command Execution and Automation Options

These options enable powerful automation workflows and command execution features:

| Option | Description | Example |
|--------|-------------|---------|
| **PermitLocalCommand** | Allow local command execution after connection (yes/no, default: no) | `PermitLocalCommand yes` |
| **LocalCommand** | Execute local command after successful connection (supports tokens: %h, %H, %n, %p, %r, %u) | `LocalCommand rsync -av ~/project/ %h:~/project/` |
| **RemoteCommand** | Execute command on remote host instead of shell | `RemoteCommand tmux attach -t dev \|\| tmux new -s dev` |
| **KnownHostsCommand** | Command to fetch host keys dynamically (supports tokens) | `KnownHostsCommand /usr/local/bin/fetch-host-key %H` |
| **ForkAfterAuthentication** | Fork to background after authentication (yes/no) | `ForkAfterAuthentication yes` |
| **SessionType** | Session type: none/subsystem/default | `SessionType none` |
| **StdinNull** | Redirect stdin from /dev/null (yes/no) | `StdinNull yes` |

**Token Substitution:**
LocalCommand and KnownHostsCommand support the following tokens:
- `%h` - Remote hostname (from config)
- `%H` - Remote hostname (as specified on command line)
- `%n` - Original hostname
- `%p` - Remote port
- `%r` - Remote username
- `%u` - Local username
- `%%` - Literal percent sign

### Host Key Verification & Security Options

These options provide enhanced security and host key management features:

| Option | Description | Example |
|--------|-------------|---------|
| **NoHostAuthenticationForLocalhost** | Skip host key verification for localhost (yes/no, default: no) | `NoHostAuthenticationForLocalhost yes` |
| **HashKnownHosts** | Hash hostnames in known_hosts file for security (yes/no, default: no) | `HashKnownHosts yes` |
| **CheckHostIP** | Check host IP address in known_hosts (yes/no, **deprecated** in OpenSSH 8.5+) | `CheckHostIP no` |
| **VisualHostKey** | Display ASCII art of host key fingerprint (yes/no, default: no) | `VisualHostKey yes` |
| **HostKeyAlias** | Alias for host key lookup in known_hosts | `HostKeyAlias lb.example.com` |
| **VerifyHostKeyDNS** | Verify host keys using DNS SSHFP records (yes/no/ask, default: no) | `VerifyHostKeyDNS ask` |
| **UpdateHostKeys** | Accept updated host keys from server (yes/no/ask, default: no) | `UpdateHostKeys ask` |

### Additional Authentication Options

These options provide fine-grained control over authentication behavior:

| Option | Description | Example |
|--------|-------------|---------|
| **NumberOfPasswordPrompts** | Password retry attempts (1-10, default: 3) | `NumberOfPasswordPrompts 1` |
| **EnableSSHKeysign** | Enable ssh-keysign for host-based auth (yes/no, default: no) | `EnableSSHKeysign yes` |

### Network & Connection Options

These options control network-level connection behavior:

| Option | Description | Example |
|--------|-------------|---------|
| **BindInterface** | Bind connection to specific network interface | `BindInterface tun0` |
| **IPQoS** | Set IP QoS/DSCP values (interactive bulk) | `IPQoS lowdelay throughput` |
| **RekeyLimit** | Control SSH session key renegotiation (data time) | `RekeyLimit 1G 1h` |

### X11 Forwarding Options

These options control X11 display forwarding behavior:

| Option | Description | Example |
|--------|-------------|---------|
| **ForwardX11Timeout** | Timeout for untrusted X11 forwarding (0 = no timeout) | `ForwardX11Timeout 1h` |
| **ForwardX11Trusted** | Enable trusted X11 forwarding (yes/no, default: no) | `ForwardX11Trusted yes` |

### Authentication and Security Management Options

These options provide essential authentication management, security enforcement, and user convenience features:

| Option | Description | Example |
|--------|-------------|---------|
| **IdentitiesOnly** | Only use identity files specified in config, ignore SSH agent (yes/no) | `IdentitiesOnly yes` |
| **AddKeysToAgent** | Auto-add keys to SSH agent (yes/no/ask/confirm) | `AddKeysToAgent yes` |
| **IdentityAgent** | Custom SSH agent socket path or "none" | `IdentityAgent ~/.1password/agent.sock` |
| **PubkeyAcceptedAlgorithms** | Restrict allowed public key algorithms (max 50) | `PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512` |
| **RequiredRSASize** | Minimum RSA key size in bits (1024-16384, warns <2048) | `RequiredRSASize 2048` |
| **FingerprintHash** | Fingerprint hash algorithm (md5/sha256) | `FingerprintHash sha256` |

**Key Benefits:**
- **IdentitiesOnly**: Solves multi-account authentication conflicts
- **AddKeysToAgent**: Eliminates manual ssh-add commands
- **IdentityAgent**: Enables modern agent tools (1Password, gpg-agent, etc.)
- **PubkeyAcceptedAlgorithms**: Enforces security policies
- **RequiredRSASize**: Prevents weak RSA keys
- **FingerprintHash**: Flexibility for legacy systems

### SSH Config Examples

#### Certificate-based Authentication

```ssh-config
# ~/.ssh/config

# Production servers with certificate authentication
Host *.prod.example.com
    User admin
    CertificateFile ~/.ssh/prod-user-cert.pub
    CertificateFile ~/.ssh/prod-host-cert.pub
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
    HostbasedAuthentication yes
    HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512
```

#### Strict Port Forwarding Control

```ssh-config
# Secure hosts with restricted port forwarding
Host *.secure.prod.example.com
    GatewayPorts clientspecified
    ExitOnForwardFailure yes
    PermitRemoteOpen localhost:8080
    PermitRemoteOpen db.internal:5432
    PermitRemoteOpen cache.internal:6379
```

#### Command Execution and Automation

```ssh-config
# Development server with automatic file synchronization
Host dev-server
    User developer
    PermitLocalCommand yes
    LocalCommand rsync -av ~/project/ %h:~/project/

# Auto-attach to tmux session on connection
Host project-server
    RemoteCommand tmux attach -t project || tmux new -s project
    RequestTTY yes

# Cloud instances with dynamic host key fetching
Host *.cloud.example.com
    KnownHostsCommand /usr/local/bin/fetch-cloud-key %H
    StrictHostKeyChecking accept-new

# Background SSH tunnel for port forwarding
Host tunnel
    ForkAfterAuthentication yes
    SessionType none
    LocalForward 8080 internal-server:80
    StdinNull yes
```

#### Host Key Verification, Authentication, and Network Options

```ssh-config
# Local development environment - skip localhost verification
Host localhost 127.0.0.1 ::1
    NoHostAuthenticationForLocalhost yes
    NumberOfPasswordPrompts 1

# Security-hardened configuration with host key protection
Host *.secure.example.com
    HashKnownHosts yes
    VisualHostKey yes
    VerifyHostKeyDNS ask
    UpdateHostKeys ask
    CheckHostIP no

# Load-balanced service with shared host key
Host lb-node-*
    HostKeyAlias lb.example.com

# Multi-homed host with specific interface binding
Host vpn-only
    BindInterface tun0
    IPQoS lowdelay throughput

# High-security session with frequent rekeying
Host sensitive-data
    RekeyLimit 500M 30m

# X11 forwarding with timeout and trust for graphics workstation
Host graphics-workstation
    ForwardX11 yes
    ForwardX11Trusted yes
    ForwardX11Timeout 2h
```

#### Authentication and Security Best Practices

```ssh-config
# Multi-account setup - prevent agent key conflicts
Host work
    HostName work.example.com
    IdentityFile ~/.ssh/work_rsa
    IdentitiesOnly yes

Host personal
    HostName github.com
    User git
    IdentityFile ~/.ssh/personal_ed25519
    IdentitiesOnly yes

# Auto-add keys to SSH agent for convenience
Host *
    AddKeysToAgent yes

# Custom SSH agent integration (1Password, gpg-agent)
Host secure-*
    IdentityAgent ~/.1password/agent.sock

# Disable SSH agent for specific hosts
Host no-agent-host
    IdentityAgent none

# Security-hardened production servers
Host *.prod.example.com
    # Only allow modern, secure algorithms
    PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
    # Enforce strong RSA keys
    RequiredRSASize 2048
    # Use modern fingerprint hashing
    FingerprintHash sha256

# Legacy system compatibility
Host legacy.example.com
    # Allow older RSA keys
    RequiredRSASize 1024
    # Use MD5 for legacy fingerprint verification
    FingerprintHash md5
```

#### Complete Example with Include and Match

```ssh-config
# Base security settings
Host *
    HostbasedAuthentication no
    ExitOnForwardFailure no
    PermitLocalCommand no

# Production certificate configuration
Host *.prod.example.com
    CertificateFile ~/.ssh/prod-cert.pub
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512
    HostbasedAuthentication yes

# Match directive for secure hosts
Match host *.secure.prod.example.com
    GatewayPorts clientspecified
    ExitOnForwardFailure yes
    PermitRemoteOpen localhost:8080

# Development hosts with automation
Match host *.dev.example.com
    PermitLocalCommand yes
    LocalCommand notify-send "Connected to %h"

# Specific host overrides
Host web.secure.prod.example.com
    User webadmin
    Port 443
    CertificateFile ~/.ssh/web-specific-cert.pub
```

### Using SSH Config with bssh

```bash
# Use default SSH config (~/.ssh/config)
bssh user@host.prod.example.com

# Use custom SSH config file
bssh -F ~/custom-ssh-config user@host.prod.example.com

# SSH config works with cluster operations
bssh -C production "uptime"

# Config options apply to all cluster nodes
bssh -F ~/.ssh/prod-config -C production upload app.tar.gz /opt/
```

## Command-Line Options

```
Options:
  -H, --hosts <HOSTS>                     Comma-separated list of hosts (user@host:port format)
  -c, --cluster <CLUSTER>                 Cluster name from configuration file
  --config <CONFIG>                       Configuration file path [default: ~/.config/bssh/config.yaml]
  -u, --user <USER>                       Default username for SSH connections
  -i, --identity <IDENTITY>               SSH private key file path (prompts for passphrase if encrypted)
  -A, --use-agent                         Use SSH agent for authentication (Unix/Linux/macOS only)
  -P, --password                          Use password authentication (will prompt for password)
  -J, --jump-host <JUMP_HOSTS>            Comma-separated list of jump hosts (ProxyJump)
  -L, --local-forward <SPEC>              Local port forwarding [bind_address:]port:host:hostport
  -R, --remote-forward <SPEC>             Remote port forwarding [bind_address:]port:host:hostport
  -D, --dynamic-forward <SPEC>            Dynamic port forwarding (SOCKS) [bind_address:]port[/version]
  --strict-host-key-checking <MODE>       Host key checking mode (yes/no/accept-new) [default: accept-new]
  -p, --parallel <PARALLEL>               Maximum parallel connections [default: 10]
  --timeout <TIMEOUT>                     Command timeout in seconds (0 for unlimited) [default: 300]
  --output-dir <OUTPUT_DIR>               Output directory for command results
  -v, --verbose                           Increase verbosity (-v, -vv, -vvv)
  -h, --help                              Print help
  -V, --version                           Print version
```

## Examples

### Backend.AI Multi-node Session
```bash
# Inside Backend.AI session - automatic cluster detection
bssh "hostname"  # Shows hostnames of all nodes
bssh "nvidia-smi --query-gpu=name,memory.total --format=csv"  # GPU info
bssh "python train.py --distributed"  # Run distributed training
```

### Run system updates
```bash
bssh -C production "sudo apt update && sudo apt upgrade -y"
```

### Check disk usage
```bash
bssh -H "server1,server2,server3" "df -h | grep -E '^/dev/'"
```

### Restart services
```bash
bssh -C webservers "sudo systemctl restart nginx"
```

### Collect logs
```bash
bssh -C production --output-dir ./logs "tail -n 100 /var/log/syslog"
```

### Long-running commands with timeout
```bash
# Set 30 minute timeout for backup operations
bssh -C production --timeout 1800 "backup-database.sh"

# No timeout for data migration (may take hours)
bssh -C production --timeout 0 "migrate-data.sh"

# Quick health check with 5 second timeout
bssh -C monitoring --timeout 5 "health-check.sh"
```

### Interactive Mode

Start an interactive shell session on cluster nodes:

```bash
# Interactive session on all nodes (multiplex mode - default)
bssh -C production interactive

# Interactive session on a single node
bssh -C production interactive --single-node

# Custom prompt format
bssh -H server1,server2 interactive --prompt-format "{user}@{host}> "

# Set initial working directory
bssh -C staging interactive --work-dir /var/www
```

#### Interactive Mode Configuration

Interactive mode can be configured in your `config.yaml` file with both global and per-cluster settings. CLI arguments always override configuration file settings.

**Global Configuration** (applies to all clusters unless overridden):
```yaml
interactive:
  default_mode: multiplex        # or single_node
  prompt_format: "[{node}] $ "
  history_file: ~/.bssh_history
  show_timestamps: true          # Add timestamps to output
  work_dir: /home/user
  broadcast_prefix: "!all "      # Custom prefix for broadcast commands
  node_switch_prefix: "!"        # Custom prefix for special commands
```

**Per-Cluster Configuration** (overrides global settings):
```yaml
clusters:
  production:
    interactive:
      default_mode: single_node  # Different mode for this cluster
      prompt_format: "PROD> "
      work_dir: /var/app
```

**Configuration Priority**:
1. CLI arguments (highest priority)
2. Cluster-specific configuration
3. Global configuration
4. Built-in defaults

In multiplex mode, commands are sent to active nodes with visual indicators:

```
[● ● ●] bssh> uptime
[node1]  10:23:45 up 5 days, 2:14, 1 user, load average: 0.15, 0.12, 0.09
[node2]  10:23:45 up 3 days, 4:22, 2 users, load average: 0.23, 0.19, 0.17
[node3]  10:23:45 up 7 days, 1:45, 1 user, load average: 0.08, 0.11, 0.10
[● ● ●] bssh> exit
```

#### Interactive Mode Special Commands

Interactive mode supports special commands for node management. By default, these commands start with `!` but the prefix can be customized in the configuration file.

| Command | Description |
|---------|-------------|
| `!all` | Activate all connected nodes |
| `!broadcast <cmd>` | Execute command on all nodes temporarily (without changing active nodes) |
| `!node<N>` or `!n<N>` | Switch to node N (e.g., `!node1`, `!n2`) |
| `!list` or `!nodes` | List all nodes with their connection status |
| `!status` | Show currently active nodes |
| `!help` or `!?` | Show help for special commands |
| `exit` | Exit interactive mode |

**Note**: The `!` prefix and `!broadcast` command can be customized via configuration:
```yaml
interactive:
  node_switch_prefix: "@"        # Use @ instead of !
  broadcast_prefix: "@all "      # Use @all instead of !broadcast
```

#### Node Indicators in Prompt

The prompt shows node status with visual indicators:
- `●` Active node (commands will be executed)
- `○` Inactive node (connected but not receiving commands)
- `·` Disconnected node

Examples:
- `[● ● ●] bssh>` - All 3 nodes active
- `[● ○ ○] bssh>` - Only first node active
- `[1 · ·] (1/3) bssh>` - Node 1 active, nodes 2 and 3 inactive

For large clusters (>10 nodes), the prompt uses a compact format:
- `[All 50/50] bssh>` - All 50 nodes active
- `[None 0/50] bssh>` - No nodes active
- `[Nodes 1,2,3... +47] (50/50) bssh>` - Specific nodes active

#### Example Interactive Session

```bash
$ bssh -C production interactive

Connected to 3 nodes
[● ● ●] bssh> !status
Active nodes: node1.example.com, node2.example.com, node3.example.com

[● ● ●] bssh> !node1
Switched to node 1

[● ○ ○] (1/3) bssh> hostname
[node1] node1.example.com

[● ○ ○] (1/3) bssh> !broadcast date
Broadcasting command to all connected nodes...
[node1] Thu Aug 22 10:30:00 UTC 2025
[node2] Thu Aug 22 10:30:00 UTC 2025
[node3] Thu Aug 22 10:30:00 UTC 2025

[● ○ ○] (1/3) bssh> !all
All nodes activated

[● ● ●] bssh> df -h /
[node1] Filesystem      Size  Used Avail Use% Mounted on
[node1] /dev/sda1        20G  5.5G   14G  30% /
[node2] Filesystem      Size  Used Avail Use% Mounted on
[node2] /dev/sda1        20G  7.2G   12G  38% /
[node3] Filesystem      Size  Used Avail Use% Mounted on
[node3] /dev/sda1        20G  4.1G   15G  22% /

[● ● ●] bssh> exit
Goodbye!
```

## Output File Management

When using the `--output-dir` option, bssh saves command outputs to structured files:

### File Structure
```
output-dir/
├── hostname1_20250821_143022.stdout   # Standard output
├── hostname1_20250821_143022.stderr   # Standard error (if any)
├── hostname2_20250821_143022.stdout   # Per-node outputs
├── hostname2_20250821_143022.error    # Connection/execution errors
├── hostname3_20250821_143022.empty    # Marker for no output
└── summary_20250821_143022.txt        # Overall execution summary
```

### File Types
- **`.stdout`**: Contains standard output from successful commands
- **`.stderr`**: Contains standard error output (created only if stderr is not empty)
- **`.error`**: Contains error messages for failed connections or executions
- **`.empty`**: Marker file when command produces no output
- **`summary_*.txt`**: Overall execution summary with success/failure counts

### File Headers
Each output file includes metadata headers:
```
# Command: df -h
# Host: server1.example.com
# User: admin
# Exit Status: 0
# Timestamp: 20250821_143022

[actual command output follows]
```

### Example Usage
```bash
# Save outputs to timestamped directory
bssh -C production --output-dir ./results/$(date +%Y%m%d) "ps aux | head -10"

# Collect system information
bssh -C all-servers --output-dir ./system-info "uname -a; df -h; free -m"

# Debug failed services
bssh -C webservers --output-dir ./debug "systemctl status nginx"
```

## Development

Read [ARCHITECTURE](ARCHITECTURE.md) documentation for more information.

### Building
```bash
cargo build
```

### Testing
```bash
cargo test
```

### Running locally
```bash
cargo run -- -H localhost "echo hello"
```

## SSH Implementation

This project's SSH functionality is built using:

- **[russh](https://github.com/Eugeny/russh)**: A pure Rust implementation of the SSH protocol, providing a modern and safe foundation for SSH communications without relying on C libraries. This is the core SSH library used directly as a dependency.
  
- **Implementation patterns from [async-ssh2-tokio](https://github.com/Miyoshi-Ryota/async-ssh2-tokio)**: While not used as a direct dependency, portions of the implementation code and architectural patterns from async-ssh2-tokio have been adapted and integrated into this project to provide high-level async/await APIs that work seamlessly with the Tokio runtime.

This combination enables bssh to achieve high performance parallel SSH operations while maintaining memory safety and avoiding common security vulnerabilities associated with traditional C-based SSH implementations.

## License

This project is licensed under the Apache License 2.0.  
See the [LICENSE](./LICENSE) file for details.

## Changelog

### Recent Updates
- **v1.0.0 (2025/10/24):** Major milestone release with comprehensive SSH configuration support (~71 options), certificate authentication, advanced security features, and modular parser architecture
- **v0.9.1 (2025/10/14):** Complete PTY terminal modes implementation with Shift key input support
- **v0.9.0 (2025/10/14):** Add SSH ProxyJump support for file transfers and interactive mode, update packages
- **v0.8.0 (2025/09/12):** Add comprehensive SSH port forwarding (local/remote/dynamic), improve error messages and remove dangerous unwrap() calls
- **v0.7.0 (2025/08/30):** Add SSH jump host (-J) infrastructure and CLI integration, improve Ubuntu PPA support and fix deprecated GitHub Actions
- **v0.6.1 (2025/08/28):** Rebrand from 'Backend.AI SSH' to 'Broadcast SSH' to emphasize the tool's core broadcast/parallel functionality
- **v0.6.0 (2025/08/28):** Add SSH config file support (-F), PTY allocation, security enhancements, performance improvements, and SSH-compatible command-line interface
- **v0.5.4 (2025/08/27):** Fix parallel config value handling and align interactive mode authentication with exec mode
- **v0.5.3 (2025/08/27):** Use Backend.AI cluster SSH key for auto-detected environments
- **v0.5.2 (2025/08/27):** Fix config file loading priority, improve BACKENDAI environment handling, use cluster SSH key config
- **v0.5.1 (2025/08/25):** Add configurable command timeout with support for unlimited execution (timeout=0), configurable via CLI and config file
- **v0.5.0 (2025/08/22):** Add interactive mode with single-node and multiplex support, broadcast command, and improved Backend.AI cluster auto-detection
- **v0.4.0 (2025/08/22):** Add password authentication, SSH key passphrase support, modern UI with colors, XDG config compliance, and Debian packaging
- **v0.3.0 (2025/08/22):** Add native SFTP directory operations and recursive file transfer support
- **v0.2.0 (2025/08/21):** Added Backend.AI multi-node session support with SSH authentication, host key verification, environment variable expansion, timeouts, and SCP file copy functionality.
- **v0.1.0 (2025/08/21):** Initial release with parallel SSH execution using async-ssh2-tokio 
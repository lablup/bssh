# bssh - Backend.AI SSH

[![Crates.io version](https://img.shields.io/crates/v/bssh.svg?style=flat-square)](https://crates.io/crates/bssh)
[![Crates.io downloads](https://img.shields.io/crates/d/bssh.svg?style=flat-square)](https://crates.io/crates/bssh)
![CI](https://github.com/lablup/bssh/workflows/CI/badge.svg)
[![dependency status](https://deps.rs/repo/github/lablup/bssh/status.svg)](https://deps.rs/repo/github/lablup/bssh)

A high-performance parallel SSH command execution tool for cluster management, built with Rust and `russh`.

*Developed and maintained as part of the Backend.AI project.*

## Features

- **Parallel Execution**: Execute commands across multiple nodes simultaneously
- **Cluster Management**: Define and manage node clusters via configuration files
- **Progress Tracking**: Real-time progress indicators for each node
- **Flexible Authentication**: Support for SSH keys, SSH agent, password authentication, and encrypted key passphrases
- **Host Key Verification**: Secure host key checking with known_hosts support
- **Cross-Platform**: Works on Linux and macOS
- **Output Management**: Save command outputs to files per node with detailed logging
- **Interactive Mode**: Interactive shell sessions with single-node or multiplexed multi-node support
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

### Execute command on multiple hosts
```bash
# Using direct host specification
bssh -H "user1@host1.com,user2@host2.com:2222" "uptime"

# Using cluster from config
bssh -c production "df -h"

# With custom SSH key
bssh -c staging -i ~/.ssh/custom_key "systemctl status nginx"

# Use SSH agent for authentication
bssh --use-agent -c production "systemctl status nginx"

# Use password authentication (will prompt for password)
bssh --password -H "user@host.com" "uptime"

# Use encrypted SSH key (will prompt for passphrase)
bssh -i ~/.ssh/encrypted_key -c production "df -h"

# Limit parallel connections
bssh -c production --parallel 5 "apt update"

# Set command timeout (10 seconds)
bssh -c production --timeout 10 "quick-check"

# No timeout (unlimited execution time)
bssh -c staging --timeout 0 "long-running-backup"
```

### Test connectivity
```bash
bssh -c production ping
```

### List configured clusters
```bash
bssh list
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
```

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
bssh -c other-cluster "command"  # Use a different cluster
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
bssh -c production "sudo apt update && sudo apt upgrade -y"
```

### Check disk usage
```bash
bssh -H "server1,server2,server3" "df -h | grep -E '^/dev/'"
```

### Restart services
```bash
bssh -c webservers "sudo systemctl restart nginx"
```

### Collect logs
```bash
bssh -c production --output-dir ./logs "tail -n 100 /var/log/syslog"
```

### Long-running commands with timeout
```bash
# Set 30 minute timeout for backup operations
bssh -c production --timeout 1800 "backup-database.sh"

# No timeout for data migration (may take hours)
bssh -c production --timeout 0 "migrate-data.sh"

# Quick health check with 5 second timeout
bssh -c monitoring --timeout 5 "health-check.sh"
```

### Interactive Mode

Start an interactive shell session on cluster nodes:

```bash
# Interactive session on all nodes (multiplex mode - default)
bssh -c production interactive

# Interactive session on a single node
bssh -c production interactive --single-node

# Custom prompt format
bssh -H server1,server2 interactive --prompt-format "{user}@{host}> "

# Set initial working directory
bssh -c staging interactive --work-dir /var/www
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
$ bssh -c production interactive

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
bssh -c production --output-dir ./results/$(date +%Y%m%d) "ps aux | head -10"

# Collect system information
bssh -c all-servers --output-dir ./system-info "uname -a; df -h; free -m"

# Debug failed services
bssh -c webservers --output-dir ./debug "systemctl status nginx"
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
- **v0.5.1 (2025/08/25):** Add configurable command timeout with support for unlimited execution (timeout=0), configurable via CLI and config file
- **v0.5.0 (2025/08/22):** Add interactive mode with single-node and multiplex support, broadcast command, and improved Backend.AI cluster auto-detection
- **v0.4.0 (2025/08/22):** Add password authentication, SSH key passphrase support, modern UI with colors, XDG config compliance, and Debian packaging
- **v0.3.0 (2025/08/22):** Add native SFTP directory operations and recursive file transfer support
- **v0.2.0 (2025/08/21):** Added Backend.AI multi-node session support with SSH authentication, host key verification, environment variable expansion, timeouts, and SCP file copy functionality.
- **v0.1.0 (2025/08/21):** Initial release with parallel SSH execution using async-ssh2-tokio 
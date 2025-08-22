# bssh - Backend.AI SSH

A high-performance parallel SSH command execution tool for cluster management, built with Rust and thrussh.

## Features

- **Parallel Execution**: Execute commands across multiple nodes simultaneously
- **Cluster Management**: Define and manage node clusters via configuration files
- **Progress Tracking**: Real-time progress indicators for each node
- **Flexible Authentication**: Support for SSH keys and SSH agent
- **Host Key Verification**: Secure host key checking with known_hosts support
- **Cross-Platform**: Works on Linux and macOS
- **Output Management**: Save command outputs to files per node with detailed logging

## Installation

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

# Limit parallel connections
bssh -c production --parallel 5 "apt update"
```

### Test connectivity
```bash
bssh -c production ping
```

### List configured clusters
```bash
bssh list
```

## Configuration

### Configuration Priority Order

bssh loads configuration from the following sources in priority order:

1. **Backend.AI Environment Variables** (automatic detection)
2. **Current directory** (`./config.yaml`)
3. **User config directory** (`~/.config/bssh/config.yaml`)
4. **Default location** (`~/.bssh/config.yaml`)

### Backend.AI Multi-node Session Support

When running inside a Backend.AI multi-node session, bssh automatically detects cluster configuration from environment variables. No manual configuration needed!

Backend.AI environment variables used:
- `BACKENDAI_CLUSTER_HOSTS`: Comma-separated list of all node hostnames
- `BACKENDAI_CLUSTER_HOST`: Current node's hostname
- `BACKENDAI_CLUSTER_ROLE`: Current node's role (main or sub)

Note: Backend.AI multi-node clusters use SSH port 2200 by default, which is automatically configured.

Example:
```bash
# Inside Backend.AI multi-node session, just run:
bssh "uptime"  # Automatically executes on all cluster nodes

# Or specify a command explicitly:
bssh "nvidia-smi" # Check GPU status on all nodes
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

clusters:
  production:
    nodes:
      - web1.example.com
      - web2.example.com
      - user@web3.example.com:2222
    ssh_key: ~/.ssh/prod_key
  
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
  -H, --hosts <HOSTS>                     Comma-separated list of hosts
  -c, --cluster <CLUSTER>                 Cluster name from configuration
  --config <CONFIG>                       Config file path [default: ~/.bssh/config.yaml]
  -u, --user <USER>                       Default username for SSH
  -i, --identity <IDENTITY>               SSH private key file
  -A, --use-agent                         Use SSH agent for authentication
  --strict-host-key-checking <MODE>       Host key checking mode [yes|no|accept-new] [default: accept-new]
  -p, --parallel <PARALLEL>               Max parallel connections [default: 10]
  --output-dir <OUTPUT_DIR>               Output directory for results
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

## License

Copyright 2024 Jeongkyu Shin

Licensed under the Apache License, Version 2.0

## Changelog

### Recent Updates
- **v0.2.0 (2025/08/21):** Added Backend.AI multi-node session support with SSH authentication, host key verification, environment variable expansion, timeouts, and SCP file copy functionality.
- **v0.1.0 (2025/08/21):** Initial release with parallel SSH execution using async-ssh2-tokio 
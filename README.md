# bssh - Backend.AI SSH

A high-performance parallel SSH command execution tool for cluster management, built with Rust and thrussh.

## Features

- **Parallel Execution**: Execute commands across multiple nodes simultaneously
- **Cluster Management**: Define and manage node clusters via configuration files
- **Progress Tracking**: Real-time progress indicators for each node
- **Flexible Authentication**: Support for SSH keys and SSH agent
- **Cross-Platform**: Works on Linux and macOS

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

Create a configuration file at `~/.bssh/config.yaml`:

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
  -H, --hosts <HOSTS>           Comma-separated list of hosts
  -c, --cluster <CLUSTER>       Cluster name from configuration
  --config <CONFIG>             Config file path [default: ~/.bssh/config.yaml]
  -u, --user <USER>             Default username for SSH
  -i, --identity <IDENTITY>     SSH private key file
  -p, --parallel <PARALLEL>     Max parallel connections [default: 10]
  --output-dir <OUTPUT_DIR>     Output directory for results
  -v, --verbose                 Increase verbosity (-v, -vv, -vvv)
  -h, --help                    Print help
  -V, --version                 Print version
```

## Examples

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
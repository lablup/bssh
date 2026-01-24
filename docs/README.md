# bssh Documentation

Welcome to the bssh documentation. This documentation covers both the bssh client and bssh-server.

## Quick Links

- **[Quick Start Guide](./quick-start.md)** - Get bssh-server running in minutes
- **[Server Configuration](./architecture/server-configuration.md)** - Complete configuration reference
- **[Security Guide](./security.md)** - Security best practices
- **[Container Deployment](./container-deployment.md)** - Docker and Kubernetes deployment

## Documentation Index

### Getting Started

| Document | Description |
|----------|-------------|
| [Quick Start](./quick-start.md) | Installation and first run guide |
| [Container Deployment](./container-deployment.md) | Docker and Kubernetes deployment |

### Server Administration

| Document | Description |
|----------|-------------|
| [Server Configuration](./architecture/server-configuration.md) | Complete configuration reference |
| [Security Guide](./security.md) | Security best practices and hardening |
| [Audit Logging](./audit-logging.md) | Audit logging setup and integration |

### Client Documentation

| Document | Description |
|----------|-------------|
| [CLI Interface](./architecture/cli-interface.md) | Command-line interface documentation |
| [Interactive Mode](./architecture/interactive-mode.md) | TUI and interactive shell mode |
| [SSH Jump Hosts](./architecture/ssh-jump-hosts.md) | ProxyJump and jump host support |
| [Port Forwarding](./architecture/ssh-port-forwarding.md) | Local, remote, and dynamic forwarding |

### Migration Guides

| Document | Description |
|----------|-------------|
| [pdsh Migration](./pdsh-migration.md) | Migrating from pdsh to bssh |
| [pdsh Examples](./pdsh-examples.md) | pdsh-style command examples |
| [pdsh Options](./pdsh-options.md) | pdsh option compatibility |

### Architecture

| Document | Description |
|----------|-------------|
| [Architecture Overview](./architecture/README.md) | System architecture overview |
| [SSH Client](./architecture/ssh-client.md) | SSH client implementation |
| [SSH Config Parser](./architecture/ssh-config-parser.md) | SSH config file parsing |
| [Executor](./architecture/executor.md) | Parallel execution engine |
| [TUI](./architecture/tui.md) | Terminal user interface |
| [Exit Codes](./architecture/exit-code-strategy.md) | Exit code handling |

### Man Pages

Man pages are located in [docs/man/](./man/):

| Man Page | Section | Description |
|----------|---------|-------------|
| [bssh(1)](./man/bssh.1) | 1 | bssh client manual |
| [bssh-server(8)](./man/bssh-server.8) | 8 | bssh-server administration manual |
| [bssh-keygen(1)](./man/bssh-keygen.1) | 1 | SSH key generation tool manual |

### Shell Integration

| Document | Description |
|----------|-------------|
| [Shell Config](./shell-config/README.md) | Shell integration and completion |

## Installation

### From Binary

```bash
# Download and install binaries
curl -LO https://github.com/lablup/bssh/releases/latest/download/bssh-linux-amd64.tar.gz
tar xzf bssh-linux-amd64.tar.gz
sudo mv bssh bssh-server bssh-keygen /usr/local/bin/
```

### From Source

```bash
git clone https://github.com/lablup/bssh.git
cd bssh
cargo build --release
sudo cp target/release/bssh /usr/local/bin/
sudo cp target/release/bssh-server /usr/local/bin/
sudo cp target/release/bssh-keygen /usr/local/bin/
```

### Man Page Installation

```bash
sudo install -Dm644 docs/man/bssh.1 /usr/share/man/man1/bssh.1
sudo install -Dm644 docs/man/bssh-keygen.1 /usr/share/man/man1/bssh-keygen.1
sudo install -Dm644 docs/man/bssh-server.8 /usr/share/man/man8/bssh-server.8
sudo mandb
```

## Components

### bssh (Client)

A high-performance SSH client that can be used as a drop-in replacement for OpenSSH while also providing parallel execution capabilities for cluster management.

```bash
# Single host (SSH compatibility)
bssh user@host

# Multiple hosts
bssh -H host1,host2,host3 'uptime'

# Using clusters
bssh -C mycluster 'hostname'
```

### bssh-server

A lightweight SSH server designed for container environments with built-in audit logging, file transfer filtering, and comprehensive security controls.

```bash
# Generate configuration
bssh-server gen-config -o /etc/bssh/server.yaml

# Generate host key
bssh-server gen-host-key -t ed25519 -o /etc/bssh/ssh_host_ed25519_key

# Start server
bssh-server -c /etc/bssh/server.yaml
```

### bssh-keygen

SSH key generation tool compatible with OpenSSH key formats.

```bash
# Generate Ed25519 key (recommended)
bssh-keygen

# Generate RSA key
bssh-keygen -t rsa -b 4096

# Generate with custom comment
bssh-keygen -C "user@hostname"
```

## Support

- **Issues**: [GitHub Issues](https://github.com/lablup/bssh/issues)
- **Repository**: [GitHub](https://github.com/lablup/bssh)

## License

Apache License 2.0

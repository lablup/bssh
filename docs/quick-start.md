# Quick Start Guide

[Back to Documentation Index](./README.md)

This guide helps you get bssh-server running quickly.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [First Run](#first-run)
- [Basic Configuration](#basic-configuration)
- [Testing the Server](#testing-the-server)
- [Next Steps](#next-steps)

## Prerequisites

- Linux operating system (x86_64 or aarch64)
- Root or sudo access for port 22, or use alternative port (e.g., 2222)
- OpenSSH client for testing (`ssh` command)

## Installation

### From Binary Release

```bash
# Download the latest release
curl -LO https://github.com/lablup/bssh/releases/latest/download/bssh-server-linux-amd64.tar.gz

# Extract
tar xzf bssh-server-linux-amd64.tar.gz

# Install to system
sudo mv bssh-server /usr/local/bin/
sudo mv bssh-keygen /usr/local/bin/

# Verify installation
bssh-server version
bssh-keygen --version
```

### From Source

```bash
# Clone the repository
git clone https://github.com/lablup/bssh.git
cd bssh

# Build with Cargo
cargo build --release --bin bssh-server --bin bssh-keygen

# Install binaries
sudo cp target/release/bssh-server /usr/local/bin/
sudo cp target/release/bssh-keygen /usr/local/bin/
```

## First Run

### 1. Create Configuration Directory

```bash
sudo mkdir -p /etc/bssh
sudo chmod 755 /etc/bssh
```

### 2. Generate Host Keys

Host keys are required for the SSH server to identify itself to clients.

```bash
# Generate Ed25519 key (recommended)
sudo bssh-server gen-host-key -t ed25519 -o /etc/bssh/ssh_host_ed25519_key

# Optionally generate RSA key for compatibility
sudo bssh-server gen-host-key -t rsa -o /etc/bssh/ssh_host_rsa_key
```

### 3. Create Configuration File

```bash
# Generate configuration template
sudo bssh-server gen-config -o /etc/bssh/server.yaml
```

### 4. Configure Authentication

Edit `/etc/bssh/server.yaml` and configure authentication:

#### Option A: Public Key Authentication (Recommended)

```yaml
auth:
  methods:
    - publickey
  publickey:
    # Use standard authorized_keys location
    authorized_keys_pattern: "/home/{user}/.ssh/authorized_keys"
```

Ensure the user's public key is in their `~/.ssh/authorized_keys` file.

#### Option B: Password Authentication

First, generate a password hash:

```bash
bssh-server hash-password
# Enter your password when prompted
# Copy the generated hash
```

Then edit the configuration:

```yaml
auth:
  methods:
    - password
  password:
    users:
      - name: myuser
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$..."  # paste hash here
```

### 5. Start the Server

```bash
# Start in foreground for testing
sudo bssh-server -c /etc/bssh/server.yaml -D -v

# Or run as daemon
sudo bssh-server -c /etc/bssh/server.yaml
```

## Basic Configuration

Here's a minimal working configuration:

```yaml
# /etc/bssh/server.yaml

server:
  bind_address: "0.0.0.0"
  port: 2222
  host_keys:
    - /etc/bssh/ssh_host_ed25519_key

auth:
  methods:
    - publickey
  publickey:
    authorized_keys_pattern: "/home/{user}/.ssh/authorized_keys"

shell:
  default: /bin/bash

sftp:
  enabled: true

scp:
  enabled: true
```

## Testing the Server

### Test SSH Connection

```bash
# From another terminal or machine
ssh -p 2222 youruser@localhost

# With verbose output for debugging
ssh -v -p 2222 youruser@localhost
```

### Test SFTP

```bash
sftp -P 2222 youruser@localhost
```

### Test SCP

```bash
# Upload a file
scp -P 2222 localfile.txt youruser@localhost:/tmp/

# Download a file
scp -P 2222 youruser@localhost:/etc/hostname ./
```

## Troubleshooting

### Server Won't Start

1. Check if the port is already in use:
   ```bash
   sudo lsof -i :2222
   ```

2. Verify host key permissions:
   ```bash
   ls -la /etc/bssh/ssh_host_*
   # Should be -rw------- (600)
   ```

3. Validate configuration:
   ```bash
   bssh-server check-config -c /etc/bssh/server.yaml
   ```

### Authentication Fails

1. Check verbose output from client:
   ```bash
   ssh -vvv -p 2222 user@localhost
   ```

2. For public key auth, verify:
   - Public key is in `~/.ssh/authorized_keys`
   - File permissions: `~/.ssh` is 700, `authorized_keys` is 600
   - Home directory is not world-writable

3. For password auth, verify:
   - Password hash is correct (regenerate with `bssh-server hash-password`)
   - Username matches exactly

### View Server Logs

Run server in foreground with verbose logging:

```bash
sudo bssh-server -c /etc/bssh/server.yaml -D -vvv
```

## Next Steps

- [Server Configuration Guide](./architecture/server-configuration.md) - Complete configuration reference
- [Security Guide](./security.md) - Security best practices
- [Container Deployment](./container-deployment.md) - Docker and Kubernetes deployment
- [Audit Logging](./audit-logging.md) - Setting up audit logging

## Running as a Service

### systemd Service File

Create `/etc/systemd/system/bssh-server.service`:

```ini
[Unit]
Description=Backend.AI SSH Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bssh-server -c /etc/bssh/server.yaml -D
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable bssh-server
sudo systemctl start bssh-server
sudo systemctl status bssh-server
```

View logs:

```bash
sudo journalctl -u bssh-server -f
```

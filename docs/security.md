# Security Guide

[Back to Documentation Index](./README.md)

This guide covers security best practices for deploying and configuring bssh-server.

## Table of Contents

- [Overview](#overview)
- [Authentication Security](#authentication-security)
- [Network Security](#network-security)
- [Session Security](#session-security)
- [File Transfer Security](#file-transfer-security)
- [Host Key Management](#host-key-management)
- [Audit and Compliance](#audit-and-compliance)
- [Hardening Checklist](#hardening-checklist)

## Overview

bssh-server is designed with security as a primary concern. It implements multiple layers of protection:

- **Authentication**: Public key and password authentication with rate limiting
- **Network**: IP allowlists/blocklists with CIDR support
- **Sessions**: Per-user session limits, idle timeouts, and maximum duration
- **File Transfers**: Path traversal prevention and file filtering
- **Audit**: Comprehensive logging with multiple export options

## Authentication Security

### Public Key Authentication (Recommended)

Public key authentication is more secure than passwords because:
- No secrets are transmitted over the network
- Keys are computationally infeasible to brute-force
- Keys can be protected with passphrases locally

**Configuration:**

```yaml
auth:
  methods:
    - publickey
  publickey:
    # Per-user directory structure
    authorized_keys_dir: /etc/bssh/authorized_keys
    # Structure: /etc/bssh/authorized_keys/{username}/authorized_keys

    # OR pattern-based (for existing systems)
    authorized_keys_pattern: "/home/{user}/.ssh/authorized_keys"
```

**Best Practices:**
- Use Ed25519 keys (`bssh-keygen -t ed25519`)
- Protect private keys with passphrases
- Restrict authorized_keys file permissions to 0600
- Regularly rotate keys (annually or when personnel changes)

### Password Authentication

If password authentication is required, use strong passwords with Argon2id hashing:

```yaml
auth:
  methods:
    - password
  password:
    users:
      - name: username
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$..."
```

**Generating Password Hashes:**

```bash
bssh-server hash-password
# Uses Argon2id with:
# - 19 MiB memory cost (resistant to GPU attacks)
# - 2 iterations
# - 1 degree of parallelism
```

**Best Practices:**
- Require minimum 12-character passwords
- Use unique passwords per user
- Consider disabling password auth in favor of keys
- Never store plaintext passwords

### Rate Limiting and Banning

Protect against brute-force attacks:

```yaml
security:
  # Ban IP after 5 failed attempts
  max_auth_attempts: 5

  # Time window for counting failures (5 minutes)
  auth_window: 300

  # Ban duration (5 minutes)
  ban_time: 300

  # IPs exempt from rate limiting
  whitelist_ips:
    - "127.0.0.1"
    - "::1"
    - "10.0.0.0/8"  # Internal network
```

## Network Security

### IP Access Control

Restrict access to trusted networks:

```yaml
security:
  # Allow only these IP ranges (whitelist mode)
  allowed_ips:
    - "192.168.1.0/24"      # Office network
    - "10.0.0.0/8"          # Internal network
    - "2001:db8::/32"       # IPv6 range

  # Always block these IPs (takes priority)
  blocked_ips:
    - "192.168.1.100/32"    # Compromised host
    - "203.0.113.0/24"      # Known bad actors
```

**Priority Rules:**
1. Blocked IPs are always denied (highest priority)
2. If allowed_ips is configured, only those IPs are permitted
3. If allowed_ips is empty, all IPs (except blocked) are permitted

**Best Practices:**
- Use CIDR notation for precise control
- Block entire ranges known for abuse
- Use allowlists in high-security environments
- Monitor blocked connection attempts

### Network Binding

Bind to specific interfaces when possible:

```yaml
server:
  # Bind to specific internal interface
  bind_address: "10.0.0.1"

  # Or all interfaces (for containers)
  bind_address: "0.0.0.0"
```

### Port Selection

```yaml
server:
  # Use non-standard port to reduce automated scans
  port: 2222

  # Or standard port 22 (requires root or capabilities)
  port: 22
```

## Session Security

### Session Limits

Prevent resource exhaustion and detect compromised accounts:

```yaml
security:
  # Maximum sessions per user
  max_sessions_per_user: 10

  # Idle session timeout (1 hour)
  idle_timeout: 3600

  # Maximum session duration (24 hours, 0 = disabled)
  session_timeout: 86400

server:
  # Maximum total connections
  max_connections: 100

  # Connection timeout (5 minutes)
  timeout: 300

  # SSH keepalive interval
  keepalive_interval: 60
```

### Shell Security

```yaml
shell:
  # Use restricted shell if available
  default: /bin/rbash

  # Command execution timeout
  command_timeout: 3600

  # Minimal environment
  env:
    PATH: /usr/bin:/bin
    LANG: C.UTF-8
```

**Per-User Shell Restrictions:**

```yaml
auth:
  password:
    users:
      - name: sftp-only
        password_hash: "..."
        shell: /usr/sbin/nologin  # No shell access
```

## File Transfer Security

### SFTP/SCP Control

```yaml
# Disable if not needed
sftp:
  enabled: false

scp:
  enabled: false

# Or enable with restrictions
sftp:
  enabled: true
  root: /data/sftp  # Chroot to this directory
```

### File Transfer Filtering

Block dangerous file types:

```yaml
filter:
  enabled: true
  rules:
    # Block executable uploads
    - pattern: "*.exe"
      action: deny
    - pattern: "*.sh"
      action: deny
    - pattern: "*.py"
      action: deny

    # Block uploads to sensitive directories
    - path_prefix: "/etc/"
      action: deny
    - path_prefix: "/usr/"
      action: deny

    # Log all transfers to temp
    - path_prefix: "/tmp/"
      action: log
```

**Filter Actions:**
- `deny`: Block the transfer
- `allow`: Explicitly allow (overrides other rules)
- `log`: Allow but log the transfer

### Path Traversal Prevention

bssh-server automatically prevents path traversal attacks:
- All paths are normalized before processing
- `..` components cannot escape the root directory
- Symlinks are resolved and validated
- Absolute paths are stripped and joined with the user's root

## Host Key Management

### Key Generation

```bash
# Generate Ed25519 key (recommended)
bssh-server gen-host-key -t ed25519 -o /etc/bssh/ssh_host_ed25519_key

# Generate RSA key (for compatibility)
bssh-server gen-host-key -t rsa -o /etc/bssh/ssh_host_rsa_key --bits 4096
```

### Key Permissions

```bash
# Ensure secure permissions
chmod 600 /etc/bssh/ssh_host_*_key
chown root:root /etc/bssh/ssh_host_*_key
```

### Key Rotation

Rotate host keys periodically (annually) or when:
- Key may have been compromised
- Significant personnel changes occur
- Migrating to new infrastructure

**Rotation Process:**
1. Generate new host key
2. Update configuration to include both old and new keys
3. Notify users of host key change
4. After transition period, remove old key

## Audit and Compliance

### Enable Audit Logging

```yaml
audit:
  enabled: true
  exporters:
    # Local file (JSON Lines format)
    - type: file
      path: /var/log/bssh/audit.log

    # Send to SIEM via OpenTelemetry
    - type: otel
      endpoint: http://otel-collector:4317

    # Send to Logstash
    - type: logstash
      host: logstash.example.com
      port: 5044
```

### Audit Events

The following events are logged:
- **Authentication**: Success, failure, rate limiting
- **Sessions**: Start, end, duration
- **Commands**: Executed commands (can contain sensitive data)
- **File Operations**: Read, write, delete, rename
- **Security**: IP blocks, suspicious activity

### Log Protection

```bash
# Protect audit logs
chmod 600 /var/log/bssh/audit.log
chown root:root /var/log/bssh/audit.log

# Configure log rotation
cat > /etc/logrotate.d/bssh << EOF
/var/log/bssh/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
EOF
```

## Hardening Checklist

### Minimal Configuration

- [ ] Use public key authentication only
- [ ] Disable password authentication
- [ ] Disable unused subsystems (SFTP/SCP)
- [ ] Set appropriate timeouts
- [ ] Configure session limits

### Network Hardening

- [ ] Configure IP allowlists for production
- [ ] Use non-standard port if appropriate
- [ ] Bind to specific interface if possible
- [ ] Deploy behind firewall/load balancer

### Key Management

- [ ] Use Ed25519 keys
- [ ] Set correct file permissions (0600)
- [ ] Rotate keys periodically
- [ ] Store keys securely (HSM for high security)

### Monitoring and Audit

- [ ] Enable audit logging
- [ ] Configure log shipping to SIEM
- [ ] Set up alerts for security events
- [ ] Regularly review access logs

### File Security

- [ ] Enable file transfer filtering
- [ ] Block dangerous file types
- [ ] Restrict upload directories
- [ ] Use SFTP chroot when possible

### Container Security

- [ ] Use minimal base image
- [ ] Run as non-root if possible
- [ ] Set resource limits
- [ ] Use read-only filesystem
- [ ] Generate unique host keys per instance

## Security Configuration Example

Complete security-focused configuration:

```yaml
# /etc/bssh/server.yaml - High Security Configuration

server:
  bind_address: "10.0.0.1"
  port: 2222
  host_keys:
    - /etc/bssh/ssh_host_ed25519_key
  max_connections: 50
  timeout: 120
  keepalive_interval: 30

auth:
  methods:
    - publickey
  publickey:
    authorized_keys_dir: /etc/bssh/authorized_keys

shell:
  default: /bin/rbash
  command_timeout: 1800
  env:
    PATH: /usr/bin:/bin

sftp:
  enabled: true
  root: /data/sftp

scp:
  enabled: false

filter:
  enabled: true
  rules:
    - pattern: "*.exe"
      action: deny
    - pattern: "*.dll"
      action: deny
    - path_prefix: "/etc/"
      action: deny

audit:
  enabled: true
  exporters:
    - type: file
      path: /var/log/bssh/audit.log
    - type: otel
      endpoint: http://siem:4317

security:
  max_auth_attempts: 3
  auth_window: 300
  ban_time: 900
  whitelist_ips:
    - "127.0.0.1"
  max_sessions_per_user: 5
  idle_timeout: 1800
  session_timeout: 28800
  allowed_ips:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  blocked_ips:
    - "0.0.0.0/8"
```

## See Also

- [Server Configuration](./architecture/server-configuration.md)
- [Audit Logging](./audit-logging.md)
- [Quick Start Guide](./quick-start.md)

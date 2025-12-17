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
- Connection timeout and keepalive handling

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
- **Keep-alive**: Automatic via russh (every 30s)

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

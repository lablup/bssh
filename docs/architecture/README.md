# Architecture Documentation

This directory contains detailed architecture documentation for bssh (Backend.AI SSH), organized by component.

## Overview

bssh is a high-performance parallel SSH command execution tool with SSH-compatible interface. For a high-level overview, see [Main Architecture](../../ARCHITECTURE.md).

## Component Documentation

### Core Components

- **[CLI Interface](./cli-interface.md)** - Command-line interface, pdsh compatibility, hostlist expressions, mode detection
- **[Configuration Management](./configuration.md)** - Configuration loading, XDG support, environment variable expansion
- **[Parallel Executor](./executor.md)** - Concurrent execution, signal handling, fail-fast mode
- **[SSH Client](./ssh-client.md)** - SSH connections, authentication, command execution, streaming output

### User Interface

- **[Terminal User Interface (TUI)](./tui.md)** - Interactive TUI with views, event handling, progress parsing
- **[Interactive Mode](./interactive-mode.md)** - PTY implementation, single/multiplex modes, control sequences

### SSH Features

- **[SSH Configuration Parser](./ssh-config-parser.md)** - SSH config file parsing, Include/Match directives, caching
- **[SSH Jump Host Support](./ssh-jump-hosts.md)** - Jump host chains, authentication, tunnel management
- **[SSH Port Forwarding](./ssh-port-forwarding.md)** - Local, remote, and dynamic (SOCKS) forwarding

### Exit Code Handling

- **[Exit Code Strategy](./exit-code-strategy.md)** - Main rank detection, exit code strategies, MPI compatibility

## Navigation

- [Main Architecture Documentation](../../ARCHITECTURE.md)
- [Project README](../../README.md)
- [Contributing Guide](../../CONTRIBUTING.md) (if exists)

## Document Organization

Each component document includes:

- **Overview** - Component purpose and capabilities
- **Architecture** - Design decisions and structure
- **Implementation Details** - Code organization and patterns
- **Integration Points** - How components interact
- **Related Documentation** - Links to related docs

## Quick Reference

### Finding Information

- **CLI options and modes** → [CLI Interface](./cli-interface.md)
- **Configuration file format** → [Configuration Management](./configuration.md)
- **Parallel execution behavior** → [Parallel Executor](./executor.md)
- **SSH connection details** → [SSH Client](./ssh-client.md)
- **Interactive terminal usage** → [TUI](./tui.md) or [Interactive Mode](./interactive-mode.md)
- **Jump host setup** → [SSH Jump Host Support](./ssh-jump-hosts.md)
- **Port forwarding** → [SSH Port Forwarding](./ssh-port-forwarding.md)
- **Exit code behavior** → [Exit Code Strategy](./exit-code-strategy.md)

### Code Organization

```
src/
├── cli/ → CLI Interface
├── config/ → Configuration Management
├── executor/ → Parallel Executor
├── ssh/ → SSH Client
├── tui/ → Terminal User Interface
├── interactive/ → Interactive Mode
├── jump/ → Jump Host Support
├── forward/ → Port Forwarding
└── commands/ → Command Implementations
```

## Contributing to Documentation

When updating architecture documentation:

1. **Focus on current state** - Describe how things work now, not how they evolved
2. **Avoid changelog content** - Don't include dates, issue numbers, or version references
3. **Keep examples practical** - Show real-world usage
4. **Maintain cross-references** - Link to related documentation
5. **Update the main ARCHITECTURE.md** - Keep the overview in sync

For detailed implementation notes, see the code comments and rustdoc documentation.

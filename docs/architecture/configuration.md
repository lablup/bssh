# Configuration Management Architecture

[← Back to Main Architecture](../../ARCHITECTURE.md)

## Table of Contents
- [Module Structure](#module-structure)
- [Design Decisions](#design-decisions)
- [Configuration Loading Priority](#configuration-loading-priority)
- [XDG Support](#xdg-support)
- [Key Features](#key-features)
- [Data Model](#data-model)

## Module Structure

The configuration system is organized into focused modules:

- `config/types.rs` - Configuration structs and enums (166 lines)
- `config/loader.rs` - Loading and priority logic (236 lines)
- `config/resolver.rs` - Node resolution (124 lines)
- `config/interactive.rs` - Interactive config management (135 lines)
- `config/utils.rs` - Utility functions (125 lines)
- `config/tests.rs` - Test suite (239 lines)
- `config/mod.rs` - Public API exports (30 lines)

## Design Decisions

- YAML format for human readability
- Hierarchical configuration with cluster → nodes structure
- Default values with override capability
- Full XDG Base Directory specification compliance

## Configuration Loading Priority

Configuration is loaded in the following priority order:

1. Backend.AI environment variables (auto-detection)
2. Current directory (`./config.yaml`)
3. XDG config directory (`$XDG_CONFIG_HOME/bssh/config.yaml` or `~/.config/bssh/config.yaml`)
4. CLI specified path (via `--config` flag)

## XDG Support

The configuration system follows the XDG Base Directory specification:

- Respects `$XDG_CONFIG_HOME` environment variable
- Uses `directories` crate's `ProjectDirs` for platform-specific paths
- Follows XDG Base Directory specification
- Tilde expansion for paths using `shellexpand`

## Key Features

- **Lazy loading of configuration** - Configuration is loaded only when needed
- **Validation at parse time** - Invalid configurations are caught early
- **Support for both file-based and CLI-specified nodes** - Flexible node specification
- **Environment variable expansion**:
 - Supports `${VAR}` and `$VAR` syntax
 - Expands in hostnames and usernames
 - Graceful fallback for undefined variables

### Environment Variable Expansion Examples

```yaml
clusters:
 production:
 nodes:
 - host: ${PROD_HOST}
 user: ${PROD_USER}
 - host: server.$DOMAIN
```

## Data Model

The configuration system uses the following core data structures:

```rust
pub struct Config {
 pub clusters: HashMap<String, Cluster>,
 pub default_cluster: Option<String>,
 pub ssh_config: SshConfig,
}

pub struct Cluster {
 pub nodes: Vec<Node>,
 pub ssh_key: Option<PathBuf>,
 pub user: Option<String>,
}
```

### Configuration File Example

```yaml
default_cluster: production

clusters:
 production:
 nodes:
 - host: node1.example.com
 port: 22
 user: admin
 - host: node2.example.com
 port: 22
 user: admin
 ssh_key: ~/.ssh/id_rsa

 staging:
 nodes:
 - host: staging1.example.com
 - host: staging2.example.com
 user: deploy
```

---

**Related Documentation:**
- [CLI Interface](./cli-interface.md)
- [Executor Architecture](./executor.md)
- [SSH Client](./ssh-client.md)
- [Main Architecture](../../ARCHITECTURE.md)

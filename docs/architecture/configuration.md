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
    pub defaults: Defaults,
    pub clusters: HashMap<String, Cluster>,
    pub default_cluster: Option<String>,
    pub ssh_config: SshConfig,
}

pub struct Defaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub ssh_key: Option<PathBuf>,
    pub parallel: Option<usize>,
    pub jump_host: Option<String>,  // Global default jump host
}

pub struct Cluster {
    pub nodes: Vec<NodeConfig>,
    pub defaults: ClusterDefaults,
    pub interactive: Option<InteractiveConfig>,
}

pub struct ClusterDefaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub ssh_key: Option<PathBuf>,
    pub jump_host: Option<String>,  // Cluster-level jump host
}

// Node can be simple string or detailed config
pub enum NodeConfig {
    Simple(String),  // "host" or "user@host:port"
    Detailed {
        host: String,
        port: Option<u16>,
        user: Option<String>,
        jump_host: Option<String>,  // Node-level jump host
    },
}
```

### Jump Host Resolution

Jump hosts are resolved with the following priority (highest to lowest):
1. **CLI `-J` option** - Always takes precedence
2. **SSH config `ProxyJump`** - From `~/.ssh/config`
3. **Node-level config** - Per-node `jump_host` field
4. **Cluster-level config** - Cluster `defaults.jump_host`
5. **Global defaults** - Top-level `defaults.jump_host`

An empty string (`""`) explicitly disables jump host inheritance.

### Configuration File Example

```yaml
default_cluster: production

defaults:
  user: admin
  port: 22
  ssh_key: ~/.ssh/id_rsa
  jump_host: global-bastion.example.com  # Default for all clusters

clusters:
  production:
    nodes:
      - host: node1.example.com
        port: 22
        user: admin
      - host: node2.example.com
        port: 22
        user: admin
        jump_host: node2-bastion.example.com  # Node-specific override
    ssh_key: ~/.ssh/id_rsa
    jump_host: prod-bastion.example.com  # Cluster-level jump host

  staging:
    nodes:
      - host: staging1.example.com
      - host: staging2.example.com
    user: deploy

  direct_access:
    nodes:
      - host: external.example.com
    jump_host: ""  # Explicitly disable jump host for this cluster
```

---

**Related Documentation:**
- [CLI Interface](./cli-interface.md)
- [Executor Architecture](./executor.md)
- [SSH Client](./ssh-client.md)
- [Main Architecture](../../ARCHITECTURE.md)

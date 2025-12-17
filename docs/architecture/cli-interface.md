# CLI Interface Architecture

[← Back to Main Architecture](../../ARCHITECTURE.md)

## Table of Contents
- [Main Entry Point Module Structure](#main-entry-point-module-structure)
- [Design Decisions](#design-decisions)
- [Backend.AI Auto-detection](#backendai-auto-detection)
- [pdsh Compatibility Mode](#pdsh-compatibility-mode)
- [Hostlist Expression Support](#hostlist-expression-support)

## Main Entry Point Module Structure

The CLI system is organized into focused modules:

- `main.rs` - Clean entry point (69 lines)
- `app/dispatcher.rs` - Command routing and dispatch (368 lines)
- `app/initialization.rs` - App initialization and config loading (206 lines)
- `app/nodes.rs` - Node resolution, filtering, and exclusion (587 lines)
- `app/cache.rs` - Cache statistics and management (142 lines)
- `app/query.rs` - SSH query options handler (58 lines)
- `app/utils.rs` - Utility functions (62 lines)
- `app/mod.rs` - Module exports (25 lines)

## Design Decisions

- Uses clap v4 with derive macros for type-safe argument parsing
- Subcommand pattern for different operations (exec, list, ping, upload, download)
- Environment variable support via `env` attribute
- Separated command logic from main.rs for better modularity
- Further split into app modules for initialization, dispatching, and utilities

### Backend.AI Auto-detection

The initialization flow (`app/initialization.rs`) performs early detection of Backend.AI environments with improved host specification heuristics.

Backend.AI environment auto-detection now works correctly when executing commands.

```rust
// looks_like_host_specification function detects:
// 1. Special hostnames (localhost, localhost.localdomain)
// 2. IPv4 addresses (e.g., 127.0.0.1, 192.168.1.1)
// 3. user@host format (contains '@')
// 4. host:port format (contains ':')
// 5. SSH URI format (starts with 'ssh://')
// 6. FQDN format (multiple dots, no spaces)
// 7. IPv6 format (starts with '[')

// Early Backend.AI environment detection in initialize_app
// Skip auto-detection if destination looks like a host specification
let destination_looks_like_host = cli
 .destination
 .as_ref
 .is_some_and(|dest| looks_like_host_specification(dest));

if Config::from_backendai_env.is_some
 && cli.cluster.is_none
 && cli.hosts.is_none
 && !destination_looks_like_host
{
 cli.cluster = Some("bai_auto".to_string);
 tracing::debug!("Auto-detected Backend.AI environment, setting cluster to 'bai_auto'");
}
```

### Host Detection Heuristics

The `looks_like_host_specification` function uses the following detection patterns (in order):

1. **Special hostnames** (checked first for performance):
 - `localhost`
 - `localhost.localdomain`

2. **IPv4 addresses** (validated format):
 - Must have exactly 4 octets separated by dots
 - Each octet must be 0-255 (valid u8)
 - Examples: `127.0.0.1`, `192.168.1.1`, `10.0.0.1`

3. **Early return patterns** (performance optimization):
 - `user@host` format (contains `@`)
 - IPv6 format (starts with `[`)
 - SSH URI format (starts with `ssh://`)
 - `host:port` format (contains `:`)

4. **FQDN format** (last check):
 - Multiple dots and no spaces
 - Valid domain structure (not empty parts, no leading/trailing dots)

### Key Points

- Detection happens BEFORE mode determination (`is_ssh_mode`)
- Auto-sets `cli.cluster` to `"bai_auto"` when Backend.AI environment variables are present
- Only activates when no explicit cluster (`-C`) or hosts (`-H`) specified
- Skips auto-detection if destination contains host indicators
- Prevents commands from being misinterpreted as hostnames in SSH mode
- Respects explicit user configuration over auto-detection

### Using SSH Single-Host Mode in Backend.AI Environments

When Backend.AI environment variables are set but you want to use bssh as a regular SSH client:

```bash
# Method 1: localhost (now works directly!)
bssh localhost "whoami"
bssh localhost.localdomain "whoami"

# Method 2: IPv4 address (now works directly!)
bssh 127.0.0.1 "whoami"
bssh 192.168.1.100 "whoami"

# Method 3: user@host format
bssh user@localhost "whoami"
bssh user@192.168.1.1 "whoami"

# Method 4: host:port format
bssh localhost:22 "whoami"
bssh 192.168.1.1:2222 "whoami"

# Method 5: FQDN format
bssh server.example.com "whoami"

# Method 6: -H flag (explicit host specification)
bssh -H myserver "whoami"

# Method 7: Temporarily unset environment variables
unset BACKENDAI_CLUSTER_HOSTS
bssh myserver "whoami"
```

**Note:** With the improved heuristics, `localhost` and IPv4 addresses are now automatically recognized as host specifications, making SSH single-host mode more intuitive in Backend.AI environments. Simple hostnames without indicators (like `myserver`) should use `-H` flag or other methods above.

### Implementation

```rust
// main.rs - Minimal entry point (69 lines)
async fn main -> Result<> {
 let cli = Cli::parse;
 app::dispatcher::dispatch(cli).await
}
```

### Trade-offs

- Derive macros increase compile time but provide better type safety
- Subcommand pattern adds complexity but improves UX
- Modular structure increases file count but improves testability

## pdsh Compatibility Mode

bssh supports pdsh compatibility mode, allowing it to act as a drop-in replacement for pdsh. This enables migration from pdsh without modifying existing scripts.

### Module Structure

- `cli/mod.rs` - CLI module exports and pdsh re-exports
- `cli/bssh.rs` - Standard bssh CLI parser
- `cli/pdsh.rs` - pdsh-compatible CLI parser and conversion logic
- `cli/mode_detection_tests.rs` - Tests for mode detection

### Activation Methods

1. **Binary name detection**: When bssh is invoked as "pdsh" (via symlink)
 ```bash
 ln -s /usr/bin/bssh /usr/local/bin/pdsh
 pdsh -w hosts "uptime" # Uses pdsh compat mode
 ```

2. **Environment variable**: `BSSH_PDSH_COMPAT=1` or `BSSH_PDSH_COMPAT=true`
 ```bash
 BSSH_PDSH_COMPAT=1 bssh -w hosts "uptime"
 ```

3. **CLI flag**: `--pdsh-compat`
 ```bash
 bssh --pdsh-compat -w hosts "uptime"
 ```

### Option Mapping

| pdsh option | bssh option | Description |
|-------------|-------------|-------------|
| `-w hosts` | `-H hosts` | Target hosts (comma-separated) |
| `-x hosts` | `--exclude hosts` | Exclude hosts from target list |
| `-f N` | `--parallel N` | Fanout (parallel connections) |
| `-l user` | `-l user` | Remote username |
| `-t N` | `--connect-timeout N` | Connection timeout (seconds) |
| `-u N` | `--timeout N` | Command timeout (seconds) |
| `-N` | `--no-prefix` | Disable hostname prefix in output |
| `-b` | `--batch` | Batch mode (single Ctrl+C terminates) |
| `-k` | `--fail-fast` | Stop on first failure |
| `-q` | (query mode) | Show hosts and exit |
| `-S` | `--any-failure` | Return largest exit code from any node |

### Implementation Details

```rust
// Mode detection in main.rs
let pdsh_mode = is_pdsh_compat_mode || has_pdsh_compat_flag(&args);

if pdsh_mode {
 return run_pdsh_mode(&args).await;
}

// pdsh CLI parsing and conversion
let pdsh_cli = PdshCli::parse_from(filtered_args.iter);
let mut cli = pdsh_cli.to_bssh_cli;
```

### Design Decisions

1. **Separate parser**: pdsh CLI uses its own clap parser to avoid conflicts with bssh options
2. **Conversion method**: `to_bssh_cli` converts pdsh options to bssh `Cli` struct
3. **Query mode**: pdsh `-q` shows target hosts without executing commands
4. **Default fanout**: pdsh default is 32, bssh default is 10 - pdsh mode uses 32

### Key Points

- Mode detection happens before any argument parsing
- pdsh and bssh modes are mutually exclusive
- Unknown pdsh options produce helpful error messages
- Normal bssh operation is completely unaffected by pdsh compat code

## Hostlist Expression Support

The hostlist module (`hostlist/*`) provides pdsh-compatible hostlist expression support.

### Module Structure

- `hostlist/mod.rs` - Module exports and comma-separated pattern handling (130 lines)
- `hostlist/parser.rs` - Range expression parser (570 lines)
- `hostlist/expander.rs` - Range expansion and cartesian product (270 lines)
- `hostlist/error.rs` - Error types with thiserror (80 lines)

### Design Decisions

- pdsh-compatible hostlist expression syntax
- Zero-cost abstraction for non-range patterns (pass-through)
- Efficient cartesian product expansion for multiple ranges
- Distinguishes hostlist expressions from glob patterns

### Hostlist Expression Syntax

```
hostlist = host_term (',' host_term)*
host_term = prefix range_expr suffix
range_expr = '[' range_list ']'
range_list = range_item (',' range_item)*
range_item = NUMBER | NUMBER '-' NUMBER
prefix = STRING (any characters before '[')
suffix = STRING (any characters after ']', may include nested ranges)
```

### Supported Features

- Simple range: `node[1-5]` -> `node1, node2, node3, node4, node5`
- Zero-padded: `node[01-05]` -> `node01, node02, node03, node04, node05`
- Comma-separated: `node[1,3,5]` -> `node1, node3, node5`
- Mixed: `node[1-3,7,9-10]` -> 7 hosts
- Cartesian product: `rack[1-2]-node[1-3]` -> 6 hosts
- With domain: `web[1-3].example.com` -> 3 hosts
- With user/port: `admin@db[01-03]:5432` -> 3 hosts with user and port
- File input: `^/path/to/file` -> read hosts from file

### Integration Points

- `-H` option in native bssh mode (all patterns automatically expanded)
- `-w` option in pdsh compatibility mode
- `--filter` option (supports both glob and hostlist patterns)
- `--exclude` option (supports both glob and hostlist patterns)
- pdsh query mode (`-q`) with full expansion support

### Pattern Detection Heuristics

```rust
// Distinguishes hostlist expressions from glob patterns
// Hostlist: [1-5], [01-05], [1,2,3], [1-3,5-7] (numeric content)
// Glob: [abc], [a-z], [!xyz] (alphabetic content)

fn is_hostlist_expression(pattern: &str) -> bool {
 // Check if brackets contain numeric ranges
 // Numeric: 1-5, 01-05, 1,2,3
 // Non-numeric (glob): abc, a-z, !xyz
}
```

### Safety Limits

- Maximum expansion size: 100,000 hosts (prevents DoS)
- Validates range direction (start <= end)
- Error on empty brackets, unclosed brackets, nested brackets
- IPv6 literal bracket disambiguation

### Data Flow

```
Input: "admin@web[1-3].example.com:22"
 ↓
 Parse user prefix: "admin@"
 ↓
 Parse hostname with range: "web[1-3].example.com"
 ↓
 Expand range: ["web1.example.com", "web2.example.com", "web3.example.com"]
 ↓
 Parse port suffix: ":22"
 ↓
Output: ["admin@web1.example.com:22", "admin@web2.example.com:22", "admin@web3.example.com:22"]
```

---

**Related Documentation:**
- [Configuration Management](./configuration.md)
- [Executor Architecture](./executor.md)
- [Main Architecture](../../ARCHITECTURE.md)

# SSH Configuration Parser

[← Back to Main Architecture](../../ARCHITECTURE.md)

### 6. SSH Configuration File Support (`ssh/ssh_config/*`)

**Status:** Fully Implemented (2025-08-28), Enhanced with Include/Match (2025-10-21)

**Features:**
- Complete SSH config file parsing with `-F` option
- Auto-loads from `~/.ssh/config` by default
- Supports 40+ SSH directives (Host, HostName, User, Port, IdentityFile, ProxyJump, etc.)
- **Include directive** with glob pattern support (OpenSSH 7.3+)
- **Match directive** with conditional configuration (host, user, localuser, exec, all)
- Wildcard pattern matching (`*`, `?`) and negation (`!`)
- Environment variable expansion in paths
- First-match-wins resolution (SSH-compatible)
- CLI arguments override config values

#### Include Directive Implementation

**Module:** `ssh/ssh_config/include.rs`

The Include directive allows loading configuration from external files, enabling modular SSH config management.

**Key Features:**
- **Glob Pattern Support:** `Include ~/.ssh/config.d/*`
- **Multiple Patterns:** `Include /etc/ssh/*.conf ~/.ssh/private/*`
- **Lexical Ordering:** Files matched by globs are processed in sorted order
- **Recursive Includes:** Included files can themselves contain Include directives
- **Tilde Expansion:** `~` expands to user home directory
- **Environment Variables:** Supports `${VAR}` expansion in paths

**Security Protections:**
- Maximum include depth: 10 levels (prevents infinite recursion)
- Maximum included files: 100 (DoS prevention)
- Cycle detection: Prevents circular Include references
- Permission warnings: Alerts on world-writable config files
- Path validation: Prevents directory traversal attacks

**Processing Order (SSH Spec Compliant):**
Include directives are processed at the location where they appear, not at the end:
```
# Main config
Host *.example.com
 User defaultuser

Include ~/.ssh/config.d/* # ← Files inserted HERE

Host specific.example.com
 Port 2222
```

**Implementation Algorithm:**
```rust
fn process_file_with_includes(file, content, context) -> Vec<IncludedFile> {
 for line in content.lines {
 if is_include_directive(line) {
 // Save accumulated content before Include
 save_current_content;
 // Recursively process included files at this location
 include_files = resolve_include_pattern(pattern);
 for inc_file in include_files {
 result.append(process_file_with_includes(inc_file));
 }
 } else {
 accumulate_line;
 }
 }
 save_remaining_content;
}
```

#### Match Directive Implementation

**Module:** `ssh/ssh_config/match_directive.rs`

The Match directive provides conditional configuration based on connection criteria, more powerful than Host patterns.

**Supported Conditions:**
- `host <pattern>` - Match hostname patterns (supports wildcards)
- `user <pattern>` - Match remote username
- `localuser <pattern>` - Match local username (auto-detected via `whoami`)
- `exec <command>` - Match based on command exit status
- `all` - Matches all connections

**Condition Logic:**
- Multiple conditions use AND semantics (all must match)
- Example: `Match host *.prod.com user admin` requires BOTH conditions

**Match vs Host Precedence:**
Both Host and Match blocks are evaluated in order of appearance. First match wins per option.

**Examples:**
```ssh
# Match production hosts for admin user
Match host *.prod.example.com user admin
 ForwardAgent yes
 IdentityFile ~/.ssh/prod_admin_key

# Match developer's local machine
Match localuser developer
 RequestTTY yes
 ForwardX11 yes

# Match VPN-connected machines
Match exec "test -f /tmp/vpn-connected"
 ProxyJump vpn-gateway.example.com

# Global defaults
Match all
 ServerAliveInterval 60
 ServerAliveCountMax 3
```

**exec Condition Security:**
The exec condition executes commands, requiring security measures:
- **Command Validation:** Blocks dangerous patterns (rm, dd, pipes, redirects, etc.)
- **Timeout:** 5-second execution limit
- **Length Limit:** Maximum 1024 bytes
- **Variable Expansion:** Supports %h (hostname), %u (user), %l (local user)
- **Environment:** Sets SSH_MATCH_* environment variables
- **Logging:** All exec commands are logged for audit

Blocked patterns in exec commands:
```rust
const DANGEROUS_PATTERNS: &[&str] = &[
 "rm ", "dd ", "mkfs", "format", "fdisk",
 ">", "|", ";", "&", "`", "$(",
];
```

**MatchContext Evaluation:**
```rust
pub struct MatchContext {
 hostname: String, // Connection target
 remote_user: Option<String>, // Remote username (if specified)
 local_user: String, // Current user (auto-detected)
 variables: HashMap<String, String>, // For exec expansion
}
```

#### Parser Architecture (2-Pass Design)

**Pass 1: Include Resolution**
- Process Include directives recursively
- Build complete configuration by inserting included files at directive locations
- Detect cycles and enforce depth limits
- Result: Flat list of configuration chunks in proper order

**Pass 2: Block Parsing**
- Parse Host and Match blocks
- Parse configuration options within each block
- Support both `Option Value` and `Option=Value` syntax
- Validate options and enforce security rules

**Module Structure:**
```
ssh/ssh_config/
├── mod.rs # Public API and coordination
├── parser.rs # 2-pass parsing logic
├── types.rs # SshHostConfig, ConfigBlock enums
├── include.rs # Include directive processing
├── match_directive.rs # Match condition evaluation
├── resolver.rs # Configuration resolution with Match support
├── pattern.rs # Wildcard pattern matching
├── path.rs # Path expansion utilities
└── security/ # Security validation modules
 ├── checks.rs
 ├── path_validation.rs
 └── string_validation.rs
```

**Configuration Resolution with Match:**
```rust
pub fn find_host_config(hosts: &[SshHostConfig], hostname: &str) -> SshHostConfig {
 let context = MatchContext::new(hostname, remote_user);

 for host_config in hosts {
 let should_apply = match host_config.block_type {
 Host(patterns) => matches_host_pattern(hostname, patterns),
 Match(conditions) => match_block.matches(&context),
 };

 if should_apply {
 merge_host_config(&mut result, host_config);
 }
 }
}
```

**Test Coverage:**
- Include: glob patterns, cycle detection, depth limits, ordering
- Match: all condition types, AND logic, precedence
- Integration: Include + Match combinations, nested includes
- Security: exec validation, path traversal prevention
- **Total:** 62 tests passing

#### Supported SSH Configuration Options

bssh supports 40+ SSH configuration directives organized into categories:

**Connection Options:**
- `HostName` - Remote hostname or IP address
- `Port` - SSH port (default: 22)
- `User` - Remote username
- `ConnectTimeout` - Connection timeout in seconds
- `ServerAliveInterval` - Keepalive interval
- `ServerAliveCountMax` - Keepalive retry count

**Authentication Options:**
- `IdentityFile` - SSH private key file (multiple allowed)
- `CertificateFile` - SSH certificate file for PKI auth (max 100)
- `HostbasedAuthentication` - Enable host-based auth (yes/no)
- `HostbasedAcceptedAlgorithms` - Host-based auth algorithms (max 50)
- `PubkeyAuthentication` - Enable public key auth
- `PasswordAuthentication` - Enable password auth
- `PreferredAuthentications` - Authentication method priority

**Security Options:**
- `StrictHostKeyChecking` - Host key verification (yes/no/accept-new)
- `UserKnownHostsFile` - Known hosts file path
- `HashKnownHosts` - Hash hostnames in known_hosts
- `CASignatureAlgorithms` - CA signature algorithms (max 50)
- `HostKeyAlgorithms` - Accepted host key types
- `PubkeyAcceptedAlgorithms` - Accepted public key types

**Port Forwarding Options:**
- `LocalForward` - Local port forwarding (-L)
- `RemoteForward` - Remote port forwarding (-R)
- `DynamicForward` - SOCKS proxy (-D)
- `GatewayPorts` - Remote forwarding access control (yes/no/clientspecified)
- `ExitOnForwardFailure` - Terminate on forwarding failure (yes/no)
- `PermitRemoteOpen` - Allowed remote forward destinations (max 1000)

**Jump Host Options:**
- `ProxyJump` - Jump host specification (-J)
- `ProxyCommand` - Custom proxy command

**PTY and Session Options:**
- `RequestTTY` - PTY allocation (yes/no/force/auto)
- `ForwardAgent` - Agent forwarding
- `ForwardX11` - X11 forwarding
- `SendEnv` - Environment variables to send
- `SetEnv` - Environment variables to set

**Option Value Formats:**
All options support both OpenSSH-compatible syntaxes:
- `Option Value` - Traditional space-separated format
- `Option=Value` - Alternative equals-sign format

**Security Limits:**
- CertificateFile: Maximum 100 entries per configuration
- CASignatureAlgorithms: Maximum 50 algorithms
- HostbasedAcceptedAlgorithms: Maximum 50 algorithms
- PermitRemoteOpen: Maximum 1000 destination entries
- Path validation prevents usage of sensitive system files
- Automatic deduplication for multi-valued options

**Configuration Merging Rules:**
- **Scalar options** (Port, User, HostName): First match wins (SSH-compatible)
- **Vector options** (IdentityFile, CertificateFile, PermitRemoteOpen): Accumulate across matches with deduplication
- **Algorithm lists** (CASignatureAlgorithms, HostbasedAcceptedAlgorithms): Later matches override earlier ones
- CLI arguments always take precedence over config file options

**Example Configuration:**
```ssh
# ~/.ssh/config

# Global defaults
Host *
 ServerAliveInterval 60
 ServerAliveCountMax 3
 HostbasedAuthentication no

# Production servers with certificate authentication
Host *.prod.example.com
 User admin
 CertificateFile ~/.ssh/prod-user-cert.pub
 CertificateFile ~/.ssh/prod-host-cert.pub
 CASignatureAlgorithms ssh-ed25519,rsa-sha2-512
 HostbasedAuthentication yes
 HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512

# Secure hosts with strict port forwarding
Match host *.secure.prod.example.com
 GatewayPorts clientspecified
 ExitOnForwardFailure yes
 PermitRemoteOpen localhost:8080
 PermitRemoteOpen db.internal:5432
```

### 7. SSH Configuration Caching (`ssh/config_cache/*`)

**Status:** Implemented (2025-08-28), Refactored (2025-10-17)

**Module Structure :**
- `config_cache/manager.rs` - Core cache manager (491 lines)
- `config_cache/maintenance.rs` - Cache maintenance operations (136 lines)
- `config_cache/stats.rs` - Statistics tracking (138 lines)
- `config_cache/entry.rs` - Cache entry management (111 lines)
- `config_cache/config.rs` - Cache configuration (74 lines)
- `config_cache/global.rs` - Global instance management (29 lines)
- `config_cache/mod.rs` - Module exports (27 lines)

**Design Motivation:**
SSH configuration files are frequently accessed and parsed during bssh operations, especially for multi-node commands. Caching eliminates redundant file I/O and parsing overhead, providing significant performance improvements for repeated operations.

**Implementation Details:**
- **LRU Cache:** Uses `lru` crate with configurable size (default: 100 entries)
- **TTL Support:** Time-to-live expiration (default: 5 minutes)
- **File Modification Detection:** Automatic cache invalidation via file mtime comparison
- **Thread Safety:** `Arc<RwLock<LruCache>>` for concurrent access
- **Global Instance:** Lazy-initialized singleton via `once_cell`

**Cache Entry Structure:**
```rust
struct CacheEntry {
 config: SshConfig, // Parsed SSH configuration
 cached_at: Instant, // Creation timestamp
 file_mtime: SystemTime, // File modification time
 access_count: u64, // Number of accesses
 last_accessed: Instant, // Last access timestamp
}
```

**Cache Invalidation Strategy:**
1. **TTL Expiration:** Remove entries older than configured TTL
2. **File Modification:** Detect changes via mtime comparison
3. **LRU Eviction:** Remove least recently used entries when full
4. **Manual Maintenance:** Periodic cleanup of expired entries

**API Design:**
```rust
// Cached versions (recommended)
SshConfig::load_from_file_cached(path)?;
SshConfig::load_default_cached?;

// Original versions (still supported)
SshConfig::load_from_file(path)?;
SshConfig::load_default?;

// Direct cache access
GLOBAL_CACHE.stats;
GLOBAL_CACHE.clear;
GLOBAL_CACHE.maintain;
```

**Configuration (Environment Variables):**
- `BSSH_CACHE_ENABLED=true/false` - Enable/disable caching (default: true)
- `BSSH_CACHE_SIZE=100` - Maximum entries (default: 100)
- `BSSH_CACHE_TTL=300` - TTL in seconds (default: 300)

**Performance Impact:**
- **Cache Hits:** 10-100x faster than file access
- **Reduced I/O:** Eliminates repeated file reads
- **Lower CPU:** Avoids re-parsing SSH config syntax
- **Memory Overhead:** ~1KB per cached config entry

**CLI Integration:**
New `cache-stats` command provides comprehensive monitoring:
```bash
bssh cache-stats # Basic statistics
bssh cache-stats --detailed # Per-entry information
bssh cache-stats --clear # Clear cache
bssh cache-stats --maintain # Remove expired entries
```

**Security Considerations:**
- Path canonicalization prevents traversal attacks
- No sensitive data cached (only configuration)
- Atomic cache operations prevent corruption
- Safe defaults for security-critical environments

**Test Coverage:**
- 10 comprehensive test cases covering all scenarios
- Cache hit/miss behavior validation
- File modification detection testing
- TTL expiration and LRU eviction testing
- Thread safety and concurrent access testing


---

**Related Documentation:**
- [Main Architecture](../../ARCHITECTURE.md)
- [CLI Interface](./cli-interface.md)
- [SSH Client](./ssh-client.md)
- [Executor Architecture](./executor.md)

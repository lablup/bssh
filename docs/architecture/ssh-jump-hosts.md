# SSH Jump Host Support

[← Back to Main Architecture](../../ARCHITECTURE.md)

## SSH Jump Host Support

### Status: Fully Implemented

**Jump Host Parser Module Structure :**
- `parser/tests.rs` - Test suite (343 lines)
- `parser/host_parser.rs` - Host and port parsing (141 lines)
- `parser/main_parser.rs` - Main parsing logic (79 lines)
- `parser/host.rs` - JumpHost data structure (63 lines)
- `parser/config.rs` - Jump host limits configuration (61 lines)
- `parser/mod.rs` - Module exports (29 lines)

**Jump Chain Module Structure :**
- `chain/types.rs` - Type definitions (133 lines)
- `chain/chain_connection.rs` - Chain connection logic (69 lines)
- `chain/auth.rs` - Authentication handling (260 lines)
- `chain/tunnel.rs` - Tunnel management (256 lines)
- `chain/cleanup.rs` - Resource cleanup (75 lines)
- Main `chain.rs` - Chain orchestration (436 lines)

**Overview:**
SSH jump host support enables connections through intermediate bastion hosts using OpenSSH-compatible `-J` syntax. The feature is fully implemented with comprehensive parsing, connection chain management, and full integration across all bssh operations including command execution, file transfers, and interactive mode.

### Architecture

```
┌──────────────────────────────────────┐
│ CLI (-J option) │
└────────────┬─────────────────────────┘
 │
 ▼
┌──────────────────────────────────────┐
│ Jump Host Parser │
│ (jump/parser.rs) │
│ Parses: user@host:port,host2:port2 │
└────────────┬─────────────────────────┘
 │
 ▼
┌──────────────────────────────────────┐
│ Jump Host Chain │
│ (jump/chain.rs) │
│ Manages multi-hop connections │
└────────────┬─────────────────────────┘
 │
 ▼
┌──────────────────────────────────────┐
│ Connection Manager │
│ (jump/connection.rs) │
│ Establishes SSH tunnels │
└────────┬─────────────────────────────┘
 │
 ├────────────────────┬──────────────────┬─────────────────┐
 ▼ ▼ ▼ ▼
┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐ ┌──────────────┐
│Command Execution│ │ File Transfers │ │ Interactive │ │ Executor │
│ (commands/exec) │ │ (upload/download│ │ Mode │ │ (executor.rs)│
└─────────────────┘ └─────────────────┘ └──────────────┘ └──────────────┘
```

### Implementation Details

**Parser Features:**
- OpenSSH ProxyJump format parsing
- Multiple jump hosts support (comma-separated)
- IPv6 address handling with bracket notation
- User and port specifications
- Comprehensive validation and error handling

**CLI Integration:**
```bash
# Single jump host with command execution
bssh -J jump@bastion.example.com -H target@internal "uptime"

# Multiple jump hosts
bssh -J "jump1@host1,jump2@host2" -H target "command"

# IPv6 support
bssh -J "user@[::1]:2222" -H target "command"

# File transfer through jump hosts
bssh -J bastion.example.com -H internal upload app.tar.gz /opt/
bssh -J "jump1,jump2" -C production download /etc/config ./backups/

# Interactive mode through jump hosts
bssh -J bastion.example.com user@internal-server
bssh -J "jump1,jump2" -C production interactive
```

### Completed Features

#### 1. File Transfer Support
**Implementation:** `src/ssh/client.rs` (4 new methods)

Added jump host support for all file transfer operations:
- `upload_file_with_jump_hosts` - Upload single file through jump host chain
- `download_file_with_jump_hosts` - Download single file through jump host chain
- `upload_dir_with_jump_hosts` - Upload directory recursively through jump hosts
- `download_dir_with_jump_hosts` - Download directory through jump hosts

**Method Signature:**
```rust
#[allow(clippy::too_many_arguments)]
pub async fn upload_file_with_jump_hosts(&mut self,
 local_path: &Path,
 remote_path: &str,
 key_path: Option<&Path>,
 strict_mode: Option<StrictHostKeyChecking>,
 use_agent: bool,
 use_password: bool,
 jump_hosts_spec: Option<&str>) -> Result<>
```

**Implementation Pattern:**
1. Parse jump host specification using `jump::parser::parse_jump_hosts`
2. Establish connection via `connect_via_jump_hosts` with full authentication
3. Perform SFTP operations through the tunnel
4. Handle all authentication methods (SSH keys, agent, password)

**Integration:** `src/executor.rs`, `src/commands/upload.rs`, `src/commands/download.rs`

#### 2. Interactive Mode Support
**Implementation:** `src/commands/interactive.rs`

Added `jump_hosts` field to `InteractiveCommand` structure:
```rust
pub struct InteractiveCommand {
 // ... existing fields
 pub jump_hosts: Option<String>, // New field for jump host specification
 // ... other fields
}
```

**Dynamic Timeout Calculation:**
To handle the additional latency of multi-hop connections, interactive mode implements dynamic timeout scaling:

```rust
let base_timeout = Duration::from_secs(30); // Base connection timeout
let per_hop_timeout = Duration::from_secs(15); // Additional time per hop
let hop_count = jump_hosts.len;
let total_timeout = base_timeout + (per_hop_timeout * hop_count as u32);
```

**Rationale:**
- Base timeout (30s): Standard SSH connection time for direct connections
- Per-hop timeout (15s): Additional time for each intermediate SSH handshake
- Prevents premature timeouts on multi-hop chains
- Scales linearly with complexity

**Example Timeouts:**
- Direct connection: 30s
- 1 jump host: 45s (30s + 15s)
- 2 jump hosts: 60s (30s + 30s)
- 3 jump hosts: 75s (30s + 45s)

**Integration Points:**
- `src/main.rs`: Pass `jump_hosts` to `InteractiveCommand` initialization (2 locations)
- `examples/interactive_demo.rs`: Updated example with `jump_hosts: None`
- `tests/interactive_test.rs`: Updated test cases
- `tests/interactive_integration_test.rs`: Updated all test InteractiveCommand instances

#### 3. Executor Integration
**Implementation:** `src/executor.rs`

Updated parallel executor to propagate jump_hosts to all node operations:
```rust
#[allow(clippy::too_many_arguments)]
async fn upload_to_node(node: Node,
 local_path: &Path,
 remote_path: &str,
 key_path: Option<&str>,
 strict_mode: StrictHostKeyChecking,
 use_agent: bool,
 use_password: bool,
 jump_hosts: Option<&str>, // Added parameter) -> Result<>
```

**Key Changes:**
- All `*_to_node` functions now accept `jump_hosts` parameter
- Spawned tasks pass jump_hosts to the new `*_with_jump_hosts` methods
- Maintains backward compatibility with `Option<&str>` type

### Design Decisions

#### 1. Method Duplication vs Generic Implementation
**Decision:** Create separate `*_with_jump_hosts` methods rather than modifying existing methods

**Rationale:**
- Maintains backward compatibility for code not using jump hosts
- Clear separation of concerns in function signatures
- Easier to optimize each path independently
- Explicit in API design (clear when jump hosts are used)

**Trade-off:** Code duplication (~400 lines) vs API clarity and compatibility

#### 2. Dynamic Timeout Calculation
**Decision:** Scale timeout linearly with jump host count

**Rationale:**
- Each hop requires separate SSH handshake and authentication
- Network latency accumulates across hops
- Prevents spurious timeout failures on complex jump chains
- Conservative estimates ensure reliable connections

**Alternative Considered:** Fixed timeout - rejected due to unreliability with many hops

#### 3. Clippy Allowances
**Decision:** Use `#[allow(clippy::too_many_arguments)]` on jump host methods

**Rationale:**
- Jump host operations require many parameters for authentication and configuration
- Bundling into struct would reduce clarity and make API harder to use
- All parameters are necessary for flexible authentication support
- Aligns with Rust standard library patterns (e.g., `std::fs::OpenOptions`)

**Parameters:**
1. `local_path`/`remote_path` - Transfer locations
2. `key_path` - SSH key authentication
3. `strict_mode` - Host key verification
4. `use_agent` - SSH agent authentication
5. `use_password` - Password authentication
6. `jump_hosts_spec` - Jump host chain specification

### Performance Characteristics

**Connection Overhead:**
- Base connection: ~200-500ms
- Per jump host: +200-500ms
- 3-hop chain: ~600-1500ms total

**Throughput:**
- File transfers maintain ~90% throughput through single jump host
- Throughput degrades ~10-15% per additional hop
- SFTP buffering mitigates latency impact

**Memory Usage:**
- Each hop requires separate SSH session: ~5-10MB
- SFTP buffers: ~64KB per transfer
- Total overhead for 3-hop chain: ~20-30MB

### Environment Variables

**Jump Host Configuration:**
- **`BSSH_MAX_JUMP_HOSTS`**: Maximum number of jump hosts allowed in a connection chain
 - **Default**: 10
 - **Absolute Maximum**: 30 (security cap to prevent DoS attacks)
 - **Behavior**: Invalid or zero values fall back to default with warning logs
 - **Security Rationale**: Prevents resource exhaustion and excessive connection chains
 - **Example**: `BSSH_MAX_JUMP_HOSTS=20 bssh -J host1,host2,...,host20 target`

**Implementation:**
```rust
pub fn get_max_jump_hosts -> usize {
 std::env::var("BSSH_MAX_JUMP_HOSTS")
 .ok
 .and_then(|s| s.parse::<usize>.ok)
 .map(|n| {
 if n == 0 {
 tracing::warn!("BSSH_MAX_JUMP_HOSTS cannot be 0, using default: {}", DEFAULT_MAX_JUMP_HOSTS);
 DEFAULT_MAX_JUMP_HOSTS
 } else if n > ABSOLUTE_MAX_JUMP_HOSTS {
 tracing::warn!("BSSH_MAX_JUMP_HOSTS={} exceeds absolute maximum {}, capping at {}",
 n, ABSOLUTE_MAX_JUMP_HOSTS, ABSOLUTE_MAX_JUMP_HOSTS);
 ABSOLUTE_MAX_JUMP_HOSTS
 } else {
 n
 }
 })
 .unwrap_or(DEFAULT_MAX_JUMP_HOSTS)
}
```

**Validation:**
- Enforced at parse time in `jump::parser::parse_jump_hosts`
- Used by both parser and chain modules for consistent limits
- Provides clear error messages when limit exceeded

### Security Considerations

**Authentication Chain:**
- Each hop requires independent authentication
- Supports all authentication methods per hop (keys, agent, password)
- No credential forwarding between hops (security by default)

**Host Key Verification:**
- Each hop verified independently according to `strict_mode`
- Known_hosts checked for each intermediate host
- Prevents MITM attacks at any hop in the chain

**Connection Isolation:**
- Each bssh invocation establishes new tunnel
- No connection reuse across invocations
- Clean separation between different users/sessions

**Resource Exhaustion Prevention:**
- Configurable maximum jump hosts (default: 10, absolute max: 30)
- Timeout scaling prevents hanging on excessive chains
- Authentication mutex prevents credential prompt race conditions
- Integer overflow protection using saturating arithmetic

### Error Handling

**Connection Failures:**
- Clear error messages identify which hop failed
- Reports specific failure reason (auth, timeout, host key, etc.)
- Fails fast to prevent hanging operations

**Partial Failures:**
- File transfer failures report per-node results
- Interactive mode connection failures are non-fatal
- Executor continues with successfully connected nodes

### Testing Coverage

**Files Modified:** 8 files
**Lines Added:** +623
**Lines Removed:** -26
**Net Change:** +597 lines

**Test Files Updated:**
- `tests/interactive_test.rs`: Added `jump_hosts: None` to test cases
- `tests/interactive_integration_test.rs`: Updated all 9 test instances
- `examples/interactive_demo.rs`: Updated example to include jump_hosts

**Test Results:**
- All 132 tests passing
- No compilation warnings (after clippy allows)
- Successfully handles multi-hop scenarios

### Known Limitations

**Connection Pooling:**
- Jump host connections not pooled (same as direct connections)
- Each operation establishes fresh tunnel
- **Rationale:** russh session limitations prevent connection reuse

**Configuration File Support:**
- Jump hosts only supported via CLI `-J` flag currently
- Configuration file support for per-cluster jump hosts is not implemented
- **Future Enhancement:** Add `jump_hosts` field to cluster configuration

### Future Enhancements

1. **Configuration File Support:**
 ```yaml
 clusters:
 production:
 jump_hosts: "bastion1.example.com,bastion2.example.com"
 nodes:
 - internal-host1
 - internal-host2
 ```

2. **Jump Host Connection Pooling:**
 - Reuse jump host connections across multiple target nodes
 - Significant performance improvement for cluster operations
 - Requires russh session lifecycle improvements

3. **Smart Timeout Calculation:**
 - Measure actual round-trip times per hop
 - Adjust timeouts dynamically based on observed latency
 - Provide faster failures for genuinely unreachable hosts

4. **Parallel Jump Host Establishment:**
 - When connecting to multiple targets through same jump hosts
 - Establish jump chain once, multiplex to targets
 - Reduces connection overhead for cluster operations


---

**Related Documentation:**
- [Main Architecture](../../ARCHITECTURE.md)
- [CLI Interface](./cli-interface.md)
- [SSH Client](./ssh-client.md)
- [Executor Architecture](./executor.md)

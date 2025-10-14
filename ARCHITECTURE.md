# bssh Architecture Documentation

## Overview

bssh (Backend.AI SSH / Broadcast SSH) is a high-performance parallel SSH command execution tool with SSH-compatible interface. This document describes the detailed architecture, implementation decisions, and design patterns used in the project.

### Core Capabilities
- Parallel command execution across multiple nodes
- SSH-compatible command-line interface (drop-in replacement)
- SSH port forwarding (-L, -R, -D/SOCKS proxy)
- SSH jump host support (-J)
- SSH configuration file parsing (-F)
- Interactive PTY sessions with single/multiplex modes
- SFTP file transfers (upload/download)
- Backend.AI cluster auto-detection

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

### Modular Design (Refactored 2025-01-22)

The codebase has been restructured for better maintainability and scalability:

1. **Minimal Entry Point (`main.rs`):**
   - Reduced from 987 lines to ~150 lines
   - Only handles CLI parsing and command dispatching
   - Delegates all business logic to specialized modules

2. **Command Modules (`commands/`):**
   - `exec.rs`: Command execution with output management
   - `ping.rs`: Connectivity testing
   - `interactive.rs`: Interactive shell sessions with PTY support
   - `list.rs`: Cluster listing
   - `upload.rs`: File upload operations
   - `download.rs`: File download operations
   - Each module is self-contained and independently testable

3. **Utility Modules (`utils/`):**
   - `fs.rs`: File system operations (glob patterns, directory walking)
   - `output.rs`: Command output file management
   - `logging.rs`: Logging initialization
   - Reusable across different commands

## Component Details

### 1. CLI Interface (`cli.rs`, `main.rs`)

**Design Decisions:**
- Uses clap v4 with derive macros for type-safe argument parsing
- Subcommand pattern for different operations (exec, list, ping, upload, download)
- Environment variable support via `env` attribute
- **Refactored (2025-01-22):** Separated command logic from main.rs

**Implementation:**
```rust
// main.rs - Minimal dispatcher
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Exec { .. } => exec::execute_command(params).await,
        Commands::List => list::list_clusters(&config),
        Commands::Ping => ping::ping_nodes(nodes, ...).await,
        Commands::Upload { .. } => upload::upload_file(params, ...).await,
        Commands::Download { .. } => download::download_file(params, ...).await,
    }
}
```

**Trade-offs:**
- Derive macros increase compile time but provide better type safety
- Subcommand pattern adds complexity but improves UX
- Modular structure increases file count but improves testability

### 2. Configuration Management (`config.rs`)

**Design Decisions:**
- YAML format for human readability
- Hierarchical configuration with cluster → nodes structure
- Default values with override capability
- Full XDG Base Directory specification compliance

**Configuration Loading Priority:**
1. Backend.AI environment variables (auto-detection)
2. Current directory (`./config.yaml`)
3. XDG config directory (`$XDG_CONFIG_HOME/bssh/config.yaml` or `~/.config/bssh/config.yaml`)
4. CLI specified path (via `--config` flag)

**XDG Support:**
- Respects `$XDG_CONFIG_HOME` environment variable
- Uses `directories` crate's `ProjectDirs` for platform-specific paths
- Follows XDG Base Directory specification
- Tilde expansion for paths using `shellexpand`

**Key Features:**
- Lazy loading of configuration
- Validation at parse time
- Support for both file-based and CLI-specified nodes
- ✅ Environment variable expansion (Phase 1 - Completed 2025-08-21)
  - Supports `${VAR}` and `$VAR` syntax
  - Expands in hostnames and usernames
  - Graceful fallback for undefined variables

**Data Model:**
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

### 3. Parallel Executor (`executor.rs`)

**Design Decisions:**
- Tokio-based async execution for maximum concurrency
- Semaphore-based concurrency limiting to prevent resource exhaustion
- Progress bar visualization using `indicatif`
- Streaming output collection for real-time feedback

**Concurrency Model:**
```rust
let semaphore = Arc::new(Semaphore::new(max_parallel));
let tasks: Vec<JoinHandle<Result<ExecutionResult>>> = nodes
    .into_iter()
    .map(|node| {
        let permit = semaphore.clone().acquire_owned();
        tokio::spawn(async move {
            let _permit = permit.await;
            execute_on_node(node, command).await
        })
    })
    .collect();
```

**Performance Optimizations:**
- Connection reuse within same node (planned)
- Buffered I/O for output collection
- Early termination on critical failures

### 4. SSH Client (`ssh/client.rs`, `ssh/tokio_client/*`)

**Library Choice: russh and russh-sftp**
- Native Rust SSH implementation with full async support
- SFTP support via russh-sftp for file operations
- Custom tokio_client wrapper providing high-level API
- Better control over SSH protocol implementation

**Implementation Details:**
- Custom tokio_client wrapper for simplified API
- Support for SSH agent, key-based, and password authentication
- Configurable timeouts and retry logic
- Full SFTP support for file transfers

**Security Implementation:**
- Host key verification with three modes:
  - `StrictHostKeyChecking::Yes` - Strict verification using known_hosts
  - `StrictHostKeyChecking::No` - Skip all verification  
  - `StrictHostKeyChecking::AcceptNew` - TOFU mode
- CLI flag `--strict-host-key-checking` with default "accept-new"
- Uses system known_hosts file (~/.ssh/known_hosts)
- SSH agent authentication with auto-detection

### 5. Connection Pooling (`ssh/pool.rs`)

**Current Status:** Placeholder implementation (Phase 3, 2025-08-21)

**Design Decision:**
After thorough analysis, connection pooling was determined to be **not beneficial** for bssh's current usage pattern. The implementation exists as a placeholder for future features.

**Analysis Results:**
- **Current Usage Pattern:** Each CLI invocation executes exactly one operation per host then terminates
- **No Reuse Scenarios:** There are no cases where connections would be reused within a single bssh execution
- **Library Limitation:** russh sessions are not reusable across operations
- **Performance Impact:** Zero benefit for current one-shot command execution model

**When Pooling Would Be Beneficial:**
- Interactive mode with persistent shell sessions
- Watch mode for periodic command execution
- Server mode providing an HTTP API
- Batch command execution from files
- Command pipelining on the same hosts

**Implementation:**
```rust
pub struct ConnectionPool {
    _connections: Arc<RwLock<Vec<ConnectionKey>>>,  // Placeholder
    ttl: Duration,
    enabled: bool,
    max_connections: usize,
}
```

**Current Behavior:**
- Always creates new connections regardless of `enabled` flag
- Provides API surface for future pooling implementation
- No performance overhead when disabled (default)

**Recommendation:**
Focus on more impactful optimizations like:
- Connection timeout tuning
- SSH compression for large outputs
- Buffered I/O optimizations
- Early termination on critical failures
- Parallel DNS resolution

### 6. SSH Configuration File Support (`ssh/ssh_config/*`)

**Status:** Fully Implemented (2025-08-28)

**Features:**
- Complete SSH config file parsing with `-F` option
- Auto-loads from `~/.ssh/config` by default
- Supports 40+ SSH directives (Host, HostName, User, Port, IdentityFile, ProxyJump, etc.)
- Wildcard pattern matching (`*`, `?`) and negation (`!`)
- Environment variable expansion in paths
- First-match-wins resolution (SSH-compatible)
- CLI arguments override config values

### 7. SSH Configuration Caching (`ssh/config_cache.rs`)

**Status:** Implemented (2025-08-28)

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
    config: SshConfig,           // Parsed SSH configuration
    cached_at: Instant,          // Creation timestamp
    file_mtime: SystemTime,      // File modification time
    access_count: u64,           // Number of accesses
    last_accessed: Instant,      // Last access timestamp
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
SshConfig::load_default_cached()?;

// Original versions (still supported)
SshConfig::load_from_file(path)?;
SshConfig::load_default()?;

// Direct cache access
GLOBAL_CACHE.stats();
GLOBAL_CACHE.clear();
GLOBAL_CACHE.maintain();
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
bssh cache-stats                    # Basic statistics
bssh cache-stats --detailed         # Per-entry information  
bssh cache-stats --clear           # Clear cache
bssh cache-stats --maintain        # Remove expired entries
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

### 8. Node Management (`node.rs`)

**Design Decisions:**
- Flexible parsing supporting multiple formats
- Smart defaults (port 22, current user)
- Validation at parse time

**Supported Formats:**
- `hostname` → Simple hostname
- `user@hostname` → With username
- `hostname:port` → With custom port
- `user@hostname:port` → Full specification
- `[ipv6::addr]:port` → IPv6 support

## Data Flow

### Command Execution Flow

1. **CLI Parsing** → Parse arguments and load configuration
2. **Node Resolution** → Determine target nodes from config or CLI
3. **Executor Setup** → Create semaphore and progress bars
4. **Parallel Spawn** → Launch tokio tasks for each node
5. **SSH Connection** → Establish authenticated SSH session
6. **Command Execution** → Run command and collect output
7. **Result Aggregation** → Collect all results and report

### Error Handling Strategy

- **Connection Failures:** Report per-node, continue with others
- **Authentication Failures:** Fail fast with clear error message
- **Command Failures:** Report exit code, continue execution
- **Timeout Handling:** Configurable per-operation timeouts

## Performance Characteristics

### Benchmarks (Target)

| Nodes | Command | Time | Memory |
|-------|---------|------|--------|
| 10    | uptime  | <2s  | <50MB  |
| 100   | uptime  | <5s  | <200MB |
| 1000  | uptime  | <30s | <1GB   |

### Bottlenecks

1. **SSH Handshake:** ~200-500ms per connection
2. **Memory:** Output buffering for large responses
3. **CPU:** Minimal, mostly I/O bound

### Optimization Strategies

1. **Connection Pooling:** Reuse connections for multiple commands
2. **Pipelining:** Send multiple commands in single session
3. **Compression:** Enable SSH compression for large outputs
4. **Caching:** Cache host keys and authentication
5. **Environment Variable Caching:** Cache safe environment variables for path expansion

### Environment Variable Caching (Added 2025-01-28)

To improve performance during SSH configuration path expansion, bssh implements a comprehensive environment variable cache:

**Implementation:** `src/ssh/ssh_config/env_cache.rs`
- Thread-safe LRU cache with configurable TTL (default: 30 seconds)
- Whitelisted safe variables only (HOME, USER, SSH_AUTH_SOCK, etc.)
- O(1) lookups using HashMap storage
- Automatic expiration and size-based eviction

**Performance Impact:**
- 6x faster path expansion (387µs → 60µs in benchmarks)
- 99%+ cache hit rate in typical usage
- Reduces system calls from repeated `std::env::var()` calls
- Memory overhead: ~50 environment variables max (configurable)

**Security Features:**
- Only whitelisted safe variables are cached
- Dangerous variables (PATH, LD_PRELOAD, etc.) are blocked
- Defense-in-depth: both cache and path expansion validate safety
- TTL prevents stale values from persisting

**Configuration:**
- `BSSH_ENV_CACHE_TTL`: Cache TTL in seconds (default: 30)
- `BSSH_ENV_CACHE_SIZE`: Max cache entries (default: 50)  
- `BSSH_ENV_CACHE_ENABLED`: Enable/disable caching (default: true)

**Usage Pattern:**
```rust
// Automatic caching during path expansion
let expanded = expand_path_internal("${HOME}/.ssh/config");

// Direct cache access (for advanced use)
if let Ok(Some(home)) = GLOBAL_ENV_CACHE.get_env_var("HOME") {
    // Use cached HOME value
}
```

## Interactive Mode Architecture

### Status: Fully Implemented (2025-08-22)

Interactive mode provides persistent shell sessions with single-node or multiplexed multi-node support, enabling real-time interaction with cluster nodes.

### Implemented Features

1. **PTY Support:**
   - Full pseudo-terminal allocation with crossterm
   - Terminal size detection and dynamic resizing (SIGWINCH)
   - ANSI escape sequence support for colored output
   - Raw mode terminal handling

2. **Session Management:**
   - Persistent SSH connections with keep-alive
   - Graceful reconnection on connection drops
   - Session state tracking (working directory, environment)
   - Command history with rustyline

3. **Multi-Node Features:**
   - Single-node mode (`--single-node`)
   - Multiplex mode (default) for parallel execution
   - Node switching commands (`!node1`, `!node2`, etc.)
   - Broadcast command (`!broadcast <cmd>`)
   - Visual status indicators (● active, ○ inactive)
   - Smart prompt scaling for many nodes

4. **Configuration Management:**
   - Global and per-cluster interactive settings
   - Customizable prompts and prefixes
   - Color schemes and timestamps
   - CLI arguments override config values

## PTY Implementation Design

### Architecture Overview

The PTY implementation provides true terminal emulation for interactive SSH sessions. It's designed with careful attention to performance, memory usage, and user experience through systematic configuration of timeouts, buffer sizes, and concurrency controls.

### Core Components

1. **PTY Session (`pty/session.rs`)**
   - Manages bidirectional terminal communication
   - Handles terminal resize events
   - Processes key sequences and ANSI escape codes
   - Provides graceful shutdown with proper cleanup

2. **PTY Manager (`pty/mod.rs`)**  
   - Orchestrates multiple PTY sessions
   - Supports both single-node and multiplex modes
   - Manages session lifecycle and resource cleanup

3. **Terminal State Management (`pty/terminal.rs`)**
   - RAII guards for terminal state preservation
   - Raw mode management with global synchronization
   - Mouse support and alternate screen handling

### Buffer Pool Design (`utils/buffer_pool.rs`)

The buffer pool uses a three-tier system optimized for different I/O patterns:

**Buffer Tier Design Rationale:**
- **Small (1KB)**: Terminal key sequences, command responses
  - Optimal for individual keypresses and short responses
  - Minimizes memory waste for frequent small allocations
- **Medium (8KB)**: SSH command I/O, multi-line output  
  - Balances memory usage with syscall efficiency
  - Matches common SSH channel packet sizes
- **Large (64KB)**: SFTP transfers, bulk operations
  - Reduces syscall overhead for high-throughput operations
  - Standard size for network I/O buffers

**Pool Management:**
- Maximum 16 buffers per tier prevents unbounded memory growth
- Total pooled memory: 16KB (small) + 128KB (medium) + 1MB (large) = ~1.14MB
- Automatic return to pool on buffer drop (RAII pattern)

### Timeout and Performance Constants

All timeouts and buffer sizes have been carefully chosen based on empirical testing and user experience requirements:

**Connection Timeouts:**
- **SSH Connection**: 30 seconds - Industry standard, handles slow networks and SSH negotiation
- **Command Execution**: 300 seconds (5 minutes) - Accommodates long-running operations
- **File Operations**: 300s (single files), 600s (directories) - Based on typical transfer sizes

**Interactive Response Times:**
- **Input Polling**: 10ms - Appears instantaneous to users (<20ms perception threshold)
- **Output Processing**: 10ms - Maintains real-time feel for terminal output
- **PTY Timeout**: 10ms - Rapid response for interactive terminals
- **Input Poll (blocking)**: 500ms - Longer timeout in blocking thread reduces CPU usage

**Channel and Buffer Sizing:**
- **PTY Message Channel**: 256 messages - Handles burst I/O without delays (~16KB memory)
- **SSH Output Channel**: 128 messages - Smooths bursty shell command output
- **Session Switch Channel**: 32 messages - Sufficient for user switching actions
- **Resize Signal Channel**: 16 messages - Handles rapid window resizing events

**Cleanup and Shutdown:**
- **Task Cleanup**: 100ms - Allows graceful task termination
- **PTY Shutdown**: 5 seconds - Time for multiple sessions to cleanup
- **SSH Exit Delay**: 100ms - Ensures remote shell processes exit command

### Memory Management Strategy

**Stack-Allocated Optimizations:**
- `SmallVec<[u8; 8]>` for key sequences - Most terminal key sequences are 1-5 bytes
- `SmallVec<[u8; 64]>` for output messages - Typical terminal lines fit in 64 bytes
- Pre-allocated constant arrays for common key sequences (Ctrl+C, arrows, function keys)

**Bounded Channels:**
- All channels use bounded capacity to prevent memory exhaustion
- Graceful degradation when channels reach capacity (drop oldest data)
- Non-blocking sends with error handling prevent deadlocks

### Concurrency Design

**Event Multiplexing:**
- Extensive use of `tokio::select!` for efficient event handling
- Separate tasks for input reading, output processing, and resize handling
- Cancellation tokens for coordinated shutdown across all tasks

**Thread Pool Usage:**
- Input reading runs in blocking thread pool (crossterm limitation)
- All other operations use async runtime for maximum concurrency
- Semaphore-based concurrency limiting in parallel execution

### Error Handling and Recovery

**Graceful Degradation:**
- Connection failures don't crash entire session
- Output channel saturation drops data rather than blocking
- Terminal state always restored on exit (RAII guards)

**Resource Cleanup:**
- Multiple cleanup mechanisms ensure terminal restoration
- `Drop` implementations provide failsafe cleanup
- Force cleanup functions for emergency recovery

### Performance Characteristics

**Target Performance:**
- **Latency**: <10ms for key press to remote echo
- **Throughput**: Handle 1000+ lines/second output streams
- **Memory**: <50MB for 100 concurrent PTY sessions
- **CPU**: <5% on modern systems for typical workloads

**Optimization Techniques:**
- Constant arrays for frequent key sequences avoid allocations
- Buffer pooling reduces GC pressure
- Bounded channels prevent unbounded memory growth
- Event-driven architecture minimizes polling overhead

### Security Considerations

**Input Sanitization:**
- All key sequences validated before transmission
- Terminal escape sequences handled safely
- No arbitrary code execution from terminal sequences

**Resource Limits:**
- Channel capacities prevent memory exhaustion attacks
- Timeout values prevent resource starvation
- Proper cleanup prevents resource leaks

This design provides a production-ready PTY implementation that balances performance, reliability, and user experience while maintaining strict resource controls and graceful error handling.

### Implementation Details

```rust
struct NodeSession {
    node: Node,
    client: Client,
    channel: Channel<Msg>,
    working_dir: String,
    is_connected: bool,
}
```

### Modes of Operation

1. **Single-Node Mode (`--single-node`):**
   - Interactive shell on one selected node
   - Full terminal emulation
   - Command history with rustyline

2. **Multiplex Mode (default):**
   - Commands sent to all nodes
   - Synchronized output display
   - Node status tracking

### Future Enhancements

- Session persistence and detach/reattach
- Full TUI with ratatui (split panes, monitoring)
- File manager integration
- Performance metrics visualization

## Security Model

### Current Implementation

- SSH key-based authentication
- No password storage
- Agent forwarding support

### Planned Improvements

1. **Host Key Verification:**
   - Known_hosts file support
   - TOFU (Trust On First Use) mode
   - Strict mode with pre-shared keys

2. **Audit Logging:**
   - Command execution history
   - Connection attempts
   - Authentication failures

3. **Secrets Management:**
   - Integration with system keyring
   - Encrypted configuration support

## User Interface System (`ui.rs`)

### Design Philosophy
The UI system provides a modern, clean, and elegant command-line interface with semantic colors and Unicode symbols for better visual hierarchy and user experience.

### Key Components

1. **Color Scheme:**
   - **Cyan**: Headers, prompts, and informational elements
   - **Green**: Success indicators and positive outcomes
   - **Red**: Failure indicators and errors
   - **Yellow**: Counts, numbers, and warnings
   - **Blue**: Active/processing states
   - **Dimmed**: Secondary information and decorative elements

2. **Unicode Symbols:**
   - `●` (filled circle): Status indicators (colored based on state)
   - `○` (empty circle): Pending/inactive state
   - `◐/◑` (partial circles): In-progress animations
   - `▶` (triangle): Section headers and actions
   - `•` (bullet): List items
   - `└` (corner): Error details and nested information
   - `✓/✗`: Success/failure checkmarks

3. **UI Components:**

   **NodeStatus Enum:**
   - Represents the current state of a node (Pending, Connecting, Executing, Success, Failed)
   - Provides colored symbols and text representations

   **NodeGrid:**
   - Compact grid layout for displaying multiple node statuses
   - Responsive to terminal width
   - Shows real-time status updates during execution

   **OutputFormatter:**
   - Formats command output with proper indentation and wrapping
   - Handles terminal width constraints
   - Provides consistent formatting for headers, summaries, and results

### Implementation Details

```rust
pub enum NodeStatus {
    Pending,
    Connecting,
    Executing,
    Success,
    Failed(String),
}

impl NodeStatus {
    pub fn symbol(&self) -> String {
        match self {
            NodeStatus::Pending => "○".dimmed(),
            NodeStatus::Connecting => "◐".yellow(),
            NodeStatus::Executing => "◑".blue(),
            NodeStatus::Success => "●".green(),
            NodeStatus::Failed(_) => "●".red(),
        }
    }
}
```

### Progress Indicators
- Uses `indicatif` for animated progress spinners during execution
- Custom tick characters for smooth animation: `⣾⣽⣻⣟⣯⣷⣿`
- Per-node progress bars with status messages

### Terminal Responsiveness
- Detects terminal width using `terminal_size` crate
- Adapts output formatting based on available space
- Wraps long lines intelligently while preserving indentation

### Output Examples

**Command Execution:**
```
► Executing on 3 nodes:
  echo 'test'

[node1] ⣾ Connecting...
[node2] ◑ Executing...
[node3] ● Success

✓ node1
  test output

✗ node2 - Failed
  └ Connection timeout

════════════════════════════════════════
 Summary: 3 nodes • 2 successful • 1 failed
════════════════════════════════════════
```

**Cluster Listing:**
```
▶ Available clusters

  ● production (5 nodes)
    • prod-1.example.com
    • prod-2.example.com
    ...
    
  ● staging (2 nodes)
    • stage-1.example.com
    • stage-2.example.com
```

## Testing Strategy

### Unit Tests

- Configuration parsing edge cases
- Node format parsing
- Error handling paths

### Integration Tests

- Mock SSH server for protocol testing
- Docker-based real SSH testing
- Cluster simulation

### Coverage Goals

- Core modules: >90%
- SSH client: >80%
- Overall: >85%

## Implementation Status Summary

### Completed Features

#### Core SSH Functionality
- Parallel command execution with semaphore-based concurrency
- SSH client using russh and russh-sftp
- Host key verification (strict/accept-new/no-check modes)
- SSH agent authentication with auto-detection
- SSH key and password authentication
- SFTP file transfers (upload/download with glob support)

#### SSH Compatibility
- SSH-compatible CLI interface (drop-in replacement)
- SSH configuration file parsing (-F option, ~/.ssh/config)
- Port forwarding (-L local, -R remote, -D SOCKS proxy)
- Jump host support (-J option) - Fully implemented for all operations
  - Command execution through jump hosts
  - File transfers (upload/download) through jump hosts
  - Interactive mode with jump hosts and dynamic timeouts
- PTY allocation for interactive sessions (-t/-T)

#### Interactive Mode
- Single-node and multiplex modes
- Full PTY support with crossterm
- Node switching and broadcast commands
- Command history with rustyline
- Configuration management (global and per-cluster)

#### Backend.AI Integration
- Automatic cluster detection from environment
- Cluster SSH key configuration
- Multi-node session support

#### Infrastructure
- XDG Base Directory compliance
- Environment variable expansion in configs
- Configuration and environment caching
- Modular command architecture
- Modern UI with semantic colors
- CI/CD pipelines (GitHub Actions)

### Pending Features

#### Technical Debt
- Connection pooling (infrastructure exists, not beneficial for current usage)
- Comprehensive test suites for jump host edge cases
- Usage examples and tutorials

#### Future Enhancements
- Session persistence and detach/reattach
- Full TUI with ratatui
- Web UI dashboard
- REST API server mode
- Metrics and monitoring integration

## Technical Debt

1. **Test Coverage:** Integration tests need expansion
2. **Error Messages:** Could provide better context and recovery suggestions
3. **Documentation:** API documentation needs completion
4. **Performance:** Connection establishment could be optimized with better DNS caching

## Development Timeline

### 2025-08-21: Foundation
- Host key verification implementation
- Environment variable expansion
- Connection pooling analysis
- SFTP file transfers

### 2025-08-22: Core Features
- Code structure refactoring (modular architecture)
- Interactive mode with PTY support
- Modern UI with semantic colors
- Password authentication support

### 2025-08-27: SSH Compatibility
- SSH-compatible CLI interface
- Configuration file improvements
- Authentication alignment

### 2025-08-28: Advanced SSH Features
- SSH configuration file parsing (-F)
- True PTY allocation
- Configuration caching

### 2025-08-30: Network Features
- SSH jump host infrastructure (-J)
- Complete port forwarding (-L, -R, -D)

### 2025-10-14: Jump Host Feature Completion (v0.9.0)
- File transfer operations through jump hosts
- Interactive mode with jump hosts and dynamic timeouts
- Executor integration for parallel operations
- Comprehensive testing and documentation

### 2025-08-22: Code Structure Refactoring

**Completed:**
1. **Modular Command Structure:** Separated commands into individual modules
2. **Utility Extraction:** Created reusable utility modules for common functions
3. **Main.rs Simplification:** Reduced from 987 to ~150 lines

**New Structure:**
```
src/
├── commands/         # Command implementations
│   ├── exec.rs      # Execute command (~75 lines)
│   ├── ping.rs      # Connectivity test (~80 lines)
│   ├── list.rs      # List clusters (~50 lines)
│   ├── upload.rs    # File upload (~175 lines)
│   └── download.rs  # File download (~240 lines)
├── utils/           # Utility functions
│   ├── fs.rs        # File system utilities (~100 lines)
│   ├── output.rs    # Output management (~200 lines)
│   └── logging.rs   # Logging setup (~30 lines)
└── main.rs          # CLI dispatcher (~150 lines)
```

**Benefits:**
- **Improved Maintainability:** Each command is self-contained
- **Better Testability:** Individual modules can be tested in isolation
- **Enhanced Scalability:** New commands can be added without touching main.rs
- **Code Reusability:** Utility functions are shared across commands
- **Clear Separation of Concerns:** Each module has a single responsibility

**Metrics:**
- Main.rs size reduction: 84% (987 → 150 lines)
- Average module size: ~100 lines
- Total modules created: 9 new files
- No functionality changes, only structural improvements

## SSH Jump Host Support

### Status: Fully Implemented (2025-08-30, Extended 2025-10-14)

**Overview:**
SSH jump host support enables connections through intermediate bastion hosts using OpenSSH-compatible `-J` syntax. The feature is fully implemented with comprehensive parsing, connection chain management, and full integration across all bssh operations including command execution, file transfers, and interactive mode.

### Architecture

```
┌──────────────────────────────────────┐
│         CLI (-J option)              │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│      Jump Host Parser                │
│    (jump/parser.rs)                  │
│  Parses: user@host:port,host2:port2  │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│      Jump Host Chain                 │
│     (jump/chain.rs)                  │
│   Manages multi-hop connections      │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│    Connection Manager                │
│   (jump/connection.rs)               │
│  Establishes SSH tunnels             │
└────────┬─────────────────────────────┘
         │
         ├────────────────────┬──────────────────┬─────────────────┐
         ▼                    ▼                  ▼                 ▼
┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  ┌──────────────┐
│Command Execution│  │ File Transfers  │  │ Interactive  │  │  Executor    │
│ (commands/exec) │  │ (upload/download│  │     Mode     │  │ (executor.rs)│
└─────────────────┘  └─────────────────┘  └──────────────┘  └──────────────┘
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

### Completed Features (v0.9.0)

#### 1. File Transfer Support
**Implementation:** `src/ssh/client.rs` (4 new methods)

Added jump host support for all file transfer operations:
- `upload_file_with_jump_hosts()` - Upload single file through jump host chain
- `download_file_with_jump_hosts()` - Download single file through jump host chain
- `upload_dir_with_jump_hosts()` - Upload directory recursively through jump hosts
- `download_dir_with_jump_hosts()` - Download directory through jump hosts

**Method Signature:**
```rust
#[allow(clippy::too_many_arguments)]
pub async fn upload_file_with_jump_hosts(
    &mut self,
    local_path: &Path,
    remote_path: &str,
    key_path: Option<&Path>,
    strict_mode: Option<StrictHostKeyChecking>,
    use_agent: bool,
    use_password: bool,
    jump_hosts_spec: Option<&str>,
) -> Result<()>
```

**Implementation Pattern:**
1. Parse jump host specification using `jump::parser::parse_jump_hosts()`
2. Establish connection via `connect_via_jump_hosts()` with full authentication
3. Perform SFTP operations through the tunnel
4. Handle all authentication methods (SSH keys, agent, password)

**Integration:** `src/executor.rs`, `src/commands/upload.rs`, `src/commands/download.rs`

#### 2. Interactive Mode Support
**Implementation:** `src/commands/interactive.rs`

Added `jump_hosts` field to `InteractiveCommand` structure:
```rust
pub struct InteractiveCommand {
    // ... existing fields
    pub jump_hosts: Option<String>,  // New field for jump host specification
    // ... other fields
}
```

**Dynamic Timeout Calculation:**
To handle the additional latency of multi-hop connections, interactive mode implements dynamic timeout scaling:

```rust
let base_timeout = Duration::from_secs(30);      // Base connection timeout
let per_hop_timeout = Duration::from_secs(15);   // Additional time per hop
let hop_count = jump_hosts.len();
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
async fn upload_to_node(
    node: Node,
    local_path: &Path,
    remote_path: &str,
    key_path: Option<&str>,
    strict_mode: StrictHostKeyChecking,
    use_agent: bool,
    use_password: bool,
    jump_hosts: Option<&str>,  // Added parameter
) -> Result<()>
```

**Key Changes:**
- All `*_to_node()` functions now accept `jump_hosts` parameter
- Spawned tasks pass jump_hosts to the new `*_with_jump_hosts()` methods
- Maintains backward compatibility with `Option<&str>` type

### Design Decisions

#### 1. Method Duplication vs Generic Implementation
**Decision:** Create separate `*_with_jump_hosts()` methods rather than modifying existing methods

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

## SSH Port Forwarding

### Status: Fully Implemented (2025-08-30)

### Overview

The port forwarding implementation provides full SSH-compatible port forwarding capabilities, supporting local (-L), remote (-R), and dynamic (-D/SOCKS) forwarding modes. The architecture is designed for high performance, reliability, and seamless integration with the existing SSH infrastructure.

### Architecture

```
┌────────────────────────────────────────────────┐
│                  CLI Interface                 │
│             (Port Forwarding Options)          │
│                 -L, -R, -D flags               │
└────────────────────────┬───────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────┐
│               ForwardingManager                │
│         (Lifecycle & Session Management)       │
│                src/forwarding/manager.rs       │
└──────┬────────────────┬────────────────┬───────┘
       │                │                │
       ▼                ▼                ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│    Local     │ │    Remote    │ │   Dynamic    │
│  Forwarder   │ │  Forwarder   │ │  Forwarder   │
│   (-L mode)  │ │   (-R mode)  │ │  (-D/SOCKS)  │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
                        ▼
               ┌─────────────────┐
               │     Tunnel      │
               │  (Bidirectional │
               │  Data Transfer) │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │   SSH Client    │
               │    (russh)      │
               └─────────────────┘
```

### Module Structure

The port forwarding functionality is organized into the following modules:

1. **`src/forwarding/mod.rs`**: Core types and module exports
   - `ForwardingType` enum for different forwarding modes
   - `ForwardingConfig` for configuration settings
   - Common error types and utilities

2. **`src/forwarding/manager.rs`**: Central coordination
   - Manages multiple forwarding sessions
   - Handles lifecycle (start/stop/cleanup)
   - Provides status monitoring and statistics

3. **`src/forwarding/spec.rs`**: OpenSSH-compatible parsing
   - Parses forwarding specifications (`[bind:]port:host:hostport`)
   - Validates port ranges and bind addresses
   - Supports IPv4/IPv6 and wildcard bindings

4. **`src/forwarding/tunnel.rs`**: Bidirectional data relay
   - High-performance async data transfer
   - Buffer pool integration for zero-copy operations
   - Statistics tracking (bytes transferred, connections)

5. **`src/forwarding/local.rs`**: Local port forwarding (-L)
   - TCP listener on local port
   - Creates SSH channels to remote destinations
   - Handles multiple concurrent connections

6. **`src/forwarding/remote.rs`**: Remote port forwarding (-R)
   - Requests remote port binding via SSH protocol
   - Handles incoming `forwarded-tcpip` channels
   - Connects to local services

7. **`src/forwarding/dynamic.rs`**: Dynamic forwarding (-D)
   - Full SOCKS4/SOCKS5 proxy implementation
   - Authentication negotiation
   - DNS resolution support
   - IPv4/IPv6 and domain name handling

### Design Decisions

#### 1. Async-First Architecture
- **Decision**: Use Tokio for all I/O operations
- **Rationale**: Enables high concurrency with minimal resource usage
- **Trade-off**: Complexity vs performance

#### 2. OpenSSH Compatibility
- **Decision**: Match OpenSSH forwarding syntax exactly
- **Rationale**: User familiarity and drop-in replacement capability
- **Implementation**: Comprehensive spec parser with error recovery

#### 3. Buffer Pool Integration
- **Decision**: Use global buffer pool for data transfer
- **Rationale**: Reduce allocations and improve cache locality
- **Performance**: ~30% reduction in memory allocations

#### 4. Modular Forwarder Design
- **Decision**: Separate implementations for L/R/D modes
- **Rationale**: Each mode has unique requirements and protocols
- **Benefit**: Easier testing and maintenance

#### 5. Statistics and Monitoring
- **Decision**: Atomic counters for real-time statistics
- **Rationale**: Zero-cost abstraction for production monitoring
- **Metrics**: Connections, bytes transferred, errors

### Implementation Details

#### Local Port Forwarding (-L)

```rust
// Simplified flow
1. Parse specification: "8080:example.com:80"
2. Bind TCP listener on localhost:8080
3. Accept incoming connections
4. For each connection:
   a. Open SSH channel to example.com:80
   b. Create bidirectional tunnel
   c. Transfer data until closed
```

**Key Features:**
- Concurrent connection handling
- Automatic retry with exponential backoff
- Resource limits (max connections per forward)
- IPv4/IPv6 dual-stack support

#### Remote Port Forwarding (-R)

```rust
// Simplified flow
1. Parse specification: "8080:localhost:80"
2. Send "tcpip-forward" global request to SSH server
3. Server binds remote port 8080
4. Handle incoming "forwarded-tcpip" channels
5. Connect to localhost:80 and relay data
```

**Implementation Status:**
- Full implementation with SSH global request handling
- Handles "tcpip-forward" and "cancel-tcpip-forward" requests
- Processes incoming "forwarded-tcpip" channels
- Automatic retry with exponential backoff

#### Dynamic Port Forwarding (-D/SOCKS)

```rust
// SOCKS proxy flow
1. Bind local port as SOCKS server
2. Handle SOCKS4/5 protocol negotiation
3. Parse connection requests (CONNECT command)
4. Open SSH channel to requested destination
5. Relay data transparently
```

**Protocol Support:**
- SOCKS4: Basic proxy with IPv4 support
- SOCKS4a: Domain name resolution via proxy
- SOCKS5: Full authentication, IPv6, UDP associate (partial)

### Performance Characteristics

#### Benchmarks

| Forwarding Type | Throughput | Latency Overhead | Memory Usage |
|-----------------|------------|------------------|--------------|
| Local (-L)      | ~950 Mbps  | <1ms             | ~10MB/conn   |
| Remote (-R)     | ~900 Mbps  | <2ms             | ~10MB/conn   |
| Dynamic (-D)    | ~850 Mbps  | <3ms             | ~15MB/conn   |

*Tested on localhost with 1Gbps connection*

#### Optimization Strategies

1. **Buffer Pooling**: Reuse buffers to reduce allocations
2. **Channel Multiplexing**: Multiple forwards over single SSH connection
3. **Adaptive Buffer Sizing**: Adjust based on throughput
4. **Connection Pooling**: Reuse SSH connections when possible

### Error Handling

The port forwarding system implements comprehensive error handling:

1. **Connection Failures**: Retry with exponential backoff
2. **Resource Exhaustion**: Graceful degradation with queuing
3. **Protocol Errors**: Detailed error messages for debugging
4. **Cleanup**: Automatic resource cleanup on shutdown

### Security Considerations

1. **Bind Address Validation**: Prevent unauthorized network exposure
2. **Port Range Validation**: Restrict to safe port ranges
3. **Rate Limiting**: Prevent resource exhaustion attacks
4. **Authentication**: Inherit SSH session authentication
5. **Privilege Separation**: No elevated privileges required

### Testing Strategy

#### Unit Tests
- Specification parsing validation
- Protocol implementation correctness
- Statistics tracking accuracy
- Error condition handling

#### Integration Tests (Marked as `#[ignore]`)
- Require SSH server connection
- Test actual data transfer
- Validate protocol compliance
- Performance benchmarks

#### Manual Testing Checklist
```bash
# Local forwarding
bssh -L 8080:example.com:80 user@host
curl http://localhost:8080

# Remote forwarding  
bssh -R 8080:localhost:80 user@host
ssh user@host "curl http://localhost:8080"

# SOCKS proxy
bssh -D 1080 user@host
curl --socks5 localhost:1080 http://example.com
```

### Future Enhancements

1. **UDP Support**: SOCKS5 UDP ASSOCIATE implementation
2. **Connection Persistence**: Automatic reconnection on failure
3. **Multiplexing**: Multiple channels per SSH connection
4. **Metrics Export**: Prometheus/OpenTelemetry integration
5. **GUI Integration**: Visual forwarding manager

### Configuration

Port forwarding can be configured via:

1. **Command-line flags**: `-L`, `-R`, `-D`
2. **Configuration file** (planned):
```yaml
forwarding:
  local:
    - "8080:localhost:80"
    - "3306:db.internal:3306"
  remote:
    - "9000:localhost:9000"
  dynamic:
    - "1080"
  max_connections: 100
  retry_attempts: 3
  buffer_size: 65536
```

3. **Environment variables** (planned):
   - `BSSH_FORWARD_TIMEOUT`: Connection timeout
   - `BSSH_FORWARD_RETRIES`: Retry attempts
   - `BSSH_FORWARD_BUFFER`: Buffer size

## Dependencies and Licensing

All dependencies are compatible with Apache-2.0 licensing:

### Core Dependencies
- `tokio`: MIT - Async runtime and I/O
- `russh`: Apache-2.0 - SSH client library
- `russh-sftp`: Apache-2.0 - SFTP support
- `clap`: MIT/Apache-2.0 - CLI argument parsing
- `serde`: MIT/Apache-2.0 - Serialization

### Port Forwarding Dependencies
- `uuid`: MIT/Apache-2.0 - Session ID generation
- `fastrand`: MIT/Apache-2.0 - Fast random number generation
- `tokio-util`: MIT - Additional async utilities

### Other Key Dependencies
- `anyhow`: MIT/Apache-2.0 - Error handling
- `tracing`: MIT - Structured logging
- `indicatif`: MIT - Progress bars
- `directories`: MIT/Apache-2.0 - Platform-specific paths

All dependencies have been chosen for their permissive licensing and compatibility with the Apache-2.0 license.

## Appendix

### A. Configuration Schema

```yaml
# Full configuration example
clusters:
  production:
    nodes:
      - host: node1.example.com
        port: 22
        user: admin
    ssh_key: ~/.ssh/id_rsa
    known_hosts: ~/.ssh/known_hosts
    
default_cluster: production

ssh_config:
  connect_timeout: 10
  command_timeout: 300
  max_retries: 3
```

### B. Error Codes

| Code | Description |
|------|-------------|
| 1    | General error |
| 2    | Configuration error |
| 3    | Connection failed |
| 4    | Authentication failed |
| 5    | Command execution failed |
| 10   | Partial failure (some nodes failed) |

### C. Performance Tuning

Environment variables for tuning:
- `BSSH_MAX_PARALLEL`: Maximum parallel connections
- `BSSH_CONNECT_TIMEOUT`: Connection timeout in seconds
- `BSSH_BUFFER_SIZE`: Output buffer size per connection
- `RUST_LOG`: Logging level (trace/debug/info/warn/error)
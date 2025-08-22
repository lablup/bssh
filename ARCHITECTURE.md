# bssh Architecture Documentation

## Overview

bssh (Backend.AI SSH) is a high-performance parallel SSH command execution tool designed for managing Backend.AI clusters. This document describes the detailed architecture, implementation decisions, and design patterns used in the project.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Interface                       │
│                       (main.rs)                         │
└─────────────────────┬───────────────────────────────────┘
                      │
        ┌─────────────┼───────────────┐
        ▼             ▼               ▼
┌──────────────┐ ┌───────────┐ ┌─────────────┐
│   Commands   │ │  Config   │ │    Utils    │
│   Module     │ │  Manager  │ │   Module    │
│ (commands/*) │ │(config.rs)│ │  (utils/*)  │
└──────┬───────┘ └───────────┘ └─────────────┘
        │
        ▼
┌──────────────┐           ┌──────────────┐  ┌──────────┐
│   Executor   │◄──────────┤     Node     │  │    UI    │
│  (Parallel)  │           │    Parser    │  │  System  │
│(executor.rs) │           │  (node.rs)   │  │ (ui.rs)  │
└──────┬───────┘           └──────────────┘  └──────────┘
       │
       ├──────────┬────────────┐
       ▼          ▼            ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│   SSH    │ │   SSH    │ │   SSH    │
│  Client  │ │  Client  │ │  Client  │
│ (async)  │ │ (async)  │ │ (async)  │
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
   - `interactive.rs`: Interactive shell sessions (Phase 1 completed)
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

### 4. SSH Client (`ssh/client.rs`)

**Library Choice: async-ssh2-tokio**
- **Why not thrussh:** async-ssh2-tokio provides simpler API and better OpenSSH compatibility
- **Why not openssh:** Need fine-grained control over connections
- **Why not ssh2:** Need async/await support for concurrent operations

**Implementation Details:**
- Async/await pattern for non-blocking I/O
- Support for both key-based and agent authentication
- Configurable timeouts and retry logic

**Security Implementation (Phase 1 - Completed 2025-08-21):**
- ✅ Host key verification with three modes:
  - `StrictHostKeyChecking::Yes` - Strict verification using known_hosts
  - `StrictHostKeyChecking::No` - Skip all verification
  - `StrictHostKeyChecking::AcceptNew` - TOFU mode (limited by library)
- ✅ CLI flag `--strict-host-key-checking` with default "accept-new"
- ✅ Uses system known_hosts file (~/.ssh/known_hosts)

**Remaining Limitations:**
- Missing SFTP support for file operations
- Accept-new mode falls back to NoCheck due to library limitations
- Connection reuse not possible with async-ssh2-tokio (see Connection Pooling section)

### 5. Connection Pooling (`ssh/pool.rs`)

**Current Status:** Placeholder implementation (Phase 3, 2025-08-21)

**Design Decision:**
After thorough analysis, connection pooling was determined to be **not beneficial** for bssh's current usage pattern. The implementation exists as a placeholder for future features.

**Analysis Results:**
- **Current Usage Pattern:** Each CLI invocation executes exactly one operation per host then terminates
- **No Reuse Scenarios:** There are no cases where connections would be reused within a single bssh execution
- **Library Limitation:** async-ssh2-tokio's `Client` type doesn't support cloning or connection reuse
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

### 6. Node Management (`node.rs`)

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

## Interactive Mode Architecture

### Overview

Interactive mode provides persistent shell sessions with single-node or multiplexed multi-node support. This feature enables real-time interaction with cluster nodes, maintaining stateful connections for extended operations.

### Design Decisions

1. **PTY Support:** 
   - Full pseudo-terminal allocation for proper shell interaction
   - Terminal size detection and dynamic resizing
   - ANSI escape sequence support for colored output

2. **Session Management:**
   - Persistent SSH connections with keep-alive
   - Graceful reconnection on connection drops
   - Session state tracking (working directory, environment)

3. **Input/Output Multiplexing:**
   - Commands broadcast to all nodes simultaneously
   - Node-prefixed output with color coding
   - Visual status indicators (● connected, ○ disconnected)

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

### Future Enhancements (Phase 2-3)

- Node switching with `!node1`, `!node2` commands
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

## Future Improvements

### Short-term (v0.2)

- [ ] Implement proper host key verification
- [ ] Add connection pooling
- [ ] Complete file copy functionality
- [ ] Add dry-run mode
- [ ] Implement output filtering

### Medium-term (v0.3)

- [ ] SFTP support for efficient file transfers
- [ ] Interactive session support (PTY)
- [ ] Command templates and scripts
- [ ] Result caching
- [ ] Parallel file distribution

### Long-term (v1.0)

- [ ] Web UI dashboard
- [ ] REST API server mode
- [ ] Kubernetes operator integration
- [ ] Metrics and monitoring
- [ ] Plugin system

## Technical Debt

1. ~~**Host Key Verification:** Currently disabled, security risk~~ ✅ Fixed in Phase 1
2. **Test Coverage:** Integration tests missing
3. **Error Messages:** Need better context and suggestions
4. **Documentation:** API docs incomplete

## Change Log

### Phase 1 - Critical Fixes (2025-08-21)

**Completed:**
1. **Host Key Verification:** Implemented three modes of verification with CLI flag
2. **List Command Bug:** Fixed logic to allow list without host specification
3. **Environment Variables:** Added expansion support for YAML configuration

**Impact:**
- Security improved with proper host key checking
- Better UX with fixed list command
- More flexible configuration with env var support

### Phase 3 - Connection Pooling Analysis (2025-08-21)

**Completed:**
1. **Connection Pool Module:** Implemented placeholder connection pool infrastructure
2. **Performance Analysis:** Determined pooling provides no benefit for current usage pattern
3. **Architecture Documentation:** Documented design decision and rationale

**Key Findings:**
- Current one-shot execution model doesn't benefit from connection pooling
- async-ssh2-tokio Client doesn't support connection reuse or cloning
- Pooling would only benefit future features like interactive mode or watch mode

**Recommendation:**
- Keep placeholder implementation for future use
- Focus on other performance optimizations with immediate impact
- Revisit when implementing persistent/interactive features

### Phase 4 - Code Structure Refactoring (2025-01-22)

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

## Dependencies and Licensing

All dependencies are compatible with Apache-2.0 licensing:

- `tokio`: MIT
- `async-ssh2-tokio`: MIT
- `clap`: MIT/Apache-2.0
- `serde`: MIT/Apache-2.0
- Other dependencies: Similar permissive licenses

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
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

### Code Structure Evolution

The codebase has undergone significant refactoring to improve maintainability, testability, and clarity:

#### Initial Modularization (2025-08-22)
- Reduced `main.rs` from 987 lines to ~150 lines
- Created command modules (`commands/`) for each operation
- Extracted utility modules (`utils/`) for reusable functions
- Established pattern of self-contained, independently testable modules

#### Large-Scale Refactoring (2025-10-17, Issue #33)
**Objective:** Split all oversized modules (>600 lines) into focused, maintainable components while maintaining full backward compatibility.

**Scope:** 13 critical/high/medium priority files refactored in multiple stages:
- **Stage 1**: 4 critical files (>1000 lines) → modular structure
- **Stage 2**: 4 high-priority files (800-1000 lines) → modular structure
- **Stage 3**: 5 medium-priority files (600-800 lines) → modular structure
- **Remaining**: 6 lower-priority files (500-600 lines) → **Intentionally skipped**

**Results:**
- All critical/high/medium files now under 700 lines
- Largest module: 691 lines (previously 1,394 lines)
- 232+ tests maintained with zero breaking changes
- Established clear separation of concerns throughout codebase

See "Issue #33 Refactoring Details" section below for comprehensive breakdown.

## Component Details

### 1. CLI Interface (`cli.rs`, `main.rs`, `app/*`)

**Main Entry Point Module Structure (Refactored 2025-10-17):**
- `main.rs` - Clean entry point (69 lines)
- `app/dispatcher.rs` - Command routing and dispatch (368 lines)
- `app/initialization.rs` - App initialization and config loading (206 lines)
- `app/nodes.rs` - Node resolution, filtering, and exclusion (587 lines)
- `app/cache.rs` - Cache statistics and management (142 lines)
- `app/query.rs` - SSH query options handler (58 lines)
- `app/utils.rs` - Utility functions (62 lines)
- `app/mod.rs` - Module exports (25 lines)

**Design Decisions:**
- Uses clap v4 with derive macros for type-safe argument parsing
- Subcommand pattern for different operations (exec, list, ping, upload, download)
- Environment variable support via `env` attribute
- **Refactored (2025-08-22):** Separated command logic from main.rs
- **Refactored (2025-10-17):** Further split into app modules for initialization, dispatching, and utilities
- **Fixed (2025-10-29, Issue #66):** Backend.AI environment auto-detection now works correctly when executing commands

**Backend.AI Auto-detection (Fixed in Issue #66):**

The initialization flow (`app/initialization.rs`) performs early detection of Backend.AI environments with improved host specification heuristics:

```rust
// looks_like_host_specification() function detects:
// 1. Special hostnames (localhost, localhost.localdomain)
// 2. IPv4 addresses (e.g., 127.0.0.1, 192.168.1.1)
// 3. user@host format (contains '@')
// 4. host:port format (contains ':')
// 5. SSH URI format (starts with 'ssh://')
// 6. FQDN format (multiple dots, no spaces)
// 7. IPv6 format (starts with '[')

// Early Backend.AI environment detection in initialize_app()
// Skip auto-detection if destination looks like a host specification
let destination_looks_like_host = cli
    .destination
    .as_ref()
    .is_some_and(|dest| looks_like_host_specification(dest));

if Config::from_backendai_env().is_some()
    && cli.cluster.is_none()
    && cli.hosts.is_none()
    && !destination_looks_like_host
{
    cli.cluster = Some("bai_auto".to_string());
    tracing::debug!("Auto-detected Backend.AI environment, setting cluster to 'bai_auto'");
}
```

**Host Detection Heuristics:**

The `looks_like_host_specification()` function uses the following detection patterns (in order):

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

**Key Points:**
- Detection happens BEFORE mode determination (`is_ssh_mode()`)
- Auto-sets `cli.cluster` to `"bai_auto"` when Backend.AI environment variables are present
- Only activates when no explicit cluster (`-C`) or hosts (`-H`) specified
- Skips auto-detection if destination contains host indicators
- Prevents commands from being misinterpreted as hostnames in SSH mode
- Respects explicit user configuration over auto-detection

**Using SSH Single-Host Mode in Backend.AI Environments:**

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

**Note:** With the improved heuristics (Issue #66), `localhost` and IPv4 addresses are now automatically recognized as host specifications, making SSH single-host mode more intuitive in Backend.AI environments. Simple hostnames without indicators (like `myserver`) should use `-H` flag or other methods above.

**Implementation:**
```rust
// main.rs - Minimal entry point (69 lines)
async fn main() -> Result<()> {
    let cli = Cli::parse();
    app::dispatcher::dispatch(cli).await
}
```

**Trade-offs:**
- Derive macros increase compile time but provide better type safety
- Subcommand pattern adds complexity but improves UX
- Modular structure increases file count but improves testability

### 2. Configuration Management (`config/*`)

**Module Structure (Refactored 2025-10-17):**
- `config/types.rs` - Configuration structs and enums (166 lines)
- `config/loader.rs` - Loading and priority logic (236 lines)
- `config/resolver.rs` - Node resolution (124 lines)
- `config/interactive.rs` - Interactive config management (135 lines)
- `config/utils.rs` - Utility functions (125 lines)
- `config/tests.rs` - Test suite (239 lines)
- `config/mod.rs` - Public API exports (30 lines)

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
- ✅ Environment variable expansion (Completed 2025-08-21)
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

### 3. Parallel Executor (`executor/*`)

**Module Structure (Refactored 2025-10-17):**
- `executor/parallel.rs` - ParallelExecutor core logic (412 lines)
- `executor/execution_strategy.rs` - Task spawning and progress bars (257 lines)
- `executor/connection_manager.rs` - SSH connection setup (168 lines)
- `executor/result_types.rs` - Result types (119 lines)
- `executor/mod.rs` - Public API exports (25 lines)

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

### 4. SSH Client (`ssh/client/*`, `ssh/tokio_client/*`)

**SSH Client Module Structure (Refactored 2025-10-17):**
- `client/core.rs` - Client struct and core functionality (44 lines)
- `client/connection.rs` - Connection establishment and management (308 lines)
- `client/command.rs` - Command execution logic (155 lines)
- `client/file_transfer.rs` - SFTP operations (691 lines)
- `client/config.rs` - Configuration types (27 lines)
- `client/result.rs` - Result types and implementations (86 lines)

**Tokio Client Module Structure (Refactored 2025-10-17):**
- `tokio_client/connection.rs` - Connection management (293 lines)
- `tokio_client/authentication.rs` - Authentication methods (378 lines)
- `tokio_client/channel_manager.rs` - Channel operations (230 lines)
- `tokio_client/file_transfer.rs` - SFTP file operations (285 lines)

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

### 4.0.1 Command Output Streaming Infrastructure

**Status:** Implemented (2025-10-29) as part of Phase 1 of Issue #68

**Design Motivation:**
Real-time command output streaming enables future UI features such as live progress bars, per-node output display, and streaming aggregation. The infrastructure provides the foundation for responsive UIs while maintaining full backward compatibility with existing synchronous APIs.

**Architecture:**

The streaming infrastructure consists of three key components:

1. **CommandOutput Enum** (`tokio_client/channel_manager.rs`)
   ```rust
   pub enum CommandOutput {
       StdOut(CryptoVec),
       StdErr(CryptoVec),
   }
   ```
   - Represents streaming output events
   - Separates stdout and stderr streams
   - Uses russh's `CryptoVec` for zero-copy efficiency

2. **CommandOutputBuffer** (`tokio_client/channel_manager.rs`)
   ```rust
   pub(crate) struct CommandOutputBuffer {
       sender: Sender<CommandOutput>,
       receiver_task: JoinHandle<(Vec<u8>, Vec<u8>)>,
   }
   ```
   - Internal buffer for collecting streaming output
   - Background task aggregates stdout and stderr
   - Channel capacity: 100 events (tunable)
   - Used by synchronous `execute()` for backward compatibility

3. **Streaming API Methods**
   - `Client::execute_streaming(command, sender)` - Low-level streaming API
   - `SshClient::connect_and_execute_with_output_streaming()` - High-level streaming API
   - Both respect timeout settings and handle errors consistently

**Implementation Pattern:**

```rust
// Streaming execution (new in Phase 1)
let (sender, receiver_task) = build_output_buffer();
let exit_status = client.execute_streaming("command", sender).await?;
let (stdout, stderr) = receiver_task.await?;

// Backward-compatible execution (refactored to use streaming)
let result = client.execute("command").await?;
// Internally uses execute_streaming() + CommandOutputBuffer
```

**Backward Compatibility:**

The existing `execute()` method was refactored to use `execute_streaming()` internally:
- Same function signature
- Same return type (`CommandExecutedResult`)
- Same error handling behavior
- Same timeout behavior
- Zero breaking changes to existing code

**Performance Characteristics:**
- Channel-based architecture with bounded buffer (100 events)
- Zero-copy transfer of SSH channel data via `CryptoVec`
- Background task for output aggregation (non-blocking)
- Memory overhead: ~16KB per streaming command (8KB stdout + 1KB stderr + buffer)
- Latency: Real-time streaming with minimal buffering delay

**Error Handling:**
- New `JoinError` variant in `tokio_client::Error`
- Handles task join failures gracefully
- Timeout handling preserved from original implementation
- Channel send errors handled silently (receiver may be dropped)

**Testing:**
- Integration tests cover streaming with stdout/stderr separation
- Backward compatibility test ensures no behavioral changes
- Tests use localhost SSH for reproducible validation
- All existing tests pass with zero modifications

**Future Phases (Issue #68):**
- ~~Phase 2: Executor integration for parallel streaming~~ ✓ Completed (2025-10-29)
- Phase 3: UI components (progress bars, live updates)
- Phase 4: Advanced features (filtering, aggregation)

### 4.0.2 Multi-Node Stream Management and Output Modes (Phase 2)

**Status:** Implemented (2025-10-29) as part of Phase 2 of Issue #68

**Design Motivation:**
Building on Phase 1's streaming infrastructure, Phase 2 adds independent stream management for multiple nodes and flexible output modes. This enables real-time monitoring of parallel command execution across clusters while maintaining full backward compatibility.

**Architecture:**

The Phase 2 implementation consists of four key components:

1. **NodeStream** (`executor/stream_manager.rs`)
   ```rust
   pub struct NodeStream {
       pub node: Node,
       receiver: mpsc::Receiver<CommandOutput>,
       stdout_buffer: Vec<u8>,
       stderr_buffer: Vec<u8>,
       status: ExecutionStatus,
       exit_code: Option<u32>,
       closed: bool,
   }
   ```
   - Independent output stream for each node
   - Non-blocking polling of command output
   - Separate buffers for stdout and stderr
   - Tracks execution status and exit codes
   - Can consume buffers incrementally for streaming

2. **MultiNodeStreamManager** (`executor/stream_manager.rs`)
   ```rust
   pub struct MultiNodeStreamManager {
       streams: Vec<NodeStream>,
   }
   ```
   - Coordinates multiple node streams
   - Non-blocking poll of all streams
   - Tracks completion status
   - Provides access to all stream states

3. **OutputMode** (`executor/output_mode.rs`)
   ```rust
   #[derive(Debug, Clone, PartialEq, Eq, Default)]
   pub enum OutputMode {
       #[default]
       Normal,    // Traditional batch mode
       Stream,    // Real-time with [node] prefixes
       File(PathBuf),  // Save to per-node files
   }
   ```
   - Three distinct output modes
   - TTY detection for automatic mode selection
   - Priority: `--output-dir` > `--stream` > default

4. **CLI Integration** (`cli.rs`)
   - `--stream` flag: Enable real-time streaming output
   - `--output-dir <DIR>`: Save per-node output to files
   - Auto-detection of non-TTY environments (pipes, CI)

**Implementation Details:**

**Streaming Execution Flow:**
```rust
// In ParallelExecutor::execute_with_streaming()
1. Create MultiNodeStreamManager
2. Spawn task per node with streaming sender
3. Poll all streams in loop:
   - Extract new output from each stream
   - Process based on output mode:
     * Stream: Print with [node] prefix
     * File: Buffer until completion
     * Normal: Use traditional execute()
4. Wait for all tasks to complete
5. Collect and return ExecutionResults
```

**Stream Mode Output:**
```
[host1] Starting process...
[host2] Starting process...
[host1] Processing data...
[host2] Processing data...
[host1] Complete
[host2] Complete
```

**File Mode Output:**
```
Output directory: ./results/
  host1_20251029_143022.stdout
  host1_20251029_143022.stderr
  host2_20251029_143022.stdout
  host2_20251029_143022.stderr
```

**Backward Compatibility:**

Phase 2 maintains full backward compatibility:
- Without `--stream` or `--output-dir`, uses traditional `execute()` method
- Existing CLI behavior unchanged
- All 396 existing tests pass without modification
- Exit code strategy and error handling preserved

**Performance Characteristics:**
- **Stream Mode:**
  - 50ms polling interval for smooth output
  - Minimal memory: only buffered lines in flight
  - Real-time latency: <100ms from node to display

- **File Mode:**
  - Buffers entire output in memory
  - Async file writes (non-blocking)
  - Timestamped filenames prevent collisions

**TTY Detection:**
- Auto-detects piped output (`stdout.is_terminal()`)
- Checks CI environment variables (CI, GITHUB_ACTIONS, etc.)
- Respects NO_COLOR convention
- Falls back gracefully when colors unavailable

**Error Handling:**
- Per-node failure tracking with ExecutionStatus
- Failed nodes still report in stream/file modes
- Exit code calculation respects user-specified strategy
- Graceful handling of channel closures

**Testing:**
- 10 unit tests for stream management
- 3 unit tests for output mode selection
- TTY detection tests
- All existing integration tests pass
- Total test coverage: 396 tests passing

**Code Organization:**
```
src/executor/
├── stream_manager.rs    # NodeStream, MultiNodeStreamManager (252 lines)
├── output_mode.rs       # OutputMode enum, TTY detection (171 lines)
├── parallel.rs          # Updated with streaming methods (+264 lines)
└── mod.rs              # Exports for new types
```

**Usage Examples:**

**Stream Mode:**
```bash
# Real-time streaming output
bssh -C production --stream "tail -f /var/log/app.log"

# With filtering
bssh -H "web*" --stream "systemctl status nginx"
```

**File Mode:**
```bash
# Save outputs to directory
bssh -C cluster --output-dir ./results "ps aux"

# Each node gets separate files with timestamps
ls ./results/
# web1_20251029_143022.stdout
# web2_20251029_143022.stdout
```

**Future Enhancements:**
- ~~Phase 3: UI components (progress bars, spinners)~~ ✅ Implemented (see Phase 3 below)
- Phase 4: Advanced filtering and aggregation
- Potential: Colored output per node
- Potential: Interactive stream control (pause/resume)

### 4.0.3 Interactive Terminal UI (Phase 3)

**Status:** Implemented (2025-10-30) as part of Phase 3 of Issue #68

**Design Motivation:**
Phase 3 builds on the streaming infrastructure from Phase 1 and multi-node management from Phase 2 to provide a rich interactive Terminal User Interface (TUI) for monitoring parallel SSH command execution. The TUI automatically activates in interactive terminals and provides multiple view modes optimized for different monitoring needs.

**Architecture:**

The Phase 3 implementation introduces a complete TUI system built with ratatui and crossterm:

#### Module Structure

```
src/ui/tui/
├── mod.rs              # TUI entry point, event loop, terminal management
├── app.rs              # TuiApp state management
├── event.rs            # Keyboard event handling
├── progress.rs         # Progress parsing utilities
├── terminal_guard.rs   # RAII terminal cleanup guards
└── views/
    ├── mod.rs
    ├── summary.rs      # Summary view (all nodes)
    ├── detail.rs       # Detail view (single node with scrolling)
    ├── split.rs        # Split view (2-4 nodes simultaneously)
    └── diff.rs         # Diff view (compare two nodes)
```

#### Core Components

1. **TuiApp State** (`app.rs`)
   ```rust
   pub struct TuiApp {
       pub view_mode: ViewMode,
       pub scroll_positions: HashMap<usize, usize>,  // Per-node scroll
       pub follow_mode: bool,                        // Auto-scroll
       pub should_quit: bool,
       pub show_help: bool,
       needs_redraw: bool,                           // Conditional rendering
       last_data_sizes: Vec<usize>,                  // Change detection
   }

   pub enum ViewMode {
       Summary,              // All nodes status
       Detail(usize),        // Single node full output
       Split(Vec<usize>),    // 2-4 nodes side-by-side
       Diff(usize, usize),   // Compare two nodes
   }
   ```
   - Manages current view mode and transitions
   - Tracks per-node scroll positions (preserved across view switches)
   - Auto-scroll (follow mode) with manual override detection
   - Conditional rendering to reduce CPU usage (80-90% reduction)

2. **View Modes:**

   **Summary View:**
   - Displays all nodes with status icons (⊙ pending, ⟳ running, ✓ completed, ✗ failed)
   - Real-time progress bars extracted from command output
   - Quick navigation keys (1-9, s, d, q, ?)
   - Compact representation for up to hundreds of nodes

   **Detail View:**
   - Full output from a single node
   - Scrolling support: ↑/↓, PgUp/PgDn, Home/End
   - Auto-scroll mode (f key) with manual override
   - Separate stderr display in red color
   - Node switching with ←/→ or number keys
   - Scroll position preserved when switching nodes

   **Split View:**
   - Monitor 2-4 nodes simultaneously in grid layout
   - Automatic layout adjustment (1x2 or 2x2)
   - Color-coded borders by node status
   - Last N lines displayed per pane
   - Focus switching between panes

   **Diff View:**
   - Side-by-side comparison of two nodes
   - Highlights output differences
   - Useful for debugging inconsistencies across nodes

3. **Progress Parsing** (`progress.rs`)
   ```rust
   lazy_static! {
       static ref PERCENT_PATTERN: Regex = Regex::new(r"(\d+)%").unwrap();
       static ref FRACTION_PATTERN: Regex = Regex::new(r"(\d+)/(\d+)").unwrap();
   }

   pub fn parse_progress(text: &str) -> Option<f32>
   ```
   - Detects percentage patterns: "78%", "Progress: 78%"
   - Detects fraction patterns: "45/100", "23 of 100"
   - Special handling for apt/dpkg output
   - Input length limits to prevent regex DoS (max 1000 chars)
   - Returns progress as 0.0-100.0 float

4. **Terminal Safety** (`terminal_guard.rs`)
   ```rust
   pub struct RawModeGuard { enabled: bool }
   pub struct AlternateScreenGuard { /* ... */ }
   ```
   - RAII-style guards ensure terminal cleanup on panic
   - Automatic restoration of terminal state on exit
   - Prevents terminal corruption from crashes
   - Guaranteed cleanup via Drop trait implementation

5. **Event Loop** (`mod.rs`)
   ```rust
   pub async fn run(
       manager: &mut MultiNodeStreamManager,
       cluster_name: &str,
       command: &str,
   ) -> Result<Vec<ExecutionResult>>
   ```
   - 50ms polling interval for responsive UI
   - Non-blocking SSH execution continues independently
   - Conditional rendering (only when data changes)
   - Keyboard event handling with crossterm
   - Proper cleanup on exit or Ctrl+C

#### Implementation Details

**Event Loop Flow:**
```rust
loop {
    // 1. Poll all node streams (non-blocking)
    manager.poll_all().await;

    // 2. Detect changes
    if data_changed || user_input {
        app.needs_redraw = true;
    }

    // 3. Render UI (conditional)
    if app.needs_redraw {
        terminal.draw(|f| {
            match app.view_mode {
                ViewMode::Summary => render_summary(f, manager),
                ViewMode::Detail(idx) => render_detail(f, &manager.streams[idx]),
                ViewMode::Split(indices) => render_split(f, manager, &indices),
                ViewMode::Diff(a, b) => render_diff(f, &streams[a], &streams[b]),
            }
        })?;
        app.needs_redraw = false;
    }

    // 4. Handle keyboard input (50ms poll)
    if event::poll(Duration::from_millis(50))? {
        if let Event::Key(key) = event::read()? {
            app.handle_key_event(key, num_nodes);
        }
    }

    // 5. Check exit conditions
    if app.should_quit || all_completed(manager) {
        break;
    }
}
```

**Auto-Detection Logic:**
```rust
let output_mode = OutputMode::from_cli_and_env(
    cli.stream,
    cli.output_dir.clone(),
    is_tty(),
);

// Priority: --output-dir > --stream > TUI (if TTY) > Normal
match output_mode {
    OutputMode::Tui => ui::tui::run(manager, cluster, cmd).await?,
    OutputMode::Stream => handle_stream_mode(manager, cmd).await?,
    OutputMode::File(dir) => handle_file_mode(manager, cmd, dir).await?,
    OutputMode::Normal => execute_normal(nodes, cmd).await?,
}
```

**Security Features:**

1. **Terminal Corruption Prevention:**
   - RAII guards guarantee terminal restoration
   - Panic detection with extra recovery attempts
   - Force terminal reset sequence on panic

2. **Scroll Boundary Validation:**
   - Comprehensive bounds checking prevents crashes
   - Safe handling of empty output
   - Terminal resize resilience

3. **Memory Protection:**
   - HashMap size limits (100 entries max for scroll_positions)
   - Automatic eviction of oldest entries
   - Uses Phase 2's RollingBuffer (10MB per node)

4. **Regex DoS Protection:**
   - Input length limits (1000 chars max)
   - Simple, non-backtracking regex patterns
   - No user-controlled regex patterns

**Performance Characteristics:**

- **CPU Usage:** <10% during idle (reduced by 80-90% via conditional rendering)
- **Memory:** ~16KB per node + UI overhead (~1MB)
- **Latency:** <100ms from output to display
- **Rendering:** Only when data changes or user input
- **Terminal Size:** Minimum 40x10, validated at startup

**Keyboard Controls:**

| Key | Action |
|-----|--------|
| `1-9` | Jump to node detail view |
| `s` | Enter split view mode |
| `d` | Enter diff view mode |
| `f` | Toggle auto-scroll (follow mode) |
| `?` | Show help overlay |
| `Esc` | Return to previous view |
| `q` | Quit |
| `↑/↓` | Scroll up/down in detail view |
| `←/→` | Switch between nodes |
| `PgUp/PgDn` | Page scroll |
| `Home/End` | Jump to top/bottom |

**Integration with Executor:**

```rust
// In ParallelExecutor::handle_tui_mode()
1. Create MultiNodeStreamManager
2. Spawn streaming task per node
3. Launch TUI with manager
4. TUI polls streams in event loop
5. Return ExecutionResults after TUI exits
```

**Backward Compatibility:**

- TUI only activates in interactive terminals (TTY detected)
- Automatically disabled in pipes, redirects, CI environments
- Existing flags (`--stream`, `--output-dir`) disable TUI
- All previous modes work identically

**Testing:**

- 20 unit tests added (app state, event handling, progress parsing)
- Terminal cleanup tested with panic scenarios
- Scroll boundary validation tests
- Memory limit enforcement tests
- All 417 tests passing (397 existing + 20 new)

**Dependencies Added:**

```toml
ratatui = "0.29"      # Terminal UI framework
regex = "1"           # Progress parsing
lazy_static = "1.5"   # Regex compilation optimization
```

**Future Enhancements:**
- Configuration file for custom keybindings
- Output filtering/search within TUI
- Mouse support for clickable UI
- Session recording and replay
- Color themes and customization

### 4.1 Authentication Module (`ssh/auth.rs`)

**Status:** Implemented (2025-10-17) as part of code deduplication refactoring (Issue #34)

**Design Motivation:**
Authentication logic was previously duplicated across multiple modules (`ssh/client.rs` and `commands/interactive.rs`) with ~90% code duplication. This created maintenance burden and potential for bugs when fixing authentication issues in one location but not the other.

**Refactoring Goals:**
- Eliminate ~15% code duplication across codebase
- Provide single source of truth for authentication
- Maintain consistent authentication behavior across all commands
- Improve testability with centralized tests
- Reduce maintenance cost for authentication logic

**Implementation:**
The `AuthContext` struct encapsulates all authentication parameters and provides a single `determine_method()` function that implements the standard authentication priority:

```rust
pub struct AuthContext {
    pub key_path: Option<PathBuf>,
    pub use_agent: bool,
    pub use_password: bool,
    pub username: String,
    pub host: String,
}

impl AuthContext {
    pub fn determine_method(&self) -> Result<AuthMethod> {
        // Priority 1: Password authentication (if explicitly requested)
        // Priority 2: SSH agent (if explicitly requested and available)
        // Priority 3: Specified key file (if provided)
        // Priority 4: SSH agent auto-detection (if use_agent is true)
        // Priority 5: Default key locations (~/.ssh/id_ed25519, ~/.ssh/id_rsa, etc.)
    }
}
```

**Builder Pattern Integration:**
The context uses a fluent builder pattern for ergonomic configuration:

```rust
let auth_ctx = AuthContext::new(username, host)
    .with_key_path(key_path.map(|p| p.to_path_buf()))
    .with_agent(use_agent)
    .with_password(use_password);

let auth_method = auth_ctx.determine_method()?;
```

**Security Features:**
- Uses `zeroize` crate to clear passwords and passphrases from memory
- Secure passphrase prompts via `rpassword` crate
- No credential caching or storage
- Platform-specific handling (SSH agent not supported on Windows)

**Code Reduction:**
- Eliminated ~130 lines of duplicated authentication logic
- Reduced from 2 implementations to 1 canonical implementation
- Client modules reduced from ~140 lines to ~10 lines for authentication

**Testing:**
Comprehensive test coverage including:
- Key file authentication
- SSH agent authentication (Unix only)
- Password authentication (manual test only)
- Default key location fallback
- Error conditions and edge cases

**Usage in Codebase:**
1. **`ssh/client.rs`**: Uses `AuthContext` for all SSH operations
   ```rust
   fn determine_auth_method(&self, ...) -> Result<AuthMethod> {
       let auth_ctx = super::auth::AuthContext::new(...)
           .with_key_path(...)
           .with_agent(...)
           .with_password(...);
       auth_ctx.determine_method()
   }
   ```

2. **`commands/interactive.rs`**: Uses `AuthContext` for interactive sessions
   ```rust
   fn determine_auth_method(&self, node: &Node) -> Result<AuthMethod> {
       let auth_ctx = crate::ssh::AuthContext::new(...)
           .with_key_path(...)
           .with_agent(...)
           .with_password(...);
       auth_ctx.determine_method()
   }
   ```

**Benefits Realized:**
- Single source of truth for authentication logic
- Easier to add new authentication methods
- Consistent behavior across all bssh commands

### 4.2 Sudo Password Support (`security/sudo.rs`)

**Status:** Implemented (2025-12-10) as Issue #74

**Overview:**
The sudo password module provides secure handling of sudo authentication for commands that require elevated privileges. When enabled with the `-S` flag, bssh automatically detects sudo password prompts in command output and injects the password without user intervention.

**Architecture Components:**

1. **SudoPassword Struct (`security/sudo.rs`)**
   - Wraps password string with automatic memory clearing via `zeroize` crate
   - Uses `Arc` for safe sharing across async tasks
   - Debug output redacts password content

   ```rust
   #[derive(Clone, ZeroizeOnDrop)]
   pub struct SudoPassword {
       inner: Arc<SudoPasswordInner>,
   }
   ```

2. **Prompt Detection Patterns**
   - Case-insensitive matching against common sudo prompts
   - Supports various Linux distributions:
     - `[sudo] password for <user>:`
     - `Password:`
     - `<user>'s password:`
   - Also detects failure patterns like "Sorry, try again"

3. **Password Injection Flow**
   ```
   Command Execution
         |
   +--> PTY Channel Opened (required for sudo interaction)
   |        |
   |    Output Monitoring
   |        |
   |    [Sudo Prompt Detected?] -- No --> Continue
   |        |Yes
   |    Send Password + Newline
   |        |
   +--- Continue Monitoring
   ```

**Implementation Details:**

```rust
// Prompt detection patterns
pub const SUDO_PROMPT_PATTERNS: &[&str] = &[
    "[sudo] password for ",
    "password for ",
    "password:",
    "'s password:",
    "sudo password",
    "enter password",
    "[sudo]",
];

// Failure detection patterns
pub const SUDO_FAILURE_PATTERNS: &[&str] = &[
    "sorry, try again",
    "incorrect password",
    "authentication failure",
    "permission denied",
];
```

**SSH Channel Integration (`tokio_client/channel_manager.rs`):**
- Executes command with PTY allocation (required for sudo to send prompts)
- Monitors both stdout and stderr for sudo prompts
- Uses `channel.data()` to write password to stdin when prompt detected
- Password sent only once per execution to prevent retry loops

```rust
pub async fn execute_with_sudo(
    &self,
    command: &str,
    sender: Sender<CommandOutput>,
    sudo_password: &SudoPassword,
) -> Result<u32, Error>
```

**Security Considerations:**
- Password stored using `zeroize` crate for automatic memory clearing
- Password never logged or printed in any output
- PTY required for proper sudo interaction (prevents stdin echo issues)
- Environment variable option (`BSSH_SUDO_PASSWORD`) with security warnings

**Execution Path Integration:**
1. CLI flag `-S/--sudo-password` triggers password prompt
2. Password wrapped in `Arc<SudoPassword>` for sharing across nodes
3. `ExecutionConfig` carries optional `sudo_password` field
4. Both streaming and non-streaming execution paths support sudo
5. Per-node execution uses `execute_with_sudo()` when password present

**Usage Patterns:**
```bash
# Basic usage - prompts for password before execution
bssh -S -C production "sudo apt update"

# Combined with SSH agent authentication
bssh -A -S -C production "sudo systemctl restart nginx"

# Environment variable (not recommended)
export BSSH_SUDO_PASSWORD="password"
bssh -S -C production "sudo apt update"
```

**Limitations:**
- Single password for all nodes (cannot handle different passwords per node)
- Assumes all nodes use the same sudo configuration
- Password cached for session duration (cleared on command completion)

**Future Enhancements:**
- Support for additional authentication methods (hardware tokens, certificates)
- Credential caching with secure storage integration
- Multi-factor authentication support
- Per-host authentication preferences

### 5. Connection Pooling (`ssh/pool.rs`)

**Current Status:** Placeholder implementation (2025-08-21)

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

Include ~/.ssh/config.d/*    # ← Files inserted HERE

Host specific.example.com
    Port 2222
```

**Implementation Algorithm:**
```rust
fn process_file_with_includes(file, content, context) -> Vec<IncludedFile> {
    for line in content.lines() {
        if is_include_directive(line) {
            // Save accumulated content before Include
            save_current_content();
            // Recursively process included files at this location
            include_files = resolve_include_pattern(pattern);
            for inc_file in include_files {
                result.append(process_file_with_includes(inc_file));
            }
        } else {
            accumulate_line();
        }
    }
    save_remaining_content();
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
    hostname: String,           // Connection target
    remote_user: Option<String>, // Remote username (if specified)
    local_user: String,          // Current user (auto-detected)
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
├── mod.rs              # Public API and coordination
├── parser.rs           # 2-pass parsing logic
├── types.rs            # SshHostConfig, ConfigBlock enums
├── include.rs          # Include directive processing
├── match_directive.rs  # Match condition evaluation
├── resolver.rs         # Configuration resolution with Match support
├── pattern.rs          # Wildcard pattern matching
├── path.rs             # Path expansion utilities
└── security/           # Security validation modules
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

**Module Structure (Refactored 2025-10-17):**
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

### Environment Variable Caching (Added 2025-08-28, Refactored 2025-10-17)

To improve performance during SSH configuration path expansion, bssh implements a comprehensive environment variable cache:

**Module Structure (Refactored 2025-10-17):**
- `env_cache/cache.rs` - Core caching logic (237 lines)
- `env_cache/tests.rs` - Test suite (239 lines)
- `env_cache/maintenance.rs` - Maintenance operations (120 lines)
- `env_cache/entry.rs` - Cache entry management (58 lines)
- `env_cache/validation.rs` - Variable validation (51 lines)
- `env_cache/global.rs` - Global instance management (49 lines)
- `env_cache/stats.rs` - Statistics tracking (42 lines)
- `env_cache/config.rs` - Configuration structure (37 lines)

**Implementation:** `src/ssh/ssh_config/env_cache/*`
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

### Status: Fully Implemented (2025-08-22), Refactored (2025-10-17)

**Module Structure (Refactored 2025-10-17):**
- `interactive/types.rs` - Type definitions and enums (142 lines)
- `interactive/connection.rs` - Connection establishment (363 lines)
- `interactive/single_node.rs` - Single node interactive mode (228 lines)
- `interactive/multiplex.rs` - Multi-node multiplexing (331 lines)
- `interactive/commands.rs` - Command processing (152 lines)
- `interactive/execution.rs` - Command execution (158 lines)
- `interactive/utils.rs` - Helper functions (135 lines)

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

1. **PTY Session (`pty/session/*`, Refactored 2025-10-17, Enhanced 2025-12-10)**
   - **Module Structure:**
     - `session/session_manager.rs` - Core session management (~400 lines)
     - `session/input.rs` - Input event handling (193 lines)
     - `session/constants.rs` - Terminal key sequences and buffers (105 lines)
     - `session/terminal_modes.rs` - Terminal mode configuration (91 lines)
     - `session/escape_filter.rs` - Terminal escape sequence filtering (~350 lines)
     - `session/mod.rs` - Module exports (23 lines)
   - Manages bidirectional terminal communication
   - Handles terminal resize events
   - Processes key sequences and ANSI escape codes
   - **Filters terminal query responses** (XTGETTCAP, DA1/DA2/DA3, OSC responses)
   - **Sets TERM environment variable** for proper terminal capability detection
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

### Terminal Escape Sequence Filtering (Added 2025-12-10)

**Problem:** When running terminal applications like Neovim via SSH, raw terminal capability query responses (XTGETTCAP, DA1/DA2/DA3, OSC responses) were appearing as visible text instead of being properly processed.

**Solution:** The `escape_filter` module implements a state machine to identify and filter terminal query responses:

**Filtered Sequences:**
- **XTGETTCAP responses** (`\x1bP+r...`): Terminal capability query responses from the remote shell
- **DA1/DA2/DA3 responses** (`\x1b[?...c`): Device Attributes responses
- **OSC responses** (`\x1b]...`): Operating System Command responses (colors, clipboard)
- **DCS responses** (`\x1bP...`): Device Control String responses

**Filter Design:**
- State machine tracks incomplete sequences across buffer boundaries
- Conservative filtering: only removes known terminal response sequences
- Preserves all valid escape sequences for colors, cursor movement, etc.
- Buffer overflow protection (4KB limit) prevents memory exhaustion from malformed sequences

**TERM Environment Variable:**
- Set before PTY allocation using russh's `set_env` API
- Also sets `COLORTERM=truecolor` for better color support
- Gracefully handles server rejection (AcceptEnv not configured)

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
- File manager integration
- Performance metrics visualization

## Terminal User Interface (TUI) Architecture

### Status: Fully Implemented (2025-12-10, Issue #68)

The TUI module provides a real-time interactive terminal interface for monitoring parallel command execution across multiple nodes. Built with `ratatui`, it offers 4 distinct view modes with keyboard-driven navigation and automatic output streaming.

### Module Structure

```
src/ui/tui/
├── mod.rs              # Public API: run_tui(), TuiExitReason
├── app.rs              # TuiApp state machine, ViewMode enum
├── event.rs            # Keyboard input handling
├── progress.rs         # Output parsing for progress indicators
├── terminal_guard.rs   # RAII cleanup on exit/panic
└── views/              # View implementations
    ├── mod.rs          # View module exports
    ├── summary.rs      # Multi-node overview
    ├── detail.rs       # Single node full output
    ├── split.rs        # Multi-pane view (2-4 nodes)
    └── diff.rs         # Side-by-side comparison
```

### Core Components

#### 1. TuiApp State Machine (`app.rs`)

**ViewMode Enum:**
```rust
pub enum ViewMode {
    Summary,              // All nodes at a glance
    Detail(usize),        // Single node full output
    Split(Vec<usize>),    // 2-4 nodes side-by-side
    Diff(usize, usize),   // Compare two nodes
}
```

**State Management:**
- **Scroll positions**: Per-node scroll state (HashMap with 100-entry limit)
- **Follow mode**: Auto-scroll to bottom (default: enabled)
- **Change detection**: Tracks data sizes to minimize unnecessary redraws
- **Completion tracking**: Monitors when all tasks finish

**Key Methods:**
- `check_data_changes()`: Detects new output from nodes
- `should_redraw()`: Optimizes rendering by tracking dirty state
- `show_detail()`, `show_split()`, `show_diff()`: View transitions
- `scroll_up()`, `scroll_down()`: Scrolling with automatic follow-mode disable
- `next_node()`, `prev_node()`: Node navigation in detail view

#### 2. Event Handler (`event.rs`)

**Keyboard Event Processing:**
- **Global keys** (work in any view):
  - `q`, `Ctrl+C`: Quit application
  - `?`: Toggle help overlay
  - `Esc`: Return to summary view or close help

- **Summary view keys**:
  - `1-9`: Jump to node N detail view
  - `s`: Enter split view (first 2-4 nodes)
  - `d`: Enter diff view (first 2 nodes)

- **Detail view keys**:
  - `↑/↓`: Scroll up/down by 1 line
  - `←/→`: Switch to previous/next node
  - `PgUp/PgDn`: Scroll by 10 lines
  - `Home/End`: Jump to top/bottom
  - `f`: Toggle auto-scroll (follow mode)
  - `1-9`: Jump to specific node

- **Split view keys**:
  - `1-4`: Focus on specific node

- **Diff view keys**:
  - `↑/↓`: Synchronized scrolling (TODO: implementation pending)

**Design Pattern:**
- Centralized event routing via `handle_key_event()`
- Mode-specific handlers for clean separation of concerns
- All scroll operations automatically disable follow mode (except `End`)

#### 3. Progress Parser (`progress.rs`)

**Output Analysis:**
Detects and extracts progress indicators from command output:

- **Percentage patterns**: `45%`, `[45%]`, `(45%)`, `45.5%`
- **Fraction patterns**: `[450/1000]`, `450 of 1000`, `450/1000`
- **apt-get output**: `Reading state information...`
- **dpkg output**: `Setting up package-name...`

**Status Message Extraction:**
- Extracts recent non-progress output lines
- Filters out empty lines and ANSI sequences
- Returns last 3 meaningful status lines

**Use Case:**
Provides real-time feedback in summary view when commands include long-running operations (package installations, file transfers, etc.)

#### 4. Terminal Guard (`terminal_guard.rs`)

**RAII-based Terminal Cleanup:**
Ensures terminal is always restored to original state, even on panic or error.

**Guard Hierarchy:**
```rust
TerminalGuard
├── RawModeGuard          # Manages terminal raw mode
└── AlternateScreenGuard  # Manages alternate screen buffer
```

**Cleanup Guarantees:**
- Raw mode disabled on drop
- Alternate screen exited on drop
- Cursor shown on drop
- Panic-safe cleanup (detected via `std::thread::panicking()`)
- Emergency terminal reset sequence on panic

**Safety Mechanisms:**
- Multiple fallback cleanup strategies
- Error logging (can't panic in Drop)
- Direct stderr writes as last resort
- Force terminal reset on panic: `\x1b[0m\x1b[?25h`

#### 5. View Implementations (`views/`)

##### Summary View (`summary.rs`)

**Layout:**
```
┌─────────────────────────────────────────────────┐
│ Cluster: production - uptime                    │
│ Total: 5 • ✓ 3 • ✗ 1 • 1 in progress           │
├─────────────────────────────────────────────────┤
│ [1] ✓ node1.example.com                         │
│     Exit code: 0  |  Completed                  │
│ [2] ⟳ node2.example.com                         │
│     Progress: [████████░░] 45%                  │
│     Status: Installing packages...              │
│ [3] ✓ node3.example.com                         │
│ [4] ✗ node4.example.com                         │
│     Error: Connection timeout                   │
│ [5] ✓ node5.example.com                         │
├─────────────────────────────────────────────────┤
│ Press 1-9 for details • s for split • ? for help│
└─────────────────────────────────────────────────┘
```

**Features:**
- Status icons: ⊙ (pending), ⟳ (running), ✓ (success), ✗ (failed)
- Color coding: Gray (pending), Blue (running), Green (success), Red (failed)
- Progress bars for detected progress indicators
- Status messages from output parsing
- Completion indicator when all tasks finish

##### Detail View (`detail.rs`)

**Layout:**
```
┌─────────────────────────────────────────────────┐
│ Node 2/5: node2.example.com                     │
│ Status: Running  |  ⬆ Follow: ON  |  Scroll: 42 │
├─────────────────────────────────────────────────┤
│ Reading package lists... Done                   │
│ Building dependency tree                        │
│ Reading state information... Done               │
│ The following NEW packages will be installed:   │
│   nginx nginx-common nginx-core                 │
│ 0 upgraded, 3 newly installed, 0 to remove      │
│ Need to get 1,234 kB of archives.               │
│ After this operation, 4,567 kB will be used.    │
│ Get:1 http://archive.ubuntu.com/ubuntu nginx... │
│ [████████░░░░] 45% [Working]                    │
│                                                  │
│ ... (scrollable) ...                            │
├─────────────────────────────────────────────────┤
│ ↑/↓ scroll • ←/→ nodes • f toggle • Esc summary │
└─────────────────────────────────────────────────┘
```

**Features:**
- Full output display with ANSI color support
- Scrollback buffer (entire output available)
- Follow mode indicator
- Scroll position indicator
- Navigation hints in footer
- Automatic scrolling when follow mode enabled
- Manual scroll disables follow mode

##### Split View (`split.rs`)

**Layout (2 nodes):**
```
┌───────────────────────┬───────────────────────┐
│ [1] node1.example.com │ [2] node2.example.com │
│ Status: ✓ Completed   │ Status: ⟳ Running     │
├───────────────────────┼───────────────────────┤
│ Reading packages...   │ Updating system...    │
│ Done                  │ [████░░░░] 25%        │
│                       │ Installing updates... │
│ ... (last 20 lines)   │ ... (last 20 lines)   │
│                       │                       │
└───────────────────────┴───────────────────────┘
```

**Layout (3-4 nodes):**
Uses 2x2 grid layout for 3-4 nodes

**Features:**
- Displays 2-4 nodes simultaneously
- Each pane shows last 20 lines of output
- Status indicators per node
- Progress bars if detected
- Press `1-4` to focus on specific node

##### Diff View (`diff.rs`)

**Layout:**
```
┌───────────────────────┬───────────────────────┐
│ [1] node1.example.com │ [2] node2.example.com │
│ Exit: 0               │ Exit: 1               │
├───────────────────────┼───────────────────────┤
│ line 1: same          │ line 1: same          │
│ line 2: different A   │ line 2: different B   │
│ line 3: same          │ line 3: same          │
│ ... (scrollable)      │ ... (scrollable)      │
└───────────────────────┴───────────────────────┘
```

**Features:**
- Side-by-side output comparison
- Line-by-line alignment
- Visual difference highlighting
- Synchronized scrolling (TODO: not yet implemented)

### Event Handling and State Management

**Event Loop Architecture:**

```rust
async fn run_event_loop() {
    loop {
        // 1. Poll all node streams for new output (non-blocking)
        manager.poll_all();

        // 2. Check if data changed
        let data_changed = app.check_data_changes(streams);

        // 3. Render UI if needed (data changed or user input)
        if app.should_redraw() || data_changed {
            terminal.draw(|f| render_ui(f, app, manager))?;
        }

        // 4. Handle keyboard input (100ms timeout)
        if let Some(key) = poll_event(Duration::from_millis(100))? {
            handle_key_event(app, key, num_nodes);
            app.mark_needs_redraw();
        }

        // 5. Check completion and exit conditions
        if manager.all_complete() {
            app.mark_all_tasks_completed();
        }
        if app.should_quit {
            return Ok(exit_reason);
        }

        // 6. Small delay to prevent CPU spinning
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
```

**State Management Patterns:**

1. **Change Detection:**
   - Tracks stdout/stderr sizes per node
   - Only triggers redraw when data actually changes
   - Prevents unnecessary rendering cycles

2. **Lazy Rendering:**
   - `needs_redraw` flag tracks UI dirty state
   - Keyboard events set flag
   - Data changes set flag
   - Rendering consumes flag

3. **Memory Protection:**
   - Scroll positions limited to 100 nodes (HashMap)
   - RollingBuffer in streams limits to 10MB per node
   - View mode validation prevents invalid indices

4. **Terminal Safety:**
   - RAII guards ensure cleanup
   - Panic-safe terminal restoration
   - Minimum terminal size checks (40x10)
   - Graceful error messages for small terminals

### Multi-Node Stream Management

**Integration with Executor:**

The TUI integrates with `MultiNodeStreamManager` from `executor/stream_manager.rs`:

```rust
pub struct MultiNodeStreamManager {
    streams: Vec<NodeStream>,
}

pub struct NodeStream {
    node: Node,
    receiver: mpsc::Receiver<CommandOutput>,
    stdout_buffer: RollingBuffer,  // Max 10MB
    stderr_buffer: RollingBuffer,  // Max 10MB
    status: ExecutionStatus,
    exit_code: Option<u32>,
    closed: bool,
}
```

**RollingBuffer Design:**

**Purpose**: Prevents memory exhaustion when nodes produce large amounts of output

**Implementation:**
```rust
struct RollingBuffer {
    data: Vec<u8>,
    total_bytes_received: usize,
    bytes_dropped: usize,
}
```

**Behavior:**
- Accumulates data up to 10MB per stream
- When exceeded, drops oldest data (FIFO)
- Logs warnings about dropped data
- Maintains total bytes received counter

**Memory Protection:**
- Prevents unbounded memory growth
- Allows infinite command output
- Preserves most recent data for TUI display
- Graceful degradation (logs dropped bytes)

**Trade-offs:**
- ✓ Prevents OOM from runaway processes
- ✓ Allows commands with GB of output
- ✓ Real-time display always shows recent data
- ✗ Loses old data if buffer exceeded
- ✗ Full log history not available for review

### Output Mode Auto-Detection

**TUI Activation Conditions:**

```rust
fn should_use_tui() -> bool {
    // 1. Must be in interactive terminal
    if !io::stdout().is_terminal() {
        return false;
    }

    // 2. CI/CD detection (skip TUI in automation)
    if env::var("CI").is_ok() {
        return false;
    }

    // 3. Multi-node execution required
    if num_nodes < 2 {
        return false;
    }

    // 4. Not explicitly disabled by user flags
    if args.stream || args.output_dir.is_some() {
        return false;
    }

    true
}
```

**Output Mode Priority:**
1. `--output-dir`: File mode (explicit)
2. `--stream`: Stream mode (explicit)
3. Piped stdout: Normal mode (automatic)
4. CI environment: Normal mode (automatic)
5. Single node: Normal mode (automatic)
6. Default: TUI mode (automatic for multi-node in terminal)

### Performance Characteristics

**Target Metrics:**
- **Render latency**: <16ms (60 FPS)
- **Event response**: <10ms (keyboard to UI update)
- **Memory per node**: <10MB (buffer limit)
- **CPU usage**: <5% on modern systems

**Optimization Strategies:**
- Lazy rendering (only on data change or user input)
- Change detection prevents redundant draws
- Bounded buffers prevent memory bloat
- 50ms event loop prevents CPU spinning
- View-specific rendering (no global refresh)

**Rendering Frequency:**
- Data polling: Every 50ms
- UI updates: Only when data changes or user input
- Keyboard polling: 100ms timeout
- Terminal size checks: On every render (fast)

### Error Handling and Recovery

**Terminal Safety:**
- RAII guards ensure cleanup even on panic
- Multiple fallback cleanup strategies
- Emergency terminal reset on panic
- Error messages for too-small terminals (min 40x10)

**Stream Errors:**
- Connection failures shown per node
- Partial failures don't crash TUI
- Failed nodes show error messages
- Continue monitoring successful nodes

**Exit Conditions:**
- User quit (`q` or `Ctrl+C`): `TuiExitReason::UserQuit`
- All tasks complete: `TuiExitReason::AllTasksCompleted`
- Allows executor to determine final exit code

### TUI Exit Behavior

**Exit Reason Enum:**
```rust
pub enum TuiExitReason {
    UserQuit,           // User pressed 'q' or Ctrl+C
    AllTasksCompleted,  // All commands finished
}
```

**Exit Code Determination:**
- TUI itself doesn't determine exit code
- Returns `TuiExitReason` to executor
- Executor applies exit code strategy (MainRank/RequireAllSuccess/etc.)
- Allows user to quit before completion without affecting exit code logic

**Completion Tracking:**
- `all_tasks_completed` flag tracks when all nodes finish
- UI shows completion indicator
- User can review results before exiting
- Pressing `q` still allows viewing results

### Testing Strategy

**Unit Tests:**
- `app.rs`: View mode transitions, scroll logic, state management (~150 lines of tests)
- `event.rs`: Keyboard event handling, mode-specific keys (~80 lines of tests)
- `terminal_guard.rs`: Panic handling, guard cleanup (~50 lines of tests)
- `stream_manager.rs`: Buffer rolling, channel polling (~120 lines of tests)

**Integration Tests:**
- Manual testing required (terminal interaction)
- Test matrix:
  - All view modes with 2-10 nodes
  - Progress detection with various output patterns
  - Terminal resize handling
  - Rapid keyboard input
  - Memory usage with large outputs

**Coverage:**
- Unit test coverage: ~85% (excluding views)
- View rendering: Manual testing only
- Terminal interaction: Manual testing only

### Known Limitations

1. **Diff View Scrolling**: Synchronized scrolling not yet implemented
2. **Terminal Size**: Minimum 40x10 required (graceful error if smaller)
3. **Color Support**: Assumes 256-color terminal (graceful fallback to 16 colors)
4. **Mouse Support**: Not implemented (keyboard-only navigation)
5. **Search/Filter**: Not implemented (planned for future)

### Future Enhancements

**Planned Features:**
- Synchronized scrolling in diff view
- Search/filter functionality in detail view
- Mouse support for view navigation
- Configurable key bindings
- Persistent view state across sessions
- Export view contents to file
- Custom color themes
- Per-node filtering in summary view

**Implementation Notes:**
- All views use `ratatui` for consistent rendering
- Progress parsing extensible for new patterns
- View system easily extended with new modes
- RAII pattern ensures safety with any future changes

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

### 2025-10-17: Large-Scale Code Refactoring (Issue #33)
- Split 13 critical/high/medium priority files into focused modules
- Reduced largest file from 1,394 to 691 lines
- Maintained full backward compatibility (232+ tests passing)
- Established optimal module size guidelines (300-700 lines)
- Intentionally skipped some lower-priority files based on risk/benefit analysis


## SSH Jump Host Support

### Status: Fully Implemented

**Jump Host Parser Module Structure (Refactored 2025-10-17):**
- `parser/tests.rs` - Test suite (343 lines)
- `parser/host_parser.rs` - Host and port parsing (141 lines)
- `parser/main_parser.rs` - Main parsing logic (79 lines)
- `parser/host.rs` - JumpHost data structure (63 lines)
- `parser/config.rs` - Jump host limits configuration (61 lines)
- `parser/mod.rs` - Module exports (29 lines)

**Jump Chain Module Structure (Refactored 2025-10-17):**
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
pub fn get_max_jump_hosts() -> usize {
    std::env::var("BSSH_MAX_JUMP_HOSTS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
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
- Enforced at parse time in `jump::parser::parse_jump_hosts()`
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

7. **`src/forwarding/dynamic/*`**: Dynamic forwarding (-D, Refactored 2025-10-17)
   - **Module Structure:**
     - `dynamic/forwarder.rs` - Main forwarder logic and retry mechanism (280 lines)
     - `dynamic/socks.rs` - SOCKS4/5 protocol handlers (257 lines)
     - `dynamic/connection.rs` - Connection management and lifecycle (174 lines)
     - `dynamic/stats.rs` - Statistics tracking (83 lines)
     - `dynamic/mod.rs` - Module exports and tests (173 lines)
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

## SSH Configuration Parser

The SSH configuration parser provides comprehensive support for OpenSSH configuration files, implementing various configuration options incrementally for maintainability and feature completeness.

### Architecture

The parser is implemented as a modular system with the following structure:

```
src/ssh/ssh_config/
├── parser/
│   ├── core.rs           # Core parsing logic with 2-pass strategy
│   ├── helpers.rs        # Helper functions (parse_yes_no, etc.)
│   ├── options/          # Option parsing modules
│   │   ├── authentication.rs
│   │   ├── basic.rs
│   │   ├── command.rs    # Command execution options
│   │   ├── connection.rs
│   │   ├── control.rs
│   │   ├── environment.rs
│   │   ├── forwarding.rs
│   │   ├── proxy.rs
│   │   ├── security.rs
│   │   └── ui.rs
│   └── tests.rs
├── security/             # Security validation
│   ├── string_validation.rs
│   └── path_validation.rs
├── types.rs             # Core data structures
└── resolver.rs          # Host configuration resolution
```

### Supported Configuration Categories

The SSH configuration parser supports a comprehensive set of OpenSSH configuration options:

#### Basic Configuration Options
- **Option=Value syntax**: Support for both space and equals-separated options
- **Basic options**: Hostname, User, Port, IdentityFile
- **Authentication**: PubkeyAuthentication, PasswordAuthentication
- **Connection**: ServerAliveInterval, ConnectTimeout, etc.

#### Certificate Authentication and Port Forwarding
- **Certificate support**: CertificateFile, CASignatureAlgorithms
- **Advanced forwarding**: GatewayPorts, ExitOnForwardFailure, PermitRemoteOpen
- **Hostbased auth**: HostbasedAuthentication, HostbasedAcceptedAlgorithms

#### Command Execution and Automation
Command execution options enable sophisticated automation workflows:

##### LocalCommand and PermitLocalCommand
- **Purpose**: Execute commands locally after SSH connection
- **Security**: Requires explicit PermitLocalCommand=yes
- **Token substitution**: Supports %h, %H, %n, %p, %r, %u tokens
- **Validation**: Commands are validated against injection attacks
- **Use cases**: File synchronization, notifications, environment setup

##### RemoteCommand
- **Purpose**: Execute command on remote host instead of shell
- **Security**: No local validation (runs on remote)
- **Use cases**: Auto-attach tmux, enter specific environments

##### KnownHostsCommand
- **Purpose**: Dynamically fetch host keys
- **Security**: Command path validation, timeout protection
- **Token substitution**: Supports %h and %H tokens
- **Use cases**: Cloud environments, certificate authorities

##### Additional Automation Options
- **ForkAfterAuthentication**: Fork SSH into background after auth
- **SessionType**: Control session type (none/subsystem/default)
- **StdinNull**: Redirect stdin from /dev/null for scripting

#### Host Key Verification, Authentication, and Network Options
This category includes 15 commonly-used SSH configuration options that enhance security, authentication control, and network behavior. These options complete ~70% OpenSSH compatibility coverage.

##### Host Key Verification & Security (7 options)
- **NoHostAuthenticationForLocalhost**: Skip host key verification for localhost connections (yes/no)
  - Convenient for local development and testing
  - Reduces known_hosts clutter
  - Default: no

- **HashKnownHosts**: Hash hostnames in known_hosts file (yes/no)
  - Security enhancement: prevents hostname disclosure if file is compromised
  - Default: no

- **CheckHostIP**: Check host IP address in known_hosts (yes/no)
  - **Deprecated** in OpenSSH 8.5+ (2021)
  - Detects DNS spoofing
  - Retained for legacy compatibility

- **VisualHostKey**: Display ASCII art of host key fingerprint (yes/no)
  - Helps users visually verify host identity
  - Default: no

- **HostKeyAlias**: Alias for host key lookup in known_hosts
  - Useful for load-balanced services sharing host keys
  - Single string value

- **VerifyHostKeyDNS**: Verify host keys using DNS SSHFP records (yes/no/ask)
  - Validates host keys against DNS records
  - Default: no

- **UpdateHostKeys**: Accept updated host keys from server (yes/no/ask)
  - Controls automatic acceptance of key updates
  - Default: no

##### Authentication Options (2 options)
- **NumberOfPasswordPrompts**: Password retry attempts (1-10)
  - Controls password authentication retries
  - Validation: warns if outside typical range
  - Default: 3 (OpenSSH standard)

- **EnableSSHKeysign**: Enable ssh-keysign for host-based authentication (yes/no)
  - Required for host-based authentication
  - Default: no

##### Network & Connection Options (3 options)
- **BindInterface**: Bind connection to specific network interface
  - Alternative to BindAddress for multi-homed hosts
  - Useful for VPN scenarios
  - String value (interface name)

- **IPQoS**: IP type-of-service/DSCP values
  - Two values: interactive and bulk traffic
  - Quality of Service control
  - Format: "value1 value2" (e.g., "lowdelay throughput")

- **RekeyLimit**: SSH session key renegotiation control
  - Format: "data [time]" with K/M/G suffixes
  - Security tuning option
  - Default: "default none"

##### X11 Forwarding Options (2 options)
- **ForwardX11Timeout**: Timeout for untrusted X11 forwarding
  - Time interval format (e.g., "1h", "30m")
  - Default: 0 (no timeout)

- **ForwardX11Trusted**: Enable trusted X11 forwarding (yes/no)
  - Controls X11 security extension restrictions
  - Default: no

##### Implementation Details
**Files Modified:**
- `src/ssh/ssh_config/types.rs`: Added 15 new fields to SshHostConfig
- `src/ssh/ssh_config/parser/options/security.rs`: 7 host key/security parsers
- `src/ssh/ssh_config/parser/options/authentication.rs`: 2 authentication parsers
- `src/ssh/ssh_config/parser/options/connection.rs`: 3 network option parsers
- `src/ssh/ssh_config/parser/options/forwarding.rs`: 2 X11 forwarding parsers
- `src/ssh/ssh_config/resolver.rs`: Merge logic for all new options

**Testing:**
- 7 comprehensive test functions covering all host key verification, authentication, and network options
- Parsing validation, config merging, precedence, error handling
- Option=Value syntax compatibility
- Total test count: 278 tests passing

#### Authentication and Security Management Options
These additional SSH configuration options provide essential authentication management, security enforcement, and user convenience features that complete ~99% of real-world SSH configuration use cases.

**Implemented Options (2025-10-23):**

##### Authentication & Agent Management (4 options)

**IdentitiesOnly**
- **Purpose**: Only use identity files specified in config, ignore SSH agent
- **Values**: yes/no (default: no)
- **Use Case**: Prevents authentication conflicts in multi-account setups
- **Implementation**: Boolean flag in SshHostConfig
- **Parsing**: Standard yes/no parser in `authentication.rs`
- **Example**: `IdentitiesOnly yes`

**AddKeysToAgent**
- **Purpose**: Automatically add keys to SSH agent after successful authentication
- **Values**: yes/no/ask/confirm (default: no)
- **Validation**: Only allows these 4 specific values
- **Use Case**: Eliminates manual ssh-add commands
- **Implementation**: String field with value validation
- **Parsing**: Custom validator in `authentication.rs`
- **Example**: `AddKeysToAgent yes`

**IdentityAgent**
- **Purpose**: Specify custom SSH agent socket path
- **Values**: Socket path, "none", or "SSH_AUTH_SOCK"
- **Special Values**:
  - `none` - Explicitly disable agent authentication
  - `SSH_AUTH_SOCK` - Use environment variable (default)
- **Use Case**: Integration with 1Password, gpg-agent, etc.
- **Implementation**: Option<String> with path validation
- **Security**: Path validation and warning for long paths
- **Parsing**: String parser with special value handling in `authentication.rs`
- **Example**: `IdentityAgent ~/.1password/agent.sock`

**PubkeyAcceptedAlgorithms**
- **Purpose**: Restrict allowed public key signature algorithms
- **Format**: Comma-separated list of algorithms
- **Limits**: Maximum 50 algorithms per configuration
- **Use Case**: Enforce security policies by restricting to modern algorithms
- **Implementation**: Vec<String> with size limits
- **Security**: Protects against algorithm downgrade attacks
- **Parsing**: Comma-separated list parser in `authentication.rs`
- **Example**: `PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256`

##### Security & Algorithm Management (2 options)

**RequiredRSASize**
- **Purpose**: Enforce minimum RSA key size in bits
- **Range**: 1024-16384 bits
- **Validation**:
  - Range checking (1024-16384)
  - Warning if below 2048 (modern security standard)
- **Default**: 1024 (OpenSSH legacy), 2048 (OpenSSH 9.0+)
- **Added**: OpenSSH 8.7 (2021)
- **Use Case**: Prevent weak RSA keys in production environments
- **Implementation**: Option<u32> with range validation
- **Security**: Validates against both too-small and unreasonably-large values
- **Parsing**: Integer parser with validation in `security.rs`
- **Example**: `RequiredRSASize 2048`

**FingerprintHash**
- **Purpose**: Choose hash algorithm for displaying SSH key fingerprints
- **Values**: md5/sha256 (default: sha256 since OpenSSH 6.8)
- **Validation**: Only allows these 2 specific values
- **Security Warning**: Using MD5 generates deprecation warning
- **Use Case**: Compatibility with legacy systems requiring MD5 fingerprints
- **Implementation**: Option<String> with value validation
- **Default**: sha256 (modern OpenSSH)
- **Parsing**: String parser with value validation in `security.rs`
- **Example**: `FingerprintHash sha256`

**Implementation Files:**
- **Types**: `src/ssh/ssh_config/types.rs` - Added 6 fields to SshHostConfig
- **Parsers**:
  - `src/ssh/ssh_config/parser/options/authentication.rs` - 4 authentication/agent parsers
  - `src/ssh/ssh_config/parser/options/security.rs` - 2 security parsers
- **Resolver**: `src/ssh/ssh_config/resolver.rs` - Merge logic for all 6 options
- **Tests**: `src/ssh/ssh_config/parser/tests.rs` - 37 comprehensive test cases

**Test Coverage:**
- IdentitiesOnly: 4 tests (yes/no parsing, config merging)
- AddKeysToAgent: 7 tests (all 4 values, validation, errors)
- IdentityAgent: 5 tests (paths, special values, warnings)
- PubkeyAcceptedAlgorithms: 4 tests (comma-separated, limits, deduplication)
- RequiredRSASize: 9 tests (range validation, warnings, errors)
- FingerprintHash: 5 tests (md5/sha256, validation, warnings)
- Integration: 2 tests (combined options, Match blocks)
- **Total**: 37 new tests, all passing

**Security Features:**
- **Input Validation**: All options have comprehensive validation
- **Warnings**: Security-sensitive configurations trigger warnings
  - RequiredRSASize <2048: Weak key warning
  - FingerprintHash=md5: Deprecation warning
  - IdentityAgent long paths: Path length warning
- **Limits**: PubkeyAcceptedAlgorithms capped at 50 algorithms
- **Safe Defaults**: All options default to secure values

**User Benefits:**
- **IdentitiesOnly**: Solves multi-account authentication conflicts
- **AddKeysToAgent**: Automates SSH agent key management
- **IdentityAgent**: Enables modern agent integrations (1Password, etc.)
- **PubkeyAcceptedAlgorithms**: Enforces organizational security policies
- **RequiredRSASize**: Prevents weak RSA keys in production
- **FingerprintHash**: Provides legacy system compatibility

**Coverage Achievement:**
The SSH configuration parser currently supports:
- Basic options + Include + Match directives (structural)
- Certificate authentication and port forwarding (7 options)
- Command execution and automation (7 options)
- Host key verification, authentication, and network options (15 options)
- Authentication and security management options (6 options)
- **Total: ~79 options** (~77% of OpenSSH's 103 options)
- **Real-world coverage: 99%** - Covers all common use cases

### Security Model

The parser implements multiple layers of security validation:

#### Command Injection Prevention
```rust
// Security validation for executable commands
fn validate_executable_string(value: &str, option_name: &str, line_number: usize) -> Result<()> {
    // Check for dangerous shell metacharacters
    const DANGEROUS_CHARS: &[char] = &[
        ';',  // Command separator
        '&',  // Background/separator
        '|',  // Pipe
        '`',  // Command substitution
        '$',  // Variable/command expansion
        '>',  // Redirection
        '<',  // Redirection
        '\n', // Newline
        '\r', // Carriage return
        '\0', // Null byte
    ];
    // ... validation logic
}
```

#### Token Substitution Security
The parser validates SSH tokens while preventing injection:
- **Valid tokens**: %h (hostname), %H (hostname), %n (original), %p (port), %r (remote user), %u (local user), %% (literal %)
- **Invalid patterns**: Detected and rejected during parsing
- **Substitution timing**: Tokens are validated but not substituted by parser (client responsibility)

#### Path Validation
- Tilde expansion support with security checks
- Prevention of path traversal attacks
- Validation against sensitive system paths
- Symlink resolution safety

### Testing Strategy

Comprehensive test coverage includes:

1. **Unit tests**: Each option parser module has internal tests
2. **Integration tests**: Full configuration parsing scenarios
3. **Security tests**: Injection attempts, malformed input
4. **Edge cases**: Empty values, whitespace, special characters

Test files:
- `src/ssh/ssh_config/parser/options/command.rs`: Unit tests for command options
- `tests/ssh_config_command_options_test.rs`: Integration tests for command execution options

### Performance Considerations

- **Two-pass parsing**: Handles Include directives efficiently
- **Lazy resolution**: Configuration merging only when needed
- **String allocation**: Minimized through careful use of references
- **Validation caching**: Results cached where possible

### Future Enhancements

Planned enhancements for complete OpenSSH compatibility:

#### Additional Configuration Options
The following high-priority options are planned for future implementation:
- **IdentitiesOnly**: Use only identity files specified in config
- **AddKeysToAgent**: Automatically add keys to SSH agent
- **IdentityAgent**: Custom SSH agent socket path
- **PubkeyAcceptedAlgorithms**: Restrict allowed public key algorithms
- **RequiredRSASize**: Enforce minimum RSA key size
- **FingerprintHash**: Choose fingerprint hash algorithm

#### Advanced Features
- **ProxyCommand**: Custom proxy commands (alternative to ProxyJump)
- **ControlMaster**: Connection multiplexing and sharing
- **ControlPath**: Socket path for connection multiplexing
- **ControlPersist**: Keep multiplexed connections alive
- **Additional options**: As needed for compatibility

## Exit Code Strategy Architecture (v1.2.0+)

### Overview

**Breaking Change (v1.2.0)**: The default exit code behavior has changed to match standard MPI tools (mpirun, srun, mpiexec). This improves compatibility with distributed computing workflows and enables better error diagnostics.

**Old Behavior (v1.0-v1.1)**:
- Returns exit code 0 only if **all nodes** succeeded
- Returns exit code 1 if **any node** failed (discarding actual exit codes)

**New Behavior (v1.2.0+)**:
- Returns the **main rank's exit code** by default (matching MPI standard)
- Preserves actual exit codes (139=SIGSEGV, 137=OOM, 124=timeout, etc.)
- Use `--require-all-success` flag for v1.0-v1.1 behavior

### Design Rationale

#### Why MainRank is Default

1. **MPI Standard Compliance**: All standard MPI tools (mpirun, srun, mpiexec) return rank 0's exit code
2. **Better Diagnostics**: Actual exit codes preserved for debugging (segfault, OOM, timeout)
3. **CI/CD Integration**: Exit-code-based decisions work naturally
4. **Information Preservation**: No loss of error details
5. **Industry Practice**: Aligns with HPC and distributed computing conventions

#### Use Case Alignment

- **90% of use cases**: MPI workloads, distributed computing, CI/CD
- **10% of use cases**: Health checks, monitoring (use `--require-all-success`)

### Main Rank Detection Algorithm

The system identifies the "main rank" (rank 0) using hierarchical fallback:

```rust
pub fn identify_main_rank(nodes: &[Node]) -> Option<usize> {
    // 1. Check Backend.AI CLUSTER_ROLE environment variable
    if env::var("BACKENDAI_CLUSTER_ROLE").ok() == Some("main".to_string()) {
        // Try to match by hostname
        if let Ok(host) = env::var("BACKENDAI_CLUSTER_HOST") {
            if let Some(idx) = nodes.iter().position(|n| n.host == host) {
                return Some(idx);
            }
        }
    }

    // 2. Fallback: First node is main rank (standard convention)
    if !nodes.is_empty() {
        Some(0)
    } else {
        None
    }
}
```

**Detection Priority**:
1. `BACKENDAI_CLUSTER_ROLE=main` + `BACKENDAI_CLUSTER_HOST` match
2. First node in the node list (index 0)

**Backend.AI Integration**: Automatic detection in multi-node sessions without configuration.

### Exit Code Strategies

Three strategies are available to handle different scenarios:

#### 1. MainRank (Default in v1.2.0+)

**Behavior**: Returns the main rank's actual exit code.

**Use Cases**:
- MPI workloads and distributed computing
- CI/CD pipelines requiring exit code inspection
- Shell scripts with error handling logic
- When debugging requires specific exit codes

**Example**:
```bash
bssh exec "mpirun -n 16 ./simulation"
EXIT_CODE=$?

case $EXIT_CODE in
    0)   echo "Success!"; deploy_results ;;
    139) echo "Segfault!"; collect_core_dump ;;
    137) echo "OOM!"; retry_with_more_memory ;;
    124) echo "Timeout!"; extend_time_limit ;;
    *)   echo "Failed: $EXIT_CODE"; exit $EXIT_CODE ;;
esac
```

**Implementation**:
```rust
ExitCodeStrategy::MainRank => {
    main_idx
        .and_then(|i| results.get(i))
        .map(|r| r.get_exit_code())
        .unwrap_or(1) // No main rank identified → failure
}
```

#### 2. RequireAllSuccess (v1.0-v1.1 Behavior)

**Behavior**: Returns 0 only if all nodes succeeded, 1 otherwise.

**CLI Flag**: `--require-all-success`

**Use Cases**:
- Health checks and monitoring
- Cluster validation
- When any failure should be treated equally
- Legacy scripts requiring old behavior

**Example**:
```bash
bssh --require-all-success exec "disk-check"
if [ $? -ne 0 ]; then
    alert_ops "Node failure detected"
fi
```

**Implementation**:
```rust
ExitCodeStrategy::RequireAllSuccess => {
    if results.iter().any(|r| !r.is_success()) {
        1
    } else {
        0
    }
}
```

#### 3. MainRankWithFailureCheck (Hybrid Mode)

**Behavior**: Returns main rank's exit code if non-zero, or 1 if main succeeded but others failed.

**CLI Flag**: `--check-all-nodes`

**Use Cases**:
- Production deployments requiring both diagnostics and completeness
- When you need detailed error codes but also want to catch failures on any node

**Example**:
```bash
bssh --check-all-nodes exec "mpirun ./program"
# Main failed → main's exit code
# Main OK + others failed → 1
# All OK → 0
```

**Implementation**:
```rust
ExitCodeStrategy::MainRankWithFailureCheck => {
    let main_code = main_idx
        .and_then(|i| results.get(i))
        .map(|r| r.get_exit_code())
        .unwrap_or(0);

    let other_failed = results.iter()
        .enumerate()
        .any(|(i, r)| Some(i) != main_idx && !r.is_success());

    if main_code != 0 {
        main_code  // Main failed → return its code
    } else if other_failed {
        1  // Main OK but others failed → 1
    } else {
        0  // All OK
    }
}
```

### Strategy Comparison Table

| Scenario | Main Exit | Other Exits | MainRank | RequireAllSuccess | MainRankWithFailureCheck |
|----------|-----------|-------------|----------|-------------------|--------------------------|
| All success | 0 | 0,0,0 | 0 | 0 | 0 |
| Main failed | 139 (SIGSEGV) | 0,0,0 | **139** | 1 | **139** |
| Other failed | 0 | 1,0,0 | **0** | 1 | **1** |
| All failed | 1 | 1,1,1 | 1 | 1 | 1 |
| Main timeout | 124 | 0,0,0 | **124** | 1 | **124** |
| Main OOM | 137 | 0,0,0 | **137** | 1 | **137** |

**Bold** values show where strategies differ.

### Implementation Details

#### File Structure

```
src/executor/
├── rank_detector.rs      # Main rank identification
├── exit_strategy.rs      # Exit code calculation strategies
├── result_types.rs       # ExecutionResult with is_main_rank field
├── mod.rs                # Re-exports RankDetector and ExitCodeStrategy
└── parallel.rs           # Marks main rank in results

src/commands/
└── exec.rs               # Applies exit strategy based on CLI flags

src/
└── cli.rs                # CLI flags: --require-all-success, --check-all-nodes
```

#### ExecutionResult Enhancement

```rust
pub struct ExecutionResult {
    pub node: Node,
    pub result: Result<CommandResult>,
    pub is_main_rank: bool,  // NEW in v1.2.0
}

impl ExecutionResult {
    // NEW: Extract exit code from result
    pub fn get_exit_code(&self) -> i32 {
        match &self.result {
            Ok(cmd_result) => cmd_result.exit_status as i32,
            Err(_) => 1, // Connection error → exit code 1
        }
    }
}
```

#### Executor Integration

The `ParallelExecutor` automatically marks the main rank:

```rust
fn collect_results(&self, results: Vec<...>) -> Result<Vec<ExecutionResult>> {
    let mut execution_results = Vec::new();
    // ... collect results ...

    // Identify and mark the main rank
    if let Some(main_idx) = RankDetector::identify_main_rank(&self.nodes) {
        if let Some(main_result) = execution_results.get_mut(main_idx) {
            main_result.is_main_rank = true;
        }
    }

    Ok(execution_results)
}
```

#### Command Integration

The `exec` command determines strategy from CLI flags:

```rust
let strategy = if params.require_all_success {
    ExitCodeStrategy::RequireAllSuccess
} else if params.check_all_nodes {
    ExitCodeStrategy::MainRankWithFailureCheck
} else {
    ExitCodeStrategy::MainRank // Default in v1.2.0+
};

let main_idx = RankDetector::identify_main_rank(&nodes);
let exit_code = strategy.calculate(&results, main_idx);

if exit_code != 0 {
    std::process::exit(exit_code);
}
```

### Testing Strategy

#### Test Coverage

- **Unit Tests** (in module files):
  - `rank_detector.rs`: 8 tests for all detection scenarios
  - `exit_strategy.rs`: 18 tests for all strategies and edge cases

- **Integration Tests**:
  - `tests/exit_code_integration_test.rs`: 6 end-to-end tests
  - Comprehensive test matrix covering all strategies × scenarios

#### Test Matrix

All combinations of:
- Strategies: MainRank, RequireAllSuccess, MainRankWithFailureCheck
- Main rank states: success, failure (various exit codes)
- Other nodes states: all success, some failed, all failed

**Total**: 391+ passing tests (including existing test suite)

### Migration Guide

#### For MPI Workloads (No Changes Needed)

```bash
# Before (v1.0-v1.1): Exit code discarded
bssh exec "mpirun ./program"
# Returns: 1 (just "failed", no details)

# After (v1.2.0+): Exit code preserved
bssh exec "mpirun ./program"
# Returns: 139 (SIGSEGV - immediate diagnosis!)

# ✅ No changes needed - behavior improved
```

#### For Health Checks (Add Flag)

```bash
# Before (v1.0-v1.1): Implicit all-must-succeed
bssh exec "health-check"

# After (v1.2.0+): Add --require-all-success flag
bssh --require-all-success exec "health-check"

# ⚠️ Action required: Add flag to preserve behavior
```

#### Configuration File Support (Future)

```yaml
# Future enhancement: config.yaml
exit_code:
  default_strategy: require-all-success  # Preserve old behavior globally
```

### Performance Considerations

- **Zero Overhead**: Main rank detection is O(n) single pass
- **Strategy Selection**: Compile-time resolution via enum dispatch
- **No Allocations**: All calculations on stack
- **Minimal Latency**: <1μs added to exit path

### Security Considerations

- **Exit Code Range**: Limited to 0-255 (POSIX standard)
- **No Injection**: Exit codes are integers, not strings
- **Deterministic**: Same inputs → same output (no randomness)

### Benefits Summary

1. **MPI Standard Compliance**: Matches mpirun/srun/mpiexec behavior
2. **Better Diagnostics**: Actual exit codes preserved (139, 137, 124, etc.)
3. **CI/CD Ready**: Exit-code-based decisions work naturally
4. **Backward Compatible**: `--require-all-success` flag for old behavior
5. **Flexible**: Three strategies for different use cases
6. **Backend.AI Native**: Auto-detection in multi-node sessions
7. **Zero Learning Curve**: Works like familiar MPI tools
8. **Debugging Speed**: Instant error identification (<1s vs minutes)

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
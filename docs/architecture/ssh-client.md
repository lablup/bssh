# SSH Client Architecture

[← Back to Main Architecture](../../ARCHITECTURE.md)

### 4. SSH Client (`ssh/client/*`, `ssh/tokio_client/*`)

**SSH Client Module Structure :**
- `client/core.rs` - Client struct and core functionality (44 lines)
- `client/connection.rs` - Connection establishment and management (308 lines)
- `client/command.rs` - Command execution logic (155 lines)
- `client/file_transfer.rs` - SFTP operations (691 lines)
- `client/config.rs` - Configuration types (27 lines)
- `client/result.rs` - Result types and implementations (86 lines)

**Tokio Client Module Structure :**
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

**Status:** Implemented (2025-10-29) as part of Phase 1 of

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
 - Used by synchronous `execute` for backward compatibility

3. **Streaming API Methods**
 - `Client::execute_streaming(command, sender)` - Low-level streaming API
 - `SshClient::connect_and_execute_with_output_streaming` - High-level streaming API
 - Both respect timeout settings and handle errors consistently

**Implementation Pattern:**

```rust
// Streaming execution (new in Phase 1)
let (sender, receiver_task) = build_output_buffer;
let exit_status = client.execute_streaming("command", sender).await?;
let (stdout, stderr) = receiver_task.await?;

// Backward-compatible execution (refactored to use streaming)
let result = client.execute("command").await?;
// Internally uses execute_streaming + CommandOutputBuffer
```

**Backward Compatibility:**

The existing `execute` method was refactored to use `execute_streaming` internally:
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

**Future Phases :**
- ~~Phase 2: Executor integration for parallel streaming~~ ✓ Completed (2025-10-29)
- Phase 3: UI components (progress bars, live updates)
- Phase 4: Advanced features (filtering, aggregation)

### 4.0.2 Multi-Node Stream Management and Output Modes (Phase 2)

**Status:** Implemented (2025-10-29) as part of Phase 2 of

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
 Normal, // Traditional batch mode
 Stream, // Real-time with [node] prefixes
 File(PathBuf), // Save to per-node files
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
// In ParallelExecutor::execute_with_streaming
1. Create MultiNodeStreamManager
2. Spawn task per node with streaming sender
3. Poll all streams in loop:
 - Extract new output from each stream
 - Process based on output mode:
 * Stream: Print with [node] prefix
 * File: Buffer until completion
 * Normal: Use traditional execute
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
- Without `--stream` or `--output-dir`, uses traditional `execute` method
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
- Auto-detects piped output (`stdout.is_terminal`)
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
├── stream_manager.rs # NodeStream, MultiNodeStreamManager (252 lines)
├── output_mode.rs # OutputMode enum, TTY detection (171 lines)
├── parallel.rs # Updated with streaming methods (+264 lines)
└── mod.rs # Exports for new types
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

**Status:** Implemented (2025-10-30) as part of Phase 3 of

**Design Motivation:**
Phase 3 builds on the streaming infrastructure from Phase 1 and multi-node management from Phase 2 to provide a rich interactive Terminal User Interface (TUI) for monitoring parallel SSH command execution. The TUI automatically activates in interactive terminals and provides multiple view modes optimized for different monitoring needs.

**Architecture:**

The Phase 3 implementation introduces a complete TUI system built with ratatui and crossterm:

#### Module Structure

```
src/ui/tui/
├── mod.rs # TUI entry point, event loop, terminal management
├── app.rs # TuiApp state management
├── event.rs # Keyboard event handling
├── progress.rs # Progress parsing utilities
├── terminal_guard.rs # RAII terminal cleanup guards
└── views/
 ├── mod.rs
 ├── summary.rs # Summary view (all nodes)
 ├── detail.rs # Detail view (single node with scrolling)
 ├── split.rs # Split view (2-4 nodes simultaneously)
 └── diff.rs # Diff view (compare two nodes)
```

#### Core Components

1. **TuiApp State** (`app.rs`)
 ```rust
 pub struct TuiApp {
 pub view_mode: ViewMode,
 pub scroll_positions: HashMap<usize, usize>, // Per-node scroll
 pub follow_mode: bool, // Auto-scroll
 pub should_quit: bool,
 pub show_help: bool,
 needs_redraw: bool, // Conditional rendering
 last_data_sizes: Vec<usize>, // Change detection
 }

 pub enum ViewMode {
 Summary, // All nodes status
 Detail(usize), // Single node full output
 Split(Vec<usize>), // 2-4 nodes side-by-side
 Diff(usize, usize), // Compare two nodes
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
 static ref PERCENT_PATTERN: Regex = Regex::new(r"(\d+)%").unwrap;
 static ref FRACTION_PATTERN: Regex = Regex::new(r"(\d+)/(\d+)").unwrap;
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
 command: &str) -> Result<Vec<ExecutionResult>>
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
 manager.poll_all.await;

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
 if let Event::Key(key) = event::read? {
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
 cli.output_dir.clone,
 is_tty);

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
// In ParallelExecutor::handle_tui_mode
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
ratatui = "0.29" # Terminal UI framework
regex = "1" # Progress parsing
lazy_static = "1.5" # Regex compilation optimization
```

**Future Enhancements:**
- Configuration file for custom keybindings
- Output filtering/search within TUI
- Mouse support for clickable UI
- Session recording and replay
- Color themes and customization

### 4.1 Authentication Module (`ssh/auth.rs`)

**Status:** Implemented (2025-10-17) as part of code deduplication refactoring

**Design Motivation:**
Authentication logic was previously duplicated across multiple modules (`ssh/client.rs` and `commands/interactive.rs`) with ~90% code duplication. This created maintenance burden and potential for bugs when fixing authentication issues in one location but not the other.

**Refactoring Goals:**
- Eliminate ~15% code duplication across codebase
- Provide single source of truth for authentication
- Maintain consistent authentication behavior across all commands
- Improve testability with centralized tests
- Reduce maintenance cost for authentication logic

**Implementation:**
The `AuthContext` struct encapsulates all authentication parameters and provides a single `determine_method` function that implements the standard authentication priority:

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
 .with_key_path(key_path.map(|p| p.to_path_buf))
 .with_agent(use_agent)
 .with_password(use_password);

let auth_method = auth_ctx.determine_method?;
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
 auth_ctx.determine_method
 }
 ```

2. **`commands/interactive.rs`**: Uses `AuthContext` for interactive sessions
 ```rust
 fn determine_auth_method(&self, node: &Node) -> Result<AuthMethod> {
 let auth_ctx = crate::ssh::AuthContext::new(...)
 .with_key_path(...)
 .with_agent(...)
 .with_password(...);
 auth_ctx.determine_method
 }
 ```

**Benefits Realized:**
- Single source of truth for authentication logic
- Easier to add new authentication methods
- Consistent behavior across all bssh commands

### 4.2 Sudo Password Support (`security/sudo.rs`)

**Status:** Implemented (2025-12-10) as

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
 | |
 | Output Monitoring
 | |
 | [Sudo Prompt Detected?] -- No --> Continue
 | |Yes
 | Send Password + Newline
 | |
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
- Uses `channel.data` to write password to stdin when prompt detected
- Password sent only once per execution to prevent retry loops

```rust
pub async fn execute_with_sudo(
 &self,
 command: &str,
 sender: Sender<CommandOutput>,
 sudo_password: &SudoPassword) -> Result<u32, Error>
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
5. Per-node execution uses `execute_with_sudo` when password present

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
 _connections: Arc<RwLock<Vec<ConnectionKey>>>, // Placeholder
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

---

**Related Documentation:**
- [Main Architecture](../../ARCHITECTURE.md)
- [Executor Architecture](./executor.md)
- [Interactive Mode](./interactive-mode.md)
- [TUI](./tui.md)

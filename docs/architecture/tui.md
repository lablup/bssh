# Terminal User Interface

[← Back to Main Architecture](../../ARCHITECTURE.md)

## Terminal User Interface (TUI) Architecture

### Status: Fully Implemented (2025-12-10)

The TUI module provides a real-time interactive terminal interface for monitoring parallel command execution across multiple nodes. Built with `ratatui`, it offers 4 distinct view modes with keyboard-driven navigation and automatic output streaming.

### Module Structure

```
src/ui/tui/
├── mod.rs # Public API: run_tui, TuiExitReason
├── app.rs # TuiApp state machine, ViewMode enum
├── event.rs # Keyboard input handling
├── progress.rs # Output parsing for progress indicators
├── terminal_guard.rs # RAII cleanup on exit/panic
├── log_buffer.rs # In-memory log buffer for TUI mode
├── log_layer.rs # Custom tracing Layer for TUI log capture
└── views/ # View implementations
 ├── mod.rs # View module exports
 ├── summary.rs # Multi-node overview
 ├── detail.rs # Single node full output
 ├── split.rs # Multi-pane view (2-4 nodes)
 ├── diff.rs # Side-by-side comparison
 └── log_panel.rs # Log panel view component
```

### Core Components

#### 1. TuiApp State Machine (`app.rs`)

**ViewMode Enum:**
```rust
pub enum ViewMode {
 Summary, // All nodes at a glance
 Detail(usize), // Single node full output
 Split(Vec<usize>), // 2-4 nodes side-by-side
 Diff(usize, usize), // Compare two nodes
}
```

**State Management:**
- **Scroll positions**: Per-node scroll state (HashMap with 100-entry limit)
- **Follow mode**: Auto-scroll to bottom (default: enabled)
- **Change detection**: Tracks data sizes to minimize unnecessary redraws
- **Completion tracking**: Monitors when all tasks finish

**Key Methods:**
- `check_data_changes`: Detects new output from nodes
- `should_redraw`: Optimizes rendering by tracking dirty state
- `show_detail`, `show_split`, `show_diff`: View transitions
- `scroll_up`, `scroll_down`: Scrolling with automatic follow-mode disable
- `next_node`, `prev_node`: Node navigation in detail view

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

- **Log panel keys** (when visible):
 - `l`: Toggle log panel visibility
 - `j/k`: Scroll log entries up/down
 - `+/-`: Increase/decrease panel height (3-10 lines)
 - `t`: Toggle timestamp display

**Design Pattern:**
- Centralized event routing via `handle_key_event`
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
├── RawModeGuard # Manages terminal raw mode
└── AlternateScreenGuard # Manages alternate screen buffer
```

**Cleanup Guarantees:**
- Raw mode disabled on drop
- Alternate screen exited on drop
- Cursor shown on drop
- Panic-safe cleanup (detected via `std::thread::panicking`)
- Emergency terminal reset sequence on panic

**Safety Mechanisms:**
- Multiple fallback cleanup strategies
- Error logging (can't panic in Drop)
- Direct stderr writes as last resort
- Force terminal reset on panic: `\x1b[0m\x1b[?25h`

#### 5. In-TUI Log Panel

**Problem Solved:**
When ERROR or WARN level logs occur during TUI mode execution, the log messages were previously printed directly to the screen, breaking the ratatui alternate screen layout. The log panel captures these messages in a buffer and displays them in a dedicated panel within the TUI.

**Architecture:**

```
┌─────────────────────────────────────────────────┐
│ tracing subscriber │
│ │ │
│ ▼ │
│ TuiLogLayer (implements Layer trait) │
│ │ │
│ ▼ │
│ Arc<Mutex<LogBuffer>> │
│ │ │
│ └────────────► LogPanel (view) │
│ │ │
│ ▼ │
│ TUI Rendering │
└─────────────────────────────────────────────────┘
```

**Components:**

1. **LogBuffer** (`log_buffer.rs`):
 - Thread-safe ring buffer with VecDeque storage
 - FIFO eviction when max capacity reached (default: 1000, max: 10000)
 - Configurable via `BSSH_TUI_LOG_MAX_ENTRIES` environment variable
 - `LogEntry` struct: level, target, message, timestamp

2. **TuiLogLayer** (`log_layer.rs`):
 - Implements `tracing_subscriber::Layer` trait
 - Captures tracing events and stores in shared LogBuffer
 - Minimal lock time: message extraction and entry creation outside lock
 - O(1) push operation inside lock to minimize contention

3. **LogPanel** (`views/log_panel.rs`):
 - Color-coded log display: ERROR (red), WARN (yellow), INFO (white), DEBUG (gray)
 - Scrollable with configurable height (3-10 lines)
 - Toggle visibility with `l` key
 - Timestamp display toggle with `t` key

**Thread Safety:**
- `Arc<Mutex<LogBuffer>>` shared between tracing layer and TUI thread
- Lock acquisition optimized for minimal contention:
 - LogLayer: only holds lock during O(1) push
 - LogPanel: clones entries quickly, renders outside lock

**State in TuiApp:**
```rust
pub log_buffer: Arc<Mutex<LogBuffer>>,
pub log_panel_visible: bool,
pub log_panel_height: u16, // 3-10 lines
pub log_scroll_offset: usize,
pub log_show_timestamps: bool,
```

#### 6. View Implementations (`views/`)

##### Summary View (`summary.rs`)

**Layout:**
```
┌─────────────────────────────────────────────────┐
│ Cluster: production - uptime │
│ Total: 5 • ✓ 3 • ✗ 1 • 1 in progress │
├─────────────────────────────────────────────────┤
│ [1] ✓ node1.example.com │
│ Exit code: 0 | Completed │
│ [2] ⟳ node2.example.com │
│ Progress: [████████░░] 45% │
│ Status: Installing packages... │
│ [3] ✓ node3.example.com │
│ [4] ✗ node4.example.com │
│ Error: Connection timeout │
│ [5] ✓ node5.example.com │
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
│ Node 2/5: node2.example.com │
│ Status: Running | ⬆ Follow: ON | Scroll: 42 │
├─────────────────────────────────────────────────┤
│ Reading package lists... Done │
│ Building dependency tree │
│ Reading state information... Done │
│ The following NEW packages will be installed: │
│ nginx nginx-common nginx-core │
│ 0 upgraded, 3 newly installed, 0 to remove │
│ Need to get 1,234 kB of archives. │
│ After this operation, 4,567 kB will be used. │
│ Get:1 http://archive.ubuntu.com/ubuntu nginx... │
│ [████████░░░░] 45% [Working] │
│ │
│ ... (scrollable) ... │
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
│ Status: ✓ Completed │ Status: ⟳ Running │
├───────────────────────┼───────────────────────┤
│ Reading packages... │ Updating system... │
│ Done │ [████░░░░] 25% │
│ │ Installing updates... │
│ ... (last 20 lines) │ ... (last 20 lines) │
│ │ │
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
│ Exit: 0 │ Exit: 1 │
├───────────────────────┼───────────────────────┤
│ line 1: same │ line 1: same │
│ line 2: different A │ line 2: different B │
│ line 3: same │ line 3: same │
│ ... (scrollable) │ ... (scrollable) │
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
async fn run_event_loop {
 loop {
 // 1. Poll all node streams for new output (non-blocking)
 manager.poll_all;

 // 2. Check if data changed
 let data_changed = app.check_data_changes(streams);

 // 3. Render UI if needed (data changed or user input)
 if app.should_redraw || data_changed {
 terminal.draw(|f| render_ui(f, app, manager))?;
 }

 // 4. Handle keyboard input (100ms timeout)
 if let Some(key) = poll_event(Duration::from_millis(100))? {
 handle_key_event(app, key, num_nodes);
 app.mark_needs_redraw;
 }

 // 5. Check completion and exit conditions
 if manager.all_complete {
 app.mark_all_tasks_completed;
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
 stdout_buffer: RollingBuffer, // Max 10MB
 stderr_buffer: RollingBuffer, // Max 10MB
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
fn should_use_tui -> bool {
 // 1. Must be in interactive terminal
 if !io::stdout.is_terminal {
 return false;
 }

 // 2. CI/CD detection (skip TUI in automation)
 if env::var("CI").is_ok {
 return false;
 }

 // 3. Multi-node execution required
 if num_nodes < 2 {
 return false;
 }

 // 4. Not explicitly disabled by user flags
 if args.stream || args.output_dir.is_some {
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
 UserQuit, // User pressed 'q' or Ctrl+C
 AllTasksCompleted, // All commands finished
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


---

**Related Documentation:**
- [Main Architecture](../../ARCHITECTURE.md)
- [CLI Interface](./cli-interface.md)
- [SSH Client](./ssh-client.md)
- [Executor Architecture](./executor.md)

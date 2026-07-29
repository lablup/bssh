# Interactive Mode and PTY Implementation

[← Back to Main Architecture](../../ARCHITECTURE.md)

## Interactive Mode Architecture

### Status: Fully Implemented, Refactored

**Module Structure :**
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

1. **PTY Session (`pty/session/*`, Refactored, Enhanced)**
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

### Terminal Escape Sequence Filtering

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
- PTY teardown disables bracketed paste, mouse tracking, Kitty keyboard progressive enhancements, and xterm `modifyOtherKeys` on both the current and main screens before returning control to the local shell

### Manual Enhanced-Keyboard Teardown Test

Run this check in Ghostty and at least one other Kitty-keyboard-compatible terminal such as Kitty or WezTerm:

1. Start an interactive session with `bssh user@host`.
2. At the remote shell, run `printf '\033[>15u'; exit` to leave all supported Kitty keyboard enhancements enabled while the PTY exits.
3. At the restored local prompt, verify that Space, Enter, arrow keys, and modified keys behave normally and do not print CSI-u fragments such as `;1:3u`, `:1C`, or `:3C`.
4. Repeat with a Kitty-keyboard-aware full-screen application on the remote host and terminate the SSH transport before the application exits cleanly.

Before starting the PTY input task, bssh uses a DA-delimited query transaction of at most 100 ms per screen to capture the Kitty enhancement flags independently for the main and alternate screens, together with the global xterm `modifyOtherKeys` value and the screen initially selected according to DEC private mode 1049. It uses DEC mode 47 to inspect the hidden buffer without the clear/initialize behavior of mode 1049, sets both screens to the legacy keyboard baseline without popping the outer application's Kitty stacks, and returns to the original screen before remote input starts. Only strict replies before the first primary DA in each transaction are consumed; post-DA bytes and user input, malformed replies, or unrelated escape sequences are retained in byte order and forwarded to the remote session. A failed hidden-screen write or flush makes a best-effort mode-47 return before capture falls back.

Teardown resets leaked stacks on both buffers and restores both captured Kitty values plus `modifyOtherKeys`. It also tracks fragmented remote `1049h`/`1049l` transitions. If bssh began on main and the connection dies in a remote-owned 1049 alternate screen, cleanup uses `1049l` to restore the remote-saved cursor before restoring both screens' keyboard state. The reverse correction is intentionally non-destructive: if bssh began inside an outer alternate screen and the remote reset 1049, cleanup selects the original buffer with mode 47 instead of forcing `1049h`. Generic terminal protocols expose only one cursor-save slot, and `1049h` clears the alternate buffer, so the 1049 mode bit, saved cursor, and existing outer contents cannot all be reconstructed exactly in that case. Keyboard state and screen contents take priority over claiming an impossible exact mode-bit restoration.

If a DA transaction or the screen-state query is unsupported, malformed, or times out, cleanup falls back to the ordinary-shell baseline from #234 rather than claiming partial preservation. The cleanup snapshot is published with poison recovery and reused by normal, forced, and repeated cleanup paths. A single-owner RAII token covers raw and deferred-raw guards alike so they cannot race the process-global snapshot, while a deferred guard that never enters raw mode performs no terminal cleanup when dropped.

To validate outer-TUI preservation in Ghostty and Kitty or WezTerm:

1. Start a Kitty-keyboard-aware TUI that can launch a child command while remaining in its alternate screen, and record its active enhancement flags with `printf '\033[?u'`.
2. Launch `bssh` from that TUI, enable different remote flags with `printf '\033[=31u'`, and exit normally.
3. Verify the outer TUI receives the same keyboard encoding it used before launching bssh and that its alternate-screen contents were not cleared by an unnecessary `1049l`/`1049h` round trip.
4. Repeat after abrupt transport loss and local `~.`. From an ordinary main-screen shell, disconnect after remote `printf '\033[?1049h'` and verify bssh safely returns with `1049l`; from an outer alternate-screen TUI, use remote `printf '\033[?1049l'` and verify cleanup returns with mode 47 without clearing the outer buffer.

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


---

**Related Documentation:**
- [Main Architecture](../../ARCHITECTURE.md)
- [CLI Interface](./cli-interface.md)
- [SSH Client](./ssh-client.md)
- [Executor Architecture](./executor.md)

# Parallel Executor Architecture

[← Back to Main Architecture](../../ARCHITECTURE.md)

## Table of Contents
- [Module Structure](#module-structure)
- [Design Decisions](#design-decisions)
- [Concurrency Model](#concurrency-model)
- [Performance Optimizations](#performance-optimizations)
- [Signal Handling](#signal-handling)
- [Fail-Fast Mode](#fail-fast-mode)

## Module Structure

The parallel executor is organized into focused modules:

- `executor/parallel.rs` - ParallelExecutor core logic (412 lines)
- `executor/execution_strategy.rs` - Task spawning and progress bars (257 lines)
- `executor/connection_manager.rs` - SSH connection setup (168 lines)
- `executor/result_types.rs` - Result types (119 lines)
- `executor/mod.rs` - Public API exports (25 lines)

## Design Decisions

- Tokio-based async execution for maximum concurrency
- Semaphore-based concurrency limiting to prevent resource exhaustion
- Progress bar visualization using `indicatif`
- Streaming output collection for real-time feedback

## Concurrency Model

The executor uses a semaphore-based concurrency model to limit parallel execution:

```rust
let semaphore = Arc::new(Semaphore::new(max_parallel));
let tasks: Vec<JoinHandle<Result<ExecutionResult>>> = nodes
 .into_iter
 .map(|node| {
 let permit = semaphore.clone.acquire_owned;
 tokio::spawn(async move {
 let _permit = permit.await;
 execute_on_node(node, command).await
 })
 })
 .collect;
```

This approach ensures:
- Limited number of concurrent SSH connections
- Efficient resource utilization
- Prevention of connection exhaustion
- Configurable parallelism via CLI flags

## Performance Optimizations

- **Connection reuse within same node** (planned)
- **Buffered I/O for output collection** - Reduces syscall overhead
- **Early termination on critical failures** - Stops execution when failures occur

## Signal Handling

The executor supports two modes for handling Ctrl+C (SIGINT) signals during parallel execution.

### Default Mode (Two-Stage)

1. **First Ctrl+C**: Displays status (running/completed job counts)
2. **Second Ctrl+C** (within 1 second): Terminates all jobs immediately with exit code 130
3. **Time window reset**: If >1 second passes, next Ctrl+C restarts the sequence and shows status again
4. Provides users visibility into execution progress before termination

### Batch Mode (`--batch` / `-b`)

- **Single Ctrl+C**: Immediately terminates all jobs with exit code 130
- Optimized for non-interactive environments (CI/CD, scripts)
- Compatible with pdsh `-b` option for tool compatibility

### Exit Code Handling

- **Normal completion**: Exit code determined by ExitCodeStrategy (MainRank/RequireAllSuccess/etc.)
- **Signal termination (Ctrl+C)**: Always exits with code 130 (standard SIGINT exit code)
- This ensures scripts can detect user interruption vs. command failure

### Implementation Coverage

Signal handling is implemented in both execution modes:
- `execute` method (normal/progress bar mode) - lines 172-280
- `handle_stream_mode` method (stream mode) - lines 714-838
- TUI mode has its own quit handling (q or Ctrl+C) and ignores the batch flag

Implementation is in `executor/parallel.rs` using `tokio::select!` to handle signals alongside normal execution:

```rust
loop {
 tokio::select! {
 _ = signal::ctrl_c => {
 if self.batch {
 // Batch mode: terminate immediately
 eprintln!("\nReceived Ctrl+C (batch mode). Terminating all jobs...");
 for handle in pending_handles.drain(..) {
 handle.abort;
 }
 // Exit with SIGINT exit code (130)
 std::process::exit(130);
 } else {
 // Two-stage mode: first shows status, second terminates
 if !first_ctrl_c {
 first_ctrl_c = true;
 ctrl_c_time = Some(std::time::Instant::now);
 eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

 // Show status
 let running_count = pending_handles.len;
 let completed_count = self.nodes.len - running_count;
 eprintln!("Status: {} running, {} completed", running_count, completed_count);
 } else {
 // Second Ctrl+C: check time window
 if let Some(first_time) = ctrl_c_time {
 if first_time.elapsed <= Duration::from_secs(1) {
 // Within time window: terminate
 eprintln!("Received second Ctrl+C. Terminating all jobs...");
 for handle in pending_handles.drain(..) {
 handle.abort;
 }
 // Exit with SIGINT exit code (130)
 std::process::exit(130);
 } else {
 // Time window expired: reset and show status again
 first_ctrl_c = true;
 ctrl_c_time = Some(std::time::Instant::now);
 eprintln!("\nReceived Ctrl+C. Press Ctrl+C again within 1 second to terminate.");

 // Show current status
 let running_count = pending_handles.len;
 let completed_count = self.nodes.len - running_count;
 eprintln!("Status: {} running, {} completed", running_count, completed_count);
 }
 }
 }
 }
 }
 // Wait for all tasks to complete
 results = join_all(pending_handles.iter_mut) => {
 return self.collect_results(results);
 }
 }

 // Small sleep to avoid busy waiting
 tokio::time::sleep(Duration::from_millis(50)).await;
}
```

The batch flag is passed through the executor chain:
- CLI `--batch` flag → `ExecuteCommandParams.batch` → `ParallelExecutor.batch`
- Applied in both normal mode (`execute`) and stream mode (`handle_stream_mode`)
- TUI mode maintains its own quit handling and ignores this flag

## Fail-Fast Mode

The `--fail-fast` / `-k` option enables immediate termination when any node fails. This is compatible with pdsh's `-k` flag and useful for:
- Critical operations where partial execution is unacceptable
- Deployment scripts where all nodes must succeed
- Validation checks across clusters

### Implementation

Implementation uses cancellation signaling via `tokio::sync::watch`:

```rust
// Cancellation signaling via tokio::sync::watch
let (cancel_tx, cancel_rx) = watch::channel(false);

// Task selection with cancellation check
tokio::select! {
 biased; // Prioritize cancellation check
 _ = cancel_rx.changed => {
 // Task cancelled due to fail-fast
 return Err(anyhow!("Execution cancelled due to fail-fast"));
 }
 permit = semaphore.acquire => {
 // Execute task normally
 }
}
```

### Integration with Other Flags

The fail-fast mode integrates with:
- `--require-all-success`: Both require all nodes to succeed, but fail-fast stops early
- `--check-all-nodes`: Fail-fast stops early, check-all-nodes affects final exit code
- `--parallel N`: Cancels pending tasks waiting in the semaphore queue

---

**Related Documentation:**
- [CLI Interface](./cli-interface.md)
- [SSH Client](./ssh-client.md)
- [Exit Code Strategy](./exit-code-strategy.md)
- [Main Architecture](../../ARCHITECTURE.md)

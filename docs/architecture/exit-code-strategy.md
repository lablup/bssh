# Exit Code Strategy Architecture

[← Back to Main Architecture](../../ARCHITECTURE.md)

## Table of Contents
- [Overview](#overview)
- [Design Rationale](#design-rationale)
- [Main Rank Detection](#main-rank-detection)
- [Exit Code Strategies](#exit-code-strategies)
- [Strategy Comparison](#strategy-comparison)
- [Implementation Details](#implementation-details)
- [Migration Guide](#migration-guide)

## Overview

The exit code strategy system determines how bssh reports success or failure when executing commands across multiple nodes.

**Breaking Change**: The default exit code behavior matches standard MPI tools (mpirun, srun, mpiexec). This improves compatibility with distributed computing workflows and enables better error diagnostics.

**Old Behavior**:
- Returns exit code 0 only if **all nodes** succeeded
- Returns exit code 1 if **any node** failed (discarding actual exit codes)

**New Behavior**:
- Returns the **main rank's exit code** by default (matching MPI standard)
- Preserves actual exit codes (139=SIGSEGV, 137=OOM, 124=timeout, etc.)
- Use `--require-all-success` flag for old behavior

## Design Rationale

### Why MainRank is Default

1. **MPI Standard Compliance**: All standard MPI tools (mpirun, srun, mpiexec) return rank 0's exit code
2. **Better Diagnostics**: Actual exit codes preserved for debugging (segfault, OOM, timeout)
3. **CI/CD Integration**: Exit-code-based decisions work naturally
4. **Information Preservation**: No loss of error details
5. **Industry Practice**: Aligns with HPC and distributed computing conventions

### Use Case Alignment

- **90% of use cases**: MPI workloads, distributed computing, CI/CD
- **10% of use cases**: Health checks, monitoring (use `--require-all-success`)

## Main Rank Detection

The system identifies the "main rank" (rank 0) using hierarchical fallback:

```rust
pub fn identify_main_rank(nodes: &[Node]) -> Option<usize> {
 // 1. Check Backend.AI CLUSTER_ROLE environment variable
 if env::var("BACKENDAI_CLUSTER_ROLE").ok == Some("main".to_string) {
 // Try to match by hostname
 if let Ok(host) = env::var("BACKENDAI_CLUSTER_HOST") {
 if let Some(idx) = nodes.iter.position(|n| n.host == host) {
 return Some(idx);
 }
 }
 }

 // 2. Fallback: First node is main rank (standard convention)
 if !nodes.is_empty {
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

## Exit Code Strategies

Three strategies are available to handle different scenarios:

### 1. MainRank (Default)

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
 0) echo "Success!"; deploy_results ;;
 139) echo "Segfault!"; collect_core_dump ;;
 137) echo "OOM!"; retry_with_more_memory ;;
 124) echo "Timeout!"; extend_time_limit ;;
 *) echo "Failed: $EXIT_CODE"; exit $EXIT_CODE ;;
esac
```

**Implementation**:
```rust
ExitCodeStrategy::MainRank => {
 main_idx
 .and_then(|i| results.get(i))
 .map(|r| r.get_exit_code)
 .unwrap_or(1) // No main rank identified → failure
}
```

### 2. RequireAllSuccess

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
 if results.iter.any(|r| !r.is_success) {
 1
 } else {
 0
 }
}
```

### 3. MainRankWithFailureCheck (Hybrid Mode)

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
 .map(|r| r.get_exit_code)
 .unwrap_or(0);

 let other_failed = results.iter
 .enumerate
 .any(|(i, r)| Some(i) != main_idx && !r.is_success);

 if main_code != 0 {
 main_code // Main failed → return its code
 } else if other_failed {
 1 // Main OK but others failed → 1
 } else {
 0 // All OK
 }
}
```

## Strategy Comparison

| Scenario | Main Exit | Other Exits | MainRank | RequireAllSuccess | MainRankWithFailureCheck |
|----------|-----------|-------------|----------|-------------------|--------------------------|
| All success | 0 | 0,0,0 | 0 | 0 | 0 |
| Main failed | 139 (SIGSEGV) | 0,0,0 | **139** | 1 | **139** |
| Other failed | 0 | 1,0,0 | **0** | 1 | **1** |
| All failed | 1 | 1,1,1 | 1 | 1 | 1 |
| Main timeout | 124 | 0,0,0 | **124** | 1 | **124** |
| Main OOM | 137 | 0,0,0 | **137** | 1 | **137** |

**Bold** values show where strategies differ.

## Implementation Details

### File Structure

```
src/executor/
├── rank_detector.rs # Main rank identification
├── exit_strategy.rs # Exit code calculation strategies
├── result_types.rs # ExecutionResult with is_main_rank field
├── mod.rs # Re-exports RankDetector and ExitCodeStrategy
└── parallel.rs # Marks main rank in results

src/commands/
└── exec.rs # Applies exit strategy based on CLI flags

src/
└── cli.rs # CLI flags: --require-all-success, --check-all-nodes
```

### ExecutionResult Enhancement

```rust
pub struct ExecutionResult {
 pub node: Node,
 pub result: Result<CommandResult>,
 pub is_main_rank: bool,
}

impl ExecutionResult {
 pub fn get_exit_code(&self) -> i32 {
 match &self.result {
 Ok(cmd_result) => cmd_result.exit_status as i32,
 Err(_) => 1, // Connection error → exit code 1
 }
 }
}
```

### Executor Integration

The `ParallelExecutor` automatically marks the main rank:

```rust
fn collect_results(&self, results: Vec<...>) -> Result<Vec<ExecutionResult>> {
 let mut execution_results = Vec::new;
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

### Command Integration

The `exec` command determines strategy from CLI flags:

```rust
let strategy = if params.require_all_success {
 ExitCodeStrategy::RequireAllSuccess
} else if params.check_all_nodes {
 ExitCodeStrategy::MainRankWithFailureCheck
} else {
 ExitCodeStrategy::MainRank // Default
};

let main_idx = RankDetector::identify_main_rank(&nodes);
let exit_code = strategy.calculate(&results, main_idx);

if exit_code != 0 {
 std::process::exit(exit_code);
}
```

## Migration Guide

### For MPI Workloads (No Changes Needed)

```bash
# Before: Exit code discarded
bssh exec "mpirun ./program"
# Returns: 1 (just "failed", no details)

# After: Exit code preserved
bssh exec "mpirun ./program"
# Returns: 139 (SIGSEGV - immediate diagnosis!)

# ✅ No changes needed - behavior improved
```

### For Health Checks (Add Flag)

```bash
# Before: Implicit all-must-succeed
bssh exec "health-check"

# After: Add --require-all-success flag
bssh --require-all-success exec "health-check"

# ⚠️ Action required: Add flag to preserve behavior
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

---

**Related Documentation:**
- [Executor Architecture](./executor.md)
- [CLI Interface](./cli-interface.md)
- [Main Architecture](../../ARCHITECTURE.md)

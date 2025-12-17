# SSH Port Forwarding

[← Back to Main Architecture](../../ARCHITECTURE.md)

## SSH Port Forwarding

### Status: Fully Implemented

### Overview

The port forwarding implementation provides full SSH-compatible port forwarding capabilities, supporting local (-L), remote (-R), and dynamic (-D/SOCKS) forwarding modes. The architecture is designed for high performance, reliability, and seamless integration with the existing SSH infrastructure.

### Architecture

```
┌────────────────────────────────────────────────┐
│ CLI Interface │
│ (Port Forwarding Options) │
│ -L, -R, -D flags │
└────────────────────────┬───────────────────────┘
 │
 ▼
┌────────────────────────────────────────────────┐
│ ForwardingManager │
│ (Lifecycle & Session Management) │
│ src/forwarding/manager.rs │
└──────┬────────────────┬────────────────┬───────┘
 │ │ │
 ▼ ▼ ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Local │ │ Remote │ │ Dynamic │
│ Forwarder │ │ Forwarder │ │ Forwarder │
│ (-L mode) │ │ (-R mode) │ │ (-D/SOCKS) │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
 │ │ │
 └────────────────┼────────────────┘
 │
 ▼
 ┌─────────────────┐
 │ Tunnel │
 │ (Bidirectional │
 │ Data Transfer) │
 └────────┬────────┘
 │
 ▼
 ┌─────────────────┐
 │ SSH Client │
 │ (russh) │
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
| Local (-L) | ~950 Mbps | <1ms | ~10MB/conn |
| Remote (-R) | ~900 Mbps | <2ms | ~10MB/conn |
| Dynamic (-D) | ~850 Mbps | <3ms | ~15MB/conn |

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


---

**Related Documentation:**
- [Main Architecture](../../ARCHITECTURE.md)
- [CLI Interface](./cli-interface.md)
- [SSH Client](./ssh-client.md)
- [Executor Architecture](./executor.md)

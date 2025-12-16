# Changelog

All notable changes to bssh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.2] - 2025-12-16

### Fixed
- **PTY Session Terminal Handling** (PR #90)
  - Fixed terminal escape sequence responses displayed on first prompt when starting tmux
  - Improved terminal compatibility with multiplexers
- **PTY Session Paste** (PR #89)
  - Fixed paste not working in PTY sessions
  - Improved clipboard/paste functionality in interactive terminal sessions

### Changed
- **Dependencies**
  - Bumped dependencies to latest versions for security and compatibility

## [1.4.1] - 2025-12-16

### Added
- **Comprehensive Test Suite** (Issue #82, PR #86)
  - tests/tui_snapshot_tests.rs: 20 tests for TUI rendering using ratatui's TestBackend
  - tests/tui_event_tests.rs: 36 tests for keyboard navigation, scroll behavior, and view transitions
  - tests/streaming_integration_tests.rs: 28 tests for NodeStream, MultiNodeStreamManager, and streaming execution
  - benches/large_output_benchmark.rs: Performance benchmarks for large output handling
  - Total: 84 new tests added

### Fixed
- **SSH Agent Password Fallback** (Issue #84, PR #85)
  - Extended password fallback to handle all SSH agent authentication failures
  - Now correctly triggers for: AgentAuthenticationFailed, AgentNoIdentities, AgentConnectionFailed, AgentRequestIdentitiesFailed
  - Added `is_auth_error_for_password_fallback()` helper function for testability
  - Added unit tests and integration tests for all error types

### Documentation
- **TUI Module Documentation** (Issue #81, PR #83)
  - Added comprehensive TUI architecture section to ARCHITECTURE.md
  - Enhanced README.md with keyboard shortcuts reference table
  - Added view modes description table
  - Added TUI activation conditions and requirements
  - Added missing "1-9: Jump to node N" shortcut in detail view help text

### Dependencies
- Added insta 1.34 (snapshot testing)
- Added criterion 0.5 (benchmarking)
- Added mockall 0.12 (mocking for integration tests)

### Technical Details
- Refactored test code quality: removed unused functions, replaced panic! with matches! macro
- Added Unicode test cases (Korean, Chinese, Emoji)
- Improved assertion messages for better debugging

## [1.4.0] - 2025-12-15

### Added
- **Sudo Password Support** (Issue #74, PR #78)
  - `-S/--sudo-password` flag for automated sudo authentication
  - Securely prompts for sudo password before command execution
  - Automatically detects and responds to sudo password prompts
  - Works with both streaming and non-streaming execution modes
  - `BSSH_SUDO_PASSWORD` environment variable support (with security warnings)
  - Uses `secrecy` crate for secure memory handling
  - Password cleared from memory immediately after use
- **Developer Tooling**
  - Added githooks for development workflow
  - Setup script for githooks configuration

### Fixed
- **Password Fallback** (PR #80)
  - Improved SSH debugging for better compatibility
  - Enhanced password authentication fallback logic
- Fixed clippy warnings for useless_vec and same_item_push

## [1.3.0] - 2025-12-10

### Added
- **Interactive TUI (Terminal User Interface)** (Phase 3 of #68)
  - Summary view: All nodes at a glance with progress bars
  - Detail view (1-9): Full output from specific node with scrolling
  - Split view (s): Monitor 2-4 nodes simultaneously
  - Diff view (d): Compare output from two nodes side-by-side
  - Auto-scroll (f): Toggle automatic scrolling
  - Navigation: Arrow keys, PgUp/PgDn, Home/End
  - Help (?): Show keyboard shortcuts
  - Press `q` to quit
- **Multi-node Stream Management** (Phase 2 of #68)
  - Real-time output modes for multi-node operations
  - Stream mode with [node] prefixes for real-time monitoring
  - Enhanced streaming infrastructure for real-time updates

### Fixed
- **PTY Escape Sequence Filtering** (PR #77)
  - Filter terminal escape sequence responses in PTY sessions
  - Fixed issue with terminal response codes appearing in output

### Technical Details
- Implemented ratatui-based TUI rendering
- Added multi-node output aggregation and display
- Performance optimizations for real-time output streaming

## [1.2.2] - 2025-10-29

### Fixed
- **Backend.AI Auto-detection** (PR #66)
  - Improved host heuristics for Backend.AI environments
  - Added localhost and localhost.localdomain detection
  - Added IPv4 address validation (127.0.0.1, 192.168.x.x, etc.)
  - Enhanced detection for user@host, host:port, FQDN, IPv6 patterns
  - Users can now use `bssh localhost "command"` naturally in Backend.AI

### Technical Details
- Extracted testable `looks_like_host_specification()` function
- Added `is_ipv4_address()` helper with strict validation
- Performance optimized with early returns
- 16 comprehensive tests added for host detection logic

## [1.2.1] - 2025-10-28

### Fixed
- **Password Authentication Fallback in Interactive Mode** (PR #65)
  - Re-implemented password authentication fallback logic for interactive mode
  - Fixed issue where password prompt was not appearing after key-based authentication failed
  - Ensured proper authentication flow in interactive sessions
- **Test Race Condition** (commit d2e8ce9)
  - Added `#[serial]` attribute to tests calling `RankDetector` to prevent environment variable race conditions
  - Tests now run sequentially when accessing shared environment state
  - Prevents intermittent test failures due to concurrent environment variable access

## [1.2.0] - 2025-10-27

### BREAKING CHANGES
- **Exit code behavior changed** (Issue #62)
  - **Old behavior (v1.0-v1.1)**: Returns 0 only if all nodes succeeded, 1 if any failed
  - **New behavior (v1.2.0+)**: Returns main rank's actual exit code (matches MPI standard: mpirun, srun, mpiexec)
  - **Impact**: Users relying on "all nodes must succeed" semantics must add `--require-all-success` flag
  - **Benefit**: Preserves actual exit codes (139=SIGSEGV, 137=OOM, 124=timeout) for better diagnostics
  - **MPI users**: No changes needed - behavior improved and matches standard tools
  - **Health checks**: Add `--require-all-success` flag to preserve old behavior

### Added
- **Exit Code Strategy** (Issue #62)
  - Main rank exit code returned by default (matches MPI standard: mpirun, srun, mpiexec)
  - Preserves actual exit codes: 139 (SIGSEGV), 137 (OOM), 124 (timeout), etc.
  - `--require-all-success` flag for v1.0-v1.1 behavior (returns 0 only if all nodes succeed)
  - `--check-all-nodes` flag for hybrid mode (main rank code + all-node check)
  - Automatic main rank detection via `BACKENDAI_CLUSTER_ROLE` environment variable
  - Example scripts: `examples/mpi_exit_code.sh`, `examples/health_check.sh`

### Changed
- Exit code behavior now aligns with HPC and distributed computing best practices
- Enables sophisticated error handling in shell scripts and CI/CD pipelines

## [1.1.0] - 2025-10-24

### Added
- **macOS Keychain Integration** (Issue #59, PR #61)
  - Automatic passphrase storage in macOS Keychain after successful SSH key authentication
  - Automatic passphrase retrieval before prompting user
  - Secure memory handling with `Zeroizing` for all sensitive data
  - Integration with SSH config `UseKeychain` option per host
  - New module `src/ssh/keychain_macos.rs` with complete Keychain API wrapper
- **ProxyUseFdpass SSH Option** (Issue #58, PR #60)
  - Added `ProxyUseFdpass` SSH configuration option support
  - Optimizes ProxyCommand usage by passing connected file descriptors back to ssh
  - Reduces overhead from lingering processes and extra read/write operations
- **Password Authentication Fallback**
  - Automatic password retry when publickey authentication fails
  - Matches OpenSSH standard behavior for seamless user experience
  - Interactive terminal detection with TTY checks
  - Works for both exec and interactive modes

### Security
- **SSH Key File Ownership Validation** (PR #61)
  - Prevents storing passphrases for SSH keys owned by other users
  - Added macOS user ID checks using libc
  - World-readable SSH key permission warnings
- **User Consent for Password Fallback** (PR #61)
  - Explicit user consent prompt before attempting password authentication
  - 30-second timeout for consent prompt
  - Prevents unexpected password prompts that could lead to credential exposure
- **Rate Limiting** (PR #61)
  - 100ms delay before initial connection attempts
  - 1 second delay before password fallback
  - Prevents brute-force attacks and fail2ban triggers

### Improved
- **Code Quality** (PR #61)
  - Eliminated 251 lines of code duplication in connection logic
  - Created `establish_connection()` helper function
  - Centralized authentication logic in auth module
  - 60% reduction in connection.rs complexity
- **Cross-Platform Support**
  - All macOS-specific code properly isolated with `#[cfg(target_os = "macos")]`
  - Conditional imports to prevent unused code warnings on non-macOS platforms
  - Stub functions for API consistency across platforms

### Fixed
- Fixed clippy warnings on non-macOS platforms (unused_mut, unused_imports, dead_code)
  - Variable shadowing for macOS-specific code paths
  - Conditional imports for platform-specific functions
- Fixed interactive mode missing `use_keychain` field causing authentication failures
- Fixed password prompt not appearing when connecting to new servers in interactive mode

### Dependencies
- Added `security-framework = "2.12.1"` for macOS Keychain API integration
- Added `libc` for macOS user ID checks (conditional on macOS)

## [1.0.0] - 2025-10-24

### Added
- **SSH Configuration: Certificate Authentication Options**
  - `CertificateFile` - Specify SSH certificate files for PKI authentication (maximum 100 certificates)
  - `CASignatureAlgorithms` - Define CA signature algorithms for certificate validation (maximum 50 algorithms)
  - `HostbasedAuthentication` - Enable/disable host-based authentication
  - `HostbasedAcceptedAlgorithms` - Specify accepted algorithms for host-based authentication (maximum 50 algorithms)

- **SSH Configuration: Advanced Port Forwarding Control**
  - `GatewayPorts` - Control remote port forwarding access (yes/no/clientspecified)
  - `ExitOnForwardFailure` - Terminate connection when port forwarding fails
  - `PermitRemoteOpen` - Specify allowed destinations for remote TCP port forwarding (maximum 1000 entries)

- **SSH Configuration: Command Execution and Automation Options**
  - `PermitLocalCommand` - Allow execution of local commands after successful SSH connection (yes/no, default: no)
  - `LocalCommand` - Execute local command after connection with token substitution support (%h, %H, %n, %p, %r, %u, %%)
  - `RemoteCommand` - Execute command on remote host instead of starting interactive shell
  - `KnownHostsCommand` - Execute command to obtain host keys dynamically (supports token substitution)
  - `ForkAfterAuthentication` - Fork SSH process to background after successful authentication (yes/no)
  - `SessionType` - Specify session type: none (port forwarding only), subsystem (e.g., SFTP), or default (shell)
  - `StdinNull` - Redirect stdin from /dev/null for background operations and scripting (yes/no)

- **SSH Configuration: Host Key Verification & Security Options**
  - `NoHostAuthenticationForLocalhost` - Skip host key verification for localhost connections (convenient for local development, default: no)
  - `HashKnownHosts` - Hash hostnames in known_hosts file to prevent hostname disclosure if compromised (default: no)
  - `CheckHostIP` - Check host IP address in known_hosts for DNS spoofing detection (deprecated in OpenSSH 8.5+, retained for legacy compatibility)
  - `VisualHostKey` - Display ASCII art of host key fingerprint for visual verification (default: no)
  - `HostKeyAlias` - Specify alias for host key lookup in known_hosts (useful for load-balanced services with shared keys)
  - `VerifyHostKeyDNS` - Verify host keys using DNS SSHFP records (yes/no/ask, default: no)
  - `UpdateHostKeys` - Accept updated host keys from server automatically (yes/no/ask, default: no)

- **SSH Configuration: Additional Authentication Options**
  - `NumberOfPasswordPrompts` - Control password authentication retry attempts (valid range: 1-10, default: 3)
  - `EnableSSHKeysign` - Enable ssh-keysign for host-based authentication (yes/no, default: no)

- **SSH Configuration: Network & Connection Options**
  - `BindInterface` - Bind SSH connection to specific network interface (alternative to BindAddress for multi-homed hosts)
  - `IPQoS` - Set IP type-of-service/DSCP values for interactive and bulk traffic (e.g., "lowdelay throughput")
  - `RekeyLimit` - Control SSH session key renegotiation frequency (format: "data [time]", e.g., "1G 1h")

- **SSH Configuration: X11 Forwarding Options**
  - `ForwardX11Timeout` - Set timeout for untrusted X11 forwarding connections (time interval, default: 0 = no timeout)
  - `ForwardX11Trusted` - Enable trusted X11 forwarding with full display access (yes/no, default: no)

- **Security Enhancements**
  - Path validation to prevent usage of sensitive system files (e.g., /etc/passwd, /etc/shadow)
  - Memory exhaustion prevention with entry limits for certificates and forwarding rules
  - Algorithm list validation with maximum entry limits
  - Deduplication for certificate files and remote forwarding destinations
  - Command injection prevention for LocalCommand and KnownHostsCommand
  - Token validation to prevent invalid substitution patterns
  - Dangerous character detection in command strings (semicolons, backticks, pipes, etc.)

### Changed
- **SSH Config Parser**: Refactored into modular structure for better maintainability
  - Split oversized parser.rs (1706 lines) into category-based modules (~200-350 lines each)
  - Organized option parsing by categories: authentication, security, forwarding, connection, etc.
  - Improved code organization and maintainability

### Technical Details
- Enhanced SSH configuration merging logic with proper priority handling
- Support for both "Option Value" and "Option=Value" syntax
- Scalar options override in later blocks, vector options accumulate with deduplication
- **SSH Configuration Coverage**: ~71 options (~69% of OpenSSH's 103 options)
  - Basic options + Include + Match directives (structural)
  - Certificate authentication and port forwarding (7 options)
  - Command execution and automation (7 options)
  - Host key verification, authentication, network, and X11 options (15 options)
- Comprehensive test coverage: 278 tests including parser, resolver, integration, and security tests
- Validation: NumberOfPasswordPrompts range checking (1-10), CheckHostIP deprecation warnings

## [0.9.1] - 2025-10-14

### Added
None

### Changed
- **PTY Terminal Modes**: Complete implementation of PTY terminal modes for better interactive session support
- **Shift Key Input Support**: Full Shift key input handling in PTY mode for proper terminal behavior

### Fixed
- Terminal mode implementation for PTY sessions
- Shift key input handling in interactive mode

### Technical Details
- Enhanced terminal mode settings for PTY allocation
- Implemented proper terminal flag handling for interactive sessions
- Improved keyboard input processing for special keys

## [0.9.0] - 2025-10-14

### Added
- **Configurable Jump Host Limit**: Maximum number of jump hosts can now be configured via environment variable
  - `BSSH_MAX_JUMP_HOSTS` environment variable for dynamic limit configuration
  - Default: 10 jump hosts, Absolute maximum: 30 (security cap)
  - Invalid/zero values fall back to default with warning logs
  - Example: `BSSH_MAX_JUMP_HOSTS=20 bssh -J host1,...,host20 target`
  - Prevents resource exhaustion attacks while allowing flexible configurations

- **Jump Host File Transfer Support**: Added complete file transfer operations through SSH jump hosts
  - `upload_file_with_jump_hosts()` - Upload single files through jump host chains
  - `download_file_with_jump_hosts()` - Download single files through jump hosts
  - `upload_dir_with_jump_hosts()` - Upload directories recursively through jump hosts
  - `download_dir_with_jump_hosts()` - Download directories through jump hosts
  - All file transfer operations now fully support multi-hop SSH connections

- **Jump Host Interactive Mode Support**: Interactive shell sessions now work through jump hosts
  - Added `jump_hosts` field to `InteractiveCommand` structure
  - Dynamic timeout calculation based on hop count (30s base + 15s per hop)
  - Prevents premature timeouts on multi-hop connections
  - Full authentication support (SSH keys, agent, password) for each hop

- **Parallel Executor Integration**: Jump host support across all parallel operations
  - Updated `executor.rs` to propagate jump_hosts to all node operations
  - Maintains backward compatibility with `Option<&str>` type
  - All `*_to_node()` functions now accept `jump_hosts` parameter

### Changed
- **Interactive Mode**: Now includes jump host support with automatic timeout adjustment
  - Connection timeout scales with hop count for reliability
  - Example timeouts: Direct (30s), 1 hop (45s), 2 hops (60s), 3 hops (75s)

- **Test Coverage**: Updated all test files to include jump_hosts parameter
  - `tests/interactive_test.rs`: Added `jump_hosts: None` to test cases
  - `tests/interactive_integration_test.rs`: Updated all 9 test instances
  - `examples/interactive_demo.rs`: Updated example with jump_hosts field

- **Dependencies**: Updated various dependencies for security patches and stability

### Fixed
- Interactive mode timeout issues when connecting through jump hosts
- File transfer operations not working with jump host chains

### Security
- Added `serial_test` dependency for thread-safe environment variable testing
- Comprehensive test coverage for environment variable functionality (6 new tests)

### Technical Details
- **Files Modified**: 8 files
- **Lines Added**: +623
- **Lines Removed**: -26
- **Net Change**: +597 lines
- **Test Results**: All 132 tests passing

## [0.8.0] - 2025-09-12

### Added
- Comprehensive SSH port forwarding support
  - Local port forwarding (`-L`) for tunneling to remote services
  - Remote port forwarding (`-R`) for exposing local services
  - Dynamic port forwarding (`-D`) for SOCKS4/5 proxy functionality
- Improved error messages with better context and recovery suggestions

### Changed
- Removed dangerous `unwrap()` calls throughout codebase
- Enhanced error handling with detailed failure reasons

## [0.7.0] - 2025-08-30

### Added
- SSH jump host infrastructure (`-J` option)
  - OpenSSH ProxyJump format parsing
  - Multiple jump hosts support (comma-separated)
  - IPv6 address handling with bracket notation
  - Jump host chain management and connection establishment

### Changed
- Improved Ubuntu PPA support with better packaging
- Fixed deprecated GitHub Actions workflows

## [0.6.1] - 2025-08-28

### Changed
- Rebranded from "Backend.AI SSH" to "Broadcast SSH"
  - Emphasizes core broadcast/parallel functionality
  - Better reflects the tool's primary purpose

## [0.6.0] - 2025-08-28

### Added
- SSH configuration file support (`-F` option)
  - Auto-loads from `~/.ssh/config` by default
  - Supports 40+ SSH directives
  - Wildcard pattern matching and negation
  - Environment variable expansion in paths
- PTY allocation for interactive sessions (`-t`/`-T` options)
- SSH configuration caching for improved performance
  - LRU cache with configurable size and TTL
  - File modification detection
  - 10-100x faster repeated operations

### Changed
- Enhanced security with improved host key verification
- Performance improvements across core operations
- SSH-compatible command-line interface (drop-in replacement)

## [0.5.4] - 2025-08-27

### Fixed
- Parallel configuration value handling issues
- Interactive mode authentication alignment with exec mode

## [0.5.3] - 2025-08-27

### Changed
- Backend.AI cluster auto-detection now uses cluster SSH key configuration

## [0.5.2] - 2025-08-27

### Fixed
- Configuration file loading priority issues
- Backend.AI environment variable handling improvements

### Changed
- Now uses cluster SSH key configuration when available

## [0.5.1] - 2025-08-25

### Added
- Configurable command timeout support
  - Set timeout via `--timeout` flag or configuration file
  - Support for unlimited execution time (`timeout=0`)
  - Default timeout: 300 seconds (5 minutes)

## [0.5.0] - 2025-08-22

### Added
- Interactive mode with PTY support
  - Single-node mode for focused interaction
  - Multiplex mode for parallel command execution
  - Node switching commands (`!node1`, `!node2`, etc.)
  - Broadcast command (`!broadcast <cmd>`)
  - Visual status indicators (● active, ○ inactive)
  - Command history with rustyline
  - Configurable prompts and settings

### Changed
- Improved Backend.AI cluster auto-detection
- Enhanced interactive shell capabilities

## [0.4.0] - 2025-08-22

### Added
- Password authentication support (`-P` flag)
- SSH key passphrase support with secure prompting
- Modern UI with semantic colors and Unicode symbols
- Debian package distribution (`.deb`)

### Changed
- XDG Base Directory specification compliance
- Improved configuration management
- Enhanced visual feedback and progress indicators

## [0.3.0] - 2025-08-22

### Added
- Native SFTP directory operations
- Recursive file transfer support
  - Upload directories with `-r` flag
  - Download entire directory trees
  - Glob pattern support for batch operations

## [0.2.0] - 2025-08-21

### Added
- Backend.AI multi-node session support
  - Automatic cluster detection from environment variables
  - Default SSH port 2200 for Backend.AI clusters
- SSH authentication enhancements
  - SSH agent authentication with auto-detection
  - Host key verification with known_hosts support
  - Multiple authentication method fallback
- Environment variable expansion in configuration files
- Connection and command timeout configuration
- SFTP file transfer (upload/download)
  - SCP-compatible file copy functionality
  - Progress tracking for file operations

### Changed
- Improved error messages and diagnostics
- Enhanced security with host key verification

## [0.1.0] - 2025-08-21

### Added
- Initial release of bssh
- Parallel SSH command execution across multiple nodes
- Cluster configuration management via YAML files
- Node specification via CLI (`-H` flag)
- SSH key-based authentication
- Real-time progress tracking with progress bars
- Per-node output collection and aggregation
- Configurable parallel execution limits
- Connectivity testing (`ping` command)
- Cluster listing (`list` command)

### Features
- Built with Rust for performance and safety
- Async/await pattern for maximum concurrency
- Tokio runtime for efficient I/O operations
- russh library for native SSH implementation
- Cross-platform support (Linux and macOS)

[1.4.2]: https://github.com/lablup/bssh/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/lablup/bssh/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/lablup/bssh/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/lablup/bssh/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/lablup/bssh/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/lablup/bssh/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/lablup/bssh/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/lablup/bssh/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lablup/bssh/compare/v0.9.1...v1.0.0
[0.9.1]: https://github.com/lablup/bssh/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/lablup/bssh/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/lablup/bssh/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/lablup/bssh/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/lablup/bssh/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/lablup/bssh/compare/v0.5.4...v0.6.0
[0.5.4]: https://github.com/lablup/bssh/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/lablup/bssh/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/lablup/bssh/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/lablup/bssh/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/lablup/bssh/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/lablup/bssh/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/lablup/bssh/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lablup/bssh/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lablup/bssh/releases/tag/v0.1.0

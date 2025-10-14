# Changelog

All notable changes to bssh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2025-10-14

### Added
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

### Fixed
- Interactive mode timeout issues when connecting through jump hosts
- File transfer operations not working with jump host chains

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

[Unreleased]: https://github.com/lablup/bssh/compare/v0.9.0...HEAD
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

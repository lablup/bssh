# Migrating from pdsh to bssh

This guide helps users transition from pdsh to bssh while maintaining existing workflows and scripts.

## Table of Contents

- [Why Migrate to bssh?](#why-migrate-to-bssh)
- [Compatibility Overview](#compatibility-overview)
- [Installation](#installation)
- [Enabling pdsh Compatibility Mode](#enabling-pdsh-compatibility-mode)
- [Command Migration](#command-migration)
- [Feature Comparison](#feature-comparison)
- [Known Differences](#known-differences)
- [Migration Checklist](#migration-checklist)
- [Troubleshooting](#troubleshooting)

## Why Migrate to bssh?

bssh provides several advantages over pdsh:

- **Modern Architecture**: Built with Rust for memory safety and performance
- **Enhanced Features**: Interactive TUI, real-time progress tracking, SSH agent support
- **Active Development**: Regular updates and security patches
- **Cross-Platform**: Native support for Linux and macOS
- **Full pdsh Compatibility**: Drop-in replacement with compatibility mode
- **Better Error Handling**: Detailed error messages and graceful failure handling

## Compatibility Overview

bssh provides **three ways** to run in pdsh compatibility mode:

1. **Symlink** (recommended for full compatibility)
2. **Environment variable**
3. **CLI flag**

All three methods enable the same pdsh-compatible behavior, mapping pdsh options to their bssh equivalents automatically.

## Installation

### Homebrew (macOS/Linux)

```bash
# Install bssh via Homebrew
brew tap lablup/tap
brew install bssh

# Create pdsh symlink (done automatically by Homebrew)
# The symlink is created at: /usr/local/bin/pdsh -> /usr/local/bin/bssh
```

### Ubuntu PPA

```bash
# Add the PPA and install
sudo add-apt-repository ppa:lablup/backend-ai
sudo apt update
sudo apt install bssh

# Create pdsh symlink manually
sudo ln -sf $(which bssh) /usr/local/bin/pdsh
```

### Debian Package

```bash
# Download and install .deb package
wget https://github.com/lablup/bssh/releases/download/vVERSION/bssh_VERSION_OS_ARCH.deb
sudo dpkg -i bssh_VERSION_OS_ARCH.deb

# Create pdsh symlink
sudo ln -sf $(which bssh) /usr/local/bin/pdsh
```

### From Source

```bash
# Build from source
cargo build --release
sudo cp target/release/bssh /usr/local/bin/

# Create pdsh symlink
sudo ln -s /usr/local/bin/bssh /usr/local/bin/pdsh
```

### Verify Installation

```bash
# Check that pdsh points to bssh
which pdsh
# Output: /usr/local/bin/pdsh

ls -l $(which pdsh)
# Output: /usr/local/bin/pdsh -> /usr/local/bin/bssh

# Verify version
pdsh --version
# Output: bssh X.Y.Z (in pdsh compatibility mode)
```

## Enabling pdsh Compatibility Mode

### Method 1: Symlink (Recommended)

Create a symlink named `pdsh` pointing to `bssh`. This is the most transparent method and requires no script modifications.

```bash
# System-wide installation
sudo ln -sf $(which bssh) /usr/local/bin/pdsh

# User installation (in $HOME/bin or similar)
ln -sf $(which bssh) ~/bin/pdsh
```

With the symlink in place, all your existing pdsh commands work unchanged:

```bash
pdsh -w host1,host2,host3 "uptime"
# Automatically runs in pdsh compatibility mode
```

### Method 2: Environment Variable

Set `BSSH_PDSH_COMPAT=1` to enable pdsh mode without a symlink:

```bash
# For a single command
BSSH_PDSH_COMPAT=1 bssh -w host1,host2 "uptime"

# Export for the entire session
export BSSH_PDSH_COMPAT=1
bssh -w host1,host2 "uptime"

# Add to shell configuration for permanent enablement
echo 'export BSSH_PDSH_COMPAT=1' >> ~/.bashrc
```

### Method 3: CLI Flag

Use the `--pdsh-compat` flag explicitly:

```bash
bssh --pdsh-compat -w host1,host2 "uptime"
```

### Method 4: Shell Alias

For users who prefer aliases over symlinks:

```bash
# Bash/Zsh
echo 'alias pdsh="bssh --pdsh-compat"' >> ~/.bashrc
# or
echo 'alias pdsh="bssh --pdsh-compat"' >> ~/.zshrc

# Fish
echo 'alias pdsh="bssh --pdsh-compat"' >> ~/.config/fish/config.fish

# Reload shell configuration
source ~/.bashrc  # or ~/.zshrc
```

## Command Migration

### Basic Command Execution

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w host1,host2 "cmd"` | Same | Works unchanged with symlink |
| `pdsh -w host[1-5] "cmd"` | Same | Hostlist expressions supported |
| `pdsh -w ^/etc/hosts.list "cmd"` | Same | File input supported |

### Fanout Control

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w hosts -f 10 "cmd"` | Same | `-f` maps to `--parallel` |
| `pdsh -w hosts -f 1 "cmd"` | Same | Sequential execution |

### Host Exclusion

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w host[1-10] -x host5 "cmd"` | Same | Direct mapping |
| `pdsh -w hosts -x "bad*" "cmd"` | Same | Glob patterns supported |

### User Specification

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w hosts -l admin "cmd"` | Same | `-l` works identically |
| `pdsh -w user@host "cmd"` | Same | User@host syntax supported |

### Timeouts

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w hosts -t 30 "cmd"` | Same | Connect timeout (seconds) |
| `pdsh -w hosts -u 600 "cmd"` | Same | Command timeout (seconds) |

### Output Control

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w hosts -N "cmd"` | Same | Disable hostname prefix |
| `pdsh -w hosts "cmd" \| dshbak` | Use `--stream` or TUI | bssh has built-in formatting |

### Query Mode

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w hosts -q` | Same | Show target hosts and exit |
| `pdsh -w hosts -x "bad*" -q` | Same | Query with exclusions |

### Batch Mode

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w hosts -b "cmd"` | Same | Single Ctrl+C terminates |

### Fail-Fast Mode

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w hosts -k "cmd"` | Same | Stop on first failure |

### Exit Code Handling

| pdsh Command | bssh Equivalent | Notes |
|--------------|-----------------|-------|
| `pdsh -w hosts -S "cmd"` | Same | Return largest exit code |

## Feature Comparison

### Features Available in Both

| Feature | pdsh | bssh | Notes |
|---------|------|------|-------|
| Basic command execution | ✅ | ✅ | Identical behavior |
| Hostlist expressions | ✅ | ✅ | `host[1-5]`, `rack[1-2]-node[1-3]` |
| Host exclusion | ✅ | ✅ | `-x` with glob patterns |
| Fanout control | ✅ | ✅ | `-f` for parallel connections |
| User specification | ✅ | ✅ | `-l user` option |
| Timeouts | ✅ | ✅ | Connect and command timeouts |
| Query mode | ✅ | ✅ | `-q` to list hosts |
| Batch mode | ✅ | ✅ | `-b` for single Ctrl+C |
| Fail-fast mode | ✅ | ✅ | `-k` to stop on failure |
| No prefix output | ✅ | ✅ | `-N` flag |

### bssh-Exclusive Features

| Feature | Description |
|---------|-------------|
| **Interactive TUI** | Real-time multi-node monitoring with Summary/Detail/Split/Diff views |
| **Progress Tracking** | Automatic detection of progress indicators (%, fractions, apt/dpkg) |
| **SSH Agent Support** | Native SSH agent authentication |
| **Jump Hosts** | ProxyJump support for bastion hosts |
| **Port Forwarding** | Local, remote, and dynamic (SOCKS) forwarding |
| **Configuration Files** | YAML-based cluster configuration |
| **Modern Output Modes** | TUI, stream, file, and normal modes with auto-detection |
| **Exit Code Strategies** | Multiple strategies for handling node failures |
| **Sudo Password Injection** | Automatic sudo password handling |
| **Backend.AI Integration** | Auto-detection of Backend.AI multi-node sessions |

### pdsh Features Not in bssh

| Feature | Alternative in bssh |
|---------|---------------------|
| RCMD modules (rsh, ssh, mrsh) | bssh uses SSH only (more secure) |
| GENDERS integration | Use YAML config files |
| dshbak output collation | Use `--stream` mode or built-in TUI |
| SLURM/TORQUE integration | Use host lists or config files |

## Known Differences

### 1. Default Fanout

- **pdsh**: Default fanout is 32
- **bssh**: Default parallel is 10 (native mode), 32 (pdsh mode)

**Migration**: When using pdsh compatibility mode, bssh automatically uses fanout=32 to match pdsh behavior.

### 2. Output Formatting

- **pdsh**: Plain text with optional dshbak post-processing
- **bssh**: Advanced TUI with real-time updates (when running in terminal)

**Migration**:
- Use `--stream` flag for pdsh-like plain output
- Use `-N` for no hostname prefix (matches pdsh behavior)
- Pipe to file/command to disable TUI auto-detection

```bash
# Plain output like pdsh
pdsh -w hosts --stream "cmd"

# Or disable TUI by piping
pdsh -w hosts "cmd" | cat
```

### 3. RCMD Modules

- **pdsh**: Supports multiple RCMD modules (ssh, rsh, mrsh, qsh)
- **bssh**: SSH only (more secure, widely available)

**Migration**: Ensure all target hosts support SSH. bssh will not work with rsh-based hosts.

### 4. Exit Code Behavior

- **pdsh**: Returns 0 on success, 1 if any host fails
- **bssh**: Returns main rank exit code by default (v1.2.0+), supports multiple strategies

**Migration**:
- Add `--require-all-success` flag for pdsh-like behavior
- Or use `-S` (equivalent to `--any-failure`) to return largest exit code

```bash
# pdsh-style behavior (fail if any host fails)
pdsh -w hosts --require-all-success "cmd"

# Return largest exit code from any host
pdsh -w hosts -S "cmd"
```

### 5. Cluster Configuration

- **pdsh**: Uses GENDERS, SLURM, or flat files
- **bssh**: Uses YAML configuration files

**Migration**: Convert cluster definitions to YAML format:

```yaml
# ~/.config/bssh/config.yaml
clusters:
  production:
    nodes:
      - web1.example.com
      - web2.example.com
      - web3.example.com
    user: admin
    ssh_key: ~/.ssh/prod_key
```

Then use with `-C` flag:

```bash
# Using config file
bssh -C production "uptime"

# Still works with -w
pdsh -w web[1-3].example.com "uptime"
```

## Migration Checklist

### Pre-Migration

- [ ] Identify all scripts and tools using pdsh
- [ ] Test bssh with pdsh compatibility mode on non-production hosts
- [ ] Verify all target hosts support SSH (not rsh/mrsh)
- [ ] Check for GENDERS/SLURM integration (migrate to YAML config)
- [ ] Review custom pdsh wrappers and automation

### Installation

- [ ] Install bssh via preferred method (Homebrew, apt, cargo)
- [ ] Create pdsh symlink (`ln -sf $(which bssh) /usr/local/bin/pdsh`)
- [ ] Verify symlink: `which pdsh` should point to bssh
- [ ] Test basic command: `pdsh -w localhost "echo test"`

### Configuration Migration

- [ ] Convert GENDERS files to bssh YAML format
- [ ] Migrate cluster definitions to `~/.config/bssh/config.yaml`
- [ ] Test cluster access: `bssh -C <cluster> "uptime"`
- [ ] Configure SSH keys and authentication methods
- [ ] Set up any required environment variables

### Script Migration

- [ ] Audit all scripts for pdsh usage
- [ ] Test scripts with pdsh symlink (should work unchanged)
- [ ] Update scripts using dshbak to use `--stream` or TUI
- [ ] Add `--require-all-success` flag where needed
- [ ] Update documentation and comments

### Testing

- [ ] Test basic command execution across all clusters
- [ ] Verify fanout/parallel behavior
- [ ] Test host exclusion patterns
- [ ] Validate timeout behavior
- [ ] Check query mode functionality
- [ ] Test error handling and exit codes
- [ ] Verify batch mode and fail-fast behavior

### Post-Migration

- [ ] Monitor for any edge cases or unexpected behavior
- [ ] Update team documentation and runbooks
- [ ] Train team members on bssh-specific features (TUI, config files)
- [ ] Consider removing old pdsh installations
- [ ] Document any bssh-specific optimizations

## Troubleshooting

### pdsh symlink not working

**Problem**: Running `pdsh` doesn't invoke bssh

**Solution**:
```bash
# Check if symlink exists and is correct
ls -l $(which pdsh)

# Recreate symlink
sudo ln -sf $(which bssh) /usr/local/bin/pdsh

# Ensure /usr/local/bin is in PATH
echo $PATH | grep -o '/usr/local/bin'
```

### pdsh options not recognized

**Problem**: `pdsh: error: unrecognized option: -w`

**Solution**: Ensure pdsh compatibility mode is active:
```bash
# Check if running in compatibility mode
pdsh --version
# Should show: "bssh X.Y.Z (pdsh compatibility mode)" or similar

# Manually enable compatibility mode
BSSH_PDSH_COMPAT=1 bssh -w hosts "cmd"
```

### Different output format

**Problem**: Output looks different from pdsh

**Solution**:
```bash
# Use stream mode for plain output
pdsh -w hosts --stream "cmd"

# Disable hostname prefix
pdsh -w hosts -N "cmd"

# Pipe to disable TUI
pdsh -w hosts "cmd" | cat
```

### Hostlist expressions not working

**Problem**: `host[1-5]` not expanding properly

**Solution**: Ensure compatibility mode is enabled and check syntax:
```bash
# Query mode to verify expansion
pdsh -w "host[1-5]" -q

# Should output:
# host1
# host2
# host3
# host4
# host5
```

### Exit code behavior differs

**Problem**: Exit codes don't match pdsh expectations

**Solution**:
```bash
# Add --require-all-success for pdsh-like behavior
pdsh -w hosts --require-all-success "cmd"

# Or use -S to return largest exit code
pdsh -w hosts -S "cmd"
```

### Authentication issues

**Problem**: SSH authentication fails

**Solution**:
```bash
# Enable SSH agent
pdsh -A -w hosts "cmd"

# Use specific SSH key
pdsh -i ~/.ssh/key -w hosts "cmd"

# Enable verbose logging
pdsh -vv -w hosts "cmd"
```

### Performance differences

**Problem**: bssh seems slower than pdsh

**Solution**:
```bash
# Increase parallel connections
pdsh -w hosts -f 50 "cmd"

# Use stream mode instead of TUI
pdsh -w hosts --stream "cmd"

# Check connection timeout
pdsh -w hosts -t 10 "cmd"
```

### File input not working

**Problem**: `pdsh -w ^/path/to/hosts` doesn't work

**Solution**: This feature may not be supported in the same way. Use:
```bash
# Alternative: Read hosts and pass directly
HOSTS=$(cat /path/to/hosts | tr '\n' ',' | sed 's/,$//')
pdsh -w "$HOSTS" "cmd"

# Or use bssh config file
bssh -C cluster-name "cmd"
```

## Getting Help

### Resources

- **Documentation**: https://github.com/lablup/bssh/blob/main/README.md
- **Issue Tracker**: https://github.com/lablup/bssh/issues
- **Architecture Guide**: https://github.com/lablup/bssh/blob/main/ARCHITECTURE.md
- **Option Mapping**: See [pdsh-options.md](pdsh-options.md)
- **Examples**: See [pdsh-examples.md](pdsh-examples.md)

### Community Support

- Open an issue on GitHub for bugs or feature requests
- Check existing issues for known problems and workarounds
- Contribute improvements via pull requests

### Reporting Issues

When reporting issues, please include:

1. **bssh version**: `bssh --version`
2. **Compatibility mode status**: How pdsh mode was enabled (symlink/env/flag)
3. **Command that failed**: Full command line
4. **Expected vs actual behavior**
5. **Error messages**: Include full error output
6. **Environment**: OS, shell, SSH version

Example bug report:
```
**Version**: bssh 1.4.0
**Mode**: pdsh symlink (/usr/local/bin/pdsh -> /usr/local/bin/bssh)
**Command**: pdsh -w host[1-3] -f 10 "uptime"
**Expected**: Output from 3 hosts
**Actual**: Error: "failed to parse hostlist expression"
**Error**: <paste full error>
**Environment**: Ubuntu 22.04, bash 5.1.16, OpenSSH 8.9p1
```

---

**Note**: This migration guide is maintained as part of the bssh project. For the latest version, see https://github.com/lablup/bssh/blob/main/docs/pdsh-migration.md

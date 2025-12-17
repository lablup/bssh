# pdsh Options Mapping Reference

Complete reference for mapping pdsh command-line options to bssh equivalents.

## Table of Contents

- [Quick Reference Table](#quick-reference-table)
- [Host Selection Options](#host-selection-options)
- [Execution Control Options](#execution-control-options)
- [Timeout Options](#timeout-options)
- [Output Control Options](#output-control-options)
- [Authentication Options](#authentication-options)
- [Query and Information Options](#query-and-information-options)
- [Exit Code Options](#exit-code-options)
- [Options Not Supported](#options-not-supported)
- [bssh-Specific Extensions](#bssh-specific-extensions)

## Quick Reference Table

| pdsh Option | bssh Equivalent | Compatibility Mode | Notes |
|-------------|-----------------|-------------------|-------|
| `-w <hosts>` | `-H <hosts>` | `-w <hosts>` | Target host specification |
| `-x <hosts>` | `--exclude <hosts>` | `-x <hosts>` | Exclude hosts from target list |
| `-f <N>` | `--parallel <N>` | `-f <N>` | Fanout / parallel connections |
| `-l <user>` | `-l <user>` | `-l <user>` | Remote username |
| `-t <N>` | `--connect-timeout <N>` | `-t <N>` | Connection timeout (seconds) |
| `-u <N>` | `--timeout <N>` | `-u <N>` | Command timeout (seconds) |
| `-N` | `--no-prefix` | `-N` | Disable hostname prefix |
| `-b` | `--batch` | `-b` | Batch mode (immediate Ctrl+C) |
| `-k` | `--fail-fast` | `-k` | Stop on first failure |
| `-q` | (query mode) | `-q` | Show hosts and exit |
| `-S` | `--any-failure` | `-S` | Return largest exit code |

**Note**: "Compatibility Mode" shows the option syntax when running `bssh --pdsh-compat` or when invoked as `pdsh` via symlink.

## Host Selection Options

### `-w <hosts>` (--hosts)

**pdsh**: Specifies target hosts

**bssh Native**: `-H <hosts>` or `--hosts <hosts>`

**pdsh Compat**: `-w <hosts>`

**Syntax**:
```bash
# Simple comma-separated list
pdsh -w host1,host2,host3 "command"

# Hostlist range expressions
pdsh -w host[1-5] "command"             # host1, host2, host3, host4, host5
pdsh -w node[01-10] "command"           # Zero-padded: node01..node10
pdsh -w rack[1-2]-node[1-3] "command"   # Cartesian product: 6 hosts

# User@host syntax
pdsh -w user1@host1,user2@host2 "command"

# With port specification
pdsh -w host1:2222,host2:2222 "command"

# File input (if supported)
pdsh -w ^/path/to/hostfile "command"
```

**Examples**:
```bash
# Single host
pdsh -w webserver "uptime"

# Multiple hosts
pdsh -w web1,web2,db1,db2 "df -h"

# Range expansion
pdsh -w compute[01-20] "nvidia-smi"

# Complex expression
pdsh -w cluster[1-3]-node[01-08] "hostname"
# Expands to: cluster1-node01, cluster1-node02, ..., cluster3-node08
```

### `-x <hosts>` (--exclude)

**pdsh**: Exclude hosts from the target list

**bssh Native**: `--exclude <hosts>`

**pdsh Compat**: `-x <hosts>`

**Syntax**:
```bash
# Exclude specific hosts
pdsh -w host[1-10] -x host5,host7 "command"

# Exclude with wildcards (glob patterns)
pdsh -w host[1-10] -x "host[3-5]" "command"
pdsh -w web1,web2,db1,db2 -x "db*" "command"

# Exclude with range expressions
pdsh -w node[1-100] -x "node[50-75]" "command"
```

**Examples**:
```bash
# Exclude maintenance hosts
pdsh -w prod[1-20] -x prod15,prod16 "systemctl status nginx"

# Exclude all database servers
pdsh -w web1,web2,web3,db1,db2,db3 -x "db*" "uptime"

# Exclude a range
pdsh -w compute[001-100] -x "compute[080-100]" "check-gpu.sh"
```

### `-g <group>` (--group) [Not Supported]

**pdsh**: Select host group from GENDERS file

**bssh Alternative**: Use cluster configuration in `~/.config/bssh/config.yaml`

**Migration**:
```bash
# pdsh with GENDERS
pdsh -g webservers "command"

# bssh equivalent
bssh -C webservers "command"
```

**Config file** (`~/.config/bssh/config.yaml`):
```yaml
clusters:
  webservers:
    nodes:
      - web1.example.com
      - web2.example.com
      - web3.example.com
```

## Execution Control Options

### `-f <N>` (--fanout)

**pdsh**: Set fanout (maximum parallel connections)

**bssh Native**: `--parallel <N>`

**pdsh Compat**: `-f <N>`

**Default**:
- pdsh: 32
- bssh native: 10
- bssh pdsh mode: 32

**Syntax**:
```bash
# Limit to 10 concurrent connections
pdsh -w host[1-100] -f 10 "command"

# No limit (maximum parallelism)
pdsh -w hosts -f 0 "command"

# Sequential execution (one at a time)
pdsh -w hosts -f 1 "command"
```

**Examples**:
```bash
# Conservative fanout for heavy operations
pdsh -w nodes -f 5 "apt upgrade -y"

# High fanout for quick checks
pdsh -w servers -f 50 "uptime"

# Sequential for ordered operations
pdsh -w backup[1-3] -f 1 "rsync-backup.sh"
```

**Performance Notes**:
- Higher fanout = faster completion, but more load on local system
- Lower fanout = slower completion, but gentler resource usage
- Optimal fanout depends on: network bandwidth, target load, command type

### `-b` (--batch)

**pdsh**: Batch mode - single Ctrl+C terminates all jobs

**bssh Native**: `--batch`

**pdsh Compat**: `-b`

**Behavior**:
- **Without `-b`**: First Ctrl+C shows status, second Ctrl+C terminates (default)
- **With `-b`**: Single Ctrl+C immediately terminates all jobs

**Syntax**:
```bash
# Batch mode for scripts
pdsh -w hosts -b "long-running-command"
```

**Examples**:
```bash
# In CI/CD pipelines
pdsh -w servers -b "deploy-script.sh"

# For automation where immediate termination is needed
pdsh -w nodes -b --timeout 600 "backup-operation"
```

### `-k` (--fail-fast)

**pdsh**: Stop execution on first failure

**bssh Native**: `--fail-fast`

**pdsh Compat**: `-k`

**Behavior**:
- Cancels remaining commands if any host fails
- Useful for critical operations that require all hosts to succeed

**Syntax**:
```bash
# Stop if any host fails
pdsh -w hosts -k "critical-deployment.sh"
```

**Examples**:
```bash
# Critical security update
pdsh -w production -k "apply-security-patch.sh"

# Database schema migration (must succeed on all)
pdsh -w db-cluster -k "migrate-schema.sql"

# Combined with --require-all-success
pdsh -w hosts -k --require-all-success "health-check.sh"
```

## Timeout Options

### `-t <seconds>` (--connect-timeout)

**pdsh**: SSH connection timeout

**bssh Native**: `--connect-timeout <seconds>`

**pdsh Compat**: `-t <seconds>`

**Default**: 30 seconds (both pdsh and bssh)

**Syntax**:
```bash
# Short timeout for fast failure detection
pdsh -w hosts -t 5 "command"

# Longer timeout for slow networks
pdsh -w remote-hosts -t 60 "command"
```

**Examples**:
```bash
# Quick connectivity test
pdsh -w datacenter[1-100] -t 3 "echo ok"

# Reliable connection over WAN
pdsh -w cloud-instances -t 90 "deploy.sh"
```

### `-u <seconds>` (--command-timeout)

**pdsh**: Command execution timeout

**bssh Native**: `--timeout <seconds>`

**pdsh Compat**: `-u <seconds>`

**Default**: 300 seconds (5 minutes)

**Syntax**:
```bash
# Short timeout for quick commands
pdsh -w hosts -u 10 "uptime"

# Long timeout for slow operations
pdsh -w hosts -u 3600 "backup-database.sh"

# No timeout (unlimited execution)
pdsh -w hosts -u 0 "indefinite-process"
```

**Examples**:
```bash
# Quick health check with short timeout
pdsh -w webservers -u 5 "curl -s http://localhost/health"

# Long-running backup operation
pdsh -w databases -u 7200 "pg_dump | gzip > backup.sql.gz"

# Continuous monitoring (no timeout)
pdsh -w monitors -u 0 "tail -f /var/log/app.log"
```

**Combined Timeout Example**:
```bash
# 10s to connect, 600s to run command
pdsh -w hosts -t 10 -u 600 "deploy-application.sh"
```

## Output Control Options

### `-N` (--no-prefix)

**pdsh**: Disable hostname prefix in output

**bssh Native**: `--no-prefix`

**pdsh Compat**: `-N`

**Behavior**:
- **Without `-N`**: `[hostname] output line`
- **With `-N`**: `output line` (no prefix)

**Syntax**:
```bash
# No hostname prefix
pdsh -w hosts -N "hostname"
```

**Examples**:
```bash
# Default behavior (with prefix)
pdsh -w web[1-2] "echo hello"
# Output:
# [web1] hello
# [web2] hello

# With -N flag (no prefix)
pdsh -w web[1-2] -N "echo hello"
# Output:
# hello
# hello

# Useful for parsing output
pdsh -w db-servers -N "SELECT COUNT(*) FROM users;" | awk '{sum+=$1} END {print sum}'
```

### `--stream` [bssh Extension]

**pdsh**: N/A (use dshbak for output processing)

**bssh Native**: `--stream`

**pdsh Compat**: `--stream`

**Behavior**:
- Forces stream mode (real-time output with prefixes)
- Disables TUI mode
- Useful when piping output

**Syntax**:
```bash
# Stream mode with prefixes
pdsh -w hosts --stream "tail -f /var/log/syslog"

# Stream mode without prefixes
pdsh -w hosts --stream -N "command"
```

**Examples**:
```bash
# Monitor logs in real-time
pdsh -w webservers --stream "tail -f /var/log/nginx/access.log"

# Pipe to grep
pdsh -w servers --stream "systemctl status nginx" | grep "active (running)"
```

### `--output-dir <dir>` [bssh Extension]

**pdsh**: N/A

**bssh Native**: `--output-dir <directory>`

**pdsh Compat**: `--output-dir <directory>`

**Behavior**:
- Saves each host's output to separate files
- Creates timestamped filenames

**Syntax**:
```bash
pdsh -w hosts --output-dir ./results "command"
```

**Examples**:
```bash
# Save diagnostic outputs
pdsh -w servers --output-dir ./diagnostics-$(date +%Y%m%d) "system-info.sh"

# Per-host logs
pdsh -w cluster --output-dir ./logs "journalctl -n 100"
```

**Output Structure**:
```
results/
├── host1_20250117_143022.stdout
├── host1_20250117_143022.stderr
├── host2_20250117_143022.stdout
└── summary_20250117_143022.txt
```

## Authentication Options

### `-l <user>` (--login)

**pdsh**: Specify remote username

**bssh Native**: `-l <user>` or `--user <user>`

**pdsh Compat**: `-l <user>`

**Syntax**:
```bash
# Specify username
pdsh -w hosts -l admin "command"

# Alternative: user@host syntax
pdsh -w admin@host1,admin@host2 "command"
```

**Examples**:
```bash
# Admin operations
pdsh -w production -l root "systemctl restart nginx"

# User-specific commands
pdsh -w devservers -l deploy "cd /app && git pull"
```

### `-i <identity_file>` [bssh Extension]

**pdsh**: N/A (uses SSH config)

**bssh Native**: `-i <path>` or `--identity <path>`

**pdsh Compat**: `-i <path>`

**Syntax**:
```bash
# Use specific SSH key
pdsh -w hosts -i ~/.ssh/production_key "command"
```

**Examples**:
```bash
# Production key
pdsh -w prod-servers -i ~/.ssh/prod_rsa "deploy.sh"

# Encrypted key (will prompt for passphrase)
pdsh -w servers -i ~/.ssh/encrypted_key "command"
```

### `-A` (--use-agent) [bssh Extension]

**pdsh**: N/A (auto-detects agent)

**bssh Native**: `-A` or `--use-agent`

**pdsh Compat**: `-A`

**Syntax**:
```bash
# Use SSH agent
pdsh -A -w hosts "command"
```

**Examples**:
```bash
# Force agent authentication
pdsh -A -w secure-hosts "sensitive-operation.sh"

# Combined with sudo
pdsh -A -S -w servers "sudo apt update"
```

### `-P` (--password) [bssh Extension]

**pdsh**: N/A

**bssh Native**: `-P` or `--password`

**pdsh Compat**: `-P`

**Behavior**: Prompts for SSH password (not recommended for scripts)

**Syntax**:
```bash
# Password authentication
pdsh -P -w hosts "command"
# Prompts: "Enter SSH password:"
```

### `-S` (--sudo-password) [bssh Extension]

**pdsh**: N/A

**bssh Native**: `-S` or `--sudo-password`

**pdsh Compat**: `-S`

**Behavior**: Prompts for sudo password and auto-injects it

**Syntax**:
```bash
# Sudo password injection
pdsh -S -w hosts "sudo apt update"
# Prompts: "Enter sudo password:"
```

**Examples**:
```bash
# System updates with sudo
pdsh -S -w servers "sudo systemctl restart nginx"

# Combined with SSH agent
pdsh -A -S -w hosts "sudo reboot"
```

## Query and Information Options

### `-q` (--query)

**pdsh**: Show target hosts and exit (do not execute command)

**bssh Native**: (query mode)

**pdsh Compat**: `-q`

**Behavior**:
- Lists all hosts that would be targeted
- Applies exclusions and filters
- Does not execute any commands

**Syntax**:
```bash
# Query mode
pdsh -w host[1-10] -q

# Query with exclusions
pdsh -w host[1-10] -x host[3-5] -q
```

**Examples**:
```bash
# Verify hostlist expansion
pdsh -w compute[01-20] -q
# Output:
# compute01
# compute02
# ...
# compute20

# Check exclusion pattern
pdsh -w web1,web2,db1,db2,cache1 -x "db*,cache*" -q
# Output:
# web1
# web2

# Verify final host list before execution
pdsh -w production[1-50] -x "production[10-15]" -q
```

**Use Cases**:
- Verify hostlist expressions expand correctly
- Check that exclusion patterns work as expected
- Audit target hosts before running destructive commands
- Debug host selection issues

### `-V` (--version)

**pdsh**: Show version information

**bssh Native**: `-V` or `--version`

**pdsh Compat**: `-V`

**Syntax**:
```bash
pdsh --version
```

**Example Output** (when running as pdsh):
```
bssh 1.4.2 (pdsh compatibility mode)
```

### `-h` (--help)

**pdsh**: Show help message

**bssh Native**: `-h` or `--help`

**pdsh Compat**: `-h`

**Syntax**:
```bash
pdsh --help
```

## Exit Code Options

### `-S` (--any-failure)

**pdsh**: Return exit status of any failing remote command

**bssh Native**: `--any-failure`

**pdsh Compat**: `-S`

**Behavior**:
- Returns the **largest** exit code from any host
- If all succeed (exit 0), returns 0
- If any fail, returns the highest failure code

**Syntax**:
```bash
pdsh -w hosts -S "command"
```

**Examples**:
```bash
# Capture worst failure
pdsh -w servers -S "health-check.sh"
# Exit codes: host1=0, host2=1, host3=2
# pdsh returns: 2

# Use in scripts
if pdsh -w cluster -S "verify.sh"; then
    echo "All hosts OK"
else
    echo "At least one host failed (exit code: $?)"
fi
```

### `--require-all-success` [bssh Extension]

**pdsh**: N/A (pdsh default behavior is similar)

**bssh Native**: `--require-all-success`

**pdsh Compat**: `--require-all-success`

**Behavior**:
- Returns 0 only if **all** hosts succeed
- Returns 1 if **any** host fails
- Similar to traditional pdsh behavior

**Syntax**:
```bash
pdsh -w hosts --require-all-success "command"
```

**Examples**:
```bash
# Health check requiring all to pass
pdsh -w production --require-all-success "health-check.sh"

# Combined with fail-fast
pdsh -w hosts -k --require-all-success "critical-operation.sh"
```

### `--check-all-nodes` [bssh Extension]

**pdsh**: N/A

**bssh Native**: `--check-all-nodes`

**pdsh Compat**: `--check-all-nodes`

**Behavior**:
- Returns main rank's exit code if main rank fails
- Returns 1 if main rank succeeds but others fail
- Useful for MPI-like workloads

**Syntax**:
```bash
pdsh -w hosts --check-all-nodes "mpirun ./simulation"
```

## Options Not Supported

The following pdsh options are **not supported** in bssh:

### RCMD Module Options

| Option | Description | Alternative |
|--------|-------------|-------------|
| `-R <module>` | Select RCMD module | bssh uses SSH only |
| `-M <module>,<module>,...` | Load specific modules | N/A |

**Reason**: bssh uses SSH exclusively for better security and wider compatibility.

### GENDERS Options

| Option | Description | Alternative |
|--------|-------------|-------------|
| `-g <group>` | Target host group | Use `-C <cluster>` with YAML config |
| `-a` | Target all hosts | Define "all" cluster in config |
| `-X <group>` | Exclude host group | Use `--exclude` with hostlist |

**Migration**: Convert GENDERS files to bssh YAML configuration.

### Output Module Options

| Option | Description | Alternative |
|--------|-------------|-------------|
| `-o <module>` | Select output module | Use `--stream` or built-in TUI |

**Reason**: bssh has advanced built-in output handling (TUI, stream mode, file output).

### Other Options

| Option | Description | Alternative |
|--------|-------------|-------------|
| `-d` | Enable debug output | Use `-v`, `-vv`, or `-vvv` |
| `-r <n>` | Retry on connection failure | Not supported |
| `-c` | Connect to all hosts first | Automatic in bssh |

## bssh-Specific Extensions

These options are available in bssh but not in pdsh:

### Advanced Features

| Option | Description | Example |
|--------|-------------|---------|
| `-J <hosts>` | Jump host (bastion) | `pdsh -J bastion -w internal-hosts "cmd"` |
| `-L <spec>` | Local port forwarding | `pdsh -L 8080:web:80 -w hosts "cmd"` |
| `-R <spec>` | Remote port forwarding | `pdsh -R 80:localhost:8080 -w hosts "cmd"` |
| `-D <spec>` | Dynamic forwarding (SOCKS) | `pdsh -D 1080 -w hosts "cmd"` |
| `-F <file>` | SSH config file | `pdsh -F ~/.ssh/custom_config -w hosts "cmd"` |
| `-C <cluster>` | Use cluster from config | `pdsh -C production "cmd"` |
| `--filter <pattern>` | Filter hosts by pattern | `pdsh -w hosts --filter "web*" "cmd"` |

### Verbosity Levels

| Option | Description |
|--------|-------------|
| `-v` | Verbose (INFO level) |
| `-vv` | More verbose (DEBUG level) |
| `-vvv` | Maximum verbosity (TRACE level) |

**Example**:
```bash
# Debug connection issues
pdsh -vv -w problematic-host "command"
```

### Modern Output Modes

| Option | Description |
|--------|-------------|
| `--stream` | Stream mode with real-time output |
| `--output-dir <dir>` | Save per-host output to files |
| `--no-prefix` | Disable hostname prefix (same as `-N`) |

### Exit Code Strategies

| Option | Description |
|--------|-------------|
| `--require-all-success` | Return 0 only if all hosts succeed |
| `--check-all-nodes` | Return main rank code, or 1 if others fail |
| `--any-failure` | Return largest exit code (same as `-S`) |

## Summary

### Full Option Compatibility Matrix

| Category | pdsh Options | bssh Support | Notes |
|----------|--------------|--------------|-------|
| **Host Selection** | `-w`, `-x`, `-g`, `-a`, `-X` | ✅ Partial | `-w`, `-x` supported; use config for groups |
| **Execution** | `-f`, `-b`, `-k` | ✅ Full | Direct mapping |
| **Timeouts** | `-t`, `-u` | ✅ Full | Direct mapping |
| **Output** | `-N`, `-o` | ✅ Partial | `-N` supported; use `--stream` instead of `-o` |
| **Authentication** | `-l` | ✅ Full | Plus additional `-i`, `-A`, `-P`, `-S` |
| **Query** | `-q` | ✅ Full | Direct mapping |
| **Exit Codes** | `-S` | ✅ Full | Plus additional strategies |
| **RCMD Modules** | `-R`, `-M` | ❌ None | SSH-only by design |
| **Debug** | `-d` | ✅ Partial | Use `-v`, `-vv`, `-vvv` |

### Recommended Reading

- [pdsh Migration Guide](pdsh-migration.md) - Complete migration instructions
- [pdsh Examples](pdsh-examples.md) - Real-world usage examples
- [bssh README](../README.md) - Full feature documentation

---

**Note**: This document is maintained as part of the bssh project. For the latest version, see https://github.com/lablup/bssh/blob/main/docs/pdsh-options.md

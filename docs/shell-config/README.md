# Shell Configuration for bssh

This directory contains shell configuration examples for bssh, including pdsh compatibility setup and useful shortcuts.

## Available Configurations

- **[bash.sh](bash.sh)** - Configuration for Bash shell
- **[zsh.sh](zsh.sh)** - Configuration for Zsh shell (with advanced features)
- **[fish.fish](fish.fish)** - Configuration for Fish shell (with abbreviations and interactive features)

## Quick Setup

### Bash

```bash
# Download and source the configuration
curl -o ~/.bssh-config.sh https://raw.githubusercontent.com/lablup/bssh/main/docs/shell-config/bash.sh
echo 'source ~/.bssh-config.sh' >> ~/.bashrc
source ~/.bashrc
```

Or manually add to `~/.bashrc`:

```bash
# bssh pdsh compatibility
alias pdsh='bssh --pdsh-compat'
```

### Zsh

```bash
# Download and source the configuration
curl -o ~/.bssh-config.zsh https://raw.githubusercontent.com/lablup/bssh/main/docs/shell-config/zsh.sh
echo 'source ~/.bssh-config.zsh' >> ~/.zshrc
source ~/.zshrc
```

Or manually add to `~/.zshrc`:

```bash
# bssh pdsh compatibility
alias pdsh='bssh --pdsh-compat'
```

### Fish

```bash
# Download and source the configuration
curl -o ~/.config/fish/conf.d/bssh.fish https://raw.githubusercontent.com/lablup/bssh/main/docs/shell-config/fish.fish

# Fish will automatically load it on next shell start
# Or reload manually:
source ~/.config/fish/conf.d/bssh.fish
```

Or manually add to `~/.config/fish/config.fish`:

```fish
# bssh pdsh compatibility
alias pdsh='bssh --pdsh-compat'
```

## Features

### All Shells

- **pdsh compatibility alias**: Makes `pdsh` command use bssh
- **Cluster shortcuts**: Quick access to common clusters
- **Helper functions**: Simplified command execution
- **Environment variables**: Default configuration paths

### Zsh-Specific

- **Cluster context**: Set and use current cluster context
- **Associative arrays**: Define cluster groups
- **Right prompt**: Show current cluster in prompt

### Fish-Specific

- **Abbreviations**: Auto-expanding shortcuts (e.g., `bsp` → `bssh-prod`)
- **Interactive selection**: Choose cluster interactively
- **Cluster info**: Quick cluster information display
- **Fish-native syntax**: Uses Fish's modern command syntax

## Common Helper Functions

All configurations include these helper functions:

### bssh-all

Execute command on all nodes in a cluster:

```bash
bssh-all production "uptime"
```

### bssh-hosts

Execute with hostlist expression:

```bash
bssh-hosts "web[1-5]" "nginx -t"
```

### bssh-health

Quick cluster health check:

```bash
bssh-health production
```

### pdsh-exec

Execute in pdsh compatibility mode:

```bash
pdsh-exec "node[1-10]" "df -h"
```

## Advanced Features

### Cluster Context (Zsh/Fish)

Set a cluster as current context:

```bash
# Set context
bssh-context production

# Execute commands in current context
bssh-ctx "uptime"
bssh-ctx "systemctl status nginx"
```

### Cluster Groups (Zsh/Fish)

Execute on multiple clusters at once:

```bash
# Zsh
bssh-group all "hostname"        # Run on all clusters
bssh-group nonprod "uptime"      # Run on non-production clusters

# Fish
bssh-group all "hostname"
bssh-group prod "df -h"
```

### Interactive Selection (Fish)

Choose cluster interactively:

```bash
# Select and execute
bssh-select "uptime"

# Select and set context
bssh-select
```

### Cluster Info (Fish)

Show cluster information:

```bash
bssh-info production
```

## Customization

### Adding Your Own Shortcuts

```bash
# Bash/Zsh
alias bssh-web='bssh -C webservers'
alias bssh-db='bssh -C databases'

# Fish
alias bssh-web='bssh -C webservers'
alias bssh-db='bssh -C databases'
# Or use abbreviations
abbr --add bsw 'bssh -C webservers'
```

### Custom Cluster Groups

```bash
# Zsh
BSSH_CLUSTER_GROUPS[critical]="production database-primary"
BSSH_CLUSTER_GROUPS[monitoring]="monitoring-prod monitoring-staging"

# Fish - modify bssh-group function in fish.fish
```

### Custom Health Checks

```bash
# Bash/Zsh
bssh-full-health() {
    bssh -C "$1" "
        echo '=== System Info ===' &&
        uname -a &&
        echo '=== Uptime ===' &&
        uptime &&
        echo '=== Memory ===' &&
        free -h &&
        echo '=== Disk ===' &&
        df -h /
    "
}

# Fish
function bssh-full-health
    bssh -C $argv[1] "
        echo '=== System Info ===' &&
        uname -a &&
        echo '=== Uptime ===' &&
        uptime &&
        echo '=== Memory ===' &&
        free -h &&
        echo '=== Disk ===' &&
        df -h /
    "
end
```

## Environment Variables

All configurations support these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `BSSH_CONFIG` | Configuration file path | `~/.config/bssh/config.yaml` |
| `BSSH_PDSH_COMPAT` | Enable pdsh mode globally | unset (disabled) |
| `BSSH_PARALLEL` | Default parallel connections | 10 |
| `BSSH_CONNECT_TIMEOUT` | Default connection timeout | 30 seconds |
| `BSSH_COMMAND_TIMEOUT` | Default command timeout | 300 seconds |

Set in your shell configuration:

```bash
# Bash/Zsh
export BSSH_PDSH_COMPAT=1
export BSSH_PARALLEL=20

# Fish
set -gx BSSH_PDSH_COMPAT 1
set -gx BSSH_PARALLEL 20
```

## Examples

### Daily Operations

```bash
# Check all production servers
bssh-prod "uptime"

# Update all staging servers
bssh-staging "sudo apt update && sudo apt upgrade -y"

# Restart service on web servers
bssh-hosts "web[1-10]" "sudo systemctl restart nginx"

# Health check
bssh-health production
```

### Using pdsh Compatibility

```bash
# All existing pdsh scripts work unchanged
pdsh -w node[1-5] "df -h"
pdsh -w servers -f 10 "uptime"
pdsh -w hosts -x badhost "systemctl status nginx"
```

### Cluster Context (Zsh/Fish)

```bash
# Set context
bssh-context production

# Execute multiple commands
bssh-ctx "systemctl status nginx"
bssh-ctx "df -h /"
bssh-ctx "free -h"

# Clear context
unset BSSH_CURRENT_CLUSTER    # Zsh
set -e BSSH_CURRENT_CLUSTER   # Fish
```

## Troubleshooting

### Alias Not Working

```bash
# Check if alias is defined
alias pdsh            # Should show: pdsh='bssh --pdsh-compat'

# Re-source configuration
source ~/.bashrc      # Bash
source ~/.zshrc       # Zsh
source ~/.config/fish/config.fish  # Fish
```

### Function Not Found

```bash
# Check if function exists
type bssh-all         # Should show function definition

# Re-source configuration file
```

### Environment Variables Not Set

```bash
# Check if variable is set
echo $BSSH_CONFIG     # Should show path

# Set manually if needed
export BSSH_CONFIG="$HOME/.config/bssh/config.yaml"  # Bash/Zsh
set -gx BSSH_CONFIG "$HOME/.config/bssh/config.yaml"  # Fish
```

## See Also

- [bssh README](../../README.md) - Main documentation
- [pdsh Migration Guide](../pdsh-migration.md) - Migrating from pdsh
- [pdsh Options](../pdsh-options.md) - Option mapping reference
- [pdsh Examples](../pdsh-examples.md) - Usage examples

## Contributing

Feel free to contribute additional shell configurations or improvements:

1. Add new shell support (e.g., PowerShell, Nushell)
2. Enhance existing configurations with new features
3. Fix bugs or improve documentation
4. Share your custom shortcuts and functions

Submit pull requests at: https://github.com/lablup/bssh

## License

These configurations are part of the bssh project and licensed under Apache 2.0.

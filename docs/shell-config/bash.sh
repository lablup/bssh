# bssh shell configuration for Bash
# Add this to your ~/.bashrc or ~/.bash_profile

# ============================================
# Method 1: pdsh Compatibility Alias
# ============================================
# This makes the 'pdsh' command use bssh in compatibility mode
alias pdsh='bssh --pdsh-compat'

# Alternatively, if you prefer environment variable:
# export BSSH_PDSH_COMPAT=1
# alias pdsh='bssh'

# ============================================
# Method 2: bssh Cluster Shortcuts
# ============================================
# Create shortcuts for frequently used clusters

# Production cluster shortcut
alias bssh-prod='bssh -C production'

# Staging cluster shortcut
alias bssh-staging='bssh -C staging'

# Development cluster shortcut
alias bssh-dev='bssh -C development'

# ============================================
# Helper Functions
# ============================================

# Quick SSH to all nodes in a cluster
bssh-all() {
    if [ -z "$1" ]; then
        echo "Usage: bssh-all <cluster> <command>"
        return 1
    fi

    local cluster="$1"
    shift
    bssh -C "$cluster" "$@"
}

# Execute command with hostlist expansion
bssh-hosts() {
    if [ $# -lt 2 ]; then
        echo "Usage: bssh-hosts <hostlist> <command>"
        return 1
    fi

    local hosts="$1"
    shift
    bssh -H "$hosts" "$@"
}

# pdsh-style execution with automatic compatibility mode
pdsh-exec() {
    if [ $# -lt 2 ]; then
        echo "Usage: pdsh-exec <hosts> <command>"
        return 1
    fi

    local hosts="$1"
    shift
    bssh --pdsh-compat -w "$hosts" "$@"
}

# Quick health check across cluster
bssh-health() {
    if [ -z "$1" ]; then
        echo "Usage: bssh-health <cluster>"
        return 1
    fi

    bssh -C "$1" "uptime; free -h | grep 'Mem:'; df -h /"
}

# ============================================
# Completion (Optional)
# ============================================
# Enable bash completion for bssh if available
if [ -f /usr/share/bash-completion/completions/bssh ]; then
    source /usr/share/bash-completion/completions/bssh
fi

# ============================================
# Environment Variables
# ============================================
# Set default bssh configuration file location
export BSSH_CONFIG="${BSSH_CONFIG:-$HOME/.config/bssh/config.yaml}"

# Enable pdsh compatibility mode globally (if desired)
# export BSSH_PDSH_COMPAT=1

# Set default parallel connections
# export BSSH_PARALLEL=10

# Set default timeouts
# export BSSH_CONNECT_TIMEOUT=30
# export BSSH_COMMAND_TIMEOUT=300

# ============================================
# Examples
# ============================================
# After sourcing this file, you can use:
#
# pdsh -w node[1-5] "uptime"                    # Using pdsh alias
# bssh-prod "systemctl status nginx"            # Production cluster
# bssh-all staging "df -h"                      # Execute on all staging nodes
# bssh-hosts "web[1-3]" "nginx -t"             # Hostlist expansion
# bssh-health production                        # Quick health check

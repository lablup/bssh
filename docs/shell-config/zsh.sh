# bssh shell configuration for Zsh
# Add this to your ~/.zshrc

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
    if [[ -z "$1" ]]; then
        echo "Usage: bssh-all <cluster> <command>"
        return 1
    fi

    local cluster="$1"
    shift
    bssh -C "$cluster" "$@"
}

# Execute command with hostlist expansion
bssh-hosts() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: bssh-hosts <hostlist> <command>"
        return 1
    fi

    local hosts="$1"
    shift
    bssh -H "$hosts" "$@"
}

# pdsh-style execution with automatic compatibility mode
pdsh-exec() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: pdsh-exec <hosts> <command>"
        return 1
    fi

    local hosts="$1"
    shift
    bssh --pdsh-compat -w "$hosts" "$@"
}

# Quick health check across cluster
bssh-health() {
    if [[ -z "$1" ]]; then
        echo "Usage: bssh-health <cluster>"
        return 1
    fi

    bssh -C "$1" "uptime; free -h | grep 'Mem:'; df -h /"
}

# Parallel execution with progress tracking
bssh-parallel() {
    if [[ $# -lt 3 ]]; then
        echo "Usage: bssh-parallel <cluster> <parallelism> <command>"
        return 1
    fi

    local cluster="$1"
    local parallel="$2"
    shift 2
    bssh -C "$cluster" --parallel "$parallel" "$@"
}

# ============================================
# Zsh Completion (Optional)
# ============================================
# Enable completion for bssh
# If bssh provides zsh completion, source it:
# if [ -f /usr/share/zsh/site-functions/_bssh ]; then
#     autoload -Uz compinit && compinit
# fi

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
# Zsh-Specific Features
# ============================================

# Custom prompt indicator when working with clusters
# (Optional: shows current cluster context if set)
if [[ -n "$BSSH_CURRENT_CLUSTER" ]]; then
    RPROMPT="%F{cyan}[cluster: $BSSH_CURRENT_CLUSTER]%f"
fi

# Quick cluster context switching
bssh-context() {
    if [[ -z "$1" ]]; then
        if [[ -n "$BSSH_CURRENT_CLUSTER" ]]; then
            echo "Current cluster: $BSSH_CURRENT_CLUSTER"
        else
            echo "No cluster context set"
        fi
        return 0
    fi

    export BSSH_CURRENT_CLUSTER="$1"
    echo "Switched to cluster: $BSSH_CURRENT_CLUSTER"

    # Update prompt if using the RPROMPT above
    RPROMPT="%F{cyan}[cluster: $BSSH_CURRENT_CLUSTER]%f"
}

# Use current cluster context
bssh-ctx() {
    if [[ -z "$BSSH_CURRENT_CLUSTER" ]]; then
        echo "No cluster context set. Use: bssh-context <cluster>"
        return 1
    fi

    bssh -C "$BSSH_CURRENT_CLUSTER" "$@"
}

# ============================================
# Array/Associative Array Utilities
# ============================================

# Define cluster groups (Zsh associative array)
typeset -A BSSH_CLUSTER_GROUPS
BSSH_CLUSTER_GROUPS=(
    all "production staging development"
    prod "production"
    nonprod "staging development"
)

# Execute command on cluster group
bssh-group() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: bssh-group <group> <command>"
        echo "Available groups: ${(k)BSSH_CLUSTER_GROUPS}"
        return 1
    fi

    local group="$1"
    shift

    if [[ -z "${BSSH_CLUSTER_GROUPS[$group]}" ]]; then
        echo "Unknown group: $group"
        echo "Available groups: ${(k)BSSH_CLUSTER_GROUPS}"
        return 1
    fi

    for cluster in ${=BSSH_CLUSTER_GROUPS[$group]}; do
        echo "===> Running on cluster: $cluster"
        bssh -C "$cluster" "$@"
    done
}

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
# bssh-context production                       # Set cluster context
# bssh-ctx "uptime"                             # Use current context
# bssh-group all "hostname"                     # Execute on cluster group

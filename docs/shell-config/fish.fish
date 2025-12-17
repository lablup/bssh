# bssh shell configuration for Fish
# Add this to your ~/.config/fish/config.fish

# ============================================
# Method 1: pdsh Compatibility Alias
# ============================================
# This makes the 'pdsh' command use bssh in compatibility mode
alias pdsh='bssh --pdsh-compat'

# Alternatively, if you prefer environment variable:
# set -gx BSSH_PDSH_COMPAT 1
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
function bssh-all
    if test (count $argv) -lt 2
        echo "Usage: bssh-all <cluster> <command>"
        return 1
    end

    set cluster $argv[1]
    set -e argv[1]
    bssh -C $cluster $argv
end

# Execute command with hostlist expansion
function bssh-hosts
    if test (count $argv) -lt 2
        echo "Usage: bssh-hosts <hostlist> <command>"
        return 1
    end

    set hosts $argv[1]
    set -e argv[1]
    bssh -H $hosts $argv
end

# pdsh-style execution with automatic compatibility mode
function pdsh-exec
    if test (count $argv) -lt 2
        echo "Usage: pdsh-exec <hosts> <command>"
        return 1
    end

    set hosts $argv[1]
    set -e argv[1]
    bssh --pdsh-compat -w $hosts $argv
end

# Quick health check across cluster
function bssh-health
    if test (count $argv) -eq 0
        echo "Usage: bssh-health <cluster>"
        return 1
    end

    bssh -C $argv[1] "uptime; free -h | grep 'Mem:'; df -h /"
end

# Parallel execution with progress tracking
function bssh-parallel
    if test (count $argv) -lt 3
        echo "Usage: bssh-parallel <cluster> <parallelism> <command>"
        return 1
    end

    set cluster $argv[1]
    set parallel $argv[2]
    set -e argv[1..2]
    bssh -C $cluster --parallel $parallel $argv
end

# ============================================
# Fish Completion (Optional)
# ============================================
# Fish auto-loads completions from ~/.config/fish/completions/
# If bssh provides fish completion, it should be at:
# ~/.config/fish/completions/bssh.fish

# ============================================
# Environment Variables
# ============================================
# Set default bssh configuration file location
set -gx BSSH_CONFIG $HOME/.config/bssh/config.yaml

# Enable pdsh compatibility mode globally (if desired)
# set -gx BSSH_PDSH_COMPAT 1

# Set default parallel connections
# set -gx BSSH_PARALLEL 10

# Set default timeouts
# set -gx BSSH_CONNECT_TIMEOUT 30
# set -gx BSSH_COMMAND_TIMEOUT 300

# ============================================
# Fish-Specific Features
# ============================================

# Custom prompt indicator when working with clusters
# (Optional: shows current cluster context if set)
function fish_right_prompt
    if set -q BSSH_CURRENT_CLUSTER
        set_color cyan
        echo -n "[cluster: $BSSH_CURRENT_CLUSTER]"
        set_color normal
    end
end

# Quick cluster context switching
function bssh-context
    if test (count $argv) -eq 0
        if set -q BSSH_CURRENT_CLUSTER
            echo "Current cluster: $BSSH_CURRENT_CLUSTER"
        else
            echo "No cluster context set"
        end
        return 0
    end

    set -gx BSSH_CURRENT_CLUSTER $argv[1]
    echo "Switched to cluster: $BSSH_CURRENT_CLUSTER"
end

# Use current cluster context
function bssh-ctx
    if not set -q BSSH_CURRENT_CLUSTER
        echo "No cluster context set. Use: bssh-context <cluster>"
        return 1
    end

    bssh -C $BSSH_CURRENT_CLUSTER $argv
end

# ============================================
# Cluster Groups
# ============================================

# Define cluster groups (Fish doesn't have associative arrays, use switch)
function bssh-group
    if test (count $argv) -lt 2
        echo "Usage: bssh-group <group> <command>"
        echo "Available groups: all, prod, nonprod"
        return 1
    end

    set group $argv[1]
    set -e argv[1]

    switch $group
        case all
            set clusters production staging development
        case prod
            set clusters production
        case nonprod
            set clusters staging development
        case '*'
            echo "Unknown group: $group"
            echo "Available groups: all, prod, nonprod"
            return 1
    end

    for cluster in $clusters
        echo "===> Running on cluster: $cluster"
        bssh -C $cluster $argv
    end
end

# ============================================
# Enhanced Utilities
# ============================================

# Interactive cluster selector
function bssh-select
    # Get list of available clusters from config
    set clusters (bssh list 2>/dev/null | tail -n +2 | awk '{print $1}')

    if test (count $clusters) -eq 0
        echo "No clusters found in configuration"
        return 1
    end

    echo "Select cluster:"
    for i in (seq (count $clusters))
        echo "  $i) $clusters[$i]"
    end

    read -P "Enter number: " selection

    if test -n "$selection" -a $selection -ge 1 -a $selection -le (count $clusters)
        set selected_cluster $clusters[$selection]
        echo "Selected: $selected_cluster"

        if test (count $argv) -gt 0
            bssh -C $selected_cluster $argv
        else
            bssh-context $selected_cluster
        end
    else
        echo "Invalid selection"
        return 1
    end
end

# Quick cluster info
function bssh-info
    if test (count $argv) -eq 0
        echo "Usage: bssh-info <cluster>"
        return 1
    end

    echo "Cluster: $argv[1]"
    echo "Nodes:"
    bssh -C $argv[1] -q 2>/dev/null | while read node
        echo "  - $node"
    end
end

# ============================================
# Abbreviations (Fish-specific)
# ============================================
# These expand automatically as you type

abbr --add bsp 'bssh-prod'
abbr --add bss 'bssh-staging'
abbr --add bsd 'bssh-dev'
abbr --add bsc 'bssh-context'
abbr --add bsx 'bssh-ctx'
abbr --add bsh 'bssh-health'

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
# bssh-select "uptime"                          # Interactive cluster selection
# bssh-info production                          # Show cluster info
#
# Abbreviations (expand automatically):
# bsp "uptime"           -> bssh-prod "uptime"
# bss "df -h"            -> bssh-staging "df -h"
# bsc production         -> bssh-context production
# bsx "hostname"         -> bssh-ctx "hostname"

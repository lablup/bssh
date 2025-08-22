#!/bin/bash
# Script to determine the next PPA version number by checking existing versions

set -e

# Arguments
VERSION="$1"  # e.g., "0.7.2"
DISTRO="$2"   # e.g., "noble"
PPA="$3"      # e.g., "lablup/backend-ai"

if [ -z "$VERSION" ] || [ -z "$DISTRO" ] || [ -z "$PPA" ]; then
    echo "Usage: $0 <version> <distro> <ppa>"
    echo "Example: $0 0.7.2 noble lablup/backend-ai"
    exit 1
fi

# Function to get the highest revision number for a given version
get_highest_revision() {
    local base_version="$1"
    local distro="$2"
    local ppa="$3"
    
    # Try to fetch package info from PPA
    # Using rmadison if available, otherwise use apt-cache policy
    if command -v rmadison >/dev/null 2>&1; then
        # rmadison can query PPAs
        existing_versions=$(rmadison -s "$distro" -a source bssh 2>/dev/null | grep -E "${base_version}-[0-9]+~${distro}[0-9]+" | awk '{print $2}' || true)
    else
        # Fallback: try to query using curl from Launchpad API
        ppa_owner=$(echo "$ppa" | cut -d'/' -f1)
        ppa_name=$(echo "$ppa" | cut -d'/' -f2)
        
        # Query Launchpad API for published sources
        api_url="https://api.launchpad.net/1.0/~${ppa_owner}/+archive/ubuntu/${ppa_name}?ws.op=getPublishedSources&source_name=bssh&distro_series=https://api.launchpad.net/1.0/ubuntu/${distro}&status=Published"
        
        existing_versions=$(curl -s "$api_url" | \
            grep -o '"source_package_version": "[^"]*"' | \
            cut -d'"' -f4 | \
            grep -E "^${base_version}-[0-9]+~${distro}[0-9]+$" || true)
    fi
    
    if [ -z "$existing_versions" ]; then
        # No existing versions found
        echo "1"
        return
    fi
    
    # Extract the highest revision number
    highest=0
    for ver in $existing_versions; do
        # Extract revision number (e.g., "0.7.2-1~noble2" -> "2")
        revision=$(echo "$ver" | sed -n "s/^${base_version}-[0-9]*~${distro}\([0-9]\+\)$/\1/p")
        if [ -n "$revision" ] && [ "$revision" -gt "$highest" ]; then
            highest=$revision
        fi
    done
    
    # Return next revision
    echo $((highest + 1))
}

# Get the next revision number
next_revision=$(get_highest_revision "$VERSION" "$DISTRO" "$PPA")

# Output the full version string
echo "${VERSION}-1~${DISTRO}${next_revision}"
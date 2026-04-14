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
    local existing_versions=""
    local ppa_owner
    local ppa_name

    fetch_versions_for_status() {
        local status="$1"
        local api_url

        api_url="https://api.launchpad.net/1.0/~${ppa_owner}/+archive/ubuntu/${ppa_name}?ws.op=getPublishedSources&source_name=bssh&distro_series=https://api.launchpad.net/1.0/ubuntu/${distro}&status=${status}"

        curl -s "$api_url" | \
            grep -o '"source_package_version": "[^"]*"' | \
            cut -d'"' -f4 | \
            grep -E "^${base_version}-[0-9]+~${distro}[0-9]+$" || true
    }

    ppa_owner=$(echo "$ppa" | cut -d'/' -f1)
    ppa_name=$(echo "$ppa" | cut -d'/' -f2)
    # Count both published and pending uploads so retries pick a fresh revision.
    existing_versions=$(
        {
            fetch_versions_for_status "Published"
            fetch_versions_for_status "Pending"
        } | sort -u
    )
    
    if [ -z "$existing_versions" ]; then
        # No existing versions found
        echo "1"
        return
    fi
    
    # Extract the highest revision number
    highest=0
    for ver in $existing_versions; do
        # Extract revision number (e.g., "0.7.2-1~noble2" -> "2")
        revision="${ver##*~${distro}}"
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

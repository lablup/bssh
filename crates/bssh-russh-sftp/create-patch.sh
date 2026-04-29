#!/bin/bash
# create-patch.sh
# Creates a patch file from the current bssh-russh-sftp changes compared to upstream russh-sftp.
#
# Usage: ./create-patch.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BSSH_ROOT="$SCRIPT_DIR/../.."
UPSTREAM_DIR="$BSSH_ROOT/references/russh-sftp/src"
CURRENT_DIR="$SCRIPT_DIR/src"
PATCH_DIR="$SCRIPT_DIR/patches"
PATCH_FILE="$PATCH_DIR/sftp-serde-bytes-perf.patch"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

if [ ! -d "$UPSTREAM_DIR" ]; then
    echo "Error: Upstream russh-sftp not found at $UPSTREAM_DIR"
    echo "Please ensure references/russh-sftp exists with the upstream source."
    exit 1
fi

mkdir -p "$PATCH_DIR"

log_info "Creating patch from differences..."

/usr/bin/diff -urN "$UPSTREAM_DIR" "$CURRENT_DIR" \
    | sed "s|$UPSTREAM_DIR|a/src|g" \
    | sed "s|$CURRENT_DIR|b/src|g" \
    > "$PATCH_FILE" || true

if [ -s "$PATCH_FILE" ]; then
    LINES=$(wc -l < "$PATCH_FILE" | tr -d ' ')
    log_info "Patch created: $PATCH_FILE ($LINES lines)"

    echo ""
    echo "Patch summary:"
    echo "=============="
    grep -E "^@@|^\+\+\+|^---" "$PATCH_FILE" | head -20
else
    log_warn "No differences found - patch file is empty"
fi

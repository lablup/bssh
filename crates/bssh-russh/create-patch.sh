#!/bin/bash
# create-patch.sh
# Regenerates patches/handle-data-fix.patch by diffing the current vendored
# source against a fresh checkout of upstream russh.
#
# Self-contained: clones upstream into a temp dir (no manually-maintained
# references/ directory needed), so it always diffs against the exact version.
#
# Usage: ./create-patch.sh [version]
#   version: optional, e.g. "0.61.1" (default: latest tag)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_URL="https://github.com/warp-tech/russh.git"
TEMP_DIR="/tmp/russh-createpatch-$$"
PATCH_DIR="$SCRIPT_DIR/patches"
PATCH_FILE="$PATCH_DIR/handle-data-fix.patch"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

cleanup() { [ -d "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

VERSION="${1:-}"

log_info "Cloning upstream russh..."
git clone --quiet --depth 100 "$UPSTREAM_URL" "$TEMP_DIR"
cd "$TEMP_DIR"

if [ -z "$VERSION" ]; then
    VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "main")
fi
if [ "$VERSION" != "main" ]; then
    git checkout --quiet "v$VERSION" 2>/dev/null || git checkout --quiet "$VERSION"
fi
log_info "Diffing against upstream $VERSION ($(git rev-parse --short HEAD))"

UPSTREAM_SRC="$TEMP_DIR/russh/src"
CURRENT_SRC="$SCRIPT_DIR/src"
mkdir -p "$PATCH_DIR"

# The only fork change is the PTY fix in server/session.rs (the batch try_recv
# drain before select!). Emit a -p1 patch with a/ b/ prefixes.
diff -u \
    --label a/src/server/session.rs \
    --label b/src/server/session.rs \
    "$UPSTREAM_SRC/server/session.rs" \
    "$CURRENT_SRC/server/session.rs" \
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

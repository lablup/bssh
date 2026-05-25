#!/bin/bash
# create-patch.sh
# Regenerates patches/pipelined-file-io.patch by diffing the current vendored
# source against a fresh checkout of upstream russh-sftp.
#
# Self-contained: clones upstream into a temp dir (no manually-maintained
# references/ directory needed), so it always diffs against the exact version.
#
# Usage: ./create-patch.sh [version]
#   version: optional, e.g. "2.3.0" (default: upstream's default branch, since
#            russh-sftp does not publish git tags)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_URL="https://github.com/AspectUnk/russh-sftp.git"
TEMP_DIR="/tmp/russh-sftp-createpatch-$$"
PATCH_DIR="$SCRIPT_DIR/patches"
PATCH_FILE="$PATCH_DIR/pipelined-file-io.patch"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

cleanup() { [ -d "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

VERSION="${1:-}"

log_info "Cloning upstream russh-sftp..."
git clone --quiet "$UPSTREAM_URL" "$TEMP_DIR"
cd "$TEMP_DIR"

if [ -z "$VERSION" ]; then
    VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "master")
fi
if [ "$VERSION" != "master" ]; then
    # russh-sftp publishes no git tags, so a version string may not be a ref.
    if ! { git checkout --quiet "v$VERSION" 2>/dev/null || git checkout --quiet "$VERSION" 2>/dev/null; }; then
        log_warn "No git ref '$VERSION' (russh-sftp publishes no tags); diffing against the default branch."
        VERSION="master"
    fi
fi
log_info "Diffing against upstream $VERSION ($(git rev-parse --short HEAD))"

UPSTREAM_SRC="$TEMP_DIR/src"
CURRENT_SRC="$SCRIPT_DIR/src"
mkdir -p "$PATCH_DIR"

# The only fork change is the pipelined File I/O in client/fs/file.rs
# (write_all_pipelined / read_to_writer_pipelined). Emit a -p1 patch.
diff -u \
    --label a/src/client/fs/file.rs \
    --label b/src/client/fs/file.rs \
    "$UPSTREAM_SRC/client/fs/file.rs" \
    "$CURRENT_SRC/client/fs/file.rs" \
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

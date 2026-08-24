#!/bin/bash
# create-patch.sh
# Regenerates every file in patches/ by diffing the current vendored source
# against a fresh checkout of upstream russh-sftp.
#
# Self-contained: clones upstream into a temp dir (no manually-maintained
# references/ directory needed), so it always diffs against the exact version.
#
# Usage: ./create-patch.sh [version]
#   version: optional, e.g. "2.4.0" (default: upstream's default branch, since
#            russh-sftp does not publish git tags)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_URL="https://github.com/AspectUnk/russh-sftp.git"
TEMP_DIR="/tmp/russh-sftp-createpatch-$$"
PATCH_DIR="$SCRIPT_DIR/patches"

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

# Every fork change, one patch per file. Keep this list in sync with the fork:
# a file that drifts from upstream without an entry here is silently deleted by
# sync-upstream.sh, which wipes src/ before copying upstream over it.
#   client/fs/file.rs - pipelined File I/O (write_all_pipelined /
#                       read_to_writer_pipelined)
#   server/mod.rs     - request read-ahead intake queue and sequential-write
#                       coalescing (issue lablup/bssh#227)
PATCH_TARGETS=(
    "client/fs/file.rs:pipelined-file-io.patch"
    "server/mod.rs:server-readahead-write-coalescing.patch"
)

# Guard against exactly the failure this list exists to prevent: any src file
# that differs from upstream but has no patch entry.
UNTRACKED=0
while IFS= read -r REL; do
    for TARGET in "${PATCH_TARGETS[@]}"; do
        [ "${TARGET%%:*}" = "$REL" ] && continue 2
    done
    log_warn "src/$REL differs from upstream but has no PATCH_TARGETS entry; sync-upstream.sh would discard it"
    UNTRACKED=1
done < <(cd "$UPSTREAM_SRC" && find . -name '*.rs' -type f | sed 's|^\./||' | while read -r F; do
    if [ ! -f "$CURRENT_SRC/$F" ] || ! diff -q "$UPSTREAM_SRC/$F" "$CURRENT_SRC/$F" > /dev/null 2>&1; then
        echo "$F"
    fi
done)

for TARGET in "${PATCH_TARGETS[@]}"; do
    REL="${TARGET%%:*}"
    OUT="$PATCH_DIR/${TARGET##*:}"

    diff -u \
        --label "a/src/$REL" \
        --label "b/src/$REL" \
        "$UPSTREAM_SRC/$REL" \
        "$CURRENT_SRC/$REL" \
        > "$OUT" || true

    if [ -s "$OUT" ]; then
        LINES=$(wc -l < "$OUT" | tr -d ' ')
        log_info "Patch created: $OUT ($LINES lines)"
    else
        log_warn "No differences in src/$REL - $OUT is empty (already upstream?)"
    fi
done

[ "$UNTRACKED" -eq 0 ] || log_warn "One or more fork changes are untracked; add them to PATCH_TARGETS before syncing."

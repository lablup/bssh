#!/bin/bash
# sync-upstream.sh
# Syncs bssh-russh with upstream russh and applies our patches
#
# Usage: ./sync-upstream.sh [version]
#   version: optional, e.g., "0.56.0" or "main" (default: latest tag)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_URL="https://github.com/warp-tech/russh.git"
TEMP_DIR="/tmp/russh-sync-$$"
PATCH_DIR="$SCRIPT_DIR/patches"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# Parse arguments
VERSION="${1:-}"

log_info "Syncing bssh-russh with upstream russh..."

# Clone upstream
log_info "Cloning upstream russh..."
git clone --depth 100 "$UPSTREAM_URL" "$TEMP_DIR"

cd "$TEMP_DIR"

# Determine version
if [ -z "$VERSION" ]; then
    VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "main")
    log_info "Using latest tag: $VERSION"
elif [ "$VERSION" != "main" ]; then
    log_info "Using specified version: $VERSION"
fi

# Checkout version
if [ "$VERSION" != "main" ]; then
    git checkout "v$VERSION" 2>/dev/null || git checkout "$VERSION"
fi

COMMIT_HASH=$(git rev-parse --short HEAD)
log_info "Upstream commit: $COMMIT_HASH"

# Copy russh source files
log_info "Copying source files..."
cd "$SCRIPT_DIR"

# Preserve our Cargo.toml and README.md
cp Cargo.toml Cargo.toml.bak
cp README.md README.md.bak 2>/dev/null || true

# Remove old source (except patches directory and scripts)
find src -type f -name "*.rs" -delete 2>/dev/null || true

# Copy new source from upstream
cp -r "$TEMP_DIR/russh/src/"* src/

# Restore our files
mv Cargo.toml.bak Cargo.toml
mv README.md.bak README.md 2>/dev/null || true

# Update version in Cargo.toml
if [ "$VERSION" != "main" ]; then
    CLEAN_VERSION="${VERSION#v}"
    sed -i '' "s/^version = \".*\"/version = \"$CLEAN_VERSION\"/" Cargo.toml
    log_info "Updated version to $CLEAN_VERSION"
fi

# Apply our patches
#
# Each *.patch file under patches/ is a forward-port of a fix that is either
# unique to this fork (e.g. handle-data-fix.patch) or a cherry-pick of an
# unreleased upstream commit. For cherry-picks, once upstream releases a
# version that includes the change, the next sync will automatically detect
# it (reverse-apply succeeds) and skip the patch — at which point the patch
# file should be deleted.
log_info "Applying patches..."

shopt -s nullglob
PATCH_FILES=("$PATCH_DIR"/*.patch)
shopt -u nullglob

if [ ${#PATCH_FILES[@]} -eq 0 ]; then
    log_warn "No patch files found in $PATCH_DIR/"
fi

OBSOLETE_PATCHES=()

for PATCH_FILE in "${PATCH_FILES[@]}"; do
    PATCH_NAME=$(basename "$PATCH_FILE")

    # If reverse-apply succeeds, the change is already in upstream — skip and
    # mark the patch as obsolete so the maintainer can delete it.
    if patch -p1 -R --dry-run --silent < "$PATCH_FILE" > /dev/null 2>&1; then
        log_info "Skipping $PATCH_NAME — already present in upstream (consider deleting this patch file)"
        OBSOLETE_PATCHES+=("$PATCH_NAME")
        continue
    fi

    if patch -p1 --dry-run --silent < "$PATCH_FILE" > /dev/null 2>&1; then
        patch -p1 --silent < "$PATCH_FILE"
        log_info "Applied $PATCH_NAME"
    else
        log_warn "$PATCH_NAME may not apply cleanly, attempting with fuzz..."
        if patch -p1 --fuzz=3 < "$PATCH_FILE"; then
            log_warn "$PATCH_NAME applied with fuzz - please verify manually"
        else
            log_error "Failed to apply $PATCH_NAME. Manual intervention required."
            log_error "Patch file: $PATCH_FILE"
            exit 1
        fi
    fi
done

# Verify build
log_info "Verifying build..."
cd "$SCRIPT_DIR/../.."
if cargo check -p bssh-russh 2>/dev/null; then
    log_info "Build verification passed"
else
    log_error "Build verification failed"
    exit 1
fi

log_info "Sync complete!"
log_info "Upstream version: $VERSION ($COMMIT_HASH)"

if [ ${#OBSOLETE_PATCHES[@]} -gt 0 ]; then
    log_info ""
    log_warn "The following patches are now obsolete (already in upstream $VERSION):"
    for p in "${OBSOLETE_PATCHES[@]}"; do
        log_warn "  - $p"
    done
    log_warn "Delete these patch files: rm $PATCH_DIR/{$(IFS=,; echo "${OBSOLETE_PATCHES[*]}")}"
fi

log_info ""
log_info "Next steps:"
log_info "  1. Review changes: git diff crates/bssh-russh/"
log_info "  2. Test: cargo test -p bssh-russh"
log_info "  3. Commit: git add -A && git commit -m 'chore: sync bssh-russh with upstream $VERSION'"

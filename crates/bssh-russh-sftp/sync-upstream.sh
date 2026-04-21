#!/bin/bash
# sync-upstream.sh
# Syncs bssh-russh-sftp with upstream russh-sftp and applies our patches.
#
# Usage: ./sync-upstream.sh [version]
#   version: optional, e.g., "2.1.1" or "master" (default: latest tag)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_URL="https://github.com/AspectUnk/russh-sftp.git"
TEMP_DIR="/tmp/russh-sftp-sync-$$"
PATCH_FILE="$SCRIPT_DIR/patches/sftp-serde-bytes-perf.patch"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

VERSION="${1:-}"

log_info "Syncing bssh-russh-sftp with upstream russh-sftp..."

log_info "Cloning upstream russh-sftp..."
git clone "$UPSTREAM_URL" "$TEMP_DIR"

cd "$TEMP_DIR"

if [ -z "$VERSION" ]; then
    VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "master")
    log_info "Using latest tag: $VERSION"
elif [ "$VERSION" != "master" ]; then
    log_info "Using specified version: $VERSION"
fi

if [ "$VERSION" != "master" ]; then
    git checkout "v$VERSION" 2>/dev/null || git checkout "$VERSION"
fi

COMMIT_HASH=$(git rev-parse --short HEAD)
log_info "Upstream commit: $COMMIT_HASH"

log_info "Copying source files..."
cd "$SCRIPT_DIR"

cp Cargo.toml Cargo.toml.bak
cp README.md README.md.bak 2>/dev/null || true

find src -type f -name "*.rs" -delete 2>/dev/null || true

cp -r "$TEMP_DIR/src/"* src/

mv Cargo.toml.bak Cargo.toml
mv README.md.bak README.md 2>/dev/null || true

if [ "$VERSION" != "master" ]; then
    CLEAN_VERSION="${VERSION#v}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/^version = \".*\"/version = \"$CLEAN_VERSION\"/" Cargo.toml
    else
        sed -i "s/^version = \".*\"/version = \"$CLEAN_VERSION\"/" Cargo.toml
    fi
    log_info "Updated version to $CLEAN_VERSION"
fi

log_info "Applying patches..."

if [ -f "$PATCH_FILE" ]; then
    if patch -p1 --dry-run < "$PATCH_FILE" > /dev/null 2>&1; then
        patch -p1 < "$PATCH_FILE"
        log_info "Applied sftp-serde-bytes-perf.patch"
    else
        log_warn "Patch may not apply cleanly, attempting with fuzz..."
        if patch -p1 --fuzz=3 < "$PATCH_FILE"; then
            log_warn "Patch applied with fuzz - please verify manually"
        else
            log_error "Failed to apply patch. Manual intervention required."
            log_error "Patch file: $PATCH_FILE"
            exit 1
        fi
    fi
else
    log_error "Patch file not found: $PATCH_FILE"
    log_error "Please create the patch file first using: ./create-patch.sh"
    exit 1
fi

log_info "Verifying build..."
cd "$SCRIPT_DIR/../.."
if cargo check -p bssh-russh-sftp 2>/dev/null; then
    log_info "Build verification passed"
else
    log_error "Build verification failed"
    exit 1
fi

log_info "Sync complete!"
log_info "Upstream version: $VERSION ($COMMIT_HASH)"
log_info ""
log_info "Next steps:"
log_info "  1. Review changes: git diff crates/bssh-russh-sftp/"
log_info "  2. Test: cargo test -p bssh-russh-sftp"
log_info "  3. Commit: git add -A && git commit -m 'chore: sync bssh-russh-sftp with upstream $VERSION'"

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
PATCH_DIR="$SCRIPT_DIR/patches"

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
    VERSION="master"
    log_info "No version given; using upstream's default branch"
else
    log_info "Using specified version: $VERSION"
fi

# russh-sftp publishes no git tags at all, so a version string is not a ref.
# Releases are marked by a "bump to <version>" commit, which is the only
# reliable way to land on released code. Never fall back to the default branch
# for an explicit version: that would vendor unreleased commits while stamping
# Cargo.toml with the version the caller asked for.
if [ "$VERSION" != "master" ]; then
    if git rev-parse --verify -q "v$VERSION^{commit}" > /dev/null; then
        REF="v$VERSION"
    elif git rev-parse --verify -q "$VERSION^{commit}" > /dev/null; then
        REF="$VERSION"
    else
        REF=$(git log --format='%H' --grep="^bump to $VERSION\$" -1)
        if [ -z "$REF" ]; then
            log_error "Cannot resolve upstream version '$VERSION': no tag, no ref, and no 'bump to $VERSION' commit."
            log_error "Available release commits:"
            git log --oneline --grep='^bump to' | head -10 >&2
            exit 1
        fi
        log_info "No tag for $VERSION (upstream publishes none); using its 'bump to' commit"
    fi
    git checkout --quiet "$REF"
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

# Apply every *.patch directly under patches/ (patches/historical/ is excluded:
# those are forward-ports already merged upstream, kept only for reference).
#
# Detection uses `git apply --check`, not `patch --dry-run`. Apple's bundled
# `patch` (2.0-12u11) silently auto-corrects direction: with no tty it answers
# "yes" to `Unreversed (or previously applied) patch detected! Ignore -R?` and
# exits 0 for a forward patch, a reverse patch, an applied patch and an
# unapplied one alike. Its exit code therefore carries no information, and the
# previous reverse-apply probe classified every fork patch as "already
# upstream" and skipped it, wiping the fork changes on every sync.
# `git apply --check` never prompts and returns a meaningful status:
#   forward ok            -> not applied yet, apply it
#   forward no, reverse ok -> already present upstream, obsolete
#   both no               -> genuine conflict, stop
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

    if git apply --check -p1 "$PATCH_FILE" > /dev/null 2>&1; then
        git apply -p1 "$PATCH_FILE"
        log_info "Applied $PATCH_NAME"
    elif git apply --reverse --check -p1 "$PATCH_FILE" > /dev/null 2>&1; then
        log_info "Skipping $PATCH_NAME: already present in upstream (consider moving to patches/historical/)"
        OBSOLETE_PATCHES+=("$PATCH_NAME")
    else
        log_error "Failed to apply $PATCH_NAME: it neither applies nor is already present."
        log_error "Upstream moved under the patch. Rebase it by hand, then regenerate with ./create-patch.sh"
        log_error "Patch file: $PATCH_FILE"
        git apply --check -p1 "$PATCH_FILE" || true
        exit 1
    fi
done

# The sync wiped src/ before copying upstream over it, so every fork change
# must be back. Reverse-applying each non-obsolete patch proves its hunks are
# present in the vendored tree. A build check alone cannot catch a lost change:
# the fork's own tests live inside the patched files, so losing a patch loses
# its tests too and everything still compiles and passes.
log_info "Verifying fork changes survived the sync..."
for PATCH_FILE in "${PATCH_FILES[@]}"; do
    PATCH_NAME=$(basename "$PATCH_FILE")

    for OBSOLETE in ${OBSOLETE_PATCHES[@]+"${OBSOLETE_PATCHES[@]}"}; do
        [ "$OBSOLETE" = "$PATCH_NAME" ] && continue 2
    done

    if git apply --reverse --check -p1 "$PATCH_FILE" > /dev/null 2>&1; then
        log_info "Present: $PATCH_NAME"
    else
        log_error "$PATCH_NAME is not present in the synced tree; the fork change was lost."
        exit 1
    fi
done

log_info "Verifying build..."
cd "$SCRIPT_DIR/../.."
if cargo check -p bssh-russh-sftp 2>/dev/null; then
    log_info "Build verification passed"
else
    log_error "Build verification failed"
    exit 1
fi

log_info "Running fork tests..."
if cargo test -p bssh-russh-sftp --quiet; then
    log_info "Fork tests passed"
else
    log_error "Fork tests failed"
    exit 1
fi

log_info "Sync complete!"
log_info "Upstream version: $VERSION ($COMMIT_HASH)"
log_info ""
log_info "Next steps:"
log_info "  1. Review changes: git diff crates/bssh-russh-sftp/"
log_info "  2. Test: cargo test -p bssh-russh-sftp"
log_info "  3. Commit: git add -A && git commit -m 'chore: sync bssh-russh-sftp with upstream $VERSION'"

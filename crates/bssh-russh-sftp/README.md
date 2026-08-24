# bssh-russh-sftp

**Temporary fork of [russh-sftp](https://crates.io/crates/russh-sftp) (tracking upstream `2.4.0`) adding pipelined SFTP file I/O and a read-ahead server loop.**

This crate exists so bssh can ship faster bulk SFTP transfers independently, while keeping the public crate name usable through Cargo's `package = "bssh-russh-sftp"` dependency alias.

## The Value-Add

### Client: pipelined file I/O (`src/client/fs/file.rs`)

Two helpers on `client::fs::File` keep many SFTP requests in flight at once, hiding per-request round-trip latency (mirroring how OpenSSH's `sftp` client keeps ~64 requests outstanding):

- `File::write_all_pipelined(reader, max_inflight)` streams a reader to the remote file with up to `max_inflight` concurrent `SSH_FXP_WRITE`s.
- `File::read_to_writer_pipelined(writer, max_inflight)` streams the remote file to a writer with up to `max_inflight` concurrent `SSH_FXP_READ`s, reassembling chunks in offset order so the output matches a sequential read.

Re-applied on sync from `patches/pipelined-file-io.patch`.

### Server: request read-ahead and write coalescing (`src/server/mod.rs`)

The serial request loop is replaced by a byte-bounded intake queue plus a processor, adding two `server::Config` knobs: `max_buffered_request_bytes` (default 8 MiB) and `max_write_coalesce_len` (default 256 KiB). Read-ahead keeps the transport decrypting requests while the handler is blocked on file I/O, and consecutive `SSH_FXP_WRITE`s to the same handle at sequential offsets are merged into one handler call while each request id still gets its own status reply. The unbounded-in-count, bounded-in-bytes intake is deliberate: stalling intake can deadlock against the russh session loop waiting on channel window (see issue lablup/bssh#227, paramiko's unbounded READ prefetch).

Re-applied on sync from `patches/server-readahead-write-coalescing.patch`.

> The `serde_bytes` packet-serialization performance fix that originally motivated this fork was upstreamed in russh-sftp 2.1.2; it is kept for reference under `patches/historical/`.

## Usage

```toml
[dependencies]
russh-sftp = { package = "bssh-russh-sftp", version = "2.4.0" }
```

## Sync with Upstream

```bash
cd crates/bssh-russh-sftp
./sync-upstream.sh 2.4.0   # omit the version to use upstream's default branch
```

`sync-upstream.sh` copies upstream `src` verbatim and re-applies every patch directly under `patches/` (anything under `patches/historical/` is excluded), then verifies each patch is present in the result, builds, and runs the fork tests.

Upstream publishes **no git tags**, and marks releases with a `bump to <version>` commit instead, so both scripts resolve a version argument to that commit. An unresolvable version is a hard error listing the available release commits: falling back to the default branch would vendor unreleased code while stamping `Cargo.toml` with the requested version. Resolution happens before anything is copied, so a bad version leaves the tree untouched.

Patch state is detected with `git apply --check`, not `patch --dry-run`. Apple's bundled `patch` silently auto-corrects direction and exits 0 whether a patch applies, is reversed, or is already applied, so its exit status cannot distinguish "already upstream" from "not applied yet".

Because the sync deletes `src/**/*.rs` before copying upstream over it, **a fork change with no patch file is silently lost**. Regenerate the patches with `./create-patch.sh <version>` after editing vendored code; it diffs every file listed in its `PATCH_TARGETS` and warns about any other file that drifts from upstream without an entry.

## License

Apache-2.0 (same as russh-sftp)

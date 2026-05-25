# bssh-russh-sftp

**Temporary fork of [russh-sftp](https://crates.io/crates/russh-sftp) (tracking upstream `2.3.0`) adding pipelined SFTP file I/O.**

This crate exists so bssh can ship faster bulk SFTP transfers independently, while keeping the public crate name usable through Cargo's `package = "bssh-russh-sftp"` dependency alias.

## The Value-Add

The fork adds two helpers to `client::fs::File` that keep many SFTP requests in flight at once, hiding per-request round-trip latency (mirroring how OpenSSH's `sftp` client keeps ~64 requests outstanding):

- `File::write_all_pipelined(reader, max_inflight)` — streams a reader to the remote file with up to `max_inflight` concurrent `SSH_FXP_WRITE`s.
- `File::read_to_writer_pipelined(writer, max_inflight)` — streams the remote file to a writer with up to `max_inflight` concurrent `SSH_FXP_READ`s, reassembling chunks in offset order so the output matches a sequential read.

These are the only additions over upstream. They live in `src/client/fs/file.rs` and are re-applied on each sync from `patches/pipelined-file-io.patch`.

> The `serde_bytes` packet-serialization performance fix that originally motivated this fork was upstreamed in russh-sftp 2.1.2; it is kept for reference under `patches/historical/`.

## Usage

```toml
[dependencies]
russh-sftp = { package = "bssh-russh-sftp", version = "2.3.0" }
```

## Sync with Upstream

```bash
cd crates/bssh-russh-sftp
./sync-upstream.sh 2.3.0   # omit the version to use upstream's default branch
```

`sync-upstream.sh` copies upstream `src` verbatim and re-applies every patch directly under `patches/` (anything under `patches/historical/` is excluded). Patches already merged upstream are detected via reverse-apply and skipped.

## License

Apache-2.0 (same as russh-sftp)

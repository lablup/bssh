# bssh-russh-sftp

Temporary fork of [russh-sftp](https://crates.io/crates/russh-sftp) tracking upstream `master` (currently 2.3.0).

The only delta vs upstream is the proposed `File::read_to_writer_pipelined` helper ([AspectUnk/russh-sftp#91](https://github.com/AspectUnk/russh-sftp/pull/91)) — a pipelined SFTP `READ` wrapper that hides per-request RTT, mirroring how OpenSSH's `sftp` client keeps ~64 outstanding requests by default. The matching write-side optimization is already upstream (see [AspectUnk/russh-sftp#85](https://github.com/AspectUnk/russh-sftp/pull/85)) and `AsyncWrite for File` is now natively pipelined, so no `write_all_pipelined` wrapper is needed here.

This crate exists so bssh can ship the read-side helper today while [#91](https://github.com/AspectUnk/russh-sftp/pull/91) is in review. Once that merges and lands in a `russh-sftp` release, this fork can be deprecated in favor of upstream.

## History

| Concern | Status |
|---|---|
| `serde_bytes` perf for `WRITE`/`DATA` payloads (~+29%) | ✅ Upstream — [AspectUnk/russh-sftp#83](https://github.com/AspectUnk/russh-sftp/pull/83) (merged 2026-04-30, in 2.3.0) |
| Pipelined `AsyncWrite for File` (dynamic chunk sizes, `write_acks` queue) | ✅ Upstream — [AspectUnk/russh-sftp#85](https://github.com/AspectUnk/russh-sftp/pull/85) (merged 2026-05-01, in 2.3.0) |
| Pipelined `File::read_to_writer_pipelined` for high-RTT reads | 🟡 Under review — [AspectUnk/russh-sftp#91](https://github.com/AspectUnk/russh-sftp/pull/91) |

## Sync with Upstream

```bash
cd crates/bssh-russh-sftp
./sync-upstream.sh master   # or pin to a specific commit / tag
```

Currently no patch files are needed — the read-side helper lives directly in `src/client/fs/file.rs` until #91 merges.

## License

Apache-2.0 (same as russh-sftp).

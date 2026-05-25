# bssh-russh

**Temporary fork of [russh](https://crates.io/crates/russh) (tracking upstream `0.61.1`) with a high-frequency PTY output fix.**

This crate exists solely to address a specific issue where `Handle::data()` messages from spawned tasks may not be delivered to SSH clients during high-throughput PTY sessions.

## The Problem

When implementing SSH servers with interactive PTY support, shell output sent via `Handle::data()` from spawned tasks may not reach the client. The `tokio::select!` in russh's server session loop doesn't always wake up promptly for messages sent through the internal mpsc channel.

## The Fix

Added a `try_recv()` batch processing loop before `select!` to drain pending messages, with a limit of 64 messages per batch to maintain input responsiveness (e.g., Ctrl+C). The change lives in `src/server/session.rs` and is re-applied on each sync from `patches/handle-data-fix.patch`. A regression test lives in `tests/pty_handle_data.rs`.

## Usage

```toml
[dependencies]
russh = { package = "bssh-russh", version = "0.61.1" }
```

## Sync with Upstream

This fork tracks upstream russh releases. To sync with a new version:

```bash
cd crates/bssh-russh
./sync-upstream.sh 0.61.1  # specify version
```

`sync-upstream.sh` copies upstream `russh/src` verbatim and re-applies every patch under `patches/`. Patches that have already landed upstream are detected (their reverse-apply succeeds) and skipped. As of the `0.61.1` sync, only `handle-data-fix.patch` remains — the previous `channel-write-ordering`, `agent-frame-length-cap`, and `sha1-mac-exclude` cherry-picks are now upstream and were removed.

## Upstream Status

- Issue: High-frequency PTY output not delivered when using `Handle::data()` from spawned tasks
- PR: https://github.com/inureyes/russh/tree/fix/handle-data-from-spawned-tasks
- When merged upstream, this fork will be deprecated

## License

Apache-2.0 (same as russh)

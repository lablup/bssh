# bssh-russh

**Temporary fork of [russh](https://crates.io/crates/russh) with high-frequency PTY output fix.**

This crate exists solely to address a specific issue where `Handle::data()` messages from spawned tasks may not be delivered to SSH clients during high-throughput PTY sessions.

## The Problem

When implementing SSH servers with interactive PTY support, shell output sent via `Handle::data()` from spawned tasks may not reach the client. The `tokio::select!` in russh's server session loop doesn't always wake up promptly for messages sent through the internal mpsc channel.

## The Fix

Added a `try_recv()` batch processing loop before `select!` to drain pending messages, with a limit of 64 messages per batch to maintain input responsiveness (e.g., Ctrl+C).

## Usage

```toml
[dependencies]
russh = { package = "bssh-russh", version = "0.56" }
```

## Sync with Upstream

This fork tracks upstream russh releases. To sync with a new version:

```bash
cd crates/bssh-russh
./sync-upstream.sh 0.57.0  # specify version
```

## Upstream Status

- Issue: High-frequency PTY output not delivered when using Handle::data() from spawned tasks
- PR: https://github.com/inureyes/russh/tree/fix/handle-data-from-spawned-tasks
- When merged upstream, this fork will be deprecated

## License

Apache-2.0 (same as russh)

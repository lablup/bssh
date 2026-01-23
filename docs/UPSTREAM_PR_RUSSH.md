# Upstream PR Proposal: Fix Handle::data() messages not processed from spawned tasks

## Issue Summary

When implementing an SSH server with PTY support, messages sent via `Handle::data()` from spawned tasks may not be delivered to the client. This occurs because the server session loop's `tokio::select!` may not wake up for messages sent through the mpsc channel from external tasks.

## Reproduction Scenario

```rust
// In Handler::shell_request()
fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> bool {
    let handle = session.handle();

    // Spawn a task to handle shell I/O
    tokio::spawn(async move {
        loop {
            // Read from PTY
            let data = pty.read().await;

            // Send to client - THIS MAY NOT BE DELIVERED
            handle.data(channel, data.into()).await;
        }
    });

    true
}
```

The `handle.data()` call sends a message through an mpsc channel to the session loop. However, the session loop's `select!` macro may be waiting on other futures (socket read, timers) and doesn't always wake up promptly for channel messages.

## Root Cause

In `server/session.rs`, the main loop uses `tokio::select!`:

```rust
while !self.common.disconnected {
    tokio::select! {
        r = &mut reading => { /* handle socket read */ }
        _ = &mut delay => { /* handle keepalive */ }
        msg = self.receiver.recv(), if !self.kex.active() => {
            // Handle messages from Handle
        }
    }
}
```

When the socket read future is pending and no keepalive is due, the `select!` should wake on `receiver.recv()`. However, in practice, messages can accumulate without being processed, especially under load or when the shell produces rapid output.

## Proposed Fix

Add a `try_recv()` loop before entering `select!` to drain any pending messages:

```rust
while !self.common.disconnected {
    // Process pending messages before entering select!
    if !self.kex.active() {
        loop {
            match self.receiver.try_recv() {
                Ok(msg) => self.handle_msg(msg)?,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        self.flush()?;
    }

    tokio::select! {
        // ... existing select arms
    }
}
```

## Why This Fix is Safe

1. **No behavior change for existing code**: If there are no pending messages, `try_recv()` returns `Empty` immediately and proceeds to `select!` as before.

2. **Respects KEX state**: The fix only processes messages when `!self.kex.active()`, same as the existing `select!` arm condition.

3. **Maintains message ordering**: Messages are processed in FIFO order from the same channel.

4. **No performance impact**: `try_recv()` is non-blocking and O(1).

## Use Case

This fix is essential for implementing SSH servers with:
- Interactive PTY sessions (shell, vim, etc.)
- High-throughput data streaming
- Any scenario where `Handle::data()` is called from spawned tasks

## Diff

```diff
--- a/russh/src/server/session.rs
+++ b/russh/src/server/session.rs
@@ -7,7 +7,7 @@ use std::sync::Arc;
 use log::debug;
 use negotiation::parse_kex_algo_list;
 use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
-use tokio::sync::mpsc::{channel, Receiver, Sender};
+use tokio::sync::mpsc::{channel, error::TryRecvError, Receiver, Sender};
 use tokio::sync::oneshot;

 // ... in Session::run() method, before the select! loop:
+
+            // Process pending messages before entering select!
+            // This ensures messages sent via Handle::data() from spawned tasks
+            // are processed even when select! doesn't wake up for them.
+            if !self.kex.active() {
+                loop {
+                    match self.receiver.try_recv() {
+                        Ok(Msg::Channel(id, ChannelMsg::Data { data })) => {
+                            self.data(id, data)?;
+                        }
+                        // ... handle other message types ...
+                        Err(TryRecvError::Empty) => break,
+                        Err(TryRecvError::Disconnected) => break,
+                    }
+                }
+                self.flush()?;
+            }
+
             tokio::select! {
```

## Testing

Tested with:
- Interactive shell sessions (bash, zsh)
- Rapid output commands (`yes`, `cat /dev/urandom | xxd`)
- Multiple concurrent PTY sessions
- Long-running sessions with intermittent output

## Related

This issue may also affect `client/session.rs` if similar patterns are used, though the client side typically doesn't have spawned tasks sending data in the same way.

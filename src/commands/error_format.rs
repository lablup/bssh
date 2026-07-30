// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Shared error formatting for user-facing connection failure messages.
//!
//! Connection errors (interactive mode, directory downloads, etc.) are
//! typically built from several layers of `anyhow::Context`, one per hop or
//! stage: for example "Failed to establish jump host connection" wrapping
//! "Failed to connect to jump host (hop N)" wrapping "Failed to open
//! direct-tcpip channel" wrapping the underlying I/O or SSH error.
//!
//! anyhow's default `Display` implementation (`{}`) only prints the
//! outermost message, which hides exactly the detail a user needs to
//! understand *which* hop failed and why. This module centralizes the fix:
//! render the full context chain instead of just the outer layer.

/// Render the full context chain of a connection-related [`anyhow::Error`].
///
/// This uses anyhow's alternate `Display` form (`{:#}`), which walks the
/// entire error chain and joins each layer with `": "`, e.g.
/// `"outer context: middle context: root cause"`. This mirrors the format
/// already used by the parallel exec path (`src/executor/parallel.rs`), so
/// interactive-mode and exec-mode terminal output stay visually consistent.
pub fn format_connection_error(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn includes_all_context_layers() {
        // Build a nested error mirroring the real jump-chain wrapping:
        // destination auth failure -> destination channel-open failure ->
        // intermediate hop failure -> outer "establish jump host connection".
        let root = anyhow!("authentication failed for user 'alice' on '10.0.0.5:22'");
        let with_channel =
            root.context("Failed to open direct-tcpip channel to destination 10.0.0.5:22");
        let with_hop = with_channel.context("Failed to connect to jump host bastion (hop 2)");
        let with_outer =
            with_hop.context("Failed to establish jump host connection to 10.0.0.5:22");

        let formatted = format_connection_error(&with_outer);

        assert!(
            formatted.contains("Failed to establish jump host connection to 10.0.0.5:22"),
            "missing outer context layer in: {formatted}"
        );
        assert!(
            formatted.contains("Failed to connect to jump host bastion (hop 2)"),
            "missing intermediate hop layer in: {formatted}"
        );
        assert!(
            formatted.contains("Failed to open direct-tcpip channel to destination 10.0.0.5:22"),
            "missing channel-open layer in: {formatted}"
        );
        assert!(
            formatted.contains("authentication failed for user 'alice' on '10.0.0.5:22'"),
            "missing innermost root cause in: {formatted}"
        );
    }

    #[test]
    fn distinguishes_different_failure_hops() {
        // A first-jump-hop failure and a destination-auth failure should
        // produce visibly different formatted output (both must contain
        // their own innermost cause), so the user can tell them apart.
        let first_jump_root = anyhow!("connection refused");
        let first_jump = first_jump_root.context("Failed to connect to first jump host: bastion1");

        let dest_auth_root = anyhow!("permission denied (publickey)");
        let dest_auth = dest_auth_root
            .context("Failed to authenticate to destination '10.0.0.5:22' as user 'alice'");

        let first_jump_msg = format_connection_error(&first_jump);
        let dest_auth_msg = format_connection_error(&dest_auth);

        assert_ne!(first_jump_msg, dest_auth_msg);
        assert!(first_jump_msg.contains("connection refused"));
        assert!(dest_auth_msg.contains("permission denied (publickey)"));
    }

    #[test]
    fn single_layer_error_still_formats() {
        // Guard against the helper depending on multi-layer chains: a bare
        // error with no added context should just render its own message.
        let error = anyhow!("simple failure");
        assert_eq!(format_connection_error(&error), "simple failure");
    }
}

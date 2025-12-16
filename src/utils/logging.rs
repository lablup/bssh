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

use crate::ui::tui::log_buffer::LogBuffer;
use crate::ui::tui::log_layer::TuiLogLayer;
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{prelude::*, EnvFilter};

/// Global log buffer for TUI mode
static LOG_BUFFER: OnceCell<Arc<Mutex<LogBuffer>>> = OnceCell::new();

/// Create an environment filter based on verbosity level
pub fn create_env_filter(verbosity: u8) -> EnvFilter {
    if std::env::var("RUST_LOG").is_ok() {
        // Use RUST_LOG if set (allows debugging russh and other dependencies)
        EnvFilter::from_default_env()
    } else {
        // Fall back to verbosity-based filter
        match verbosity {
            0 => EnvFilter::new("bssh=warn"),
            1 => EnvFilter::new("bssh=info"),
            // -vv: Include russh debug logs for SSH troubleshooting
            2 => EnvFilter::new("bssh=debug,russh=debug"),
            // -vvv: Full trace including all dependencies
            _ => EnvFilter::new("bssh=trace,russh=trace,russh_sftp=debug"),
        }
    }
}

/// Check if TUI mode is likely to be used
///
/// TUI is used when:
/// - stdout is a TTY (interactive terminal)
/// - CI environment variable is not set
fn is_tui_likely() -> bool {
    // Check if stdout is a TTY
    let is_tty = atty::is(atty::Stream::Stdout);

    // Check if we're in a CI environment
    let in_ci = std::env::var("CI").is_ok();

    is_tty && !in_ci
}

/// Initialize logging with TUI support
///
/// Automatically detects whether TUI mode is likely and sets up appropriate logging:
/// - TUI mode: Uses TuiLogLayer to capture logs in a buffer (prevents screen corruption)
/// - Non-TUI mode: Uses standard fmt layer for console output
///
/// Returns the shared log buffer (may be empty if TUI is not used).
pub fn init_logging(verbosity: u8) -> Arc<Mutex<LogBuffer>> {
    let log_buffer = Arc::new(Mutex::new(LogBuffer::default()));
    let _ = LOG_BUFFER.set(Arc::clone(&log_buffer));

    let filter = create_env_filter(verbosity);

    if is_tui_likely() {
        // TUI mode: use TuiLogLayer to capture logs in buffer
        let tui_layer = TuiLogLayer::new(Arc::clone(&log_buffer));

        tracing_subscriber::registry()
            .with(filter)
            .with(tui_layer)
            .init();
    } else {
        // Non-TUI mode: use standard fmt layer for console output
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .init();
    }

    log_buffer
}

/// Initialize logging for console output only (non-TUI mode)
///
/// Use this when you know TUI will not be used (e.g., stream mode, file output).
pub fn init_logging_console_only(verbosity: u8) {
    let filter = create_env_filter(verbosity);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}

/// Initialize logging for TUI mode only
///
/// Use this when you know TUI will be used.
/// Returns the shared log buffer for TUI display.
pub fn init_logging_tui_only(verbosity: u8) -> Arc<Mutex<LogBuffer>> {
    let log_buffer = Arc::new(Mutex::new(LogBuffer::default()));
    let _ = LOG_BUFFER.set(Arc::clone(&log_buffer));

    let filter = create_env_filter(verbosity);
    let tui_layer = TuiLogLayer::new(Arc::clone(&log_buffer));

    tracing_subscriber::registry()
        .with(filter)
        .with(tui_layer)
        .init();

    log_buffer
}

/// Get the global log buffer
///
/// Returns the shared log buffer if logging has been initialized.
pub fn get_log_buffer() -> Option<Arc<Mutex<LogBuffer>>> {
    LOG_BUFFER.get().cloned()
}

// Stub functions for compatibility (no-op in non-reload mode)
pub fn disable_fmt_logging() {
    // No-op: fmt layer cannot be disabled without reload feature
    // In TUI mode, we initialize with TuiLogLayer only, so no fmt output
}

pub fn enable_fmt_logging() {
    // No-op: fmt layer cannot be re-enabled without reload feature
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_env_filter() {
        // Test verbosity levels create valid filters
        let _ = create_env_filter(0);
        let _ = create_env_filter(1);
        let _ = create_env_filter(2);
        let _ = create_env_filter(3);
    }
}

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

use tracing_subscriber::EnvFilter;

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

/// Initialize standard logging with console output
///
/// This is the default logging mode for non-TUI operation.
/// For TUI mode, use `crate::ui::tui::init_tui_logging()` instead
/// to capture logs in an in-memory buffer without breaking the TUI layout.
pub fn init_logging(verbosity: u8) {
    let filter = create_env_filter(verbosity);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true) // Show module targets for better debugging
        .init();
}

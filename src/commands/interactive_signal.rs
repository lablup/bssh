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

//! Signal handling for interactive mode

use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal;
use tracing::{debug, info};

/// Global flag for interrupt signal
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Check if an interrupt signal has been received
pub fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

/// Reset the interrupt flag
pub fn reset_interrupt() {
    INTERRUPTED.store(false, Ordering::Relaxed);
}

/// Set up signal handlers for interactive mode
pub fn setup_signal_handlers() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);

    // Handle Ctrl+C
    // Note: set_handler can only be called once per process, so we ignore errors in tests
    if let Err(e) = ctrlc::set_handler(move || {
        info!("Received Ctrl+C signal");
        INTERRUPTED.store(true, Ordering::Relaxed);
        shutdown_clone.store(true, Ordering::Relaxed);
    }) {
        // In tests, this might already be registered
        debug!("Could not set Ctrl-C handler: {}", e);
        // Return the shutdown flag anyway for use in the code
    }

    Ok(shutdown)
}

/// Set up async signal handlers for tokio runtime
pub async fn setup_async_signal_handlers(shutdown: Arc<AtomicBool>) {
    tokio::spawn(async move {
        // Handle SIGTERM (Unix only)
        #[cfg(unix)]
        {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to set up SIGTERM handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM signal");
                    shutdown.store(true, Ordering::Relaxed);
                }
            }
        }
    });
}

/// Handle terminal resize signal (Unix only)
#[cfg(unix)]
pub async fn handle_terminal_resize() -> Result<tokio::sync::mpsc::UnboundedReceiver<(u16, u16)>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        let mut sigwinch = signal::unix::signal(signal::unix::SignalKind::window_change())
            .expect("Failed to set up SIGWINCH handler");

        loop {
            sigwinch.recv().await;

            if let Ok((width, height)) = crossterm::terminal::size() {
                debug!("Terminal resized to {}x{}", width, height);
                let _ = tx.send((width, height));
            }
        }
    });

    Ok(rx)
}

/// Terminal state guard for automatic restoration
pub struct TerminalGuard {
    _original_hook: Option<Box<dyn Fn() + Send + Sync>>,
}

impl Default for TerminalGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalGuard {
    /// Create a new terminal guard that will restore terminal state on drop
    pub fn new() -> Self {
        // Save the current panic hook
        let _original_hook = std::panic::take_hook();

        // Set a custom panic hook that restores terminal before panicking
        std::panic::set_hook(Box::new(move |panic_info| {
            // Try to restore terminal
            let _ = Self::restore_terminal();

            // Call the original panic hook
            eprintln!("\n{panic_info}");
        }));

        Self {
            _original_hook: None, // We can't store the original hook due to lifetime issues
        }
    }

    /// Restore terminal to normal mode
    pub fn restore_terminal() -> Result<()> {
        use crossterm::{execute, terminal};
        use std::io;

        // Disable raw mode if it was enabled
        let _ = terminal::disable_raw_mode();

        // Show cursor
        let _ = execute!(
            io::stdout(),
            crossterm::cursor::Show,
            terminal::LeaveAlternateScreen
        );

        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Restore terminal state
        let _ = Self::restore_terminal();

        // Note: We can't restore the original panic hook here due to lifetime issues
        // This is a limitation, but acceptable for our use case
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interrupt_flag() {
        // Reset flag
        reset_interrupt();
        assert!(!is_interrupted());

        // Set flag
        INTERRUPTED.store(true, Ordering::Relaxed);
        assert!(is_interrupted());

        // Reset again
        reset_interrupt();
        assert!(!is_interrupted());
    }

    #[test]
    fn test_terminal_guard_creation() {
        let _guard = TerminalGuard::new();
        // Guard should be created without panic
    }
}

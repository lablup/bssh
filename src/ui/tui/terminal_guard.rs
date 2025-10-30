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

//! Terminal state guard for ensuring cleanup on panic or error
//!
//! This module provides RAII-style guards to ensure the terminal is always
//! restored to its original state, even if the program panics or returns
//! early due to an error.

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::{self, Write};
use tracing::{error, warn};

/// RAII guard for terminal raw mode
///
/// Automatically disables raw mode when dropped, ensuring terminal
/// is restored even on panic or error.
pub struct RawModeGuard {
    enabled: bool,
}

impl RawModeGuard {
    /// Enable raw mode and return a guard
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self { enabled: true })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = disable_raw_mode() {
                // We can't panic in drop, so just log the error
                error!("Failed to disable raw mode: {}", e);
                // Try to print to stderr directly as a last resort
                let _ = writeln!(io::stderr(), "\r\nWarning: Failed to restore terminal mode");
            } else {
                self.enabled = false;
            }
        }
    }
}

/// RAII guard for alternate screen
///
/// Automatically leaves alternate screen when dropped, ensuring terminal
/// is restored even on panic or error.
pub struct AlternateScreenGuard {
    stdout: io::Stdout,
    active: bool,
}

impl AlternateScreenGuard {
    /// Enter alternate screen and return a guard
    pub fn new() -> io::Result<Self> {
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        Ok(Self {
            stdout,
            active: true,
        })
    }

    /// Get a mutable reference to stdout
    pub fn stdout_mut(&mut self) -> &mut io::Stdout {
        &mut self.stdout
    }
}

impl Drop for AlternateScreenGuard {
    fn drop(&mut self) {
        if self.active {
            if let Err(e) = execute!(self.stdout, LeaveAlternateScreen) {
                error!("Failed to leave alternate screen: {}", e);
                // Try to print to stderr as a fallback
                let _ = writeln!(io::stderr(), "\r\nWarning: Failed to restore screen");
            } else {
                self.active = false;
            }
            // Also try to show cursor in case it was hidden
            let _ = execute!(self.stdout, crossterm::cursor::Show);
        }
    }
}

/// Combined terminal guard for both raw mode and alternate screen
///
/// This guard ensures complete terminal cleanup on drop.
pub struct TerminalGuard {
    _raw_mode: RawModeGuard,
    alternate_screen: AlternateScreenGuard,
}

impl TerminalGuard {
    /// Set up terminal for TUI mode with automatic cleanup on drop
    pub fn new() -> io::Result<Self> {
        // Order matters: raw mode first, then alternate screen
        let raw_mode = RawModeGuard::new()?;
        let alternate_screen = AlternateScreenGuard::new()?;

        Ok(Self {
            _raw_mode: raw_mode,
            alternate_screen,
        })
    }

    /// Get a mutable reference to stdout
    pub fn stdout_mut(&mut self) -> &mut io::Stdout {
        self.alternate_screen.stdout_mut()
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // The individual guards will handle their own cleanup
        // This is just for additional safety measures

        // Check if we're panicking
        if std::thread::panicking() {
            warn!("Terminal cleanup during panic");
            // Extra attempt to restore terminal
            let _ = execute!(io::stdout(), crossterm::cursor::Show);
            let _ = disable_raw_mode();
            // Force a terminal reset sequence
            let _ = write!(io::stderr(), "\x1b[0m\x1b[?25h");
            let _ = io::stderr().flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_creation() {
        // Note: These tests can't actually test terminal state changes
        // in a unit test environment, but we can verify the guards
        // are created without errors

        // Test that guards can be created and dropped without panic
        {
            let _guard = RawModeGuard { enabled: false };
            // Guard drops here
        }

        {
            let _guard = AlternateScreenGuard {
                stdout: io::stdout(),
                active: false,
            };
            // Guard drops here
        }
    }

    #[test]
    fn test_panic_handling() {
        // Simulate what happens during a panic
        // We can't actually enable raw mode in tests, but we can
        // verify the drop logic doesn't panic
        std::panic::catch_unwind(|| {
            let _guard = RawModeGuard { enabled: false };
            panic!("Test panic");
        })
        .unwrap_err();
    }
}

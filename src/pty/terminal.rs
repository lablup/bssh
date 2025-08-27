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

//! Terminal state management for PTY sessions.

use anyhow::{Context, Result};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use once_cell::sync::Lazy;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

/// Global terminal cleanup synchronization
/// Ensures only one cleanup attempt happens even with multiple guards
static TERMINAL_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static RAW_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Terminal state information that needs to be preserved and restored
#[derive(Debug, Clone)]
pub struct TerminalState {
    /// Whether raw mode was enabled before we took control
    pub was_raw_mode: bool,
    /// Terminal size when state was saved
    pub size: (u32, u32),
    /// Whether alternate screen buffer was in use
    pub was_alternate_screen: bool,
    /// Whether mouse reporting was enabled
    pub was_mouse_enabled: bool,
}

impl Default for TerminalState {
    fn default() -> Self {
        Self {
            was_raw_mode: false,
            size: (80, 24),
            was_alternate_screen: false,
            was_mouse_enabled: false,
        }
    }
}

/// RAII guard for terminal state management
///
/// This ensures that terminal state is properly restored even if
/// the PTY session is interrupted or fails.
pub struct TerminalStateGuard {
    saved_state: TerminalState,
    is_raw_mode_active: Arc<AtomicBool>,
    // Simplified cleanup - just track if we need cleanup
    _needs_cleanup: bool,
}

impl TerminalStateGuard {
    /// Create a new terminal state guard and enter raw mode
    pub fn new() -> Result<Self> {
        let saved_state = Self::save_terminal_state()?;
        let is_raw_mode_active = Arc::new(AtomicBool::new(false));

        // Enter raw mode with global synchronization
        let _guard = TERMINAL_MUTEX.lock().unwrap();
        if !RAW_MODE_ACTIVE.load(Ordering::SeqCst) {
            enable_raw_mode().with_context(|| "Failed to enable raw mode")?;
            RAW_MODE_ACTIVE.store(true, Ordering::SeqCst);
            is_raw_mode_active.store(true, Ordering::Relaxed);
        }

        Ok(Self {
            saved_state,
            is_raw_mode_active,
            _needs_cleanup: true,
        })
    }

    /// Create a terminal state guard without entering raw mode
    pub fn new_without_raw_mode() -> Result<Self> {
        let saved_state = Self::save_terminal_state()?;
        let is_raw_mode_active = Arc::new(AtomicBool::new(false));

        Ok(Self {
            saved_state,
            is_raw_mode_active,
            _needs_cleanup: false,
        })
    }

    /// Manually enter raw mode
    pub fn enter_raw_mode(&self) -> Result<()> {
        let _guard = TERMINAL_MUTEX.lock().unwrap();
        if !RAW_MODE_ACTIVE.load(Ordering::SeqCst) {
            enable_raw_mode().with_context(|| "Failed to enable raw mode")?;
            RAW_MODE_ACTIVE.store(true, Ordering::SeqCst);
            self.is_raw_mode_active.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Manually exit raw mode
    pub fn exit_raw_mode(&self) -> Result<()> {
        let _guard = TERMINAL_MUTEX.lock().unwrap();
        if RAW_MODE_ACTIVE.load(Ordering::SeqCst) {
            disable_raw_mode().with_context(|| "Failed to disable raw mode")?;
            RAW_MODE_ACTIVE.store(false, Ordering::SeqCst);
            self.is_raw_mode_active.store(false, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Check if raw mode is currently active
    pub fn is_raw_mode_active(&self) -> bool {
        self.is_raw_mode_active.load(Ordering::Relaxed)
    }

    /// Get the saved terminal state
    pub fn saved_state(&self) -> &TerminalState {
        &self.saved_state
    }

    /// Save current terminal state
    fn save_terminal_state() -> Result<TerminalState> {
        let size = if let Some((terminal_size::Width(w), terminal_size::Height(h))) =
            terminal_size::terminal_size()
        {
            (u32::from(w), u32::from(h))
        } else {
            (80, 24) // Default fallback
        };

        // TODO: Detect if we're already in raw mode, alternate screen, etc.
        // For now, assume we're starting from a clean state
        Ok(TerminalState {
            was_raw_mode: false,
            size,
            was_alternate_screen: false,
            was_mouse_enabled: false,
        })
    }

    /// Restore terminal state to its original condition
    fn restore_terminal_state(&self) -> Result<()> {
        // Use global synchronization to prevent race conditions
        let _guard = TERMINAL_MUTEX.lock().unwrap();

        // Exit raw mode if it's globally active
        if RAW_MODE_ACTIVE.load(Ordering::SeqCst) {
            if let Err(e) = disable_raw_mode() {
                eprintln!("Warning: Failed to disable raw mode during cleanup: {e}");
            } else {
                RAW_MODE_ACTIVE.store(false, Ordering::SeqCst);
            }
        }

        // Mark our local state as cleaned
        if self.is_raw_mode_active.load(Ordering::Relaxed) {
            self.is_raw_mode_active.store(false, Ordering::Relaxed);
        }

        // TODO: Restore other terminal settings if needed
        // For now, just exiting raw mode is sufficient

        Ok(())
    }
}

impl Drop for TerminalStateGuard {
    fn drop(&mut self) {
        if let Err(e) = self.restore_terminal_state() {
            eprintln!("Warning: Failed to restore terminal state: {e}");
        }
    }
}

/// Force terminal cleanup - can be called from anywhere to ensure terminal is restored
pub fn force_terminal_cleanup() {
    let _guard = TERMINAL_MUTEX.lock().unwrap();
    if RAW_MODE_ACTIVE.load(Ordering::SeqCst) {
        let _ = disable_raw_mode();
        RAW_MODE_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Terminal operations for PTY sessions
pub struct TerminalOps;

impl TerminalOps {
    /// Enable mouse support in terminal
    pub fn enable_mouse() -> Result<()> {
        use crossterm::event::EnableMouseCapture;
        use crossterm::execute;

        execute!(std::io::stdout(), EnableMouseCapture)
            .with_context(|| "Failed to enable mouse capture")?;

        Ok(())
    }

    /// Disable mouse support in terminal
    pub fn disable_mouse() -> Result<()> {
        use crossterm::event::DisableMouseCapture;
        use crossterm::execute;

        execute!(std::io::stdout(), DisableMouseCapture)
            .with_context(|| "Failed to disable mouse capture")?;

        Ok(())
    }

    /// Enable alternate screen buffer
    pub fn enable_alternate_screen() -> Result<()> {
        use crossterm::execute;
        use crossterm::terminal::EnterAlternateScreen;

        execute!(std::io::stdout(), EnterAlternateScreen)
            .with_context(|| "Failed to enter alternate screen")?;

        Ok(())
    }

    /// Disable alternate screen buffer
    pub fn disable_alternate_screen() -> Result<()> {
        use crossterm::execute;
        use crossterm::terminal::LeaveAlternateScreen;

        execute!(std::io::stdout(), LeaveAlternateScreen)
            .with_context(|| "Failed to leave alternate screen")?;

        Ok(())
    }

    /// Clear the terminal screen
    pub fn clear_screen() -> Result<()> {
        use crossterm::execute;
        use crossterm::terminal::{Clear, ClearType};

        execute!(std::io::stdout(), Clear(ClearType::All))
            .with_context(|| "Failed to clear screen")?;

        Ok(())
    }

    /// Move cursor to home position (0, 0)
    pub fn cursor_home() -> Result<()> {
        use crossterm::cursor::MoveTo;
        use crossterm::execute;

        execute!(std::io::stdout(), MoveTo(0, 0))
            .with_context(|| "Failed to move cursor to home")?;

        Ok(())
    }

    /// Set terminal title
    pub fn set_title(title: &str) -> Result<()> {
        use crossterm::execute;
        use crossterm::terminal::SetTitle;

        execute!(std::io::stdout(), SetTitle(title))
            .with_context(|| "Failed to set terminal title")?;

        Ok(())
    }
}

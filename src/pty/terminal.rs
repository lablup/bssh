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

use std::sync::{
    Arc, LazyLock, Mutex, MutexGuard, PoisonError, TryLockError,
    atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result};
use crossterm::{
    event::EnableBracketedPaste,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode},
};

use crate::diagnosticln as eprintln;

use super::terminal_protocol::{ProtocolState, capture_protocol_state, write_terminal_cleanup};
use super::terminal_screen::ScreenModeTracker;

/// Global terminal cleanup synchronization
/// Ensures only one cleanup attempt happens even with multiple guards
static TERMINAL_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static SAVED_PROTOCOL_STATE: LazyLock<Mutex<Option<ProtocolState>>> =
    LazyLock::new(|| Mutex::new(None));
static RAW_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);
static TERMINAL_OWNER_ACTIVE: AtomicBool = AtomicBool::new(false);

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn publish_protocol_state(state: &ProtocolState) {
    *lock_recover(&SAVED_PROTOCOL_STATE) = Some(state.clone());
}

struct TerminalOwner;

impl TerminalOwner {
    fn acquire() -> Result<Self> {
        if TERMINAL_OWNER_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            anyhow::bail!("Another terminal state guard is already active");
        }
        Ok(Self)
    }
}

impl Drop for TerminalOwner {
    fn drop(&mut self) {
        TERMINAL_OWNER_ACTIVE.store(false, Ordering::SeqCst);
    }
}

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
    needs_cleanup: AtomicBool,
    protocol_cleanup_needed: bool,
    pending_input: Vec<u8>,
    protocol_state: ProtocolState,
    screen_mode_tracker: ScreenModeTracker,
    _owner: TerminalOwner,
}

impl TerminalStateGuard {
    /// Create a new terminal state guard and enter raw mode
    pub fn new() -> Result<Self> {
        let owner = TerminalOwner::acquire()?;
        let saved_state = Self::save_terminal_state()?;
        let is_raw_mode_active = Arc::new(AtomicBool::new(false));

        // Enter raw mode with global synchronization
        let _guard = TERMINAL_MUTEX.lock().unwrap();
        if !RAW_MODE_ACTIVE.load(Ordering::SeqCst) {
            enable_raw_mode().with_context(|| "Failed to enable raw mode")?;
            RAW_MODE_ACTIVE.store(true, Ordering::SeqCst);
            is_raw_mode_active.store(true, Ordering::Relaxed);
        }

        // This bounded query runs before the PTY input task exists, so terminal
        // replies cannot race normal input forwarding.
        let capture = capture_protocol_state(&mut std::io::stdout());
        let protocol_state = capture.state.clone();

        // Publish the snapshot before any later fallible setup so the caller's
        // forced cleanup can preserve it if construction returns an error.
        publish_protocol_state(&protocol_state);
        // Enable bracketed paste mode
        execute!(std::io::stdout(), EnableBracketedPaste)
            .with_context(|| "Failed to enable bracketed paste mode")?;

        Ok(Self {
            saved_state,
            is_raw_mode_active,
            needs_cleanup: AtomicBool::new(true),
            protocol_cleanup_needed: true,
            pending_input: capture.pending_input,
            protocol_state,
            screen_mode_tracker: ScreenModeTracker::new(),
            _owner: owner,
        })
    }

    /// Create a terminal state guard without entering raw mode
    pub fn new_without_raw_mode() -> Result<Self> {
        let owner = TerminalOwner::acquire()?;
        let saved_state = Self::save_terminal_state()?;
        let is_raw_mode_active = Arc::new(AtomicBool::new(false));

        Ok(Self {
            saved_state,
            is_raw_mode_active,
            needs_cleanup: AtomicBool::new(false),
            protocol_cleanup_needed: false,
            pending_input: Vec::new(),
            protocol_state: ProtocolState::default(),
            screen_mode_tracker: ScreenModeTracker::new(),
            _owner: owner,
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
        self.needs_cleanup.store(true, Ordering::Release);
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
        if !self.protocol_cleanup_needed {
            self.needs_cleanup.store(false, Ordering::Release);
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

    /// Take bytes read during the pre-input terminal query that were not replies.
    pub(crate) fn take_pending_input(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending_input)
    }

    /// Observe remote DEC 1049 transitions so safe teardown can leave a
    /// remote-owned alternate screen when bssh originally started on main.
    pub(crate) fn observe_remote_output(&mut self, output: &[u8]) {
        if let Some(current) = self.screen_mode_tracker.observe(output) {
            self.protocol_state.current_1049 = Some(current);
            publish_protocol_state(&self.protocol_state);
        }
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

        // Reset every terminal mode owned by the remote PTY through the same path
        // used by panic and last-resort cleanup.
        if self.protocol_cleanup_needed {
            write_terminal_cleanup(&mut std::io::stdout(), &self.protocol_state);
        }

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
        self.needs_cleanup.store(false, Ordering::Release);

        Ok(())
    }
}

impl Drop for TerminalStateGuard {
    fn drop(&mut self) {
        if self.needs_cleanup.load(Ordering::Acquire)
            && let Err(e) = self.restore_terminal_state()
        {
            eprintln!("Warning: Failed to restore terminal state: {e}");
        }
    }
}

/// Force terminal cleanup - can be called from anywhere to ensure terminal is restored.
///
/// This is a best-effort, infallible cleanup that disables bracketed paste, enhanced
/// keyboard reporting, and mouse tracking, resets alternate screen and cursor
/// visibility, and exits raw mode.
///
/// # Panic-safety
///
/// This function is safe to call from a panic hook. It uses `try_lock()` rather than
/// `lock()` so it never deadlocks if the panicking thread already holds
/// `TERMINAL_MUTEX` (re-entrant acquisition of `std::sync::Mutex` on the same thread
/// would otherwise deadlock), and it tolerates a poisoned mutex without secondary
/// panics. The underlying operations (stdout writes, `disable_raw_mode`) are
/// individually safe to run without the mutex; the lock only serializes concurrent
/// teardown attempts.
///
/// When `try_lock()` fails — whether because the mutex is already held or because it
/// is poisoned — the cleanup body **always executes** regardless. The word
/// "unsynchronized" in the inline comment means the cleanup runs without holding the
/// lock; it does **not** mean the cleanup is skipped.
pub fn force_terminal_cleanup() {
    // Acquire the mutex if we can, but never block or panic on it. If the mutex is
    // already held by this thread (re-entrant via panic hook) or poisoned by a
    // previous panic, fall through and run the cleanup unsynchronized — the
    // operations below are individually safe.
    let _guard = TERMINAL_MUTEX.try_lock().ok();

    let state = match SAVED_PROTOCOL_STATE.try_lock() {
        Ok(saved) => saved.clone(),
        Err(TryLockError::Poisoned(error)) => error.into_inner().clone(),
        Err(TryLockError::WouldBlock) => None,
    }
    .unwrap_or_default();
    write_terminal_cleanup(&mut std::io::stdout(), &state);

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

#[cfg(test)]
mod tests {
    use super::*;

    // TTY mutations are not observable under the test harness, so these tests
    // cover idempotency and synchronization behavior without enabling raw mode.

    /// Calling force_terminal_cleanup() twice in succession must not panic.
    ///
    /// In a non-TTY test environment RAW_MODE_ACTIVE is false (no test calls
    /// enable_raw_mode), so disable_raw_mode() is never invoked. The escape-
    /// sequence writes succeed silently against cargo's stdout pipe.
    #[test]
    fn test_force_terminal_cleanup_idempotent() {
        force_terminal_cleanup();
        force_terminal_cleanup();
        // Reaching here without a panic is the assertion.
    }

    /// When a Mutex is poisoned, try_lock() returns Err(TryLockError::Poisoned)
    /// and .ok() converts it to None — no secondary panic occurs. This mirrors
    /// the exact pattern used inside force_terminal_cleanup() for TERMINAL_MUTEX.
    ///
    /// We verify the property on a local Mutex so we never poison the global
    /// TERMINAL_MUTEX (which would break other tests in this process).
    #[test]
    fn test_try_lock_ok_survives_poisoned_mutex() {
        let m = Mutex::new(());

        // Poison the mutex by panicking while holding the lock.
        let _ = std::panic::catch_unwind(|| {
            let _guard = m.lock().unwrap();
            panic!("intentional poison");
        });

        assert!(m.is_poisoned(), "mutex should be poisoned after the above");

        // try_lock().ok() must yield None without panicking — the same
        // guarantee force_terminal_cleanup() relies on for TERMINAL_MUTEX.
        let guard = m.try_lock().ok();
        assert!(guard.is_none(), "expected None for a poisoned mutex");
        // Reaching here without a panic confirms resilience.
    }

    /// When a Mutex is currently held, try_lock() returns
    /// Err(TryLockError::WouldBlock) and .ok() yields None immediately —
    /// no blocking or deadlock. This mirrors the re-entrant panic-hook
    /// scenario that force_terminal_cleanup() is designed to survive.
    #[test]
    fn test_try_lock_ok_does_not_block_when_held() {
        let m = Mutex::new(());
        let _held = m.lock().unwrap(); // hold the lock on this thread

        // On std::sync::Mutex a second try_lock from the same thread is
        // Err(WouldBlock) (not a deadlock), and .ok() converts it to None.
        let guard = m.try_lock().ok();
        assert!(guard.is_none(), "expected None when lock is already held");
        // Reaching here without blocking confirms the non-deadlock guarantee.
    }

    #[test]
    fn test_terminal_state_default() {
        let state = TerminalState::default();
        assert!(!state.was_raw_mode);
        assert!(!state.was_alternate_screen);
        assert!(!state.was_mouse_enabled);
        assert_eq!(state.size, (80, 24));
    }

    #[test]
    #[serial_test::serial(terminal_owner)]
    fn test_terminal_owner_applies_to_non_raw_guard_and_releases_on_drop() {
        let guard = TerminalStateGuard::new_without_raw_mode().unwrap();
        assert!(!guard.needs_cleanup.load(Ordering::Acquire));
        assert!(TerminalStateGuard::new_without_raw_mode().is_err());

        drop(guard);

        assert!(TerminalOwner::acquire().is_ok());
    }

    #[test]
    fn test_lock_recover_allows_guaranteed_publication_after_poison() {
        let saved = Mutex::new(None);
        let _ = std::panic::catch_unwind(|| {
            let _guard = saved.lock().unwrap();
            panic!("intentional poison");
        });
        let expected = ProtocolState {
            main_kitty_flags: Some(7),
            ..ProtocolState::default()
        };

        *lock_recover(&saved) = Some(expected.clone());

        assert_eq!(*lock_recover(&saved), Some(expected));
    }
}

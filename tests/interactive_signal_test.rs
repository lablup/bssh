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

use bssh::commands::interactive_signal::{
    TerminalGuard, is_interrupted, reset_interrupt, setup_signal_handlers,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
fn test_interrupt_flag_operations() {
    // Start with clean state
    reset_interrupt();
    assert!(!is_interrupted(), "Flag should be false after reset");

    // Signal handlers will set the flag (we can't easily test actual signal)
    // but we can test the flag mechanism
    reset_interrupt();
    assert!(!is_interrupted());
}

#[test]
fn test_terminal_guard_creation_and_drop() {
    // Create guard
    {
        let _guard = TerminalGuard::new();
        // Guard should exist without panicking
    }
    // Guard should be dropped and terminal restored
    // (Can't easily test actual terminal restoration in unit test)
}

#[tokio::test]
async fn test_signal_handler_setup() {
    // Set up signal handlers
    let shutdown = setup_signal_handlers();
    assert!(shutdown.is_ok(), "Signal handler setup should succeed");

    let shutdown_flag = shutdown.unwrap();
    assert!(
        !shutdown_flag.load(Ordering::Relaxed),
        "Shutdown flag should be false initially"
    );
}

#[tokio::test]
async fn test_shutdown_flag_coordination() {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);

    // Spawn a task that checks the shutdown flag
    let handle = tokio::spawn(async move {
        let mut iterations = 0;
        while !shutdown_clone.load(Ordering::Relaxed) && iterations < 100 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            iterations += 1;
        }
        iterations
    });

    // Set the shutdown flag after a delay
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.store(true, Ordering::Relaxed);

    // Task should exit soon after flag is set
    let iterations = handle.await.unwrap();
    assert!(iterations < 100, "Task should exit before max iterations");
    assert!(
        iterations >= 4,
        "Task should run for some iterations before shutdown"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_terminal_resize_handler() {
    use bssh::commands::interactive_signal::handle_terminal_resize;

    // Set up resize handler
    let result = handle_terminal_resize().await;
    assert!(
        result.is_ok(),
        "Terminal resize handler should set up successfully"
    );

    let mut resize_rx = result.unwrap();

    // We can't easily trigger SIGWINCH in a test, but we can verify the channel works
    // by checking it doesn't block indefinitely
    let timeout_result = tokio::time::timeout(Duration::from_millis(100), resize_rx.recv()).await;

    // Should timeout (no resize signal sent)
    assert!(
        timeout_result.is_err(),
        "Should timeout when no resize signal"
    );
}

#[test]
fn test_terminal_restoration_on_panic() {
    // This test verifies that terminal guard sets up panic handler
    // We can't easily test the actual restoration, but we can verify
    // the guard doesn't panic during setup

    std::panic::catch_unwind(|| {
        let _guard = TerminalGuard::new();
        // Simulate some work
        std::thread::sleep(Duration::from_millis(10));
    })
    .expect("Terminal guard should not panic during normal operation");
}

// Mock interactive session for testing signal handling
struct MockInteractiveSession {
    shutdown: Arc<AtomicBool>,
    commands_received: Vec<String>,
}

impl MockInteractiveSession {
    fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            commands_received: Vec::new(),
        }
    }

    async fn run(&mut self) -> Result<usize, anyhow::Error> {
        let mut commands = 0;

        while !self.shutdown.load(Ordering::Relaxed) && !is_interrupted() {
            // Simulate processing
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Simulate receiving a command
            if commands < 5 {
                self.commands_received.push(format!("command_{commands}"));
                commands += 1;
            }
        }

        Ok(commands)
    }
}

#[tokio::test]
async fn test_mock_session_with_shutdown() {
    let mut session = MockInteractiveSession::new();
    let shutdown_clone = Arc::clone(&session.shutdown);

    // Run session in background
    let handle = tokio::spawn(async move { session.run().await });

    // Let it run for a bit
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Signal shutdown
    shutdown_clone.store(true, Ordering::Relaxed);

    // Session should complete
    let result = handle.await.unwrap();
    assert!(result.is_ok(), "Session should complete successfully");

    let commands = result.unwrap();
    assert!(commands > 0, "Should have processed some commands");
    assert!(commands <= 5, "Should not exceed max commands");
}

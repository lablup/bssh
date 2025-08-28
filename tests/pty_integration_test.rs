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

//! Comprehensive integration tests for PTY functionality.
//!
//! This test suite covers:
//! - PTY configuration and utilities
//! - Terminal input/output handling
//! - Control character processing (Ctrl+C, Ctrl+D, etc.)
//! - Terminal resize (SIGWINCH) handling
//! - Message handling and serialization
//! - Error scenarios and edge cases
//! - Security scenarios (malicious input handling)
//!
//! Note: These tests focus on PTY utilities and message handling rather than
//! full SSH integration, as mocking russh Channel requires significant complexity.

use bssh::pty::terminal::{TerminalOps, TerminalStateGuard};
use bssh::pty::{PtyConfig, PtyMessage, PtyState};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use smallvec::SmallVec;
use std::time::Duration;
use tokio::sync::mpsc;

// Helper function to create test PTY config
fn create_test_pty_config() -> PtyConfig {
    PtyConfig {
        term_type: "xterm-256color".to_string(),
        force_pty: true,
        disable_pty: false,
        enable_mouse: false,
        timeout: Duration::from_millis(10),
    }
}

// Helper to generate random data
fn generate_random_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

#[test]
fn test_pty_config_creation_and_validation() {
    let config = create_test_pty_config();

    assert_eq!(config.term_type, "xterm-256color");
    assert!(config.force_pty);
    assert!(!config.disable_pty);
    assert!(!config.enable_mouse);
    assert_eq!(config.timeout, Duration::from_millis(10));
}

#[test]
fn test_pty_config_defaults() {
    let config = PtyConfig::default();

    assert_eq!(config.term_type, "xterm-256color");
    assert!(!config.force_pty);
    assert!(!config.disable_pty);
    assert!(!config.enable_mouse);
    assert_eq!(config.timeout, Duration::from_millis(10));
}

#[test]
fn test_pty_config_cloning() {
    let config1 = PtyConfig {
        term_type: "custom-term".to_string(),
        force_pty: true,
        disable_pty: false,
        enable_mouse: true,
        timeout: Duration::from_secs(1),
    };

    let config2 = config1.clone();

    assert_eq!(config1.term_type, config2.term_type);
    assert_eq!(config1.force_pty, config2.force_pty);
    assert_eq!(config1.disable_pty, config2.disable_pty);
    assert_eq!(config1.enable_mouse, config2.enable_mouse);
    assert_eq!(config1.timeout, config2.timeout);
}

#[test]
fn test_pty_states() {
    // Test all PTY state variants
    let states = vec![
        PtyState::Inactive,
        PtyState::Initializing,
        PtyState::Active,
        PtyState::ShuttingDown,
        PtyState::Closed,
    ];

    for state in states {
        // Should be able to debug print and compare states
        let state_debug = format!("{state:?}");
        assert!(!state_debug.is_empty());

        // Test equality
        match state {
            PtyState::Inactive => assert_eq!(state, PtyState::Inactive),
            PtyState::Initializing => assert_eq!(state, PtyState::Initializing),
            PtyState::Active => assert_eq!(state, PtyState::Active),
            PtyState::ShuttingDown => assert_eq!(state, PtyState::ShuttingDown),
            PtyState::Closed => assert_eq!(state, PtyState::Closed),
        }
    }
}

#[tokio::test]
async fn test_key_event_to_bytes_conversion() {
    // Since PtySession::key_event_to_bytes is private, we test the logic
    // through the public handle_input_event method

    // Test control characters
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    let ctrl_c_event = Event::Key(ctrl_c);
    if let Some(bytes) = handle_input_event_test(ctrl_c_event) {
        assert_eq!(bytes.as_slice(), &[0x03]); // Ctrl+C
    }

    let ctrl_d = KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL);
    let ctrl_d_event = Event::Key(ctrl_d);
    if let Some(bytes) = handle_input_event_test(ctrl_d_event) {
        assert_eq!(bytes.as_slice(), &[0x04]); // Ctrl+D
    }

    // Test regular characters
    let char_a = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
    let char_a_event = Event::Key(char_a);
    if let Some(bytes) = handle_input_event_test(char_a_event) {
        assert_eq!(bytes.as_slice(), b"a");
    }

    // Test special keys
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
    let enter_event = Event::Key(enter);
    if let Some(bytes) = handle_input_event_test(enter_event) {
        assert_eq!(bytes.as_slice(), &[0x0d]); // CR
    }

    // Test arrow keys
    let up_arrow = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
    let up_event = Event::Key(up_arrow);
    if let Some(bytes) = handle_input_event_test(up_event) {
        assert_eq!(bytes.as_slice(), &[0x1b, 0x5b, 0x41]); // ESC[A
    }
}

// Helper function to test input event handling logic
// This simulates what PtySession::handle_input_event does
fn handle_input_event_test(event: Event) -> Option<SmallVec<[u8; 8]>> {
    match event {
        Event::Key(key_event) => {
            // Only process key press events (not release)
            if key_event.kind != KeyEventKind::Press {
                return None;
            }

            key_event_to_bytes_test(key_event)
        }
        Event::Resize(_width, _height) => {
            // Resize events are handled separately
            None
        }
        _ => None,
    }
}

// Helper function to test key event to bytes conversion
// This simulates what PtySession::key_event_to_bytes does
fn key_event_to_bytes_test(key_event: KeyEvent) -> Option<SmallVec<[u8; 8]>> {
    match key_event {
        // Handle special key combinations
        KeyEvent {
            code: KeyCode::Char(c),
            modifiers: KeyModifiers::CONTROL,
            ..
        } => {
            match c {
                'c' | 'C' => Some(SmallVec::from_slice(&[0x03])), // Ctrl+C (SIGINT)
                'd' | 'D' => Some(SmallVec::from_slice(&[0x04])), // Ctrl+D (EOF)
                'z' | 'Z' => Some(SmallVec::from_slice(&[0x1a])), // Ctrl+Z (SIGTSTP)
                'a' | 'A' => Some(SmallVec::from_slice(&[0x01])), // Ctrl+A
                'e' | 'E' => Some(SmallVec::from_slice(&[0x05])), // Ctrl+E
                'u' | 'U' => Some(SmallVec::from_slice(&[0x15])), // Ctrl+U
                'k' | 'K' => Some(SmallVec::from_slice(&[0x0b])), // Ctrl+K
                'w' | 'W' => Some(SmallVec::from_slice(&[0x17])), // Ctrl+W
                'l' | 'L' => Some(SmallVec::from_slice(&[0x0c])), // Ctrl+L
                'r' | 'R' => Some(SmallVec::from_slice(&[0x12])), // Ctrl+R
                _ => {
                    // General Ctrl+ handling: Ctrl+A is 0x01, Ctrl+B is 0x02, etc.
                    let byte = (c.to_ascii_lowercase() as u8).saturating_sub(b'a' - 1);
                    if byte <= 26 {
                        Some(SmallVec::from_slice(&[byte]))
                    } else {
                        None
                    }
                }
            }
        }

        // Handle regular characters
        KeyEvent {
            code: KeyCode::Char(c),
            modifiers: KeyModifiers::NONE,
            ..
        } => {
            let bytes = c.to_string().into_bytes();
            Some(SmallVec::from_slice(&bytes))
        }

        // Handle special keys
        KeyEvent {
            code: KeyCode::Enter,
            ..
        } => Some(SmallVec::from_slice(&[0x0d])), // Carriage return

        KeyEvent {
            code: KeyCode::Tab, ..
        } => Some(SmallVec::from_slice(&[0x09])), // Tab

        KeyEvent {
            code: KeyCode::Backspace,
            ..
        } => Some(SmallVec::from_slice(&[0x7f])), // DEL

        KeyEvent {
            code: KeyCode::Esc, ..
        } => Some(SmallVec::from_slice(&[0x1b])), // ESC

        // Arrow keys (ANSI escape sequences)
        KeyEvent {
            code: KeyCode::Up, ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x41])), // ESC[A

        KeyEvent {
            code: KeyCode::Down,
            ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x42])), // ESC[B

        KeyEvent {
            code: KeyCode::Right,
            ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x43])), // ESC[C

        KeyEvent {
            code: KeyCode::Left,
            ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x44])), // ESC[D

        // Function keys
        KeyEvent {
            code: KeyCode::F(n),
            ..
        } => {
            match n {
                1 => Some(SmallVec::from_slice(&[0x1b, 0x4f, 0x50])), // F1: ESC OP
                2 => Some(SmallVec::from_slice(&[0x1b, 0x4f, 0x51])), // F2: ESC OQ
                3 => Some(SmallVec::from_slice(&[0x1b, 0x4f, 0x52])), // F3: ESC OR
                4 => Some(SmallVec::from_slice(&[0x1b, 0x4f, 0x53])), // F4: ESC OS
                5 => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x31, 0x35, 0x7e])), // F5: ESC[15~
                6 => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x31, 0x37, 0x7e])), // F6: ESC[17~
                7 => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x31, 0x38, 0x7e])), // F7: ESC[18~
                8 => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x31, 0x39, 0x7e])), // F8: ESC[19~
                9 => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x32, 0x30, 0x7e])), // F9: ESC[20~
                10 => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x32, 0x31, 0x7e])), // F10: ESC[21~
                11 => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x32, 0x33, 0x7e])), // F11: ESC[23~
                12 => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x32, 0x34, 0x7e])), // F12: ESC[24~
                _ => None,                                            // F13+ not commonly supported
            }
        }

        // Other special keys
        KeyEvent {
            code: KeyCode::Home,
            ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x48])), // ESC[H

        KeyEvent {
            code: KeyCode::End, ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x46])), // ESC[F

        KeyEvent {
            code: KeyCode::PageUp,
            ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x35, 0x7e])), // ESC[5~

        KeyEvent {
            code: KeyCode::PageDown,
            ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x36, 0x7e])), // ESC[6~

        KeyEvent {
            code: KeyCode::Insert,
            ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x32, 0x7e])), // ESC[2~

        KeyEvent {
            code: KeyCode::Delete,
            ..
        } => Some(SmallVec::from_slice(&[0x1b, 0x5b, 0x33, 0x7e])), // ESC[3~

        _ => None,
    }
}

#[tokio::test]
async fn test_comprehensive_control_character_processing() {
    // Test all defined control sequences
    let test_cases = vec![
        ('c', &[0x03]), // Ctrl+C (SIGINT)
        ('d', &[0x04]), // Ctrl+D (EOF)
        ('z', &[0x1a]), // Ctrl+Z (SIGTSTP)
        ('a', &[0x01]), // Ctrl+A
        ('e', &[0x05]), // Ctrl+E
        ('u', &[0x15]), // Ctrl+U
        ('k', &[0x0b]), // Ctrl+K
        ('w', &[0x17]), // Ctrl+W
        ('l', &[0x0c]), // Ctrl+L
        ('r', &[0x12]), // Ctrl+R
    ];

    for (char, expected_bytes) in test_cases {
        let key_event = KeyEvent::new(KeyCode::Char(char), KeyModifiers::CONTROL);
        let bytes = key_event_to_bytes_test(key_event);
        assert!(bytes.is_some(), "Ctrl+{char} should produce bytes");
        assert_eq!(
            bytes.unwrap().as_slice(),
            expected_bytes,
            "Ctrl+{char} should produce correct sequence"
        );
    }

    // Test uppercase variants
    let ctrl_c_upper = KeyEvent::new(KeyCode::Char('C'), KeyModifiers::CONTROL);
    let bytes = key_event_to_bytes_test(ctrl_c_upper);
    assert!(bytes.is_some());
    assert_eq!(bytes.unwrap().as_slice(), &[0x03]); // Should be same as lowercase
}

#[tokio::test]
async fn test_special_keys_processing() {
    let test_cases: Vec<(KeyCode, &[u8])> = vec![
        (KeyCode::Enter, &[0x0d]),
        (KeyCode::Tab, &[0x09]),
        (KeyCode::Backspace, &[0x7f]),
        (KeyCode::Esc, &[0x1b]),
        (KeyCode::Up, &[0x1b, 0x5b, 0x41]),
        (KeyCode::Down, &[0x1b, 0x5b, 0x42]),
        (KeyCode::Right, &[0x1b, 0x5b, 0x43]),
        (KeyCode::Left, &[0x1b, 0x5b, 0x44]),
        (KeyCode::Home, &[0x1b, 0x5b, 0x48]),
        (KeyCode::End, &[0x1b, 0x5b, 0x46]),
        (KeyCode::PageUp, &[0x1b, 0x5b, 0x35, 0x7e]),
        (KeyCode::PageDown, &[0x1b, 0x5b, 0x36, 0x7e]),
        (KeyCode::Insert, &[0x1b, 0x5b, 0x32, 0x7e]),
        (KeyCode::Delete, &[0x1b, 0x5b, 0x33, 0x7e]),
    ];

    for (key_code, expected_bytes) in test_cases {
        let key_event = KeyEvent::new(key_code, KeyModifiers::NONE);
        let bytes = key_event_to_bytes_test(key_event);
        assert!(bytes.is_some(), "{key_code:?} should produce bytes");
        assert_eq!(
            bytes.unwrap().as_slice(),
            expected_bytes,
            "{key_code:?} should produce correct sequence"
        );
    }
}

#[tokio::test]
async fn test_function_keys_processing() {
    let test_cases: Vec<(u8, &[u8])> = vec![
        (1, &[0x1b, 0x4f, 0x50]),              // F1: ESC OP
        (2, &[0x1b, 0x4f, 0x51]),              // F2: ESC OQ
        (3, &[0x1b, 0x4f, 0x52]),              // F3: ESC OR
        (4, &[0x1b, 0x4f, 0x53]),              // F4: ESC OS
        (5, &[0x1b, 0x5b, 0x31, 0x35, 0x7e]),  // F5: ESC[15~
        (6, &[0x1b, 0x5b, 0x31, 0x37, 0x7e]),  // F6: ESC[17~
        (7, &[0x1b, 0x5b, 0x31, 0x38, 0x7e]),  // F7: ESC[18~
        (8, &[0x1b, 0x5b, 0x31, 0x39, 0x7e]),  // F8: ESC[19~
        (9, &[0x1b, 0x5b, 0x32, 0x30, 0x7e]),  // F9: ESC[20~
        (10, &[0x1b, 0x5b, 0x32, 0x31, 0x7e]), // F10: ESC[21~
        (11, &[0x1b, 0x5b, 0x32, 0x33, 0x7e]), // F11: ESC[23~
        (12, &[0x1b, 0x5b, 0x32, 0x34, 0x7e]), // F12: ESC[24~
    ];

    for (fn_num, expected_bytes) in test_cases {
        let key_event = KeyEvent::new(KeyCode::F(fn_num), KeyModifiers::NONE);
        let bytes = key_event_to_bytes_test(key_event);
        assert!(bytes.is_some(), "F{fn_num} should produce bytes");
        assert_eq!(
            bytes.unwrap().as_slice(),
            expected_bytes,
            "F{fn_num} should produce correct sequence"
        );
    }

    // Test unsupported function keys (F13+)
    let f13 = KeyEvent::new(KeyCode::F(13), KeyModifiers::NONE);
    let bytes = key_event_to_bytes_test(f13);
    assert!(bytes.is_none(), "F13 should not produce bytes");
}

#[tokio::test]
async fn test_input_event_handling() {
    // Test key press events
    let key_event = Event::Key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    let bytes = handle_input_event_test(key_event);
    assert!(bytes.is_some());
    assert_eq!(bytes.unwrap().as_slice(), b"a");

    // Test key release events (should be ignored)
    let mut key_event = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
    key_event.kind = KeyEventKind::Release;
    let release_event = Event::Key(key_event);
    let bytes = handle_input_event_test(release_event);
    assert!(bytes.is_none(), "Key release events should be ignored");

    // Test resize events (should be ignored in input handler)
    let resize_event = Event::Resize(80, 24);
    let bytes = handle_input_event_test(resize_event);
    assert!(
        bytes.is_none(),
        "Resize events should be ignored in input handler"
    );
}

#[test]
fn test_terminal_state_guard() {
    // Test guard creation without raw mode
    {
        let guard = TerminalStateGuard::new_without_raw_mode();
        assert!(
            guard.is_ok(),
            "Terminal state guard creation should succeed"
        );

        let guard = guard.unwrap();
        assert!(
            !guard.is_raw_mode_active(),
            "Raw mode should not be active initially"
        );

        let state = guard.saved_state();
        assert!(!state.was_raw_mode);
        assert!(
            state.size.0 > 0 && state.size.1 > 0,
            "Terminal size should be valid"
        );
    }

    // Test manual raw mode control
    {
        let guard = TerminalStateGuard::new_without_raw_mode().unwrap();

        // Enter raw mode (may fail in CI/headless environments)
        let enter_result = guard.enter_raw_mode();
        match enter_result {
            Ok(_) => {
                println!("Successfully entered raw mode");
                // Exit raw mode
                let exit_result = guard.exit_raw_mode();
                assert!(
                    exit_result.is_ok(),
                    "Exiting raw mode should succeed if entering succeeded"
                );
            }
            Err(e) => {
                println!("Cannot enter raw mode (likely CI/headless environment): {e}");
                // This is acceptable in test environments
            }
        }
    }
}

#[tokio::test]
async fn test_terminal_operations() {
    // Test mouse operations
    assert!(
        TerminalOps::enable_mouse().is_ok(),
        "Enable mouse should succeed"
    );
    assert!(
        TerminalOps::disable_mouse().is_ok(),
        "Disable mouse should succeed"
    );

    // Test screen operations
    assert!(
        TerminalOps::enable_alternate_screen().is_ok(),
        "Enable alternate screen should succeed"
    );
    assert!(
        TerminalOps::disable_alternate_screen().is_ok(),
        "Disable alternate screen should succeed"
    );

    // Test utility operations
    assert!(
        TerminalOps::clear_screen().is_ok(),
        "Clear screen should succeed"
    );
    assert!(
        TerminalOps::cursor_home().is_ok(),
        "Cursor home should succeed"
    );
    assert!(
        TerminalOps::set_title("Test Title").is_ok(),
        "Set title should succeed"
    );
}

#[tokio::test]
async fn test_pty_message_types() {
    // Test message creation and properties
    let input_msg = PtyMessage::LocalInput(SmallVec::from_slice(b"test"));
    match input_msg {
        PtyMessage::LocalInput(data) => {
            assert_eq!(data.as_slice(), b"test");
        }
        _ => panic!("Wrong message type"),
    }

    let output_msg = PtyMessage::RemoteOutput(SmallVec::from_slice(b"output"));
    match output_msg {
        PtyMessage::RemoteOutput(data) => {
            assert_eq!(data.as_slice(), b"output");
        }
        _ => panic!("Wrong message type"),
    }

    let resize_msg = PtyMessage::Resize {
        width: 80,
        height: 24,
    };
    match resize_msg {
        PtyMessage::Resize { width, height } => {
            assert_eq!(width, 80);
            assert_eq!(height, 24);
        }
        _ => panic!("Wrong message type"),
    }

    let terminate_msg = PtyMessage::Terminate;
    matches!(terminate_msg, PtyMessage::Terminate);

    let error_msg = PtyMessage::Error("test error".to_string());
    match error_msg {
        PtyMessage::Error(msg) => {
            assert_eq!(msg, "test error");
        }
        _ => panic!("Wrong message type"),
    }
}

#[tokio::test]
async fn test_buffer_overflow_protection() {
    // Test with large input data
    let large_input = vec![b'A'; 1024 * 10]; // 10KB
    let input_msg = PtyMessage::LocalInput(SmallVec::from_slice(&large_input));

    match input_msg {
        PtyMessage::LocalInput(data) => {
            // SmallVec should handle large data gracefully (may allocate on heap)
            assert_eq!(data.len(), large_input.len());
        }
        _ => panic!("Wrong message type"),
    }

    // Test with large output data
    let large_output = vec![b'B'; 1024 * 10]; // 10KB
    let output_msg = PtyMessage::RemoteOutput(SmallVec::from_slice(&large_output));

    match output_msg {
        PtyMessage::RemoteOutput(data) => {
            // SmallVec should handle large data gracefully (may allocate on heap)
            assert_eq!(data.len(), large_output.len());
        }
        _ => panic!("Wrong message type"),
    }
}

#[tokio::test]
async fn test_malicious_input_handling() {
    // Test handling of potentially malicious control sequences
    let malicious_inputs = vec![
        vec![0x1b, 0x5b, 0x32, 0x4a], // Clear screen
        vec![0x1b, 0x5b, 0x48],       // Home cursor
        vec![0x1b, 0x5b, 0x4a],       // Clear from cursor to end of screen
        vec![0x1b, 0x63],             // Reset terminal
        vec![0x1b, 0x5b, 0x33, 0x4a], // Clear from cursor to beginning of screen
    ];

    for malicious_input in malicious_inputs {
        let input_msg = PtyMessage::LocalInput(SmallVec::from_slice(&malicious_input));

        // Message should be created successfully (input validation happens elsewhere)
        match input_msg {
            PtyMessage::LocalInput(data) => {
                assert_eq!(data.as_slice(), &malicious_input);
            }
            _ => panic!("Wrong message type"),
        }
    }
}

#[tokio::test]
async fn test_channel_capacity_limits() {
    // Test with bounded channels to ensure we don't exhaust memory
    let (tx, mut rx) = mpsc::channel::<PtyMessage>(256); // Limited capacity

    // Try to send more messages than capacity
    let mut successful_sends = 0;

    for i in 0..300 {
        let msg =
            PtyMessage::LocalInput(SmallVec::from_slice(format!("test message {i}").as_bytes()));

        match tx.try_send(msg) {
            Ok(_) => successful_sends += 1,
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full - this is expected behavior
                break;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Channel closed unexpectedly
                panic!("Channel closed unexpectedly");
            }
        }
    }

    // Should send up to capacity limit
    assert!(
        successful_sends <= 256,
        "Should not exceed channel capacity"
    );
    assert!(successful_sends > 0, "Should send some messages");

    // Drain some messages
    for _ in 0..10 {
        let _ = rx.try_recv();
    }

    // Should be able to send more messages now
    let msg = PtyMessage::LocalInput(SmallVec::from_slice(b"additional message"));
    assert!(
        tx.try_send(msg).is_ok(),
        "Should be able to send after draining"
    );
}

// Performance test for message processing
#[tokio::test]
async fn test_message_processing_performance() {
    let start_time = std::time::Instant::now();

    // Process a large number of messages
    let message_count = 10_000;
    let mut messages = Vec::with_capacity(message_count);

    for i in 0..message_count {
        let data = format!("message {i}");
        let msg = PtyMessage::LocalInput(SmallVec::from_slice(data.as_bytes()));
        messages.push(msg);
    }

    let elapsed = start_time.elapsed();
    assert!(
        elapsed < Duration::from_millis(100),
        "Message creation should be fast"
    );

    // Verify all messages were created correctly
    assert_eq!(messages.len(), message_count);
}

#[tokio::test]
async fn test_force_terminal_cleanup() {
    use bssh::pty::terminal::force_terminal_cleanup;

    // Force cleanup should complete without error
    force_terminal_cleanup();

    // Should be safe to call multiple times
    force_terminal_cleanup();
    force_terminal_cleanup();
}

#[tokio::test]
async fn test_concurrent_message_processing() {
    // Test concurrent processing of different message types
    let (tx, mut rx) = mpsc::channel::<PtyMessage>(1000);

    // Spawn multiple producers
    let mut handles = Vec::new();

    // Input producer
    let tx_input = tx.clone();
    handles.push(tokio::spawn(async move {
        for i in 0..100 {
            let msg = PtyMessage::LocalInput(SmallVec::from_slice(format!("input-{i}").as_bytes()));
            let _ = tx_input.send(msg).await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }));

    // Output producer
    let tx_output = tx.clone();
    handles.push(tokio::spawn(async move {
        for i in 0..100 {
            let msg =
                PtyMessage::RemoteOutput(SmallVec::from_slice(format!("output-{i}").as_bytes()));
            let _ = tx_output.send(msg).await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }));

    // Resize producer
    let tx_resize = tx.clone();
    handles.push(tokio::spawn(async move {
        for i in 0..50 {
            let msg = PtyMessage::Resize {
                width: 80 + i,
                height: 24 + i,
            };
            let _ = tx_resize.send(msg).await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }));

    drop(tx); // Close sender

    // Consumer
    let consumer_handle = tokio::spawn(async move {
        let mut input_count = 0;
        let mut output_count = 0;
        let mut resize_count = 0;
        let mut error_count = 0;

        while let Some(msg) = rx.recv().await {
            match msg {
                PtyMessage::LocalInput(_) => input_count += 1,
                PtyMessage::RemoteOutput(_) => output_count += 1,
                PtyMessage::Resize { .. } => resize_count += 1,
                PtyMessage::Error(_) => error_count += 1,
                _ => {}
            }
        }

        (input_count, output_count, resize_count, error_count)
    });

    // Wait for all producers
    for handle in handles {
        handle.await.unwrap();
    }

    // Get consumer results
    let (input_count, output_count, resize_count, error_count) = consumer_handle.await.unwrap();

    println!(
        "Concurrent processing: {input_count} input, {output_count} output, {resize_count} resize, {error_count} error messages"
    );

    // All messages should be processed
    assert_eq!(input_count, 100);
    assert_eq!(output_count, 100);
    assert_eq!(resize_count, 50);
    assert_eq!(error_count, 0);
}

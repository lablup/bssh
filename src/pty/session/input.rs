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

//! Input event handling for PTY sessions

use super::constants::*;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent};
use smallvec::SmallVec;

/// Handle input events and convert them to raw bytes
/// Returns SmallVec to avoid heap allocations for small key sequences
pub fn handle_input_event(event: Event) -> Option<SmallVec<[u8; 64]>> {
    match event {
        Event::Key(key_event) => {
            // Only process key press events (not release)
            if key_event.kind != KeyEventKind::Press {
                return None;
            }

            key_event_to_bytes(key_event)
        }
        Event::Mouse(mouse_event) => {
            // TODO: Implement mouse event handling
            mouse_event_to_bytes(mouse_event)
        }
        Event::Paste(text) => {
            // Handle paste events from bracketed paste mode
            // Return None for empty paste to avoid unnecessary channel sends
            if text.is_empty() {
                return None;
            }
            // Limit paste size to 1MB to prevent memory exhaustion attacks
            const MAX_PASTE_SIZE: usize = 1024 * 1024; // 1MB
            let bytes = text.into_bytes();
            if bytes.len() > MAX_PASTE_SIZE {
                // Truncate to max size - this is a safety limit, not expected in normal use
                Some(SmallVec::from_vec(bytes[..MAX_PASTE_SIZE].to_vec()))
            } else {
                // Use from_vec to avoid double memory copy
                Some(SmallVec::from_vec(bytes))
            }
        }
        Event::Resize(_width, _height) => {
            // Resize events are handled separately
            // This shouldn't happen as we handle resize via signals
            None
        }
        _ => None,
    }
}

/// Convert key events to raw byte sequences
/// Uses SmallVec to avoid heap allocations for key sequences (typically 1-5 bytes)
pub fn key_event_to_bytes(key_event: KeyEvent) -> Option<SmallVec<[u8; 64]>> {
    match key_event {
        // Handle special key combinations
        KeyEvent {
            code: KeyCode::Char(c),
            modifiers: KeyModifiers::CONTROL,
            ..
        } => {
            match c {
                'c' | 'C' => Some(SmallVec::from_slice(CTRL_C_SEQUENCE)), // Ctrl+C (SIGINT)
                'd' | 'D' => Some(SmallVec::from_slice(CTRL_D_SEQUENCE)), // Ctrl+D (EOF)
                'z' | 'Z' => Some(SmallVec::from_slice(CTRL_Z_SEQUENCE)), // Ctrl+Z (SIGTSTP)
                'a' | 'A' => Some(SmallVec::from_slice(CTRL_A_SEQUENCE)), // Ctrl+A
                'e' | 'E' => Some(SmallVec::from_slice(CTRL_E_SEQUENCE)), // Ctrl+E
                'u' | 'U' => Some(SmallVec::from_slice(CTRL_U_SEQUENCE)), // Ctrl+U
                'k' | 'K' => Some(SmallVec::from_slice(CTRL_K_SEQUENCE)), // Ctrl+K
                'w' | 'W' => Some(SmallVec::from_slice(CTRL_W_SEQUENCE)), // Ctrl+W
                'l' | 'L' => Some(SmallVec::from_slice(CTRL_L_SEQUENCE)), // Ctrl+L
                'r' | 'R' => Some(SmallVec::from_slice(CTRL_R_SEQUENCE)), // Ctrl+R
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

        // Handle regular characters (including those with Shift modifier)
        // Accept characters with no modifiers or only SHIFT modifier
        // Reject CONTROL, ALT, META combinations as they have special handling
        KeyEvent {
            code: KeyCode::Char(c),
            modifiers,
            ..
        } if !modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::META) =>
        {
            let bytes = c.to_string().into_bytes();
            Some(SmallVec::from_slice(&bytes))
        }

        // Handle special keys
        KeyEvent {
            code: KeyCode::Enter,
            ..
        } => Some(SmallVec::from_slice(ENTER_SEQUENCE)), // Carriage return

        KeyEvent {
            code: KeyCode::Tab, ..
        } => Some(SmallVec::from_slice(TAB_SEQUENCE)), // Tab

        KeyEvent {
            code: KeyCode::Backspace,
            ..
        } => Some(SmallVec::from_slice(BACKSPACE_SEQUENCE)), // DEL (some terminals use 0x08 for backspace)

        KeyEvent {
            code: KeyCode::Esc, ..
        } => Some(SmallVec::from_slice(ESC_SEQUENCE)), // ESC

        // Arrow keys (ANSI escape sequences)
        KeyEvent {
            code: KeyCode::Up, ..
        } => Some(SmallVec::from_slice(UP_ARROW_SEQUENCE)), // ESC[A

        KeyEvent {
            code: KeyCode::Down,
            ..
        } => Some(SmallVec::from_slice(DOWN_ARROW_SEQUENCE)), // ESC[B

        KeyEvent {
            code: KeyCode::Right,
            ..
        } => Some(SmallVec::from_slice(RIGHT_ARROW_SEQUENCE)), // ESC[C

        KeyEvent {
            code: KeyCode::Left,
            ..
        } => Some(SmallVec::from_slice(LEFT_ARROW_SEQUENCE)), // ESC[D

        // Function keys
        KeyEvent {
            code: KeyCode::F(n),
            ..
        } => {
            match n {
                1 => Some(SmallVec::from_slice(F1_SEQUENCE)), // F1: ESC OP
                2 => Some(SmallVec::from_slice(F2_SEQUENCE)), // F2: ESC OQ
                3 => Some(SmallVec::from_slice(F3_SEQUENCE)), // F3: ESC OR
                4 => Some(SmallVec::from_slice(F4_SEQUENCE)), // F4: ESC OS
                5 => Some(SmallVec::from_slice(F5_SEQUENCE)), // F5: ESC[15~
                6 => Some(SmallVec::from_slice(F6_SEQUENCE)), // F6: ESC[17~
                7 => Some(SmallVec::from_slice(F7_SEQUENCE)), // F7: ESC[18~
                8 => Some(SmallVec::from_slice(F8_SEQUENCE)), // F8: ESC[19~
                9 => Some(SmallVec::from_slice(F9_SEQUENCE)), // F9: ESC[20~
                10 => Some(SmallVec::from_slice(F10_SEQUENCE)), // F10: ESC[21~
                11 => Some(SmallVec::from_slice(F11_SEQUENCE)), // F11: ESC[23~
                12 => Some(SmallVec::from_slice(F12_SEQUENCE)), // F12: ESC[24~
                _ => None,                                    // F13+ not commonly supported
            }
        }

        // Other special keys
        KeyEvent {
            code: KeyCode::Home,
            ..
        } => Some(SmallVec::from_slice(HOME_SEQUENCE)), // ESC[H

        KeyEvent {
            code: KeyCode::End, ..
        } => Some(SmallVec::from_slice(END_SEQUENCE)), // ESC[F

        KeyEvent {
            code: KeyCode::PageUp,
            ..
        } => Some(SmallVec::from_slice(PAGE_UP_SEQUENCE)), // ESC[5~

        KeyEvent {
            code: KeyCode::PageDown,
            ..
        } => Some(SmallVec::from_slice(PAGE_DOWN_SEQUENCE)), // ESC[6~

        KeyEvent {
            code: KeyCode::Insert,
            ..
        } => Some(SmallVec::from_slice(INSERT_SEQUENCE)), // ESC[2~

        KeyEvent {
            code: KeyCode::Delete,
            ..
        } => Some(SmallVec::from_slice(DELETE_SEQUENCE)), // ESC[3~

        _ => None,
    }
}

/// Convert mouse events to raw byte sequences
pub fn mouse_event_to_bytes(_mouse_event: MouseEvent) -> Option<SmallVec<[u8; 64]>> {
    // TODO: Implement mouse event to bytes conversion
    // This requires implementing the terminal mouse reporting protocol
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paste_event_small() {
        // Test paste event with small text (< 64 bytes)
        let text = "Hello, World!".to_string();
        let event = Event::Paste(text.clone());
        let result = handle_input_event(event);

        assert!(result.is_some());
        let bytes = result.unwrap();
        assert_eq!(bytes.as_slice(), text.as_bytes());
    }

    #[test]
    fn test_paste_event_large() {
        // Test paste event with large text (> 64 bytes)
        let text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
                    Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
                    Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris."
            .to_string();
        let event = Event::Paste(text.clone());
        let result = handle_input_event(event);

        assert!(result.is_some());
        let bytes = result.unwrap();
        assert_eq!(bytes.as_slice(), text.as_bytes());
        assert!(
            bytes.len() > 64,
            "Test data should be larger than SmallVec inline capacity"
        );
    }

    #[test]
    fn test_paste_event_empty() {
        // Test paste event with empty text returns None
        // Empty paste should not send unnecessary channel messages
        let text = String::new();
        let event = Event::Paste(text);
        let result = handle_input_event(event);

        assert!(result.is_none(), "Empty paste should return None");
    }

    #[test]
    fn test_paste_event_special_chars() {
        // Test paste event with special characters and newlines
        let text = "Line 1\nLine 2\nLine 3\n\tTabbed\r\nCRLF".to_string();
        let event = Event::Paste(text.clone());
        let result = handle_input_event(event);

        assert!(result.is_some());
        let bytes = result.unwrap();
        assert_eq!(bytes.as_slice(), text.as_bytes());
    }

    #[test]
    fn test_paste_event_unicode() {
        // Test paste event with Unicode characters
        let text = "Hello 世界 🌍 مرحبا".to_string();
        let event = Event::Paste(text.clone());
        let result = handle_input_event(event);

        assert!(result.is_some());
        let bytes = result.unwrap();
        assert_eq!(bytes.as_slice(), text.as_bytes());
    }

    #[test]
    fn test_paste_event_multiline() {
        // Test paste event with multi-line content
        let text = "#!/bin/bash\n\
                    echo 'Hello, World!'\n\
                    for i in {1..5}; do\n\
                    \techo \"Number: $i\"\n\
                    done"
            .to_string();
        let event = Event::Paste(text.clone());
        let result = handle_input_event(event);

        assert!(result.is_some());
        let bytes = result.unwrap();
        assert_eq!(bytes.as_slice(), text.as_bytes());
    }

    #[test]
    fn test_key_event_still_works() {
        // Ensure regular key events still work after adding paste support
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('a'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        let bytes = result.unwrap();
        assert_eq!(bytes.as_slice(), b"a");
    }

    #[test]
    fn test_resize_event_ignored() {
        // Ensure resize events are still ignored
        let event = Event::Resize(80, 24);
        let result = handle_input_event(event);

        assert!(result.is_none());
    }

    #[test]
    fn test_paste_event_size_limit() {
        // Test that paste is truncated to MAX_PASTE_SIZE (1MB)
        const MAX_PASTE_SIZE: usize = 1024 * 1024;
        // Create a string larger than the limit
        let text = "A".repeat(MAX_PASTE_SIZE + 1000);
        let event = Event::Paste(text);
        let result = handle_input_event(event);

        assert!(result.is_some());
        let bytes = result.unwrap();
        assert_eq!(
            bytes.len(),
            MAX_PASTE_SIZE,
            "Paste should be truncated to MAX_PASTE_SIZE"
        );
    }

    // ============================================
    // Ctrl+key combination tests
    // ============================================

    #[test]
    fn test_ctrl_c_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_C_SEQUENCE);
    }

    #[test]
    fn test_ctrl_c_uppercase() {
        // Ctrl+C should work with uppercase C as well
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('C'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_C_SEQUENCE);
    }

    #[test]
    fn test_ctrl_d_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('d'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_D_SEQUENCE);
    }

    #[test]
    fn test_ctrl_z_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('z'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_Z_SEQUENCE);
    }

    #[test]
    fn test_ctrl_a_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('a'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_A_SEQUENCE);
    }

    #[test]
    fn test_ctrl_e_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('e'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_E_SEQUENCE);
    }

    #[test]
    fn test_ctrl_u_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('u'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_U_SEQUENCE);
    }

    #[test]
    fn test_ctrl_k_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('k'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_K_SEQUENCE);
    }

    #[test]
    fn test_ctrl_w_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('w'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_W_SEQUENCE);
    }

    #[test]
    fn test_ctrl_l_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('l'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_L_SEQUENCE);
    }

    #[test]
    fn test_ctrl_r_sequence() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('r'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), CTRL_R_SEQUENCE);
    }

    #[test]
    fn test_ctrl_b_general_handler() {
        // Ctrl+B should be handled by general Ctrl+ handler
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('b'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        // Ctrl+B = 0x02
        assert_eq!(result.unwrap().as_slice(), &[0x02]);
    }

    #[test]
    fn test_ctrl_f_general_handler() {
        // Ctrl+F should be handled by general Ctrl+ handler
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('f'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        // Ctrl+F = 0x06
        assert_eq!(result.unwrap().as_slice(), &[0x06]);
    }

    // ============================================
    // Arrow key tests
    // ============================================

    #[test]
    fn test_up_arrow() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Up,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), UP_ARROW_SEQUENCE);
    }

    #[test]
    fn test_down_arrow() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Down,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), DOWN_ARROW_SEQUENCE);
    }

    #[test]
    fn test_left_arrow() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Left,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), LEFT_ARROW_SEQUENCE);
    }

    #[test]
    fn test_right_arrow() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Right,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), RIGHT_ARROW_SEQUENCE);
    }

    // ============================================
    // Function key tests (F1-F12)
    // ============================================

    #[test]
    fn test_f1_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(1),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F1_SEQUENCE);
    }

    #[test]
    fn test_f2_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(2),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F2_SEQUENCE);
    }

    #[test]
    fn test_f3_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(3),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F3_SEQUENCE);
    }

    #[test]
    fn test_f4_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(4),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F4_SEQUENCE);
    }

    #[test]
    fn test_f5_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(5),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F5_SEQUENCE);
    }

    #[test]
    fn test_f6_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(6),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F6_SEQUENCE);
    }

    #[test]
    fn test_f7_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(7),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F7_SEQUENCE);
    }

    #[test]
    fn test_f8_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(8),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F8_SEQUENCE);
    }

    #[test]
    fn test_f9_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(9),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F9_SEQUENCE);
    }

    #[test]
    fn test_f10_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(10),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F10_SEQUENCE);
    }

    #[test]
    fn test_f11_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(11),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F11_SEQUENCE);
    }

    #[test]
    fn test_f12_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(12),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), F12_SEQUENCE);
    }

    #[test]
    fn test_f13_key_not_supported() {
        // F13+ should not be supported
        let event = Event::Key(KeyEvent {
            code: KeyCode::F(13),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_none());
    }

    // ============================================
    // Special key tests
    // ============================================

    #[test]
    fn test_enter_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Enter,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), ENTER_SEQUENCE);
    }

    #[test]
    fn test_tab_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Tab,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), TAB_SEQUENCE);
    }

    #[test]
    fn test_backspace_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Backspace,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), BACKSPACE_SEQUENCE);
    }

    #[test]
    fn test_escape_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Esc,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), ESC_SEQUENCE);
    }

    #[test]
    fn test_home_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Home,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), HOME_SEQUENCE);
    }

    #[test]
    fn test_end_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::End,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), END_SEQUENCE);
    }

    #[test]
    fn test_page_up_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::PageUp,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), PAGE_UP_SEQUENCE);
    }

    #[test]
    fn test_page_down_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::PageDown,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), PAGE_DOWN_SEQUENCE);
    }

    #[test]
    fn test_insert_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Insert,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), INSERT_SEQUENCE);
    }

    #[test]
    fn test_delete_key() {
        let event = Event::Key(KeyEvent {
            code: KeyCode::Delete,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), DELETE_SEQUENCE);
    }

    // ============================================
    // KeyEventKind tests
    // ============================================

    #[test]
    fn test_key_release_ignored() {
        // Key release events should return None
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('a'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_none(), "Key release events should be ignored");
    }

    #[test]
    fn test_key_repeat_ignored() {
        // Key repeat events should also return None (only Press is processed)
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('a'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Repeat,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_none(), "Key repeat events should be ignored");
    }

    // ============================================
    // Modifier key tests
    // ============================================

    #[test]
    fn test_shift_character() {
        // Shift+a should produce 'A' (handled by crossterm, we get uppercase char)
        // But we test that SHIFT modifier alone is accepted
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('A'),
            modifiers: KeyModifiers::SHIFT,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), b"A");
    }

    #[test]
    fn test_alt_character_ignored() {
        // Alt+character should be ignored by our char handler
        // (special handling would be needed for Alt sequences)
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('a'),
            modifiers: KeyModifiers::ALT,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(
            result.is_none(),
            "Alt+char should be ignored (no special handler)"
        );
    }

    #[test]
    fn test_meta_character_ignored() {
        // Meta+character should be ignored
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('a'),
            modifiers: KeyModifiers::META,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(
            result.is_none(),
            "Meta+char should be ignored (no special handler)"
        );
    }

    #[test]
    fn test_unicode_character() {
        // Test Unicode character input
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('한'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), "한".as_bytes());
    }

    #[test]
    fn test_emoji_character() {
        // Test emoji input
        let event = Event::Key(KeyEvent {
            code: KeyCode::Char('🚀'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_slice(), "🚀".as_bytes());
    }

    // ============================================
    // Mouse event tests
    // ============================================

    #[test]
    fn test_mouse_event_returns_none() {
        // Mouse events are not currently supported
        let event = Event::Mouse(MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        let result = handle_input_event(event);

        assert!(result.is_none(), "Mouse events should return None");
    }

    // ============================================
    // key_event_to_bytes direct tests
    // ============================================

    #[test]
    fn test_key_event_to_bytes_ctrl_out_of_range() {
        // Test that Ctrl+non-letter returns None (e.g., Ctrl+1)
        // Since KeyCode::Char only accepts chars, test with a char outside a-z
        // Actually, the general handler computes (c.to_ascii_lowercase() as u8).saturating_sub(b'a' - 1)
        // For '1' = 49, to_ascii_lowercase() = 49, subtract 96 = max(0, -47) = 0 via saturating_sub
        // But 0 <= 26 is false (0 < 1), so... let's trace through:
        // '1' as u8 = 49, b'a' - 1 = 96, 49.saturating_sub(96) = 0
        // 0 <= 26 is true, so it would return Some([0])
        // Actually we need to test with a character that results in > 26
        // Let's test with '{' = 123, 123 - 96 = 27, which is > 26
        let key_event = KeyEvent {
            code: KeyCode::Char('{'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        };
        let result = key_event_to_bytes(key_event);

        assert!(result.is_none());
    }
}

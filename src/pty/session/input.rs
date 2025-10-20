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
pub fn handle_input_event(event: Event) -> Option<SmallVec<[u8; 8]>> {
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
pub fn key_event_to_bytes(key_event: KeyEvent) -> Option<SmallVec<[u8; 8]>> {
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
pub fn mouse_event_to_bytes(_mouse_event: MouseEvent) -> Option<SmallVec<[u8; 8]>> {
    // TODO: Implement mouse event to bytes conversion
    // This requires implementing the terminal mouse reporting protocol
    None
}

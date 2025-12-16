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

//! Terminal constants and key sequence definitions
//!
//! NOTE: Many key sequence constants are currently unused since we switched to
//! raw byte passthrough (see issue #87), but are kept for reference and potential
//! future debugging use.

// Allow dead code for unused key sequence constants
#![allow(dead_code)]

// Buffer size constants for allocation optimization
// These values are chosen based on empirical testing and SSH protocol characteristics

/// Maximum size for terminal key sequences (ANSI escape sequences are typically 3-7 bytes)
/// Value: 8 bytes - Accommodates the longest standard ANSI sequences (F-keys: ESC[2x~)
/// Rationale: Most key sequences are 1-5 bytes, 8 provides safe headroom without waste
pub const MAX_KEY_SEQUENCE_SIZE: usize = 8;

/// Buffer size for SSH I/O operations (4KB aligns with typical SSH packet sizes)
/// Value: 4096 bytes - Matches common SSH packet fragmentation boundaries
/// Rationale: SSH protocol commonly uses 4KB packets; larger buffers reduce syscalls
/// but increase memory usage. 4KB provides optimal balance for interactive sessions.
pub const SSH_IO_BUFFER_SIZE: usize = 4096;

/// Maximum size for terminal output chunks processed at once
/// Value: 1024 bytes - Balance between responsiveness and efficiency
/// Rationale: Smaller chunks improve perceived responsiveness for interactive use,
/// while still being large enough to batch terminal escape sequences efficiently.
pub const TERMINAL_OUTPUT_CHUNK_SIZE: usize = 1024;

/// PTY message channel sizing:
/// - 256 messages capacity balances memory usage with responsiveness
/// - Each message is ~8-64 bytes (key presses/small terminal output)
/// - Total memory: ~16KB worst case, prevents unbounded growth
/// - Large enough to handle burst input/output without blocking
pub const PTY_MESSAGE_CHANNEL_SIZE: usize = 256;

/// Input polling timeout design:
/// - 500ms provides good balance between CPU usage and responsiveness
/// - Longer than async timeouts (10-100ms) since this is blocking thread
/// - Still responsive enough that users won't notice delay
/// - Reduces CPU usage compared to tight polling loops
pub const INPUT_POLL_TIMEOUT_MS: u64 = 500;

/// Task cleanup timeout design:
/// - 100ms is sufficient for tasks to receive cancellation signal and exit
/// - Short timeout prevents hanging on cleanup but allows graceful shutdown
/// - Tasks should check cancellation signal frequently (10-50ms intervals)
pub const TASK_CLEANUP_TIMEOUT_MS: u64 = 100;

// Const arrays for frequently used key sequences to avoid repeated allocations.
/// Control key sequences - frequently used in terminal input
pub const CTRL_C_SEQUENCE: &[u8] = &[0x03]; // Ctrl+C (SIGINT)
pub const CTRL_D_SEQUENCE: &[u8] = &[0x04]; // Ctrl+D (EOF)
pub const CTRL_Z_SEQUENCE: &[u8] = &[0x1a]; // Ctrl+Z (SIGTSTP)
pub const CTRL_A_SEQUENCE: &[u8] = &[0x01]; // Ctrl+A
pub const CTRL_E_SEQUENCE: &[u8] = &[0x05]; // Ctrl+E
pub const CTRL_U_SEQUENCE: &[u8] = &[0x15]; // Ctrl+U
pub const CTRL_K_SEQUENCE: &[u8] = &[0x0b]; // Ctrl+K
pub const CTRL_W_SEQUENCE: &[u8] = &[0x17]; // Ctrl+W
pub const CTRL_L_SEQUENCE: &[u8] = &[0x0c]; // Ctrl+L
pub const CTRL_R_SEQUENCE: &[u8] = &[0x12]; // Ctrl+R

/// Special keys - frequently used in terminal input
pub const ENTER_SEQUENCE: &[u8] = &[0x0d]; // Carriage return
pub const TAB_SEQUENCE: &[u8] = &[0x09]; // Tab
pub const BACKSPACE_SEQUENCE: &[u8] = &[0x7f]; // DEL
pub const ESC_SEQUENCE: &[u8] = &[0x1b]; // ESC

/// Arrow keys - Application Cursor Keys mode (SS3 sequences)
/// ncurses applications (htop, etc.) typically expect this format when
/// DECCKM (DEC Cursor Key Mode) is enabled via \x1b[?1h
/// Most terminal emulators and applications (vim, neovim) accept both formats,
/// but ncurses strictly follows terminfo which often specifies SS3 format.
pub const UP_ARROW_SEQUENCE: &[u8] = &[0x1b, 0x4f, 0x41]; // ESC O A
pub const DOWN_ARROW_SEQUENCE: &[u8] = &[0x1b, 0x4f, 0x42]; // ESC O B
pub const RIGHT_ARROW_SEQUENCE: &[u8] = &[0x1b, 0x4f, 0x43]; // ESC O C
pub const LEFT_ARROW_SEQUENCE: &[u8] = &[0x1b, 0x4f, 0x44]; // ESC O D

/// Function keys - commonly used
pub const F1_SEQUENCE: &[u8] = &[0x1b, 0x4f, 0x50]; // F1: ESC OP
pub const F2_SEQUENCE: &[u8] = &[0x1b, 0x4f, 0x51]; // F2: ESC OQ
pub const F3_SEQUENCE: &[u8] = &[0x1b, 0x4f, 0x52]; // F3: ESC OR
pub const F4_SEQUENCE: &[u8] = &[0x1b, 0x4f, 0x53]; // F4: ESC OS
pub const F5_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x31, 0x35, 0x7e]; // F5: ESC[15~
pub const F6_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x31, 0x37, 0x7e]; // F6: ESC[17~
pub const F7_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x31, 0x38, 0x7e]; // F7: ESC[18~
pub const F8_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x31, 0x39, 0x7e]; // F8: ESC[19~
pub const F9_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x32, 0x30, 0x7e]; // F9: ESC[20~
pub const F10_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x32, 0x31, 0x7e]; // F10: ESC[21~
pub const F11_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x32, 0x33, 0x7e]; // F11: ESC[23~
pub const F12_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x32, 0x34, 0x7e]; // F12: ESC[24~

/// Other special keys
pub const HOME_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x48]; // ESC[H
pub const END_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x46]; // ESC[F
pub const PAGE_UP_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x35, 0x7e]; // ESC[5~
pub const PAGE_DOWN_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x36, 0x7e]; // ESC[6~
pub const INSERT_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x32, 0x7e]; // ESC[2~
pub const DELETE_SEQUENCE: &[u8] = &[0x1b, 0x5b, 0x33, 0x7e]; // ESC[3~

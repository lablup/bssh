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

//! Terminal mode configuration for PTY sessions

use russh::Pty;

/// Configure terminal modes for proper PTY behavior
///
/// Returns a vector of (Pty, u32) tuples that configure the remote PTY's terminal behavior.
/// These settings are critical for proper operation of interactive programs like sudo and passwd.
///
/// # Terminal Mode Configuration
///
/// The modes are configured to provide a standard Unix terminal environment:
/// - **Control Characters**: Ctrl+C (SIGINT), Ctrl+Z (SIGTSTP), Ctrl+D (EOF), etc.
/// - **Input Modes**: CR to NL mapping for Enter key, flow control disabled
/// - **Local Modes**: Signal generation, canonical mode, echo control (for password prompts)
/// - **Output Modes**: NL to CR-NL mapping for proper line endings
/// - **Control Modes**: 8-bit character size
///
/// These settings match typical Unix terminal configurations and ensure compatibility
/// with command-line utilities that depend on specific terminal behaviors.
pub fn configure_terminal_modes() -> Vec<(Pty, u32)> {
    vec![
        // Special control characters - complete set matching OpenSSH
        (Pty::VINTR, 0x03),    // Ctrl+C (SIGINT)
        (Pty::VQUIT, 0x1C),    // Ctrl+\ (SIGQUIT)
        (Pty::VERASE, 0x7F),   // DEL (Backspace)
        (Pty::VKILL, 0x15),    // Ctrl+U (Kill line)
        (Pty::VEOF, 0x04),     // Ctrl+D (EOF)
        (Pty::VEOL, 0xFF),     // Undefined (0xFF = disabled)
        (Pty::VEOL2, 0xFF),    // Undefined (0xFF = disabled)
        (Pty::VSTART, 0x11),   // Ctrl+Q (XON - resume output)
        (Pty::VSTOP, 0x13),    // Ctrl+S (XOFF - stop output)
        (Pty::VSUSP, 0x1A),    // Ctrl+Z (SIGTSTP)
        (Pty::VREPRINT, 0x12), // Ctrl+R (reprint current line)
        (Pty::VWERASE, 0x17),  // Ctrl+W (erase word)
        (Pty::VLNEXT, 0x16),   // Ctrl+V (literal next character)
        (Pty::VDISCARD, 0x0F), // Ctrl+O (discard output)
        // Input modes - comprehensive configuration
        (Pty::IGNPAR, 0),  // Don't ignore parity errors
        (Pty::PARMRK, 0),  // Don't mark parity errors
        (Pty::INPCK, 0),   // Disable input parity checking
        (Pty::ISTRIP, 0),  // Don't strip 8th bit
        (Pty::INLCR, 0),   // Don't map NL to CR on input
        (Pty::IGNCR, 0),   // Don't ignore CR
        (Pty::ICRNL, 1),   // Map CR to NL (Enter key works correctly)
        (Pty::IXON, 0),    // Disable flow control (Ctrl+S/Ctrl+Q usable)
        (Pty::IXANY, 0),   // Don't restart output on any character
        (Pty::IXOFF, 0),   // Disable input flow control
        (Pty::IMAXBEL, 1), // Ring bell on input queue full
        // Local modes - CRITICAL for sudo/passwd password prompts
        (Pty::ISIG, 1),    // Enable signal generation (Ctrl+C, Ctrl+Z work)
        (Pty::ICANON, 1),  // Enable canonical mode (line editing with backspace)
        (Pty::ECHO, 1),    // Enable echo (programs like sudo can disable for passwords)
        (Pty::ECHOE, 1),   // Visual erase (backspace removes characters visually)
        (Pty::ECHOK, 1),   // Echo newline after kill character
        (Pty::ECHONL, 0),  // Don't echo NL when echo is off
        (Pty::NOFLSH, 0),  // Flush after interrupt/quit (normal behavior)
        (Pty::TOSTOP, 0),  // Don't stop background processes writing to tty
        (Pty::IEXTEN, 1),  // Enable extended input processing
        (Pty::ECHOCTL, 1), // Echo control chars as ^X
        (Pty::ECHOKE, 1),  // Visual erase for kill character
        (Pty::PENDIN, 0),  // Don't retype pending input
        // Output modes - configure for proper line ending handling
        (Pty::OPOST, 1),  // Enable output processing
        (Pty::ONLCR, 1),  // Map NL to CR-NL (proper line endings)
        (Pty::OCRNL, 0),  // Don't map CR to NL on output
        (Pty::ONOCR, 0),  // Output CR even at column 0
        (Pty::ONLRET, 0), // NL doesn't do CR function
        // Control modes - 8-bit character size
        (Pty::CS8, 1),    // 8-bit character size (standard for modern terminals)
        (Pty::PARENB, 0), // Disable parity
        (Pty::PARODD, 0), // Even parity (when enabled)
        // Baud rate (nominal values for compatibility)
        (Pty::TTY_OP_ISPEED, 38400), // Input baud rate
        (Pty::TTY_OP_OSPEED, 38400), // Output baud rate
    ]
}

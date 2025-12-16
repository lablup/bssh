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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to find a mode's value in the modes list
    fn find_mode(modes: &[(Pty, u32)], target: Pty) -> Option<u32> {
        modes.iter().find(|(k, _)| *k == target).map(|(_, v)| *v)
    }

    #[test]
    fn test_configure_terminal_modes_returns_non_empty() {
        let modes = configure_terminal_modes();
        assert!(!modes.is_empty(), "Terminal modes should not be empty");
    }

    #[test]
    fn test_configure_terminal_modes_count() {
        let modes = configure_terminal_modes();
        // We expect a comprehensive set of terminal modes
        // Currently 38 modes: 14 control chars + 12 input modes + 10 local modes + 5 output modes + 3 control modes + 2 baud rates - some overlap
        assert!(
            modes.len() >= 30,
            "Expected at least 30 terminal modes, got {}",
            modes.len()
        );
    }

    #[test]
    fn test_control_characters_configured() {
        let modes = configure_terminal_modes();

        // Verify critical control characters
        assert_eq!(
            find_mode(&modes, Pty::VINTR),
            Some(0x03),
            "VINTR should be Ctrl+C (0x03)"
        );
        assert_eq!(
            find_mode(&modes, Pty::VEOF),
            Some(0x04),
            "VEOF should be Ctrl+D (0x04)"
        );
        assert_eq!(
            find_mode(&modes, Pty::VSUSP),
            Some(0x1A),
            "VSUSP should be Ctrl+Z (0x1A)"
        );
        assert_eq!(
            find_mode(&modes, Pty::VERASE),
            Some(0x7F),
            "VERASE should be DEL (0x7F)"
        );
        assert_eq!(
            find_mode(&modes, Pty::VKILL),
            Some(0x15),
            "VKILL should be Ctrl+U (0x15)"
        );
    }

    #[test]
    fn test_signal_generation_enabled() {
        let modes = configure_terminal_modes();

        // ISIG enables signal generation (critical for Ctrl+C, Ctrl+Z)
        assert_eq!(
            find_mode(&modes, Pty::ISIG),
            Some(1),
            "ISIG should be enabled for signal generation"
        );
    }

    #[test]
    fn test_canonical_mode_enabled() {
        let modes = configure_terminal_modes();

        // ICANON enables line editing (backspace, etc.)
        assert_eq!(
            find_mode(&modes, Pty::ICANON),
            Some(1),
            "ICANON should be enabled for line editing"
        );
    }

    #[test]
    fn test_echo_enabled() {
        let modes = configure_terminal_modes();

        // ECHO enables character echo (programs can disable for passwords)
        assert_eq!(
            find_mode(&modes, Pty::ECHO),
            Some(1),
            "ECHO should be enabled by default"
        );
    }

    #[test]
    fn test_cr_to_nl_mapping() {
        let modes = configure_terminal_modes();

        // ICRNL maps CR to NL (Enter key works correctly)
        assert_eq!(
            find_mode(&modes, Pty::ICRNL),
            Some(1),
            "ICRNL should be enabled for Enter key"
        );
    }

    #[test]
    fn test_output_processing() {
        let modes = configure_terminal_modes();

        // OPOST enables output processing
        assert_eq!(
            find_mode(&modes, Pty::OPOST),
            Some(1),
            "OPOST should be enabled for output processing"
        );
        // ONLCR maps NL to CR-NL (proper line endings)
        assert_eq!(
            find_mode(&modes, Pty::ONLCR),
            Some(1),
            "ONLCR should be enabled for proper line endings"
        );
    }

    #[test]
    fn test_8bit_character_size() {
        let modes = configure_terminal_modes();

        // CS8 enables 8-bit characters
        assert_eq!(
            find_mode(&modes, Pty::CS8),
            Some(1),
            "CS8 should be enabled for 8-bit characters"
        );
    }

    #[test]
    fn test_flow_control_disabled() {
        let modes = configure_terminal_modes();

        // Flow control disabled so Ctrl+S/Ctrl+Q work normally
        assert_eq!(
            find_mode(&modes, Pty::IXON),
            Some(0),
            "IXON should be disabled (no flow control)"
        );
        assert_eq!(
            find_mode(&modes, Pty::IXOFF),
            Some(0),
            "IXOFF should be disabled (no flow control)"
        );
    }

    #[test]
    fn test_baud_rates() {
        let modes = configure_terminal_modes();

        // Baud rates should be set (nominal values)
        assert_eq!(
            find_mode(&modes, Pty::TTY_OP_ISPEED),
            Some(38400),
            "Input baud rate should be 38400"
        );
        assert_eq!(
            find_mode(&modes, Pty::TTY_OP_OSPEED),
            Some(38400),
            "Output baud rate should be 38400"
        );
    }

    #[test]
    fn test_parity_disabled() {
        let modes = configure_terminal_modes();

        assert_eq!(
            find_mode(&modes, Pty::PARENB),
            Some(0),
            "Parity should be disabled"
        );
    }

    #[test]
    fn test_disabled_control_chars_set_to_0xff() {
        let modes = configure_terminal_modes();

        // Disabled control characters should be 0xFF
        assert_eq!(
            find_mode(&modes, Pty::VEOL),
            Some(0xFF),
            "VEOL should be disabled (0xFF)"
        );
        assert_eq!(
            find_mode(&modes, Pty::VEOL2),
            Some(0xFF),
            "VEOL2 should be disabled (0xFF)"
        );
    }

    #[test]
    fn test_extended_input_processing() {
        let modes = configure_terminal_modes();

        // IEXTEN enables extended processing (Ctrl+V literal, etc.)
        assert_eq!(
            find_mode(&modes, Pty::IEXTEN),
            Some(1),
            "IEXTEN should be enabled for extended input"
        );
    }

    #[test]
    fn test_no_duplicate_modes() {
        let modes = configure_terminal_modes();

        for (i, (mode_i, _)) in modes.iter().enumerate() {
            for (j, (mode_j, _)) in modes.iter().enumerate() {
                if i != j {
                    assert!(
                        mode_i != mode_j,
                        "Duplicate terminal mode found: {:?}",
                        mode_i
                    );
                }
            }
        }
    }

    #[test]
    fn test_all_control_chars_present() {
        let modes = configure_terminal_modes();

        // Check all expected control characters are present
        let control_chars = [
            Pty::VINTR,
            Pty::VQUIT,
            Pty::VERASE,
            Pty::VKILL,
            Pty::VEOF,
            Pty::VEOL,
            Pty::VEOL2,
            Pty::VSTART,
            Pty::VSTOP,
            Pty::VSUSP,
            Pty::VREPRINT,
            Pty::VWERASE,
            Pty::VLNEXT,
            Pty::VDISCARD,
        ];

        for ctrl in control_chars {
            assert!(
                find_mode(&modes, ctrl).is_some(),
                "Control character {:?} should be present",
                ctrl
            );
        }
    }

    #[test]
    fn test_xon_xoff_chars() {
        let modes = configure_terminal_modes();

        // VSTART (Ctrl+Q) and VSTOP (Ctrl+S) should be configured
        assert_eq!(
            find_mode(&modes, Pty::VSTART),
            Some(0x11),
            "VSTART should be Ctrl+Q (0x11)"
        );
        assert_eq!(
            find_mode(&modes, Pty::VSTOP),
            Some(0x13),
            "VSTOP should be Ctrl+S (0x13)"
        );
    }

    #[test]
    fn test_visual_erase_enabled() {
        let modes = configure_terminal_modes();

        // ECHOE enables visual erase (backspace removes characters visually)
        assert_eq!(
            find_mode(&modes, Pty::ECHOE),
            Some(1),
            "ECHOE should be enabled for visual erase"
        );
    }
}

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

use std::io::Write;

use super::terminal_protocol::{ModifyOtherKeys, ProtocolState};

const COMMON_RESET_PREFIX: &[u8] =
    b"\x1b[?2004l\x1b[<999u\x1b[=0u\x1b[>4;0m\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l";
const SELECT_MAIN_SCREEN: &[u8] = b"\x1b[?47l";
const SELECT_ALTERNATE_SCREEN: &[u8] = b"\x1b[?47h";
const KEYBOARD_RESET: &[u8] = b"\x1b[<999u\x1b[=0u\x1b[>4;0m";
const SHOW_CURSOR: &[u8] = b"\x1b[?25h";

/// Reset remote-owned modes on both screens and restore both captured states.
pub(crate) fn write_terminal_cleanup(writer: &mut impl Write, state: &ProtocolState) {
    let _ = (|| -> std::io::Result<()> {
        writer.write_all(COMMON_RESET_PREFIX)?;
        let Some(initial_alternate) = state.alternate_screen else {
            writer.write_all(b"\x1b[?1049l")?;
            writer.write_all(KEYBOARD_RESET)?;
            writer.write_all(SHOW_CURSOR)?;
            return writer.flush();
        };

        writer.write_all(screen_select(!initial_alternate))?;
        writer.write_all(KEYBOARD_RESET)?;
        write_kitty_restore(writer, kitty_flags(state, !initial_alternate))?;

        writer.write_all(screen_select(initial_alternate))?;
        writer.write_all(KEYBOARD_RESET)?;
        write_kitty_restore(writer, kitty_flags(state, initial_alternate))?;
        write_modify_other_keys_restore(writer, state.modify_other_keys)?;
        writer.write_all(SHOW_CURSOR)?;
        writer.flush()
    })();
}

fn screen_select(alternate: bool) -> &'static [u8] {
    if alternate {
        SELECT_ALTERNATE_SCREEN
    } else {
        SELECT_MAIN_SCREEN
    }
}

fn kitty_flags(state: &ProtocolState, alternate: bool) -> Option<u32> {
    if alternate {
        state.alternate_kitty_flags
    } else {
        state.main_kitty_flags
    }
}

fn write_kitty_restore(writer: &mut impl Write, flags: Option<u32>) -> std::io::Result<()> {
    if let Some(flags) = flags {
        write!(writer, "\x1b[={flags}u")?;
    }
    Ok(())
}

fn write_modify_other_keys_restore(
    writer: &mut impl Write,
    value: Option<ModifyOtherKeys>,
) -> std::io::Result<()> {
    match value {
        Some(ModifyOtherKeys::Value(value)) => write!(writer, "\x1b[>4;{value}m"),
        Some(ModifyOtherKeys::Disabled) => writer.write_all(b"\x1b[>4n"),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_both_screens_then_returns_to_initial_main() {
        let state = ProtocolState {
            main_kitty_flags: Some(31),
            alternate_kitty_flags: Some(15),
            modify_other_keys: Some(ModifyOtherKeys::Value(2)),
            alternate_screen: Some(false),
        };
        let mut output = Vec::new();

        write_terminal_cleanup(&mut output, &state);

        assert_eq!(
            output,
            b"\x1b[?2004l\x1b[<999u\x1b[=0u\x1b[>4;0m\
              \x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\
              \x1b[?47h\x1b[<999u\x1b[=0u\x1b[>4;0m\x1b[=15u\
              \x1b[?47l\x1b[<999u\x1b[=0u\x1b[>4;0m\
              \x1b[=31u\x1b[>4;2m\x1b[?25h"
        );
    }

    #[test]
    fn restores_both_screens_then_returns_to_initial_alternate() {
        let state = ProtocolState {
            main_kitty_flags: Some(3),
            alternate_kitty_flags: Some(7),
            modify_other_keys: Some(ModifyOtherKeys::Value(1)),
            alternate_screen: Some(true),
        };
        let mut output = Vec::new();

        write_terminal_cleanup(&mut output, &state);

        assert_eq!(
            output,
            b"\x1b[?2004l\x1b[<999u\x1b[=0u\x1b[>4;0m\
              \x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\
              \x1b[?47l\x1b[<999u\x1b[=0u\x1b[>4;0m\x1b[=3u\
              \x1b[?47h\x1b[<999u\x1b[=0u\x1b[>4;0m\
              \x1b[=7u\x1b[>4;1m\x1b[?25h"
        );
    }

    #[test]
    fn repeated_cleanup_restores_same_effective_state() {
        let state = ProtocolState {
            main_kitty_flags: Some(31),
            alternate_kitty_flags: Some(15),
            modify_other_keys: None,
            alternate_screen: Some(false),
        };
        let mut output = Vec::new();

        write_terminal_cleanup(&mut output, &state);
        write_terminal_cleanup(&mut output, &state);

        assert_eq!(
            output
                .windows(b"\x1b[=31u".len())
                .filter(|window| *window == b"\x1b[=31u")
                .count(),
            2
        );
    }
}

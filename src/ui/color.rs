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

//! Process-wide color policy with independent stdout and stderr detection.

use std::ffi::OsStr;
use std::fmt;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicU8, Ordering};

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

static COLOR_MODE: AtomicU8 = AtomicU8::new(ColorMode::Auto as u8);

pub fn configure_color(mode: ColorMode) {
    COLOR_MODE.store(mode as u8, Ordering::Relaxed);
}

fn configured_mode() -> ColorMode {
    match COLOR_MODE.load(Ordering::Relaxed) {
        value if value == ColorMode::Always as u8 => ColorMode::Always,
        value if value == ColorMode::Never as u8 => ColorMode::Never,
        _ => ColorMode::Auto,
    }
}

fn auto_color_enabled(is_terminal: bool, no_color: Option<&OsStr>, term: Option<&OsStr>) -> bool {
    is_terminal
        && !no_color.is_some_and(|value| !value.is_empty())
        && !term.is_some_and(|value| value.eq_ignore_ascii_case(OsStr::new("dumb")))
}

fn color_enabled_for(
    mode: ColorMode,
    is_terminal: bool,
    no_color: Option<&OsStr>,
    term: Option<&OsStr>,
) -> bool {
    match mode {
        ColorMode::Auto => auto_color_enabled(is_terminal, no_color, term),
        ColorMode::Always => true,
        ColorMode::Never => false,
    }
}

pub fn colors_enabled(stream: OutputStream) -> bool {
    let is_terminal = match stream {
        OutputStream::Stdout => std::io::stdout().is_terminal(),
        OutputStream::Stderr => std::io::stderr().is_terminal(),
    };
    color_enabled_for(
        configured_mode(),
        is_terminal,
        std::env::var_os("NO_COLOR").as_deref(),
        std::env::var_os("TERM").as_deref(),
    )
}

pub trait Colorize: fmt::Display {
    fn styled_for(&self, ansi_code: &'static str, stream: OutputStream) -> StyledText {
        StyledText {
            text: self.to_string(),
            ansi_code,
            stream,
        }
    }
    fn styled(&self, ansi_code: &'static str) -> StyledText {
        self.styled_for(ansi_code, OutputStream::Stdout)
    }
    fn red(&self) -> StyledText {
        self.styled("31")
    }
    fn red_stderr(&self) -> StyledText {
        self.styled_for("31", OutputStream::Stderr)
    }
    fn green(&self) -> StyledText {
        self.styled("32")
    }
    fn yellow(&self) -> StyledText {
        self.styled("33")
    }
    fn blue(&self) -> StyledText {
        self.styled("34")
    }
    fn cyan(&self) -> StyledText {
        self.styled("36")
    }
    fn bright_blue(&self) -> StyledText {
        self.styled("94")
    }
    fn bold(&self) -> StyledText {
        self.styled("1")
    }
    fn dimmed(&self) -> StyledText {
        self.styled("2")
    }
}

impl<T: fmt::Display> Colorize for T {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StyledText {
    text: String,
    ansi_code: &'static str,
    stream: OutputStream,
}

impl fmt::Display for StyledText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if colors_enabled(self.stream) {
            write!(formatter, "\x1b[{}m{}\x1b[0m", self.ansi_code, self.text)
        } else {
            formatter.write_str(&self.text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_requires_a_terminal() {
        assert!(!color_enabled_for(ColorMode::Auto, false, None, None));
        assert!(color_enabled_for(ColorMode::Auto, true, None, None));
    }

    #[test]
    fn auto_honors_non_empty_no_color_and_dumb_term() {
        assert!(!color_enabled_for(
            ColorMode::Auto,
            true,
            Some(OsStr::new("1")),
            None
        ));
        assert!(color_enabled_for(
            ColorMode::Auto,
            true,
            Some(OsStr::new("")),
            None
        ));
        assert!(!color_enabled_for(
            ColorMode::Auto,
            true,
            None,
            Some(OsStr::new("dumb"))
        ));
    }

    #[test]
    fn explicit_modes_override_environment_and_terminal_detection() {
        assert!(color_enabled_for(
            ColorMode::Always,
            false,
            Some(OsStr::new("1")),
            Some(OsStr::new("dumb")),
        ));
        assert!(!color_enabled_for(ColorMode::Never, true, None, None));
    }

    #[test]
    fn styled_text_tracks_its_destination_stream() {
        assert_eq!("stdout".red().stream, OutputStream::Stdout);
        assert_eq!("stderr".red_stderr().stream, OutputStream::Stderr);
    }
}

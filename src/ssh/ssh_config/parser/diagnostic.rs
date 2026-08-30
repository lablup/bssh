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

use std::{borrow::Cow, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiagnosticSource<'a> {
    Config {
        path: Option<&'a Path>,
        line_number: usize,
    },
    CliOption {
        option_number: usize,
    },
}

impl DiagnosticSource<'_> {
    pub(super) fn number(self) -> usize {
        match self {
            Self::Config { line_number, .. } => line_number,
            Self::CliOption { option_number } => option_number,
        }
    }

    pub(super) fn location(self) -> String {
        match self {
            Self::Config {
                path: Some(path),
                line_number,
            } => format!("{}:{line_number}", escape_diagnostic_path(path)),
            Self::Config {
                path: None,
                line_number,
            } => format!("line {line_number}"),
            Self::CliOption { option_number } => format!("-o option #{option_number}"),
        }
    }
}

pub(super) fn escape_diagnostic_field(value: &str) -> Cow<'_, str> {
    if !value.chars().any(char::is_control) {
        return Cow::Borrowed(value);
    }

    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    Cow::Owned(escaped)
}

fn escape_diagnostic_path(path: &Path) -> String {
    escape_diagnostic_field(&path.to_string_lossy()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_fields_escape_controls_but_preserve_printable_unicode() {
        assert_eq!(
            escape_diagnostic_field("경로/é/λ\r\n\t\u{1b}\u{7f}\u{85}"),
            "경로/é/λ\\r\\n\\t\\u{1b}\\u{7f}\\u{85}"
        );
        assert!(matches!(
            escape_diagnostic_field("경로/é/λ"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn diagnostic_locations_distinguish_files_lines_and_cli_options() {
        assert_eq!(
            DiagnosticSource::Config {
                path: Some(Path::new("safe\nFORGED")),
                line_number: 7,
            }
            .location(),
            "safe\\nFORGED:7"
        );
        assert_eq!(
            DiagnosticSource::Config {
                path: None,
                line_number: 3,
            }
            .location(),
            "line 3"
        );
        assert_eq!(
            DiagnosticSource::CliOption { option_number: 4 }.location(),
            "-o option #4"
        );
    }
}

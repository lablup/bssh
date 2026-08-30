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

pub(crate) fn escape_field(value: &str) -> Cow<'_, str> {
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

pub(crate) fn escape_path(path: &Path) -> Cow<'_, str> {
    match path.to_string_lossy() {
        Cow::Borrowed(value) => escape_field(value),
        Cow::Owned(value) => Cow::Owned(escape_field(&value).into_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_escape_controls_but_preserve_printable_unicode() {
        assert_eq!(
            escape_field("경로/é/λ\r\n\t\u{1b}\u{7f}\u{85}"),
            "경로/é/λ\\r\\n\\t\\u{1b}\\u{7f}\\u{85}"
        );
        assert!(matches!(escape_field("경로/é/λ"), Cow::Borrowed(_)));
    }

    #[test]
    fn paths_use_the_same_control_escaping_contract() {
        assert_eq!(escape_path(Path::new("safe\nFORGED")), "safe\\nFORGED");
        assert!(matches!(
            escape_path(Path::new("printable/경로")),
            Cow::Borrowed(_)
        ));
    }
}

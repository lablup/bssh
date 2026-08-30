// Copyright 2025 Lablup Inc. and Jeongkyu Shin
// Licensed under the Apache License, Version 2.0.

//! OpenSSH-compatible configuration argument lexing and serialization.

use anyhow::Result;

pub(super) fn tokenize(input: &str, line_number: usize) -> Result<Vec<String>> {
    let chars = input.chars().collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        while index < chars.len() && matches!(chars[index], ' ' | '\t') {
            index += 1;
        }
        if index == chars.len() || chars[index] == '#' {
            break;
        }

        let mut value = String::new();
        let mut quote = None;
        while index < chars.len() {
            let ch = chars[index];
            if ch == '\\' {
                let next = chars.get(index + 1).copied();
                if next.is_some_and(|next| {
                    matches!(next, '\\' | '\'' | '"') || (quote.is_none() && next == ' ')
                }) {
                    index += 1;
                    value.push(chars[index]);
                } else {
                    value.push(ch);
                }
            } else if quote.is_none() && matches!(ch, '\'' | '"') {
                quote = Some(ch);
            } else if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() && matches!(ch, ' ' | '\t') {
                break;
            } else {
                value.push(ch);
            }
            index += 1;
        }
        if quote.is_some() {
            anyhow::bail!("Invalid quotes at line {line_number}");
        }
        result.push(value);
    }
    Ok(result)
}

pub(super) fn encode(value: &str) -> Result<String> {
    if value.chars().any(|ch| matches!(ch, '\0' | '\r' | '\n')) {
        anyhow::bail!("Resolved SSH configuration contains an unsafe value");
    }
    let needs_quotes = value.is_empty()
        || value
            .chars()
            .any(|ch| matches!(ch, ' ' | '\t' | '#' | '\\' | '\'' | '"'));
    if !needs_quotes {
        return Ok(value.to_string());
    }
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for ch in value.chars() {
        if matches!(ch, '\\' | '\'' | '"') {
            encoded.push('\\');
        }
        encoded.push(ch);
    }
    encoded.push('"');
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::{encode, tokenize};

    #[test]
    fn matches_openssh_quote_escape_and_comment_rules() {
        assert_eq!(
            tokenize(
                r#"one "two three" 'four' five\ six seven\#eight # comment"#,
                1
            )
            .unwrap(),
            ["one", "two three", "four", "five six", r"seven\#eight"]
        );
        assert!(tokenize("'unterminated", 1).is_err());
    }

    #[test]
    fn encoded_values_round_trip_without_losing_boundaries() {
        for value in [
            "",
            "/tmp/a b",
            "a\tb",
            "a#b",
            "#",
            r#"a\"b'c"#,
            r"unknown\qescape",
        ] {
            let encoded = encode(value).unwrap();
            assert_eq!(tokenize(&encoded, 1).unwrap(), [value]);
        }
    }
}

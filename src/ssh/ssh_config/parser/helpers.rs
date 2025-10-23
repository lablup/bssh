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

//! Helper functions for SSH configuration parsing

use anyhow::Result;

/// Parse yes/no boolean values from SSH configuration
pub fn parse_yes_no(value: &str, line_number: usize) -> Result<bool> {
    match value.to_lowercase().as_str() {
        "yes" | "true" | "1" => Ok(true),
        "no" | "false" | "0" => Ok(false),
        _ => {
            anyhow::bail!("Invalid yes/no value '{value}' at line {line_number} (expected yes/no)")
        }
    }
}

/// Parse yes/no/ask tri-state values from SSH configuration
#[allow(dead_code)] // Will be used in future refactoring
pub fn parse_yes_no_ask(value: &str, line_number: usize) -> Result<String> {
    match value.to_lowercase().as_str() {
        "yes" | "no" | "ask" => Ok(value.to_lowercase()),
        _ => {
            anyhow::bail!("Invalid value '{value}' at line {line_number} (expected yes/no/ask)")
        }
    }
}

/// Validate that arguments are not empty
#[allow(dead_code)] // Will be used in future refactoring
pub fn require_argument(keyword: &str, args: &[String], line_number: usize) -> Result<()> {
    if args.is_empty() {
        anyhow::bail!("{keyword} requires a value at line {line_number}");
    }
    Ok(())
}

/// Parse an unsigned integer value with error context
#[allow(dead_code)] // Will be used in future refactoring
pub fn parse_u32(keyword: &str, value: &str, line_number: usize) -> Result<u32> {
    value.parse::<u32>().map_err(|_| {
        anyhow::anyhow!(
            "Invalid {keyword} value '{value}' at line {line_number} (expected a number)"
        )
    })
}

/// Validate string length to prevent memory exhaustion
#[allow(dead_code)] // Will be used in future refactoring
pub fn validate_string_length(
    keyword: &str,
    value: &str,
    max_length: usize,
    line_number: usize,
) -> Result<()> {
    if value.len() > max_length {
        anyhow::bail!(
            "{keyword} value at line {line_number} is too long (max {max_length} characters)"
        );
    }
    Ok(())
}

/// Check if a string contains potentially dangerous characters for shell injection
#[allow(dead_code)] // Will be used in future refactoring
pub fn check_no_shell_metacharacters(keyword: &str, value: &str, line_number: usize) -> Result<()> {
    const DANGEROUS_CHARS: &[char] = &[
        ';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\0', '\\',
    ];

    if value.chars().any(|c| DANGEROUS_CHARS.contains(&c)) {
        anyhow::bail!(
            "{keyword} value '{value}' at line {line_number} contains potentially dangerous characters"
        );
    }
    Ok(())
}

/// Validate hostname characters (alphanumeric, dots, hyphens, underscores)
#[allow(dead_code)] // Will be used in future refactoring
pub fn validate_hostname_chars(keyword: &str, value: &str, line_number: usize) -> Result<()> {
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        anyhow::bail!(
            "{keyword} value '{value}' at line {line_number} contains invalid characters. \
             Only alphanumeric characters, dots, hyphens, and underscores are allowed"
        );
    }

    // Additional validation: shouldn't start with dot or hyphen
    if value.starts_with('.') || value.starts_with('-') {
        anyhow::bail!(
            "{keyword} value '{value}' at line {line_number} cannot start with a dot or hyphen"
        );
    }

    Ok(())
}

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

//! Configuration utility functions.

use std::path::{Path, PathBuf};

/// Expand tilde (~) in path to home directory.
pub fn expand_tilde(path: &Path) -> PathBuf {
    if let Some(path_str) = path.to_str() {
        if path_str.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(path_str.replacen("~", &home, 1));
            }
        }
    }
    path.to_path_buf()
}

/// Expand environment variables in a string.
/// Supports ${VAR} and $VAR syntax.
pub fn expand_env_vars(input: &str) -> String {
    let mut result = input.to_string();
    let mut processed = 0;

    // Handle ${VAR} syntax
    while processed < result.len() {
        if let Some(start) = result[processed..].find("${") {
            let abs_start = processed + start;
            if let Some(end) = result[abs_start..].find('}') {
                let var_name = &result[abs_start + 2..abs_start + end];
                if !var_name.is_empty() && var_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    let replacement = std::env::var(var_name).unwrap_or_else(|_| {
                        tracing::debug!("Environment variable {} not found", var_name);
                        format!("${{{var_name}}}")
                    });
                    result.replace_range(abs_start..abs_start + end + 1, &replacement);
                    processed = abs_start + replacement.len();
                } else {
                    processed = abs_start + end + 1;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    // Handle $VAR syntax (but be careful not to expand ${} again)
    let mut i = 0;
    let bytes = result.as_bytes();
    let mut new_result = String::new();

    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] != b'{' {
            let start = i;
            i += 1;

            // Find the end of the variable name
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }

            if i > start + 1 {
                let var_name = match std::str::from_utf8(&bytes[start + 1..i]) {
                    Ok(name) => name,
                    Err(_) => {
                        // Invalid UTF-8 in environment variable name, skip
                        new_result.push('$');
                        continue;
                    }
                };
                let replacement = std::env::var(var_name).unwrap_or_else(|_| {
                    tracing::debug!("Environment variable {} not found", var_name);
                    match String::from_utf8(bytes[start..i].to_vec()) {
                        Ok(original) => original,
                        Err(_) => {
                            // Invalid UTF-8, use placeholder
                            format!("$INVALID_UTF8_{start}")
                        }
                    }
                });
                new_result.push_str(&replacement);
            } else {
                new_result.push('$');
            }
        } else {
            new_result.push(bytes[i] as char);
            i += 1;
        }
    }

    new_result
}

/// Get current username from environment or system.
pub fn get_current_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| {
            // Try to get current user from system
            whoami::username().unwrap_or_else(|_| "user".to_string())
        })
}

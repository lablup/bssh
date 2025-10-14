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

//! Path expansion and environment variable handling for SSH configuration
//!
//! This module provides secure path expansion capabilities with environment variable
//! substitution while preventing injection attacks and path traversal vulnerabilities.

use anyhow::Result;
use std::path::PathBuf;

use super::env_cache::GLOBAL_ENV_CACHE;

/// Expand tilde and environment variables in a path (secure implementation)
///
/// # Security Features
/// - Uses whitelist approach for environment variable expansion
/// - Prevents recursive expansion attacks
/// - Sanitizes expanded values to prevent injection
/// - Limits expansion depth to prevent infinite recursion
/// - Validates final expanded path for security
///
/// # Returns
/// * `Ok(PathBuf)` - Successfully expanded path
/// * `Err(anyhow::Error)` - Expansion failed due to security violations
pub(super) fn expand_path_internal(path: &str) -> Result<PathBuf> {
    let path = if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            home.join(stripped)
        } else {
            PathBuf::from(path)
        }
    } else {
        PathBuf::from(path)
    };

    // Secure environment variable expansion
    let path_str = path.to_string_lossy();
    if path_str.contains('$') {
        match secure_expand_environment_variables(&path_str) {
            Ok(expanded) => Ok(PathBuf::from(expanded)),
            Err(e) => {
                // Check if this is a security violation that should cause hard failure
                let error_msg = e.to_string();
                if error_msg.contains("Security violation") {
                    // Re-throw security violations - don't silently ignore them
                    Err(e.context("Environment variable expansion security violation"))
                } else {
                    tracing::warn!(
                        "Environment variable expansion failed for '{}': {}. Using original path.",
                        path_str,
                        e
                    );
                    Ok(path)
                }
            }
        }
    } else {
        Ok(path)
    }
}

/// Securely expand environment variables with whitelist and validation
///
/// # Security Implementation
/// - Only allows specific safe environment variables (whitelist approach)
/// - Prevents recursive expansion by limiting depth
/// - Sanitizes values to prevent secondary injection
/// - Validates expanded content for dangerous patterns
///
/// # Arguments
/// * `input` - The string containing environment variables to expand
///
/// # Returns
/// * `Ok(String)` - Successfully expanded string
/// * `Err(anyhow::Error)` - Expansion failed due to security restrictions
fn secure_expand_environment_variables(input: &str) -> Result<String> {
    // Maximum expansion depth to prevent infinite recursion
    const MAX_EXPANSION_DEPTH: usize = 5;

    // Whitelist of safe environment variables
    let safe_variables = std::collections::HashSet::from([
        // User identity variables (generally safe)
        "HOME",
        "USER",
        "LOGNAME",
        "USERNAME",
        // SSH-specific variables (contextually safe)
        "SSH_AUTH_SOCK",
        "SSH_CONNECTION",
        "SSH_CLIENT",
        "SSH_TTY",
        // Locale settings (safe for paths)
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        // Safe system variables
        "TMPDIR",
        "TEMP",
        "TMP",
        // Terminal-related (generally safe)
        "TERM",
        "COLORTERM",
    ]);

    // Variables that are explicitly dangerous and should never be expanded
    let dangerous_variables = std::collections::HashSet::from([
        "PATH",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "PERL5LIB",
        "RUBYLIB",
        "CLASSPATH",
        "IFS",
        "PS1",
        "PS2",
        "PS4",
        "PROMPT_COMMAND",
        "SHELL",
        "BASH_ENV",
        "ENV",
        "FCEDIT",
        "FPATH",
        "CDPATH",
        "GLOBIGNORE",
        "HISTFILE",
        "HISTSIZE",
        "MAILCHECK",
        "MAILPATH",
        "MANPATH",
    ]);

    let mut result = input.to_string();
    let mut expansion_depth = 0;
    let mut changed = true;

    // Iteratively expand variables until no more changes or max depth reached
    while changed && expansion_depth < MAX_EXPANSION_DEPTH {
        changed = false;
        expansion_depth += 1;

        // Find all variable references in current iteration
        let mut vars_to_expand = Vec::new();

        // Match ${VAR} pattern
        let mut pos = 0;
        while let Some(start) = result[pos..].find("${") {
            let abs_start = pos + start;
            if let Some(end) = result[abs_start + 2..].find('}') {
                let abs_end = abs_start + 2 + end;
                let var_name = &result[abs_start + 2..abs_end];
                vars_to_expand.push((abs_start, abs_end + 1, var_name.to_string(), true));
                pos = abs_end + 1;
            } else {
                // Unclosed brace - potential injection attempt
                anyhow::bail!(
                    "Security violation: Unclosed brace in environment variable expansion. \
                     This could indicate an injection attempt."
                );
            }
        }

        // Match $VAR pattern (simpler, more limited)
        pos = 0;
        while let Some(start) = result[pos..].find('$') {
            let abs_start = pos + start;
            if abs_start + 1 < result.len()
                && !result
                    .chars()
                    .nth(abs_start + 1)
                    .unwrap()
                    .is_ascii_alphabetic()
            {
                pos = abs_start + 1;
                continue;
            }

            // Find end of variable name
            let var_start = abs_start + 1;
            let var_end = result[var_start..]
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .map(|i| var_start + i)
                .unwrap_or(result.len());

            if var_start < var_end {
                let var_name = &result[var_start..var_end];
                // Only process if not already found as ${VAR}
                if !vars_to_expand
                    .iter()
                    .any(|(_, _, name, _)| name == var_name)
                {
                    vars_to_expand.push((abs_start, var_end, var_name.to_string(), false));
                }
            }
            pos = var_end.max(abs_start + 1);
        }

        // Sort by position (descending) to replace from end to start
        vars_to_expand.sort_by(|a, b| b.0.cmp(&a.0));

        // Process each variable
        for (start_pos, end_pos, var_name, is_braced) in vars_to_expand {
            // Security check: Is this variable dangerous?
            if dangerous_variables.contains(var_name.as_str()) {
                tracing::warn!(
                    "Blocked expansion of dangerous environment variable '{}'. \
                     This variable could be used for injection attacks.",
                    var_name
                );
                anyhow::bail!(
                    "Security violation: Attempted to expand dangerous environment variable '{var_name}'. \
                     Variables like PATH, LD_LIBRARY_PATH, LD_PRELOAD are not allowed for security reasons."
                );
            }

            // Security check: Is this variable in our whitelist?
            // Note: The environment cache now handles whitelist validation,
            // but we keep this check for defense in depth
            if !safe_variables.contains(var_name.as_str()) {
                tracing::warn!(
                    "Blocked expansion of non-whitelisted environment variable '{}'. \
                     Only specific safe variables are allowed.",
                    var_name
                );
                // For non-whitelisted variables, we continue without expanding rather than failing
                // This maintains compatibility while being secure
                continue;
            }

            // Get the variable value from cache
            match GLOBAL_ENV_CACHE.get_env_var(&var_name) {
                Ok(Some(var_value)) => {
                    // Security validation of the variable value
                    let sanitized_value = sanitize_environment_value(&var_value, &var_name)?;

                    // Replace the variable reference with the sanitized value
                    result.replace_range(start_pos..end_pos, &sanitized_value);
                    changed = true;

                    tracing::debug!(
                        "Expanded environment variable '{}' (length: {}) in path expansion",
                        var_name,
                        sanitized_value.len()
                    );
                }
                Ok(None) => {
                    // Variable not found or not whitelisted - leave as-is or replace with empty based on SSH conventions
                    if is_braced {
                        // ${VAR} when VAR doesn't exist typically becomes empty
                        result.replace_range(start_pos..end_pos, "");
                        changed = true;
                    }
                    // $VAR when VAR doesn't exist is typically left as-is
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to get environment variable '{}' from cache: {}. Skipping expansion.",
                        var_name,
                        e
                    );
                    // Continue without expanding - fail safely
                }
            }
        }
    }

    // Security check: Did we hit the expansion depth limit?
    if expansion_depth >= MAX_EXPANSION_DEPTH {
        anyhow::bail!(
            "Security violation: Environment variable expansion depth limit exceeded ({MAX_EXPANSION_DEPTH} levels). \
             This could indicate a recursive expansion attack."
        );
    }

    // Final security validation of the result
    validate_expanded_path_content(&result)?;

    Ok(result)
}

/// Sanitize environment variable values to prevent secondary injection
///
/// # Security Features
/// - Removes or escapes dangerous shell metacharacters
/// - Validates against known dangerous patterns
/// - Prevents path traversal sequences in values
/// - Limits value length to prevent DoS
///
/// # Arguments
/// * `value` - The environment variable value to sanitize
/// * `var_name` - The variable name (for error reporting)
///
/// # Returns
/// * `Ok(String)` - Sanitized value safe for use
/// * `Err(anyhow::Error)` - Value contains dangerous content that cannot be sanitized
fn sanitize_environment_value(value: &str, var_name: &str) -> Result<String> {
    // Limit value length to prevent DoS attacks
    const MAX_VALUE_LENGTH: usize = 4096;
    if value.len() > MAX_VALUE_LENGTH {
        anyhow::bail!(
            "Security violation: Environment variable '{}' value is too long ({} bytes). \
             Maximum allowed length is {} bytes to prevent DoS attacks.",
            var_name,
            value.len(),
            MAX_VALUE_LENGTH
        );
    }

    // Check for null bytes (could be used for path truncation attacks)
    if value.contains('\0') {
        anyhow::bail!(
            "Security violation: Environment variable '{var_name}' contains null byte. \
             This could be used for path truncation attacks."
        );
    }

    // Check for dangerous shell metacharacters that could enable injection
    const DANGEROUS_CHARS: &[char] = &[';', '&', '|', '`', '\n', '\r'];
    if let Some(dangerous_char) = value.chars().find(|c| DANGEROUS_CHARS.contains(c)) {
        anyhow::bail!(
            "Security violation: Environment variable '{var_name}' contains dangerous character '{dangerous_char}'. \
             This could enable command injection attacks."
        );
    }

    // Check for command substitution patterns
    if value.contains("$(") || value.contains("${") {
        anyhow::bail!(
            "Security violation: Environment variable '{var_name}' contains command substitution pattern. \
             This could enable command injection attacks."
        );
    }

    // Check for path traversal sequences
    if value.contains("../") || value.contains("..\\") {
        // For some variables like HOME, relative paths might be legitimate
        // but we should be very cautious
        match var_name {
            "HOME" | "TMPDIR" | "TEMP" | "TMP" => {
                // For these variables, warn but allow (they're typically set by the system)
                tracing::warn!(
                    "Environment variable '{}' contains path traversal sequence '{}'. \
                     This may be legitimate for system variables but could indicate an attack.",
                    var_name,
                    value
                );
            }
            _ => {
                anyhow::bail!(
                    "Security violation: Environment variable '{var_name}' contains path traversal sequence. \
                     This could enable directory traversal attacks."
                );
            }
        }
    }

    // Additional validation for specific variable types
    match var_name {
        "SSH_AUTH_SOCK" => {
            // Should be a socket path, typically in /tmp or similar
            if !value.starts_with('/') && !value.starts_with("./") {
                tracing::warn!(
                    "SSH_AUTH_SOCK '{}' does not look like a typical socket path",
                    value
                );
            }
        }
        "HOME" => {
            // Should be an absolute path to a directory
            if !value.starts_with('/') && !value.contains(":\\") {
                tracing::warn!(
                    "HOME '{}' does not look like a typical home directory path",
                    value
                );
            }
        }
        _ => {}
    }

    Ok(value.to_string())
}

/// Validate the final expanded path content for security
///
/// # Security Features
/// - Checks for remaining dangerous patterns after expansion
/// - Validates overall path structure
/// - Ensures no injection sequences remain
///
/// # Arguments
/// * `expanded` - The fully expanded path string
///
/// # Returns
/// * `Ok(())` - Path content is safe
/// * `Err(anyhow::Error)` - Path contains dangerous patterns
fn validate_expanded_path_content(expanded: &str) -> Result<()> {
    // Check for any remaining unexpanded variables that could indicate failed injection
    if expanded.contains("$(") || expanded.contains("`") {
        anyhow::bail!(
            "Security violation: Expanded path still contains command substitution patterns. \
             This could indicate a sophisticated injection attempt."
        );
    }

    // Check for suspicious patterns that might have been introduced during expansion
    if expanded.contains("//") && !expanded.starts_with("http") {
        // Multiple slashes could indicate path confusion attacks
        tracing::debug!(
            "Expanded path contains multiple consecutive slashes: '{}'",
            expanded
        );
    }

    // Check length to prevent extremely long paths that could cause issues
    const MAX_PATH_LENGTH: usize = 4096;
    if expanded.len() > MAX_PATH_LENGTH {
        anyhow::bail!(
            "Security violation: Expanded path is too long ({} characters). \
             Maximum allowed length is {} characters.",
            expanded.len(),
            MAX_PATH_LENGTH
        );
    }

    // Check for control characters that could cause terminal escape sequences
    if expanded.chars().any(|c| c.is_control() && c != '\t') {
        anyhow::bail!(
            "Security violation: Expanded path contains control characters. \
             This could be used for terminal escape sequence attacks."
        );
    }

    Ok(())
}

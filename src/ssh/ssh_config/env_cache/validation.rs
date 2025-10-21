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

//! Environment variable validation and safety checks

use std::collections::HashSet;

/// Create the whitelist of safe environment variables
pub fn create_safe_variables() -> HashSet<&'static str> {
    // Define the whitelist of safe environment variables
    // This is the same whitelist used in path.rs for security
    HashSet::from([
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
    ])
}

/// Check if a variable is in the safe whitelist
#[allow(dead_code)]
pub fn is_safe_variable(var_name: &str, safe_variables: &HashSet<&str>) -> bool {
    safe_variables.contains(var_name)
}

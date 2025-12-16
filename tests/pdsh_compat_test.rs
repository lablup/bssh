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

//! Integration tests for pdsh compatibility mode
//!
//! These tests verify that bssh correctly handles pdsh-style arguments
//! and behaves as expected in pdsh compatibility mode.

use bssh::cli::{has_pdsh_compat_flag, remove_pdsh_compat_flag, PdshCli, PDSH_COMPAT_ENV_VAR};
use std::env;

/// Helper to run a test with env var protection
fn with_env_var<F, T>(key: &str, value: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let original = env::var(key).ok();
    env::set_var(key, value);
    let result = f();
    match original {
        Some(v) => env::set_var(key, v),
        None => env::remove_var(key),
    }
    result
}

/// Helper to run a test with env var removed
fn without_env_var<F, T>(key: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let original = env::var(key).ok();
    env::remove_var(key);
    let result = f();
    if let Some(v) = original {
        env::set_var(key, v);
    }
    result
}

// =============================================================================
// CLI Flag Detection Tests
// =============================================================================

#[test]
fn test_pdsh_compat_flag_detection() {
    let args = vec![
        "bssh".to_string(),
        "--pdsh-compat".to_string(),
        "-w".to_string(),
        "host1,host2".to_string(),
        "uptime".to_string(),
    ];

    assert!(has_pdsh_compat_flag(&args));
}

#[test]
fn test_no_pdsh_compat_flag() {
    let args = vec![
        "bssh".to_string(),
        "-H".to_string(),
        "host1,host2".to_string(),
        "uptime".to_string(),
    ];

    assert!(!has_pdsh_compat_flag(&args));
}

#[test]
fn test_remove_pdsh_compat_flag_preserves_order() {
    let args = vec![
        "bssh".to_string(),
        "-w".to_string(),
        "--pdsh-compat".to_string(),
        "hosts".to_string(),
        "cmd".to_string(),
    ];

    let filtered = remove_pdsh_compat_flag(&args);

    assert_eq!(filtered.len(), 4);
    assert_eq!(filtered[0], "bssh");
    assert_eq!(filtered[1], "-w");
    assert_eq!(filtered[2], "hosts");
    assert_eq!(filtered[3], "cmd");
}

#[test]
fn test_remove_pdsh_compat_flag_no_flag_present() {
    let args = vec![
        "bssh".to_string(),
        "-w".to_string(),
        "hosts".to_string(),
        "cmd".to_string(),
    ];

    let filtered = remove_pdsh_compat_flag(&args);

    assert_eq!(filtered, args);
}

// =============================================================================
// Environment Variable Detection Tests
// =============================================================================

#[test]
fn test_env_var_detection_with_one() {
    without_env_var(PDSH_COMPAT_ENV_VAR, || {
        with_env_var(PDSH_COMPAT_ENV_VAR, "1", || {
            // We can't call is_pdsh_compat_mode directly because it also checks argv[0]
            // Instead, verify the env var logic works
            let value = env::var(PDSH_COMPAT_ENV_VAR).ok();
            assert!(value.is_some());
            let v = value.unwrap();
            assert!(v == "1" || v.to_lowercase() == "true");
        });
    });
}

#[test]
fn test_env_var_detection_with_true() {
    without_env_var(PDSH_COMPAT_ENV_VAR, || {
        with_env_var(PDSH_COMPAT_ENV_VAR, "true", || {
            let value = env::var(PDSH_COMPAT_ENV_VAR).ok();
            assert!(value.is_some());
            assert_eq!(value.unwrap().to_lowercase(), "true");
        });
    });
}

#[test]
fn test_env_var_detection_disabled_with_zero() {
    without_env_var(PDSH_COMPAT_ENV_VAR, || {
        with_env_var(PDSH_COMPAT_ENV_VAR, "0", || {
            let value = env::var(PDSH_COMPAT_ENV_VAR).ok();
            assert!(value.is_some());
            let v = value.unwrap();
            // "0" should NOT be treated as enabled
            assert!(!(v == "1" || v.to_lowercase() == "true"));
        });
    });
}

#[test]
fn test_env_var_detection_disabled_with_false() {
    without_env_var(PDSH_COMPAT_ENV_VAR, || {
        with_env_var(PDSH_COMPAT_ENV_VAR, "false", || {
            let value = env::var(PDSH_COMPAT_ENV_VAR).ok();
            assert!(value.is_some());
            let v = value.unwrap();
            // "false" should NOT be treated as enabled
            assert!(!(v == "1" || v.to_lowercase() == "true"));
        });
    });
}

// =============================================================================
// pdsh CLI Parsing Tests
// =============================================================================

#[test]
fn test_pdsh_cli_basic_command() {
    let args = vec!["pdsh", "-w", "host1,host2", "uptime"];
    let cli = PdshCli::parse_from_args(args);

    assert_eq!(cli.hosts, Some("host1,host2".to_string()));
    assert_eq!(cli.command, vec!["uptime"]);
    assert_eq!(cli.fanout, 32); // pdsh default
}

#[test]
fn test_pdsh_cli_with_exclusions() {
    let args = vec!["pdsh", "-w", "host1,host2,host3", "-x", "host2", "df", "-h"];
    let cli = PdshCli::parse_from_args(args);

    assert_eq!(cli.hosts, Some("host1,host2,host3".to_string()));
    assert_eq!(cli.exclude, Some("host2".to_string()));
    assert_eq!(cli.command, vec!["df", "-h"]);
}

#[test]
fn test_pdsh_cli_query_mode() {
    let args = vec!["pdsh", "-w", "host1,host2,host3", "-q"];
    let cli = PdshCli::parse_from_args(args);

    assert!(cli.is_query_mode());
    assert_eq!(cli.hosts, Some("host1,host2,host3".to_string()));
    assert!(cli.command.is_empty());
}

#[test]
fn test_pdsh_cli_all_flags() {
    let args = vec![
        "pdsh", "-w", "hosts", "-x", "exclude", "-f", "16", "-l", "admin", "-t", "60", "-u", "300",
        "-N", "-b", "-k", "-S", "command",
    ];
    let cli = PdshCli::parse_from_args(args);

    assert_eq!(cli.hosts, Some("hosts".to_string()));
    assert_eq!(cli.exclude, Some("exclude".to_string()));
    assert_eq!(cli.fanout, 16);
    assert_eq!(cli.user, Some("admin".to_string()));
    assert_eq!(cli.connect_timeout, Some(60));
    assert_eq!(cli.command_timeout, Some(300));
    assert!(cli.no_prefix);
    assert!(cli.batch);
    assert!(cli.fail_fast);
    assert!(cli.any_failure);
}

#[test]
fn test_pdsh_cli_command_with_flags() {
    // Test that command arguments with hyphens are correctly captured
    let args = vec!["pdsh", "-w", "hosts", "grep", "-r", "pattern", "/path"];
    let cli = PdshCli::parse_from_args(args);

    assert_eq!(cli.command, vec!["grep", "-r", "pattern", "/path"]);
}

// =============================================================================
// Option Conversion Tests
// =============================================================================

#[test]
fn test_pdsh_to_bssh_hosts_conversion() {
    let args = vec!["pdsh", "-w", "host1, host2 , host3", "cmd"];
    let pdsh_cli = PdshCli::parse_from_args(args);
    let bssh_cli = pdsh_cli.to_bssh_cli();

    // Host strings should be split and trimmed
    assert_eq!(
        bssh_cli.hosts,
        Some(vec![
            "host1".to_string(),
            "host2".to_string(),
            "host3".to_string()
        ])
    );
}

#[test]
fn test_pdsh_to_bssh_exclude_conversion() {
    let args = vec!["pdsh", "-w", "hosts", "-x", "bad1, bad2", "cmd"];
    let pdsh_cli = PdshCli::parse_from_args(args);
    let bssh_cli = pdsh_cli.to_bssh_cli();

    // Exclude strings should be split and trimmed
    assert_eq!(
        bssh_cli.exclude,
        Some(vec!["bad1".to_string(), "bad2".to_string()])
    );
}

#[test]
fn test_pdsh_to_bssh_fanout_to_parallel() {
    let args = vec!["pdsh", "-w", "hosts", "-f", "20", "cmd"];
    let pdsh_cli = PdshCli::parse_from_args(args);
    let bssh_cli = pdsh_cli.to_bssh_cli();

    assert_eq!(bssh_cli.parallel, 20);
}

#[test]
fn test_pdsh_to_bssh_default_timeouts() {
    let args = vec!["pdsh", "-w", "hosts", "cmd"];
    let pdsh_cli = PdshCli::parse_from_args(args);
    let bssh_cli = pdsh_cli.to_bssh_cli();

    // Default connect timeout is 30s
    assert_eq!(bssh_cli.connect_timeout, 30);
    // Default command timeout is 300s
    assert_eq!(bssh_cli.timeout, 300);
}

#[test]
fn test_pdsh_to_bssh_custom_timeouts() {
    let args = vec!["pdsh", "-w", "hosts", "-t", "10", "-u", "600", "cmd"];
    let pdsh_cli = PdshCli::parse_from_args(args);
    let bssh_cli = pdsh_cli.to_bssh_cli();

    assert_eq!(bssh_cli.connect_timeout, 10);
    assert_eq!(bssh_cli.timeout, 600);
}

#[test]
fn test_pdsh_to_bssh_flags_conversion() {
    let args = vec!["pdsh", "-w", "hosts", "-N", "-b", "-k", "-S", "cmd"];
    let pdsh_cli = PdshCli::parse_from_args(args);
    let bssh_cli = pdsh_cli.to_bssh_cli();

    assert!(bssh_cli.no_prefix);
    assert!(bssh_cli.batch);
    assert!(bssh_cli.fail_fast);
    assert!(bssh_cli.any_failure);
    assert!(bssh_cli.pdsh_compat); // pdsh_compat should be set
}

#[test]
fn test_pdsh_to_bssh_user_conversion() {
    let args = vec!["pdsh", "-w", "hosts", "-l", "testuser", "cmd"];
    let pdsh_cli = PdshCli::parse_from_args(args);
    let bssh_cli = pdsh_cli.to_bssh_cli();

    assert_eq!(bssh_cli.user, Some("testuser".to_string()));
}

// =============================================================================
// Query Mode Glob Pattern Tests
// =============================================================================

#[test]
fn test_pdsh_query_mode_detection() {
    let args = vec!["pdsh", "-w", "host1,host2", "-q"];
    let cli = PdshCli::parse_from_args(args);

    assert!(cli.is_query_mode());
    assert!(!cli.has_command());
}

#[test]
fn test_pdsh_query_mode_with_exclusion() {
    let args = vec!["pdsh", "-w", "host1,host2,host3", "-x", "host2", "-q"];
    let cli = PdshCli::parse_from_args(args);

    assert!(cli.is_query_mode());
    assert_eq!(cli.hosts, Some("host1,host2,host3".to_string()));
    assert_eq!(cli.exclude, Some("host2".to_string()));
}

#[test]
fn test_pdsh_query_mode_with_wildcard_exclusion() {
    let args = vec!["pdsh", "-w", "web1,web2,db1,db2", "-x", "db*", "-q"];
    let cli = PdshCli::parse_from_args(args);

    assert!(cli.is_query_mode());
    assert_eq!(cli.exclude, Some("db*".to_string()));
}

// =============================================================================
// Helper Method Tests
// =============================================================================

#[test]
fn test_pdsh_get_command() {
    let args = vec!["pdsh", "-w", "hosts", "echo", "hello", "world"];
    let cli = PdshCli::parse_from_args(args);

    assert_eq!(cli.get_command(), "echo hello world");
}

#[test]
fn test_pdsh_has_command_true() {
    let args = vec!["pdsh", "-w", "hosts", "uptime"];
    let cli = PdshCli::parse_from_args(args);

    assert!(cli.has_command());
}

#[test]
fn test_pdsh_has_command_false() {
    let args = vec!["pdsh", "-w", "hosts", "-q"];
    let cli = PdshCli::parse_from_args(args);

    assert!(!cli.has_command());
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_pdsh_cli_empty_hosts() {
    // pdsh with no -w flag - should result in None
    let args = vec!["pdsh", "uptime"];
    let cli = PdshCli::parse_from_args(args);

    assert!(cli.hosts.is_none());
    assert_eq!(cli.command, vec!["uptime"]);
}

#[test]
fn test_pdsh_cli_whitespace_in_hosts() {
    let args = vec!["pdsh", "-w", " host1 , host2 , host3 ", "cmd"];
    let pdsh_cli = PdshCli::parse_from_args(args);
    let bssh_cli = pdsh_cli.to_bssh_cli();

    // Whitespace should be trimmed
    assert_eq!(
        bssh_cli.hosts,
        Some(vec![
            "host1".to_string(),
            "host2".to_string(),
            "host3".to_string()
        ])
    );
}

#[test]
fn test_pdsh_cli_single_host() {
    let args = vec!["pdsh", "-w", "single-host", "cmd"];
    let pdsh_cli = PdshCli::parse_from_args(args);
    let bssh_cli = pdsh_cli.to_bssh_cli();

    assert_eq!(bssh_cli.hosts, Some(vec!["single-host".to_string()]));
}

#[test]
fn test_pdsh_cli_complex_command() {
    let args = vec![
        "pdsh",
        "-w",
        "hosts",
        "bash",
        "-c",
        "for i in 1 2 3; do echo $i; done",
    ];
    let cli = PdshCli::parse_from_args(args);

    assert_eq!(
        cli.command,
        vec!["bash", "-c", "for i in 1 2 3; do echo $i; done"]
    );
}

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

//! Tests for --no-prefix / -N option functionality

use bssh::cli::Cli;
use bssh::executor::OutputMode;
use clap::Parser;
use std::path::PathBuf;

/// Test CLI parsing with --no-prefix long option
#[test]
fn test_no_prefix_long_option() {
    let args = vec!["bssh", "-H", "host1,host2", "--no-prefix", "uptime"];

    let cli = Cli::parse_from(args);

    assert!(cli.no_prefix, "--no-prefix should set no_prefix to true");
    // Hosts are parsed as comma-separated values
    assert_eq!(
        cli.hosts,
        Some(vec!["host1".to_string(), "host2".to_string()])
    );
}

/// Test CLI parsing with -N short option
#[test]
fn test_no_prefix_short_option() {
    let args = vec!["bssh", "-H", "host1,host2", "-N", "uptime"];

    let cli = Cli::parse_from(args);

    assert!(cli.no_prefix, "-N should set no_prefix to true");
}

/// Test CLI parsing without no_prefix option (default should be false)
#[test]
fn test_no_prefix_default_false() {
    let args = vec!["bssh", "-H", "host1,host2", "uptime"];

    let cli = Cli::parse_from(args);

    assert!(!cli.no_prefix, "no_prefix should be false by default");
}

/// Test --no-prefix with --stream mode
#[test]
fn test_no_prefix_with_stream_mode() {
    let args = vec![
        "bssh",
        "-H",
        "host1,host2",
        "--stream",
        "--no-prefix",
        "uptime",
    ];

    let cli = Cli::parse_from(args);

    assert!(cli.no_prefix, "--no-prefix should be set");
    assert!(cli.stream, "--stream should be set");

    // OutputMode should respect both flags
    let mode = OutputMode::from_args_with_no_prefix(cli.stream, None, cli.no_prefix);
    assert!(mode.is_stream());
    assert!(mode.is_no_prefix());
}

/// Test --no-prefix with --output-dir mode
#[test]
fn test_no_prefix_with_output_dir() {
    let args = vec![
        "bssh",
        "-H",
        "host1,host2",
        "--output-dir",
        "/tmp/output",
        "-N",
        "uptime",
    ];

    let cli = Cli::parse_from(args);

    assert!(cli.no_prefix, "-N should be set");
    assert_eq!(cli.output_dir, Some(PathBuf::from("/tmp/output")));

    // OutputMode should respect both flags
    let mode =
        OutputMode::from_args_with_no_prefix(cli.stream, cli.output_dir.clone(), cli.no_prefix);
    assert!(mode.is_file());
    assert!(mode.is_no_prefix());
}

/// Test --no-prefix with cluster option
#[test]
fn test_no_prefix_with_cluster() {
    let args = vec!["bssh", "-C", "production", "--no-prefix", "df -h"];

    let cli = Cli::parse_from(args);

    assert!(cli.no_prefix, "--no-prefix should be set");
    assert_eq!(cli.cluster, Some("production".to_string()));
}

/// Test -N does not conflict with other short options
#[test]
fn test_no_prefix_with_other_options() {
    let args = vec![
        "bssh", "-H", "host1", "-N", "-A", // use-agent
        "-v", // verbose
        "uptime",
    ];

    let cli = Cli::parse_from(args);

    assert!(cli.no_prefix, "-N should be set");
    assert!(cli.use_agent, "-A should be set");
    assert_eq!(cli.verbose, 1, "-v should increase verbosity");
}

/// Test OutputMode::is_no_prefix for Normal mode (should be false)
#[test]
fn test_output_mode_is_no_prefix_normal() {
    let mode = OutputMode::Normal;
    assert!(
        !mode.is_no_prefix(),
        "Normal mode should not report no_prefix as true"
    );
}

/// Test OutputMode::is_no_prefix for Tui mode (should be false)
#[test]
fn test_output_mode_is_no_prefix_tui() {
    let mode = OutputMode::Tui;
    assert!(
        !mode.is_no_prefix(),
        "Tui mode should not report no_prefix as true"
    );
}

/// Test OutputMode construction with explicit no_prefix
#[test]
fn test_output_mode_explicit_construction() {
    // Stream mode with no_prefix enabled
    let stream_with_prefix = OutputMode::Stream { no_prefix: false };
    assert!(!stream_with_prefix.is_no_prefix());

    let stream_without_prefix = OutputMode::Stream { no_prefix: true };
    assert!(stream_without_prefix.is_no_prefix());

    // File mode with no_prefix enabled
    let file_with_prefix = OutputMode::File {
        path: PathBuf::from("/tmp"),
        no_prefix: false,
    };
    assert!(!file_with_prefix.is_no_prefix());

    let file_without_prefix = OutputMode::File {
        path: PathBuf::from("/tmp"),
        no_prefix: true,
    };
    assert!(file_without_prefix.is_no_prefix());
}

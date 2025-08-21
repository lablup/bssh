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

use bssh::cli::{Cli, Commands};
use clap::Parser;
use std::path::PathBuf;

#[test]
fn test_upload_command_parsing() {
    let args = vec![
        "bssh",
        "-H",
        "host1,host2",
        "upload",
        "/tmp/test.txt",
        "/remote/path/test.txt",
    ];

    let cli = Cli::parse_from(args);

    assert!(matches!(
        cli.command,
        Some(Commands::Upload {
            source: _,
            destination: _,
            recursive: _
        })
    ));

    if let Some(Commands::Upload {
        source,
        destination,
        recursive: _,
    }) = cli.command
    {
        assert_eq!(source, PathBuf::from("/tmp/test.txt"));
        assert_eq!(destination, "/remote/path/test.txt");
    }
}

#[test]
fn test_upload_command_with_cluster() {
    let args = vec![
        "bssh",
        "-c",
        "production",
        "upload",
        "./local.conf",
        "/etc/app.conf",
    ];

    let cli = Cli::parse_from(args);

    assert_eq!(cli.cluster, Some("production".to_string()));
    assert!(matches!(
        cli.command,
        Some(Commands::Upload {
            source: _,
            destination: _,
            recursive: _
        })
    ));
}

#[test]
fn test_upload_command_with_options() {
    let args = vec![
        "bssh",
        "-H",
        "server1",
        "-i",
        "~/.ssh/custom_key",
        "-p",
        "5",
        "upload",
        "data.csv",
        "/data/uploads/",
    ];

    let cli = Cli::parse_from(args);

    assert_eq!(cli.hosts, Some(vec!["server1".to_string()]));
    assert_eq!(cli.identity, Some(PathBuf::from("~/.ssh/custom_key")));
    assert_eq!(cli.parallel, 5);

    if let Some(Commands::Upload {
        source,
        destination,
        recursive: _,
    }) = cli.command
    {
        assert_eq!(source, PathBuf::from("data.csv"));
        assert_eq!(destination, "/data/uploads/");
    }
}

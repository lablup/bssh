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
fn test_download_command_parsing() {
    let args = vec![
        "bssh",
        "-H",
        "host1,host2",
        "download",
        "/remote/file.txt",
        "/local/downloads/",
    ];

    let cli = Cli::parse_from(args);

    assert!(matches!(
        cli.command,
        Some(Commands::Download {
            source: _,
            destination: _,
            recursive: _
        })
    ));

    if let Some(Commands::Download {
        source,
        destination,
        recursive: _,
    }) = cli.command
    {
        assert_eq!(source, "/remote/file.txt");
        assert_eq!(destination, PathBuf::from("/local/downloads/"));
    }
}

#[test]
fn test_download_command_with_cluster() {
    let args = vec![
        "bssh",
        "-C",
        "staging",
        "download",
        "/var/log/app.log",
        "./logs/",
    ];

    let cli = Cli::parse_from(args);

    assert_eq!(cli.cluster, Some("staging".to_string()));
    assert!(matches!(
        cli.command,
        Some(Commands::Download {
            source: _,
            destination: _,
            recursive: _
        })
    ));
}

#[test]
fn test_download_command_with_glob() {
    let args = vec![
        "bssh",
        "-H",
        "server1",
        "download",
        "/var/log/*.log",
        "/tmp/collected_logs/",
    ];

    let cli = Cli::parse_from(args);

    if let Some(Commands::Download {
        source,
        destination,
        recursive: _,
    }) = cli.command
    {
        assert_eq!(source, "/var/log/*.log");
        assert_eq!(destination, PathBuf::from("/tmp/collected_logs/"));
    }
}

#[test]
fn test_download_command_with_options() {
    let args = vec![
        "bssh",
        "-H",
        "node1,node2",
        "-i",
        "~/.ssh/id_ed25519",
        "--parallel",
        "20",
        "--use-agent",
        "download",
        "/etc/config.conf",
        "./backups/",
    ];

    let cli = Cli::parse_from(args);

    assert_eq!(
        cli.hosts,
        Some(vec!["node1".to_string(), "node2".to_string()])
    );
    assert_eq!(cli.identity, Some(PathBuf::from("~/.ssh/id_ed25519")));
    assert_eq!(cli.parallel, 20);
    assert!(cli.use_agent);

    if let Some(Commands::Download {
        source,
        destination,
        recursive: _,
    }) = cli.command
    {
        assert_eq!(source, "/etc/config.conf");
        assert_eq!(destination, PathBuf::from("./backups/"));
    }
}

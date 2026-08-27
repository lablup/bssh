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

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bssh::cli::Cli;
use bssh::executor::NodeOutputWriter;
use clap::Parser;
use tempfile::tempdir;

fn run_bssh(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bssh"))
        .env_remove("RUST_LOG")
        .env_remove("BSSH_PDSH_COMPAT")
        .args(arguments)
        .output()
        .expect("failed to run bssh")
}

fn as_str(path: &Path) -> &str {
    path.to_str().expect("temporary path should be UTF-8")
}

#[test]
fn parses_separated_and_attached_log_file_options() {
    let separated = Cli::try_parse_from(["bssh", "-E", "/tmp/bssh.log", "example.com"])
        .expect("separated -E should parse");
    let attached = Cli::try_parse_from(["bssh", "-E/tmp/bssh.log", "example.com"])
        .expect("attached -Epath should parse");

    let expected = Some(PathBuf::from("/tmp/bssh.log"));
    assert_eq!(separated.log_file, expected);
    assert_eq!(attached.log_file, expected);
}

#[test]
fn human_diagnostics_are_routed_and_repeated_runs_append() {
    let directory = tempdir().expect("failed to create temporary directory");
    let log = directory.path().join("bssh.log");

    for _ in 0..2 {
        let output = run_bssh(&["-E", as_str(&log), "-Q", "not-a-query"]);
        assert!(!output.status.success(), "an unknown query should fail");
        assert!(
            output.stderr.is_empty(),
            "bssh diagnostic leaked to stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let contents = std::fs::read_to_string(&log).expect("failed to read diagnostic log");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&log)
            .expect("failed to inspect diagnostic log")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "new diagnostic logs must be private");
    }
    assert_eq!(
        contents
            .matches("Unknown query option: not-a-query")
            .count(),
        2
    );
    assert_eq!(
        contents
            .matches("Use 'bssh -Q help' to see available options")
            .count(),
        2
    );
}

#[test]
fn remote_stderr_helper() {
    if std::env::var_os("BSSH_LOG_FILE_TEST_HELPER").is_none() {
        return;
    }

    let log = PathBuf::from(
        std::env::var_os("BSSH_LOG_FILE_TEST_PATH").expect("helper log path should be set"),
    );
    bssh::utils::diagnostics::set_log_file(&log).expect("helper should open diagnostic log");
    bssh::diagnosticln!("bssh-owned diagnostic");
    NodeOutputWriter::new_with_no_prefix("example", true)
        .write_stderr_lines("remote command stderr")
        .expect("helper should write remote stderr");
}

#[test]
fn remote_command_stderr_stays_on_fd_2() {
    let directory = tempdir().expect("failed to create temporary directory");
    let log = directory.path().join("bssh.log");
    let output = Command::new(std::env::current_exe().expect("test executable should exist"))
        .args(["--exact", "remote_stderr_helper", "--nocapture"])
        .env("BSSH_LOG_FILE_TEST_HELPER", "1")
        .env("BSSH_LOG_FILE_TEST_PATH", &log)
        .output()
        .expect("failed to run remote stderr helper");

    assert!(output.status.success(), "remote stderr helper should pass");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("remote command stderr"),
        "stderr was: {stderr}"
    );
    assert!(!stderr.contains("bssh-owned diagnostic"));

    let contents = std::fs::read_to_string(&log).expect("failed to read diagnostic log");
    assert!(contents.contains("bssh-owned diagnostic"));
    assert!(!contents.contains("remote command stderr"));
}

#[test]
fn tracing_and_top_level_errors_use_the_log_file() {
    let directory = tempdir().expect("failed to create temporary directory");
    let log = directory.path().join("bssh.log");
    let missing_config = directory.path().join("missing.yaml");

    let output = run_bssh(&[
        "-vv",
        "-E",
        as_str(&log),
        "--config",
        as_str(&missing_config),
        "-H",
        "example.invalid",
        "true",
    ]);

    assert!(!output.status.success(), "missing config must fail");
    assert!(
        output.stderr.is_empty(),
        "bssh diagnostic leaked to stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let contents = std::fs::read_to_string(&log).expect("failed to read diagnostic log");
    assert!(contents.contains("Appending bssh diagnostics to log file"));
    assert!(contents.contains("Config file not found"));
    assert!(contents.contains(as_str(&missing_config)));
}

#[test]
fn log_open_failure_is_actionable_and_exits_nonzero() {
    let directory = tempdir().expect("failed to create temporary directory");
    let output = run_bssh(&["-E", as_str(directory.path()), "-Q", "help"]);

    assert!(!output.status.success(), "a directory cannot be a log file");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Cannot open log file"),
        "stderr was: {stderr}"
    );
    assert!(
        stderr.contains(as_str(directory.path())),
        "stderr did not name the failed path: {stderr}"
    );
}

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

//! Utility functions for the application

use std::time::Duration;

/// Show concise usage message (like SSH)
pub fn show_usage() {
    println!("usage: bssh [-46AqtTvx] [-C cluster] [-F ssh_configfile] [-H hosts]");
    println!("           [-i identity_file] [-J destination] [-l login_name]");
    println!("           [-o option] [-p port] [--config config] [--parallel N]");
    println!("           [--output-dir dir] [--timeout seconds] [--use-agent]");
    println!("           destination [command [argument ...]]");
    println!("       bssh [-Q query_option]");
    println!("       bssh [list|ping|upload|download|interactive] ...");
    println!();
    println!("SSH Config Support:");
    println!("  -F ssh_configfile    Use alternative SSH configuration file");
    println!("                       Defaults to ~/.ssh/config if available");
    println!("                       Supports: Host, HostName, User, Port, IdentityFile,");
    println!("                       StrictHostKeyChecking, ProxyJump, and more");
    println!();
    println!("For more information, try 'bssh --help'");
}

/// Format a Duration into a human-readable string
pub fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs_f64();

    if total_seconds < 1.0 {
        // Less than 1 second: show in milliseconds
        format!("{:.1} ms", duration.as_secs_f64() * 1000.0)
    } else if total_seconds < 60.0 {
        // Less than 1 minute: show in seconds with 2 decimal places
        format!("{total_seconds:.2} s")
    } else {
        // 1 minute or more: show in minutes and seconds
        let minutes = duration.as_secs() / 60;
        let seconds = duration.as_secs() % 60;
        let millis = duration.subsec_millis();

        if seconds == 0 {
            format!("{minutes}m")
        } else if millis > 0 {
            format!("{minutes}m {seconds}.{millis:03}s")
        } else {
            format!("{minutes}m {seconds}s")
        }
    }
}

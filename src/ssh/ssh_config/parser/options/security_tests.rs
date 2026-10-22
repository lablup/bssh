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

use crate::ssh::ssh_config::SshConfig;

fn revoked_host_keys(source: &str) -> anyhow::Result<Vec<String>> {
    Ok(SshConfig::parse(source)?
        .find_host_config("node")
        .revoked_host_keys)
}

#[test]
fn revoked_host_keys_accepts_a_list_of_files() {
    assert_eq!(
        revoked_host_keys("Host *\n    RevokedHostKeys /etc/ssh/revoked_a ~/.ssh/revoked_b\n")
            .unwrap(),
        vec!["/etc/ssh/revoked_a", "~/.ssh/revoked_b"]
    );
    assert_eq!(
        revoked_host_keys("Host *\n    RevokedHostKeys /etc/ssh/revoked\n").unwrap(),
        vec!["/etc/ssh/revoked"]
    );
    assert!(revoked_host_keys("Host *\n").unwrap().is_empty());
    // The first obtained value wins, as for every other option.
    assert_eq!(
        revoked_host_keys(
            "Host node\n    RevokedHostKeys /first\nHost *\n    RevokedHostKeys /second /third\n"
        )
        .unwrap(),
        vec!["/first"]
    );
}

#[test]
fn revoked_host_keys_none_is_valid_only_as_the_sole_value() {
    for sole in ["none", "NONE", "/dev/null"] {
        assert_eq!(
            revoked_host_keys(&format!("Host *\n    RevokedHostKeys {sole}\n")).unwrap(),
            vec![sole],
            "{sole}"
        );
    }
    for mixed in ["none /x", "/x none", "/dev/null /x", "/x NONE"] {
        let error =
            revoked_host_keys(&format!("Host *\n    RevokedHostKeys {mixed}\n")).expect_err(mixed);
        let error = format!("{error:#}");
        assert!(error.contains("RevokedHostKeys"), "{mixed}: {error}");
    }
}

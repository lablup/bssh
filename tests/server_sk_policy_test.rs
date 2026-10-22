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

use std::sync::Arc;

use bssh::server::{config::ServerConfig, handler::SshHandler, session::SessionManager};
use russh::keys::ssh_key::{
    PublicKey,
    public::{Ed25519PublicKey, KeyData, SkEcdsaSha2NistP256, SkEd25519},
};
use russh::server::{Auth, Handler};
use tokio::sync::RwLock;

fn keys() -> [PublicKey; 3] {
    let ed = Ed25519PublicKey([7; 32]);
    let signing = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
    let point = signing.verifying_key().to_sec1_point(false);
    [
        PublicKey::new(KeyData::SkEd25519(SkEd25519::new(ed, "ssh:")), ""),
        PublicKey::new(
            KeyData::SkEcdsaSha2NistP256(SkEcdsaSha2NistP256::new(point, "ssh:")),
            "",
        ),
        PublicKey::new(KeyData::Ed25519(ed), ""),
    ]
}

async fn authenticate(key: &PublicKey, lines: &[String]) -> bool {
    let dir = tempfile::tempdir().unwrap();
    let user_dir = dir.path().join("alice");
    std::fs::create_dir(&user_dir).unwrap();
    let path = user_dir.join("authorized_keys");
    std::fs::write(&path, lines.join("\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&user_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = ServerConfig::builder()
        .allow_publickey_auth(true)
        .allow_password_auth(false)
        .authorized_keys_dir(dir.path())
        .build();
    let mut handler = SshHandler::new(
        None,
        Arc::new(config),
        Arc::new(RwLock::new(SessionManager::new())),
    );
    matches!(
        handler.auth_publickey("alice", key).await.unwrap(),
        Auth::Accept
    )
}

#[tokio::test]
async fn server_sk_policy_enforces_each_authorized_key_option_combination() {
    for (index, key) in keys().iter().enumerate() {
        for options in [
            "",
            "no-touch-required",
            "verify-required",
            "no-touch-required,verify-required",
            "verify-required,no-touch-required",
            "no-pty,no-touch-required",
        ] {
            let line = format!("{options} {}", key.to_openssh().unwrap());
            let accepted = authenticate(key, &[line]).await;
            let expected = index == 2
                || (options.contains("no-touch-required") && !options.contains("verify-required"));
            assert_eq!(accepted, expected, "{}: {options}", key.algorithm());
        }
    }
}

#[tokio::test]
async fn server_sk_policy_uses_first_matching_entry() {
    let keys = keys();
    for key in &keys[..2] {
        let public = key.to_openssh().unwrap();
        let restricted = format!("verify-required {public}");
        let allowed = format!("no-touch-required {public}");
        assert!(!authenticate(key, &[restricted.clone(), allowed.clone()]).await);
        assert!(authenticate(key, &[allowed.clone(), restricted]).await);
        // An exception for a different key must never relax this key's policy.
        let unrelated = format!("no-touch-required {}", keys[2].to_openssh().unwrap());
        assert!(!authenticate(key, &[public, unrelated.clone()]).await);
        assert!(authenticate(key, &[unrelated, allowed]).await);
    }
}

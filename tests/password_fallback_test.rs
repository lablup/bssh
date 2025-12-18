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

//! Tests for password fallback functionality in SSH connections.
//!
//! These tests verify that the password fallback mechanism correctly triggers
//! for various SSH authentication error types, including SSH agent errors.

use bssh::commands::interactive::connection::is_auth_error_for_password_fallback;
use bssh::ssh::tokio_client::Error as SshError;

/// Test that all SSH agent-related authentication failures trigger password fallback
#[test]
fn test_all_agent_errors_trigger_password_fallback() {
    let agent_errors = vec![
        (
            SshError::AgentAuthenticationFailed,
            "AgentAuthenticationFailed",
        ),
        (SshError::AgentNoIdentities, "AgentNoIdentities"),
        (SshError::AgentConnectionFailed, "AgentConnectionFailed"),
        (
            SshError::AgentRequestIdentitiesFailed,
            "AgentRequestIdentitiesFailed",
        ),
    ];

    for (error, name) in agent_errors {
        assert!(
            is_auth_error_for_password_fallback(&error),
            "{} should trigger password fallback",
            name
        );
    }
}

/// Test that key authentication failure triggers password fallback
#[test]
fn test_key_auth_failure_triggers_password_fallback() {
    let error = SshError::KeyAuthFailed;
    assert!(
        is_auth_error_for_password_fallback(&error),
        "KeyAuthFailed should trigger password fallback"
    );
}

/// Test that non-authentication errors do NOT trigger password fallback
#[test]
fn test_non_auth_errors_do_not_trigger_fallback() {
    let non_auth_errors: Vec<(SshError, &str)> = vec![
        (SshError::PasswordWrong, "PasswordWrong"),
        (SshError::ServerCheckFailed, "ServerCheckFailed"),
        (SshError::CommandDidntExit, "CommandDidntExit"),
        (
            SshError::KeyboardInteractiveAuthFailed,
            "KeyboardInteractiveAuthFailed",
        ),
        (
            SshError::IoError(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused",
            )),
            "IoError",
        ),
    ];

    for (error, name) in non_auth_errors {
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "{} should NOT trigger password fallback",
            name
        );
    }
}

/// Test that PasswordWrong specifically does not trigger fallback
/// (to prevent infinite password retry loops)
#[test]
fn test_password_wrong_prevents_infinite_loop() {
    let error = SshError::PasswordWrong;
    assert!(
        !is_auth_error_for_password_fallback(&error),
        "PasswordWrong must NOT trigger password fallback to prevent infinite retry loops"
    );
}

/// Test that ServerCheckFailed (host key verification) does not trigger password fallback
/// (security: host key issues should not be bypassed)
#[test]
fn test_host_key_verification_not_bypassed() {
    let error = SshError::ServerCheckFailed;
    assert!(
        !is_auth_error_for_password_fallback(&error),
        "ServerCheckFailed must NOT trigger password fallback - host key verification is a security feature"
    );
}

// Tests for issue #113: Handle SshError(Disconnect) during authentication
// The russh library may disconnect the connection before returning authentication failure,
// which manifests as SshError(Disconnect) instead of KeyAuthFailed.

/// Test that SshError(Disconnect) triggers password fallback.
/// This is the key fix for GitHub issue #113.
#[test]
fn test_ssh_disconnect_during_auth_triggers_password_fallback() {
    let error = SshError::SshError(russh::Error::Disconnect);
    assert!(
        is_auth_error_for_password_fallback(&error),
        "SshError(Disconnect) should trigger password fallback - \
         server may disconnect after key authentication rejection (issue #113)"
    );
}

/// Test that SshError(RecvError) triggers password fallback.
/// The server may close the channel during authentication, resulting in RecvError.
#[test]
fn test_ssh_recv_error_during_auth_triggers_password_fallback() {
    let error = SshError::SshError(russh::Error::RecvError);
    assert!(
        is_auth_error_for_password_fallback(&error),
        "SshError(RecvError) should trigger password fallback - \
         server may close connection during authentication"
    );
}

/// Test that other SSH errors (HUP, ConnectionTimeout) do NOT trigger password fallback.
/// These indicate network issues, not authentication failures.
#[test]
fn test_other_ssh_errors_do_not_trigger_fallback() {
    let non_auth_ssh_errors: Vec<(SshError, &str)> = vec![
        (
            SshError::SshError(russh::Error::HUP),
            "HUP - remote closed connection",
        ),
        (
            SshError::SshError(russh::Error::ConnectionTimeout),
            "ConnectionTimeout - network issue",
        ),
        (
            SshError::SshError(russh::Error::NotAuthenticated),
            "NotAuthenticated - auth not attempted yet",
        ),
    ];

    for (error, desc) in non_auth_ssh_errors {
        assert!(
            !is_auth_error_for_password_fallback(&error),
            "{} should NOT trigger password fallback",
            desc
        );
    }
}

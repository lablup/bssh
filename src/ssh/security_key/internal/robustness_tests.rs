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

//! Misbehaving and unusual devices over the mock transport: refused touch
//! probes, duplicate and excess enumeration entries, devices that never
//! finish, unpaced polling, and late `getInfo` replies.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::ctap2::status;
use super::device::counts_as_touch;
use super::mock::{
    CredentialKey, Fido2Config, Flood, MockAuthenticator, MockBackend, Protocol, Request,
};
use super::tests::{credential, fido2, provider_with, public_key, request, verify};
use super::*;
use crate::ssh::security_key::encode_signature;

const TIMED_OUT: &str = "timed out waiting for the security key";

fn short_deadline(deadline: Duration) -> Timing {
    Timing {
        sign_timeout: deadline,
        ..Timing::default()
    }
}

#[test]
fn only_success_and_pin_errors_count_as_a_touch() {
    for touched in [
        status::OK,
        status::PIN_AUTH_INVALID,
        status::PIN_INVALID,
        status::PIN_NOT_SET,
    ] {
        assert!(counts_as_touch(touched), "{touched:#04x}");
    }
    for refused in [
        status::OPERATION_DENIED,
        status::PIN_REQUIRED,
        status::KEEPALIVE_CANCEL,
        status::USER_ACTION_TIMEOUT,
        0x01,
    ] {
        assert!(!counts_as_touch(refused), "{refused:#04x}");
    }
}

#[test]
fn a_device_refusing_the_touch_probe_is_dropped_and_the_touched_one_wins() {
    let mut refusing = fido2(
        Fido2Config::with_pin("123456"),
        Some(CredentialKey::ed25519(7)),
    );
    refusing.touch_status = status::OPERATION_DENIED;
    let (provider, devices) = provider_with(vec![
        ("/dev/hidraw1", refusing),
        (
            "/dev/hidraw2",
            fido2(
                Fido2Config::with_pin("123456"),
                Some(CredentialKey::ed25519(1)),
            ),
        ),
    ]);
    let response = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x05), Some("123456"))
        .unwrap();
    verify(
        &public_key(&devices[1].lock().unwrap()),
        &encode_signature(SkAlgorithm::Ed25519, &response).unwrap(),
    );
    // The refusing device answered at once but was never treated as
    // touched, so it never saw the PIN exchange.
    assert_eq!(
        devices[0].lock().unwrap().requests,
        [Request::GetInfo, Request::TouchProbe]
    );
}

#[test]
fn duplicate_entries_are_merged_and_at_most_eight_devices_are_considered() {
    let mut backend = MockBackend::default();
    let mut handles = vec![backend.add("/dev/hidraw1", fido2(Fido2Config::plain(), None))];
    for _ in 0..5 {
        backend.add_alias("/dev/hidraw1");
    }
    for index in 2..=10 {
        handles.push(backend.add(
            &format!("/dev/hidraw{index}"),
            fido2(Fido2Config::plain(), None),
        ));
    }
    let paths = select::fido_devices(&backend)
        .unwrap()
        .into_iter()
        .map(|device| device.path)
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        (1..=8)
            .map(|index| format!("/dev/hidraw{index}"))
            .collect::<Vec<_>>()
    );

    let provider = InternalProvider::with_backend(Arc::new(backend));
    assert_eq!(
        provider
            .sign(&request(SkAlgorithm::Ed25519, 0x01), None)
            .unwrap_err(),
        SecurityKeyError::DeviceNotFound
    );
    let get_infos = |index: usize| {
        handles[index]
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|request| **request == Request::GetInfo)
            .count()
    };
    assert_eq!(get_infos(0), 1, "the repeated device is opened once");
    assert_eq!(get_infos(7), 1);
    assert_eq!(get_infos(8), 0, "the ninth device is never opened");
    assert_eq!(get_infos(9), 0);
}

/// A lone CTAP2 device that reports `uv`, so no probe precedes the
/// signature request, holding its reply back behind `flood`.
fn stalled_device(flood: Flood) -> MockAuthenticator {
    let mut config = Fido2Config::plain();
    config.options.insert("uv".to_string(), false);
    let mut device = fido2(config, Some(CredentialKey::ed25519(1)));
    device.stall = Some((flood, Duration::from_secs(3)));
    device
}

fn assert_times_out(provider: &InternalProvider, algorithm: SkAlgorithm) {
    let started = Instant::now();
    let error = provider.sign(&request(algorithm, 0x01), None).unwrap_err();
    assert_eq!(error, SecurityKeyError::Failed(TIMED_OUT.to_string()));
    assert_eq!(error.to_string(), format!("sk_sign failed: {TIMED_OUT}"));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn an_endless_keepalive_stream_ends_at_the_deadline_with_a_cancel() {
    for flood in [Flood::Keepalive, Flood::ForeignChannel] {
        let (provider, devices) = provider_with(vec![("/dev/hidraw1", stalled_device(flood))]);
        let provider = provider.with_timing(short_deadline(Duration::from_millis(300)));
        assert_times_out(&provider, SkAlgorithm::Ed25519);
        let device = devices[0].lock().unwrap();
        assert_eq!(device.assertion_requests().len(), 1, "{flood:?}");
        assert_eq!(device.requests.last(), Some(&Request::Cancel), "{flood:?}");
    }
}

#[test]
fn an_untouched_u2f_key_ends_at_the_deadline_without_a_cancel() {
    let mut u2f = MockAuthenticator::new(Protocol::U2f, Some(credential(CredentialKey::p256(3))));
    // 40 presence retries paced 100 ms apart: about 4 s without a deadline.
    u2f.u2f_presence_retries = 40;
    let (provider, devices) = provider_with(vec![("/dev/hidraw1", u2f)]);
    let provider = provider.with_timing(short_deadline(Duration::from_millis(300)));
    assert_times_out(&provider, SkAlgorithm::EcdsaSha2NistP256);
    let device = devices[0].lock().unwrap();
    assert!(device.requests.contains(&Request::U2fSign));
    assert_eq!(device.cancels, 0, "U2F devices get no CTAPHID CANCEL");
}

#[test]
fn touch_polling_rounds_are_paced() {
    let mut u2f = MockAuthenticator::new(Protocol::U2f, None);
    u2f.touch_on_probe = false;
    let mut ctap2 = fido2(Fido2Config::with_pin("123456"), None);
    ctap2.touch_on_probe = false;
    let (provider, devices) = provider_with(vec![("/dev/hidraw1", u2f), ("/dev/hidraw2", ctap2)]);
    let provider = provider.with_timing(Timing {
        select_timeout: Duration::from_secs(1),
        ..Timing::default()
    });
    let started = Instant::now();
    assert_eq!(
        provider
            .sign(&request(SkAlgorithm::Ed25519, 0x05), Some("123456"))
            .unwrap_err(),
        SecurityKeyError::DeviceNotFound
    );
    assert!(started.elapsed() >= Duration::from_millis(900));
    // The U2F device answers every REGISTER at once, so the probe is re-sent
    // once per round: about five rounds of 200 ms fit in the second.
    let registers = devices[0].lock().unwrap().requests.len();
    assert!((2..=8).contains(&registers), "{registers} REGISTER probes");
}

#[test]
fn a_late_get_info_reply_does_not_break_the_u2f_fallback() {
    let mut late = fido2(Fido2Config::plain(), Some(CredentialKey::p256(4)));
    late.late_get_info = true;
    let (provider, devices) = provider_with(vec![("/dev/hidraw1", late)]);
    let response = provider
        .sign(&request(SkAlgorithm::EcdsaSha2NistP256, 0x01), None)
        .unwrap();
    verify(
        &public_key(&devices[0].lock().unwrap()),
        &encode_signature(SkAlgorithm::EcdsaSha2NistP256, &response).unwrap(),
    );
    let device = devices[0].lock().unwrap();
    assert_eq!(
        device.requests,
        [
            Request::GetInfo,
            Request::U2fCheck,
            Request::U2fCheck,
            Request::U2fSign,
        ]
    );
    assert_eq!(device.cancels, 0);
}

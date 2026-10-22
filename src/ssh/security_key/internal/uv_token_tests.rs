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

//! CTAP 2.1 built-in user verification token flows.

use super::mock::{CredentialKey, Fido2Config, Request};
use super::tests::{APPLICATION, fido2, provider_with, public_key, request, verify};
use super::*;
use crate::ssh::security_key::encode_signature;

fn biometric(protocol: u64) -> Fido2Config {
    let mut config = Fido2Config::with_pin("123456");
    config.options.insert("uv".to_string(), true);
    config.pin_protocols = vec![protocol];
    config
}

#[test]
fn a_built_in_sensor_obtains_a_uv_token_without_a_pin() {
    for protocol in [1_u64, 2] {
        let (provider, devices) = provider_with(vec![(
            "/dev/hidraw1",
            fido2(
                biometric(protocol),
                Some(CredentialKey::ed25519(protocol as u8)),
            ),
        )]);
        let response = provider
            .sign(&request(SkAlgorithm::Ed25519, 0x05), None)
            .unwrap();
        assert_eq!(response.flags, 0x05);
        verify(
            &public_key(&devices[0].lock().unwrap()),
            &encode_signature(SkAlgorithm::Ed25519, &response).unwrap(),
        );
        let device = devices[0].lock().unwrap();
        assert!(device.requests.contains(&Request::ClientPin {
            subcommand: 0x06,
            protocol: protocol as i64,
            permissions: Some((0x02, APPLICATION.to_string())),
        }));
        assert!(matches!(
            device.assertion_requests()[0],
            Request::GetAssertion {
                uv: None,
                pin_auth: Some((param, actual_protocol)),
                ..
            } if *actual_protocol == protocol as i64
                && param.len() == if protocol == 1 { 16 } else { 32 }
        ));
    }
}

#[test]
fn a_refused_uv_token_prompts_for_a_pin_then_retries_with_subcommand_0x09() {
    for protocol in [1_u64, 2] {
        let mut authenticator = fido2(
            biometric(protocol),
            Some(CredentialKey::ed25519(protocol as u8)),
        );
        authenticator.uv_token_status = Some(ctap2::status::PIN_REQUIRED);
        let (provider, devices) = provider_with(vec![("/dev/hidraw1", authenticator)]);

        assert_eq!(
            provider
                .sign(&request(SkAlgorithm::Ed25519, 0x05), None)
                .unwrap_err(),
            SecurityKeyError::PinRequired
        );
        provider
            .sign(&request(SkAlgorithm::Ed25519, 0x05), Some("123456"))
            .unwrap();

        let device = devices[0].lock().unwrap();
        let client_pin = device
            .requests
            .iter()
            .filter_map(|request| match request {
                Request::ClientPin {
                    subcommand,
                    protocol,
                    ..
                } => Some((*subcommand, *protocol)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            client_pin,
            [
                (0x02, protocol as i64),
                (0x06, protocol as i64),
                (0x02, protocol as i64),
                (0x09, protocol as i64),
            ]
        );
        assert!(matches!(
            device.assertion_requests()[0],
            Request::GetAssertion {
                uv: None,
                pin_auth: Some((_, actual_protocol)),
                ..
            } if *actual_protocol == protocol as i64
        ));
    }
}

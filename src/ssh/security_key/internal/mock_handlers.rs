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

//! CTAP2 and U2F message handling of the scripted authenticator.

use sha2::{Digest, Sha256};

use super::super::cbor::{self, Value};
use super::super::ctap2::{self, CosePublicKey, status};
use super::super::pin_protocol::{
    PinProtocol, PlatformKeyAgreement, SharedSecret, authenticate_with,
};
use super::super::u2f;
use super::{MockAuthenticator, Protocol, Request, ok};

impl MockAuthenticator {
    pub(super) fn handle_cbor(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let Protocol::Fido2(config) = &self.protocol else {
            return Some(vec![0x01]);
        };
        let (&command, body) = payload.split_first()?;
        match command {
            ctap2::CMD_GET_INFO => {
                self.requests.push(Request::GetInfo);
                let mut pairs = vec![
                    (
                        Value::Int(2),
                        Value::Array(if config.options.get("testCredProtect") == Some(&true) {
                            vec![Value::from("credProtect")]
                        } else {
                            vec![]
                        }),
                    ),
                    (
                        Value::Int(1),
                        Value::Array(vec![Value::from("FIDO_2_0"), Value::from("FIDO_2_1")]),
                    ),
                    (Value::Int(3), Value::Bytes(vec![0xa0; 16])),
                    (
                        Value::Int(4),
                        Value::Map(
                            config
                                .options
                                .iter()
                                .map(|(name, value)| {
                                    (Value::from(name.as_str()), Value::Bool(*value))
                                })
                                .collect(),
                        ),
                    ),
                ];
                if !config.pin_protocols.is_empty() {
                    pairs.push((
                        Value::Int(6),
                        Value::Array(
                            config
                                .pin_protocols
                                .iter()
                                .map(|protocol| Value::Int(*protocol as i64))
                                .collect(),
                        ),
                    ));
                }
                Some(ok(&Value::Map(pairs)))
            }
            ctap2::CMD_GET_ASSERTION => self.handle_get_assertion(body),
            ctap2::CMD_CLIENT_PIN => self.handle_client_pin(body),
            0x0a | 0x41 => self.handle_management(body),
            ctap2::CMD_MAKE_CREDENTIAL
                if cbor::decode(body)
                    .ok()
                    .and_then(|v| {
                        v.get_int(2)
                            .and_then(|rp| rp.get(&Value::from("id")))
                            .and_then(Value::as_text)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    != Some("localhost") =>
            {
                self.handle_enrollment(body)
            }
            ctap2::CMD_MAKE_CREDENTIAL => {
                self.requests.push(Request::TouchProbe);
                self.touch_on_probe.then(|| vec![self.touch_status])
            }
            _ => Some(vec![0x01]),
        }
    }

    fn handle_get_assertion(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let map = cbor::decode(body).expect("valid getAssertion CBOR");
        let rp_id = map.get_int(1)?.as_text()?.to_string();
        let client_data_hash = map.get_int(2)?.as_bytes()?.to_vec();
        let credential_ids = map
            .get_int(3)?
            .as_array()?
            .iter()
            .filter_map(|item| item.get(&Value::from("id"))?.as_bytes().map(<[u8]>::to_vec))
            .collect::<Vec<_>>();
        let option = |name: &str| map.get_int(5)?.get(&Value::from(name))?.as_bool();
        let (up, uv) = (option("up"), option("uv"));
        let pin_auth = match (
            map.get_int(6).and_then(Value::as_bytes),
            map.get_int(7).and_then(Value::as_int),
        ) {
            (Some(param), Some(protocol)) => Some((param.to_vec(), protocol)),
            _ => None,
        };
        self.requests.push(Request::GetAssertion {
            rp_id: rp_id.clone(),
            credential_ids: credential_ids.clone(),
            up,
            uv,
            pin_auth: pin_auth.clone(),
        });
        if let Some(code) = self.forced_status {
            return Some(vec![code]);
        }
        let Protocol::Fido2(config) = &self.protocol else {
            unreachable!()
        };
        let Some(credential) = self.credential.as_ref().filter(|credential| {
            credential.rp_id == rp_id && credential_ids.contains(&credential.id)
        }) else {
            return Some(vec![status::NO_CREDENTIALS]);
        };
        let mut flags = 0u8;
        if up != Some(false) {
            flags |= 0x01;
        }
        if let Some((param, protocol)) = pin_auth {
            let protocol = if protocol == 2 {
                PinProtocol::V2
            } else {
                PinProtocol::V1
            };
            if param != authenticate_with(protocol, &self.pin_token, &client_data_hash) {
                return Some(vec![status::PIN_AUTH_INVALID]);
            }
            flags |= 0x04;
        } else if uv == Some(true) {
            if config.options.get("uv") != Some(&true) {
                return Some(vec![status::UNSUPPORTED_OPTION]);
            }
            flags |= 0x04;
        }
        self.counter += 1;
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash);
        let signature = credential.key.sign(&signed);
        Some(ok(&Value::Map(vec![
            (
                Value::Int(1),
                Value::Map(vec![
                    (Value::from("id"), Value::from(credential.id.as_slice())),
                    (Value::from("type"), Value::from("public-key")),
                ]),
            ),
            (Value::Int(2), Value::Bytes(auth_data)),
            (Value::Int(3), Value::Bytes(signature)),
        ])))
    }

    fn handle_client_pin(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let map = cbor::decode(body).expect("valid clientPIN CBOR");
        self.pin_messages.push(map.clone());
        let protocol_number = map.get_int(1)?.as_int()?;
        let subcommand = map.get_int(2)?.as_int()?;
        let permissions = map
            .get_int(9)
            .and_then(Value::as_int)
            .and_then(|bits| Some((bits, map.get_int(10)?.as_text()?.to_string())));
        let has_permissions = map.get_int(9).is_some();
        self.requests.push(Request::ClientPin {
            subcommand,
            protocol: protocol_number,
            permissions,
        });
        let Protocol::Fido2(config) = &self.protocol else {
            unreachable!()
        };
        let protocol = if protocol_number == 2 {
            PinProtocol::V2
        } else {
            PinProtocol::V1
        };
        match subcommand {
            0x02 => {
                let agreement = PlatformKeyAgreement::generate(&mut rand::rng());
                let reply = ok(&Value::Map(vec![(
                    Value::Int(1),
                    agreement.public_key().to_value(),
                )]));
                self.agreement = Some(agreement);
                Some(reply)
            }
            0x05 | 0x06 | 0x09 => {
                let platform = CosePublicKey::from_value(map.get_int(3)?).ok()?;
                let secret: SharedSecret = self
                    .agreement
                    .as_ref()?
                    .shared_secret(protocol, &platform)
                    .ok()?;
                if subcommand == 0x06 {
                    if let Some(status) = self.uv_token_status {
                        return Some(vec![status]);
                    }
                    if config.options.get("uv") != Some(&true)
                        || config.options.get("pinUvAuthToken") != Some(&true)
                        || !has_permissions
                        || map.get_int(6).is_some()
                    {
                        return Some(vec![status::INVALID_OPTION]);
                    }
                } else {
                    let pin_hash = secret.decrypt(map.get_int(6)?.as_bytes()?).ok()?;
                    let expected = Sha256::digest(config.pin.as_deref()?.as_bytes());
                    if pin_hash[..] != expected[..16] {
                        return Some(vec![status::PIN_INVALID]);
                    }
                }
                let token = secret
                    .encrypt(&self.pin_token, &mut rand::rng())
                    .expect("whole blocks");
                Some(ok(&Value::Map(vec![(Value::Int(2), Value::Bytes(token))])))
            }
            _ => Some(vec![0x01]),
        }
    }

    pub(super) fn handle_apdu(&mut self, apdu: &[u8]) -> Option<Vec<u8>> {
        let ins = apdu[1];
        let p1 = apdu[2];
        let len = usize::from(u16::from_be_bytes([apdu[5], apdu[6]]));
        let data = &apdu[7..7 + len];
        match ins {
            u2f::INS_REGISTER if data.iter().any(|v| *v != 0) => self.handle_registration(data, p1),
            u2f::INS_REGISTER => {
                self.requests.push(Request::U2fRegister { p1 });
                Some(if self.touch_on_probe {
                    let mut reply = vec![0x05; 70];
                    reply.extend_from_slice(&u2f::SW_NO_ERROR.to_be_bytes());
                    reply
                } else {
                    u2f::SW_CONDITIONS_NOT_SATISFIED.to_be_bytes().to_vec()
                })
            }
            u2f::INS_AUTHENTICATE => {
                let challenge = &data[..32];
                let application = &data[32..64];
                let key_handle = &data[65..65 + usize::from(data[64])];
                let holds = self.credential.as_ref().is_some_and(|credential| {
                    Sha256::digest(credential.rp_id.as_bytes())[..] == *application
                        && credential.id == key_handle
                });
                if p1 == u2f::P1_CHECK_ONLY {
                    self.requests.push(Request::U2fCheck);
                    return Some(
                        if holds {
                            u2f::SW_CONDITIONS_NOT_SATISFIED
                        } else {
                            u2f::SW_WRONG_DATA
                        }
                        .to_be_bytes()
                        .to_vec(),
                    );
                }
                self.requests.push(Request::U2fSign);
                if !holds {
                    return Some(u2f::SW_WRONG_DATA.to_be_bytes().to_vec());
                }
                if self.u2f_presence_retries > 0 {
                    self.u2f_presence_retries -= 1;
                    return Some(u2f::SW_CONDITIONS_NOT_SATISFIED.to_be_bytes().to_vec());
                }
                self.counter += 1;
                let mut signed = Vec::with_capacity(69);
                signed.extend_from_slice(application);
                signed.push(0x01);
                signed.extend_from_slice(&self.counter.to_be_bytes());
                signed.extend_from_slice(challenge);
                let signature = self.credential.as_ref()?.key.sign(&signed);
                let mut reply = vec![0x01];
                reply.extend_from_slice(&self.counter.to_be_bytes());
                reply.extend_from_slice(&signature);
                reply.extend_from_slice(&u2f::SW_NO_ERROR.to_be_bytes());
                Some(reply)
            }
            _ => Some(0x6d00u16.to_be_bytes().to_vec()),
        }
    }
}

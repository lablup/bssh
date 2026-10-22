// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

//! Stateful authenticator enrollment mocks; PIN MACs checked independently.

use super::super::pin_protocol::{PinProtocol, authenticate_with};
use super::super::u2f;
use super::*;
use sha2::{Digest, Sha256};

pub struct Resident {
    pub credential: Credential,
    pub user: Vec<u8>,
    pub protection: i64,
}

impl CredentialKey {
    pub(super) fn cose(&self) -> Value {
        match self {
            Self::Ed25519(key) => Value::Map(vec![
                (Value::Int(1), Value::Int(1)),
                (Value::Int(3), Value::Int(-8)),
                (Value::Int(-1), Value::Int(6)),
                (
                    Value::Int(-2),
                    Value::Bytes(key.verifying_key().to_bytes().to_vec()),
                ),
            ]),
            Self::P256(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                Value::Map(vec![
                    (Value::Int(1), Value::Int(2)),
                    (Value::Int(3), Value::Int(-7)),
                    (Value::Int(-1), Value::Int(1)),
                    (
                        Value::Int(-2),
                        Value::Bytes(point.as_bytes()[1..33].to_vec()),
                    ),
                    (
                        Value::Int(-3),
                        Value::Bytes(point.as_bytes()[33..].to_vec()),
                    ),
                ])
            }
        }
    }
}

impl MockAuthenticator {
    pub(super) fn handle_enrollment(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let map = cbor::decode(body).ok()?;
        self.requests.push(Request::MakeCredential(map.clone()));
        if let Some(reply) = &self.enrollment_reply {
            return Some(reply.clone());
        }
        let rp = map
            .get_int(2)?
            .get(&Value::from("id"))?
            .as_text()?
            .to_owned();
        let hash = map.get_int(1)?.as_bytes()?;
        let user = map
            .get_int(3)?
            .get(&Value::from("id"))?
            .as_bytes()?
            .to_vec();
        let algorithm = map
            .get_int(4)?
            .as_array()?
            .first()?
            .get(&Value::from("alg"))?
            .as_int()?;
        let protocol = map.get_int(9).and_then(Value::as_int).map(|v| {
            if v == 2 {
                PinProtocol::V2
            } else {
                PinProtocol::V1
            }
        });
        let mut flags = 0x41;
        if let Some(protocol) = protocol {
            if map.get_int(8)?.as_bytes()? != authenticate_with(protocol, &self.pin_token, hash) {
                return Some(vec![status::PIN_AUTH_INVALID]);
            }
            flags |= 4;
        } else if map
            .get_int(7)
            .and_then(|v| v.get(&Value::from("uv")))
            .and_then(Value::as_bool)
            == Some(true)
        {
            flags |= 4;
        }
        let policy = map
            .get_int(6)
            .and_then(|v| v.get(&Value::from("credProtect")))
            .and_then(Value::as_int);
        if policy.is_some() {
            flags |= 0x80;
        }
        let key = if algorithm == -8 {
            CredentialKey::ed25519(12)
        } else if algorithm == -7 {
            CredentialKey::p256(12)
        } else {
            return Some(vec![status::UNSUPPORTED_ALGORITHM]);
        };
        let id = vec![0x42, 0x43, self.resident_credentials.len() as u8];
        let mut auth = Sha256::digest(rp.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend([0; 20]);
        auth.extend((id.len() as u16).to_be_bytes());
        auth.extend(&id);
        auth.extend(cbor::encode(&key.cose()));
        if let Some(policy) = policy {
            auth.extend(cbor::encode(&Value::Map(vec![(
                Value::from("credProtect"),
                Value::Int(policy),
            )])));
        }
        let credential = Credential { rp_id: rp, id, key };
        if map
            .get_int(7)
            .and_then(|v| v.get(&Value::from("rk")))
            .and_then(Value::as_bool)
            == Some(true)
        {
            self.resident_credentials.push(Resident {
                credential: credential.clone(),
                user,
                protection: policy.unwrap_or(1),
            });
        }
        self.credential = Some(credential);
        Some(ok(&Value::Map(vec![
            (Value::Int(1), Value::from("none")),
            (Value::Int(2), Value::Bytes(auth)),
            (Value::Int(3), Value::Map(vec![])),
        ])))
    }

    pub(super) fn handle_management(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let map = cbor::decode(body).ok()?;
        self.requests
            .push(Request::CredentialManagement(map.clone()));
        if let Some(reply) = &self.management_reply {
            return Some(reply.clone());
        }
        let sub = map.get_int(1)?.as_int()?;
        if matches!(sub, 2 | 4) {
            let protocol = if map.get_int(3)?.as_int()? == 2 {
                PinProtocol::V2
            } else {
                PinProtocol::V1
            };
            let mut message = vec![sub as u8];
            if let Some(params) = map.get_int(2) {
                message.extend(cbor::encode(params));
            }
            if map.get_int(4)?.as_bytes()? != authenticate_with(protocol, &self.pin_token, &message)
            {
                return Some(vec![status::PIN_AUTH_INVALID]);
            }
        } else if map.get_int(3).is_some() || map.get_int(4).is_some() {
            return Some(vec![status::INVALID_OPTION]);
        }
        let parties = self
            .resident_credentials
            .iter()
            .map(|r| r.credential.rp_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        match sub {
            2 | 3 => {
                if sub == 2 {
                    self.rp_cursor = 0;
                } else {
                    self.rp_cursor += 1;
                }
                let Some(rp) = parties.get(self.rp_cursor) else {
                    return Some(vec![status::NO_CREDENTIALS]);
                };
                let mut pairs = vec![
                    (
                        Value::Int(3),
                        Value::Map(vec![(Value::from("id"), Value::from(rp.as_str()))]),
                    ),
                    (
                        Value::Int(4),
                        Value::Bytes(Sha256::digest(rp.as_bytes()).to_vec()),
                    ),
                ];
                if sub == 2 {
                    pairs.push((Value::Int(5), Value::Int(parties.len() as i64)));
                }
                Some(ok(&Value::Map(pairs)))
            }
            4 | 5 => {
                if sub == 4 {
                    let hash = map.get_int(2)?.get_int(1)?.as_bytes()?;
                    self.selected_rp = parties
                        .into_iter()
                        .find(|rp| Sha256::digest(rp.as_bytes()).as_slice() == hash);
                    self.credential_cursor = 0;
                } else {
                    self.credential_cursor += 1;
                }
                let credentials = self
                    .resident_credentials
                    .iter()
                    .filter(|r| Some(&r.credential.rp_id) == self.selected_rp.as_ref())
                    .collect::<Vec<_>>();
                let resident = credentials.get(self.credential_cursor)?;
                let mut pairs = vec![
                    (
                        Value::Int(6),
                        Value::Map(vec![(
                            Value::from("id"),
                            Value::Bytes(resident.user.clone()),
                        )]),
                    ),
                    (
                        Value::Int(7),
                        Value::Map(vec![
                            (
                                Value::from("id"),
                                Value::Bytes(resident.credential.id.clone()),
                            ),
                            (Value::from("type"), Value::from("public-key")),
                        ]),
                    ),
                    (Value::Int(8), resident.credential.key.cose()),
                    (Value::Int(10), Value::Int(resident.protection)),
                ];
                if sub == 4 {
                    pairs.push((Value::Int(9), Value::Int(credentials.len() as i64)));
                }
                Some(ok(&Value::Map(pairs)))
            }
            _ => Some(vec![0x01]),
        }
    }

    pub(super) fn handle_registration(&mut self, data: &[u8], p1: u8) -> Option<Vec<u8>> {
        self.requests.push(Request::U2fRegister { p1 });
        if let Some(reply) = &self.enrollment_reply {
            return Some(reply.clone());
        }
        if self.u2f_presence_retries > 0 {
            self.u2f_presence_retries -= 1;
            return Some(u2f::SW_CONDITIONS_NOT_SATISFIED.to_be_bytes().to_vec());
        }
        let key = CredentialKey::p256(15);
        let CredentialKey::P256(signing) = &key else {
            unreachable!()
        };
        let mut reply = vec![5];
        reply.extend(signing.verifying_key().to_sec1_point(false).as_bytes());
        reply.extend([3, 0x42, 0x43, 0x44]);
        let challenge: [u8; 32] = data[..32].try_into().unwrap();
        let application: [u8; 32] = data[32..64].try_into().unwrap();
        let (certificate, signature) = super::super::attestation::tests::u2f_attestation(
            &application,
            &challenge,
            &[0x42, 0x43, 0x44],
            &reply[1..66],
        );
        reply.extend(certificate);
        reply.extend(signature);
        reply.extend(u2f::SW_NO_ERROR.to_be_bytes());
        Some(reply)
    }
}

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

//! A scripted authenticator behind the [`HidDevice`] trait: it speaks
//! CTAPHID on the wire (channel allocation, reassembly, KEEPALIVE), answers
//! CTAP2 `getInfo`/`getAssertion`/`clientPIN` or U2F APDUs, and signs
//! assertions with a real Ed25519 or P-256 key so the resulting SSH
//! signature can be verified with `ssh-key`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use p256::ecdsa::signature::Signer as _;

use super::CtapError;
use super::cbor::{self, Value};
use super::ctap2::{self, status};
use super::ctaphid::{
    Assembler, BROADCAST_CID, CAPABILITY_CBOR, CMD_CANCEL, CMD_CBOR, CMD_ERROR, CMD_INIT,
    CMD_KEEPALIVE, CMD_MSG, FIDO_USAGE_CTAPHID, FIDO_USAGE_PAGE, Frame, HidBackend, HidDevice,
    HidDeviceInfo, Report, frame_message,
};
use super::pin_protocol::PlatformKeyAgreement;

#[path = "mock_handlers.rs"]
mod handlers;

pub enum CredentialKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl CredentialKey {
    pub fn ed25519(seed: u8) -> Self {
        Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    pub fn p256(seed: u8) -> Self {
        Self::P256(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("valid scalar"))
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.sign(message).to_bytes().to_vec(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_der().to_bytes().to_vec()
            }
        }
    }
}

pub struct Credential {
    pub rp_id: String,
    pub id: Vec<u8>,
    pub key: CredentialKey,
}

/// What the device records about each request, for assertions in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetInfo,
    GetAssertion {
        rp_id: String,
        credential_ids: Vec<Vec<u8>>,
        up: Option<bool>,
        uv: Option<bool>,
        pin_auth: Option<(Vec<u8>, i64)>,
    },
    ClientPin {
        subcommand: i64,
        protocol: i64,
        permissions: Option<(i64, String)>,
    },
    TouchProbe,
    U2fCheck,
    U2fSign,
    U2fRegister {
        p1: u8,
    },
    Cancel,
}

/// What a stalled device sends while it holds a `getAssertion` reply back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flood {
    /// KEEPALIVE frames on our channel.
    Keepalive,
    /// Frames addressed to another host's channel.
    ForeignChannel,
}

struct Stalled {
    since: Instant,
    reports: Vec<Report>,
}

pub struct Fido2Config {
    pub options: BTreeMap<String, bool>,
    pub pin_protocols: Vec<u64>,
    pub pin: Option<String>,
}

impl Fido2Config {
    /// A CTAP 2.1 device with a PIN set, protocol 2, and permission tokens.
    pub fn with_pin(pin: &str) -> Self {
        Self {
            options: BTreeMap::from([
                ("clientPin".to_string(), true),
                ("pinUvAuthToken".to_string(), true),
                ("up".to_string(), true),
            ]),
            pin_protocols: vec![1, 2],
            pin: Some(pin.to_string()),
        }
    }

    /// A CTAP 2.0 device without a PIN and without a `uv` option.
    pub fn plain() -> Self {
        Self {
            options: BTreeMap::from([("up".to_string(), true)]),
            pin_protocols: vec![1],
            pin: None,
        }
    }
}

pub enum Protocol {
    Fido2(Fido2Config),
    U2f,
}

pub struct MockAuthenticator {
    pub protocol: Protocol,
    pub credential: Option<Credential>,
    pub counter: u32,
    /// KEEPALIVE frames sent before every CBOR reply.
    pub keepalives_before_reply: usize,
    /// Whether a touch probe (dummy makeCredential or REGISTER) is answered,
    /// standing in for the user touching this device.
    pub touch_on_probe: bool,
    /// The CTAP2 status a touched device answers the dummy makeCredential
    /// with.
    pub touch_status: u8,
    /// Hold the first `getInfo` reply back until the next report arrives,
    /// as a device does that answers after the host stopped waiting.
    pub late_get_info: bool,
    /// Hold every `getAssertion` reply back for this long, sending the
    /// given frames meanwhile.
    pub stall: Option<(Flood, Duration)>,
    /// U2F: ENFORCE requests answered with "conditions not satisfied"
    /// before the device signs.
    pub u2f_presence_retries: usize,
    /// Answer every getAssertion with this status instead of signing.
    pub forced_status: Option<u8>,
    /// Answer `getPinUvAuthTokenUsingUvWithPermissions` with this status.
    pub uv_token_status: Option<u8>,
    pub requests: Vec<Request>,
    pub cancels: usize,
    cid: [u8; 4],
    assembler: Assembler,
    outbound: VecDeque<Report>,
    late: Vec<Report>,
    stalled: Option<Stalled>,
    agreement: Option<PlatformKeyAgreement>,
    pin_token: [u8; 32],
}

impl MockAuthenticator {
    pub fn new(protocol: Protocol, credential: Option<Credential>) -> Self {
        Self {
            protocol,
            credential,
            counter: 41,
            keepalives_before_reply: 0,
            touch_on_probe: true,
            touch_status: status::PIN_NOT_SET,
            late_get_info: false,
            stall: None,
            u2f_presence_retries: 0,
            forced_status: None,
            uv_token_status: None,
            requests: Vec::new(),
            cancels: 0,
            cid: [0x0b, 0x55, 0x47, 0x01],
            assembler: Assembler::default(),
            outbound: VecDeque::new(),
            late: Vec::new(),
            stalled: None,
            agreement: None,
            pin_token: [0x7a; 32],
        }
    }

    pub fn assertion_requests(&self) -> Vec<&Request> {
        self.requests
            .iter()
            .filter(|request| matches!(request, Request::GetAssertion { .. }))
            .collect()
    }

    fn is_fido2(&self) -> bool {
        matches!(self.protocol, Protocol::Fido2(_))
    }

    fn handle_report(&mut self, report: &Report) {
        let late = std::mem::take(&mut self.late);
        self.outbound.extend(late);
        let frame = Frame::parse(report);
        if let Frame::Init {
            cid: BROADCAST_CID,
            cmd: CMD_INIT,
            data,
            ..
        } = frame
        {
            // Every INIT allocates a new channel, as real devices do.
            self.cid[3] = self.cid[3].wrapping_add(1);
            let mut reply = Vec::with_capacity(17);
            reply.extend_from_slice(&data[..8]);
            reply.extend_from_slice(&self.cid);
            reply.extend_from_slice(&[2, 1, 0, 0]);
            reply.push(if self.is_fido2() { CAPABILITY_CBOR } else { 0 });
            self.queue(CMD_INIT, &reply, BROADCAST_CID, 0);
            return;
        }
        if frame.cid() != self.cid {
            return;
        }
        let Some((cmd, payload)) = self.assembler.push(&frame).expect("well-formed frames") else {
            return;
        };
        match cmd {
            CMD_CANCEL => {
                self.cancels += 1;
                self.requests.push(Request::Cancel);
            }
            CMD_CBOR => {
                let command = payload.first().copied();
                if let Some(reply) = self.handle_cbor(&payload) {
                    if command == Some(ctap2::CMD_GET_INFO) && self.late_get_info {
                        self.late_get_info = false;
                        self.late = frame_message(self.cid, CMD_CBOR, &reply).expect("fits");
                    } else if command == Some(ctap2::CMD_GET_ASSERTION) && self.stall.is_some() {
                        self.stalled = Some(Stalled {
                            since: Instant::now(),
                            reports: frame_message(self.cid, CMD_CBOR, &reply).expect("fits"),
                        });
                    } else {
                        let keepalives = self.keepalives_before_reply;
                        self.queue(CMD_CBOR, &reply, self.cid, keepalives);
                    }
                }
            }
            CMD_MSG => {
                if let Some(reply) = self.handle_apdu(&payload) {
                    self.queue(CMD_MSG, &reply, self.cid, 0);
                }
            }
            _ => self.queue(CMD_ERROR, &[0x01], self.cid, 0),
        }
    }

    /// The next report the device sends, if any.
    fn next_report(&mut self) -> Option<Report> {
        if let Some(report) = self.outbound.pop_front() {
            return Some(report);
        }
        let (flood, duration) = self.stall?;
        let stalled = self.stalled.as_ref()?;
        if stalled.since.elapsed() < duration {
            let cid = match flood {
                Flood::Keepalive => self.cid,
                Flood::ForeignChannel => [0x99; 4],
            };
            let cmd = match flood {
                Flood::Keepalive => CMD_KEEPALIVE,
                Flood::ForeignChannel => CMD_CBOR,
            };
            return Some(frame_message(cid, cmd, &[0x02]).expect("fits")[0]);
        }
        let stalled = self.stalled.take()?;
        self.outbound.extend(stalled.reports);
        self.outbound.pop_front()
    }

    fn queue(&mut self, cmd: u8, payload: &[u8], cid: [u8; 4], keepalives: usize) {
        for _ in 0..keepalives {
            self.outbound
                .extend(frame_message(cid, CMD_KEEPALIVE, &[0x02]).expect("fits"));
        }
        self.outbound
            .extend(frame_message(cid, cmd, payload).expect("fits"));
    }
}

pub(super) fn ok(value: &Value) -> Vec<u8> {
    let mut reply = vec![status::OK];
    reply.extend(cbor::encode(value));
    reply
}

/// The [`HidDevice`] handle tests hand to the provider.
pub struct MockDevice {
    inner: Arc<Mutex<MockAuthenticator>>,
}

impl HidDevice for MockDevice {
    fn write_report(&mut self, report: &Report) -> Result<(), CtapError> {
        self.inner.lock().unwrap().handle_report(report);
        Ok(())
    }

    fn read_report(&mut self, _timeout: Option<Duration>) -> Result<Option<Report>, CtapError> {
        Ok(self.inner.lock().unwrap().next_report())
    }
}

/// A set of attached HID devices.
#[derive(Default)]
pub struct MockBackend {
    devices: Vec<(HidDeviceInfo, Option<Arc<Mutex<MockAuthenticator>>>)>,
    pub unopenable: Vec<String>,
}

impl MockBackend {
    pub fn add(
        &mut self,
        path: &str,
        authenticator: MockAuthenticator,
    ) -> Arc<Mutex<MockAuthenticator>> {
        let shared = Arc::new(Mutex::new(authenticator));
        self.devices.push((
            HidDeviceInfo {
                path: path.to_string(),
                usage_page: FIDO_USAGE_PAGE,
                usage: FIDO_USAGE_CTAPHID,
                vendor_id: 0x1050,
                product_id: 0x0407,
                product: Some("Mock Key".to_string()),
            },
            Some(Arc::clone(&shared)),
        ));
        shared
    }

    /// Another enumeration entry for a device already added, as hidapi lists
    /// one per top-level collection of the report descriptor.
    pub fn add_alias(&mut self, path: &str) {
        let entry = self
            .devices
            .iter()
            .find(|(info, _)| info.path == path)
            .map(|(info, device)| (info.clone(), device.clone()))
            .expect("device added before its alias");
        self.devices.push(entry);
    }

    /// A HID device on another usage page (a keyboard), which must be ignored.
    pub fn add_non_fido(&mut self, path: &str) {
        self.devices.push((
            HidDeviceInfo {
                path: path.to_string(),
                usage_page: 0x01,
                usage: 0x06,
                vendor_id: 0x046d,
                product_id: 0xc31c,
                product: Some("Keyboard".to_string()),
            },
            None,
        ));
    }
}

impl HidBackend for MockBackend {
    fn enumerate(&self) -> Result<Vec<HidDeviceInfo>, CtapError> {
        Ok(self.devices.iter().map(|(info, _)| info.clone()).collect())
    }

    fn open(&self, path: &str) -> Result<Box<dyn HidDevice>, CtapError> {
        if self.unopenable.iter().any(|blocked| blocked == path) {
            return Err(CtapError::Transport(format!(
                "failed to open device with path {path}: Permission denied"
            )));
        }
        let (_, authenticator) = self
            .devices
            .iter()
            .find(|(info, _)| info.path == path)
            .ok_or_else(|| CtapError::Transport("no such device".to_string()))?;
        let inner = authenticator
            .as_ref()
            .ok_or_else(|| CtapError::Transport("not a FIDO device".to_string()))?;
        Ok(Box::new(MockDevice {
            inner: Arc::clone(inner),
        }))
    }
}

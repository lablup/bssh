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

//! CTAPHID: the USB HID framing under CTAP2 and U2F (CTAP 2.1 section 11.2).
//!
//! A message is carried in 64-byte reports: an initialization packet
//! `CID(4) | CMD(1, bit 7 set) | BCNT(2, big-endian) | data(57)` followed by
//! continuation packets `CID(4) | SEQ(1) | data(59)`. The HID device itself is
//! behind [`HidDevice`], so the framing, channel allocation, KEEPALIVE and
//! ERROR handling are exercised against a mock in tests.

use std::time::{Duration, Instant};

use super::CtapError;

/// Report size every CTAPHID authenticator uses.
pub const REPORT_LEN: usize = 64;
/// One HID report.
pub type Report = [u8; REPORT_LEN];

const INIT_HEADER_LEN: usize = 7;
const CONT_HEADER_LEN: usize = 5;
const INIT_DATA_LEN: usize = REPORT_LEN - INIT_HEADER_LEN;
const CONT_DATA_LEN: usize = REPORT_LEN - CONT_HEADER_LEN;
/// Sequence numbers run 0..=127, so a message fits in 1 + 128 packets.
pub const MAX_MESSAGE_LEN: usize = INIT_DATA_LEN + 128 * CONT_DATA_LEN;

/// `CTAPHID_MSG`: a U2F APDU.
pub const CMD_MSG: u8 = 0x03;
/// `CTAPHID_INIT`: channel allocation.
pub const CMD_INIT: u8 = 0x06;
/// `CTAPHID_CBOR`: a CTAP2 command.
pub const CMD_CBOR: u8 = 0x10;
/// `CTAPHID_CANCEL`.
pub const CMD_CANCEL: u8 = 0x11;
/// `CTAPHID_KEEPALIVE`: the authenticator is still busy (status byte).
pub const CMD_KEEPALIVE: u8 = 0x3b;
/// `CTAPHID_ERROR`: a transport-level error code.
pub const CMD_ERROR: u8 = 0x3f;

/// The channel every device listens on before one is allocated.
pub const BROADCAST_CID: [u8; 4] = [0xff; 4];
/// `CAPFLAG_CBOR`: the device speaks CTAP2.
pub const CAPABILITY_CBOR: u8 = 0x04;

/// Bound on channel allocation; a device that does not answer `INIT` is
/// not a working authenticator, and waiting forever on it would block
/// every other device behind the provider lock.
const INIT_TIMEOUT: Duration = Duration::from_secs(2);

/// One open HID report pipe.
pub trait HidDevice: Send {
    fn write_report(&mut self, report: &Report) -> Result<(), CtapError>;

    /// `Ok(None)` when `timeout` elapsed without a report; `None` waits
    /// without limit.
    fn read_report(&mut self, timeout: Option<Duration>) -> Result<Option<Report>, CtapError>;
}

/// A HID device as the host enumerates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HidDeviceInfo {
    /// Backend-specific path handed back to [`HidBackend::open`].
    pub path: String,
    pub usage_page: u16,
    pub usage: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    pub product: Option<String>,
}

/// FIDO alliance HID usage page and the U2F/CTAPHID usage on it.
pub const FIDO_USAGE_PAGE: u16 = 0xf1d0;
pub const FIDO_USAGE_CTAPHID: u16 = 0x01;

impl HidDeviceInfo {
    #[must_use]
    pub fn is_fido(&self) -> bool {
        self.usage_page == FIDO_USAGE_PAGE && self.usage == FIDO_USAGE_CTAPHID
    }
}

/// Enumerates and opens HID devices; the real one wraps hidapi.
pub trait HidBackend: Send + Sync {
    fn enumerate(&self) -> Result<Vec<HidDeviceInfo>, CtapError>;
    fn open(&self, path: &str) -> Result<Box<dyn HidDevice>, CtapError>;
}

/// Split `payload` into the reports that carry command `cmd` on `cid`.
pub fn frame_message(cid: [u8; 4], cmd: u8, payload: &[u8]) -> Result<Vec<Report>, CtapError> {
    if payload.len() > MAX_MESSAGE_LEN {
        return Err(CtapError::Protocol("message too long for CTAPHID"));
    }
    let mut reports = Vec::with_capacity(1 + payload.len() / CONT_DATA_LEN);
    let mut init = [0u8; REPORT_LEN];
    init[..4].copy_from_slice(&cid);
    init[4] = cmd | 0x80;
    init[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let first = payload.len().min(INIT_DATA_LEN);
    init[INIT_HEADER_LEN..INIT_HEADER_LEN + first].copy_from_slice(&payload[..first]);
    reports.push(init);
    for (seq, chunk) in payload[first..].chunks(CONT_DATA_LEN).enumerate() {
        let mut cont = [0u8; REPORT_LEN];
        cont[..4].copy_from_slice(&cid);
        cont[4] = seq as u8;
        cont[CONT_HEADER_LEN..CONT_HEADER_LEN + chunk.len()].copy_from_slice(chunk);
        reports.push(cont);
    }
    Ok(reports)
}

/// A parsed report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    Init {
        cid: [u8; 4],
        cmd: u8,
        len: usize,
        data: &'a [u8],
    },
    Continuation {
        cid: [u8; 4],
        seq: u8,
        data: &'a [u8],
    },
}

impl<'a> Frame<'a> {
    #[must_use]
    pub fn parse(report: &'a Report) -> Self {
        let cid: [u8; 4] = report[..4].try_into().expect("four bytes");
        if report[4] & 0x80 != 0 {
            Self::Init {
                cid,
                cmd: report[4] & 0x7f,
                len: usize::from(u16::from_be_bytes([report[5], report[6]])),
                data: &report[INIT_HEADER_LEN..],
            }
        } else {
            Self::Continuation {
                cid,
                seq: report[4],
                data: &report[CONT_HEADER_LEN..],
            }
        }
    }

    #[must_use]
    pub fn cid(&self) -> [u8; 4] {
        match self {
            Self::Init { cid, .. } | Self::Continuation { cid, .. } => *cid,
        }
    }
}

/// Reassembles one message from its initialization and continuation packets.
#[derive(Debug, Default)]
pub struct Assembler {
    current: Option<Partial>,
}

#[derive(Debug)]
struct Partial {
    cmd: u8,
    expected: usize,
    next_seq: u8,
    buffer: Vec<u8>,
}

impl Assembler {
    /// Feed one frame already known to belong to this channel. Returns the
    /// completed `(cmd, payload)` when the frame finished a message.
    pub fn push(&mut self, frame: &Frame<'_>) -> Result<Option<(u8, Vec<u8>)>, CtapError> {
        match frame {
            Frame::Init { cmd, len, data, .. } => {
                if *len > MAX_MESSAGE_LEN {
                    return Err(CtapError::Protocol("announced length too long"));
                }
                let take = (*len).min(data.len());
                let partial = Partial {
                    cmd: *cmd,
                    expected: *len,
                    next_seq: 0,
                    buffer: data[..take].to_vec(),
                };
                self.current = Some(partial);
            }
            Frame::Continuation { seq, data, .. } => {
                let Some(partial) = self.current.as_mut() else {
                    // A stray continuation (for example the tail of a
                    // message an earlier, abandoned read left behind).
                    return Ok(None);
                };
                if *seq != partial.next_seq {
                    self.current = None;
                    return Err(CtapError::Protocol("continuation out of sequence"));
                }
                partial.next_seq = partial.next_seq.wrapping_add(1) & 0x7f;
                let remaining = partial.expected - partial.buffer.len();
                partial
                    .buffer
                    .extend_from_slice(&data[..remaining.min(data.len())]);
            }
        }
        let complete = self
            .current
            .as_ref()
            .is_some_and(|partial| partial.buffer.len() >= partial.expected);
        if complete {
            let partial = self.current.take().expect("checked above");
            return Ok(Some((partial.cmd, partial.buffer)));
        }
        Ok(None)
    }
}

/// An allocated CTAPHID channel to one device.
pub struct CtapHidChannel {
    device: Box<dyn HidDevice>,
    cid: [u8; 4],
    capabilities: u8,
    /// A request was sent and its reply not yet consumed; `CANCEL` is sent
    /// on drop so a device left blinking for a touch stops.
    pending: bool,
}

impl std::fmt::Debug for CtapHidChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CtapHidChannel")
            .field("cid", &self.cid)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl CtapHidChannel {
    /// Allocate a channel with `CTAPHID_INIT`; `nonce` identifies our reply
    /// among those of other hosts sharing the broadcast channel.
    pub fn open(device: Box<dyn HidDevice>, nonce: [u8; 8]) -> Result<Self, CtapError> {
        Self::open_within(device, nonce, INIT_TIMEOUT)
    }

    /// [`open`](Self::open), waiting at most `timeout` (capped at the usual
    /// `INIT` bound) for the reply.
    pub fn open_within(
        mut device: Box<dyn HidDevice>,
        nonce: [u8; 8],
        timeout: Duration,
    ) -> Result<Self, CtapError> {
        let (cid, capabilities) = allocate(&mut *device, nonce, timeout.min(INIT_TIMEOUT))?;
        Ok(Self {
            device,
            cid,
            capabilities,
            pending: false,
        })
    }

    /// Allocate a fresh channel on the same device. The device abandons the
    /// pending transaction, and a reply to it that is still in flight
    /// carries the old channel ID, so [`receive`](Self::receive) drops it.
    pub fn reinit(&mut self, nonce: [u8; 8], timeout: Duration) -> Result<(), CtapError> {
        let (cid, capabilities) = allocate(&mut *self.device, nonce, timeout.min(INIT_TIMEOUT))?;
        self.cid = cid;
        self.capabilities = capabilities;
        self.pending = false;
        Ok(())
    }

    /// Treat the device as U2F-only from now on, as libfido2's
    /// `fido_dev_force_u2f` does when `getInfo` fails: it clears the CBOR
    /// capability, and with it the `CANCEL` libfido2 only sends to FIDO2
    /// devices.
    pub fn force_u2f(&mut self) {
        self.capabilities &= !CAPABILITY_CBOR;
    }

    /// `CAPFLAG_CBOR`: the device accepts CTAP2 commands.
    #[must_use]
    pub fn supports_cbor(&self) -> bool {
        self.capabilities & CAPABILITY_CBOR != 0
    }

    pub fn send(&mut self, cmd: u8, payload: &[u8]) -> Result<(), CtapError> {
        for report in frame_message(self.cid, cmd, payload)? {
            self.device.write_report(&report)?;
        }
        self.pending = true;
        Ok(())
    }

    /// Wait for the reply to the last [`send`](Self::send). `Ok(None)` when
    /// `timeout` elapses first (the request stays pending); KEEPALIVE frames
    /// are skipped without extending the deadline, as libfido2 does, and an
    /// ERROR frame becomes [`CtapError::HidError`].
    pub fn receive(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<Option<(u8, Vec<u8>)>, CtapError> {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let mut assembler = Assembler::default();
        loop {
            let remaining = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    Some(remaining)
                }
                None => None,
            };
            let Some(report) = self.device.read_report(remaining)? else {
                return Ok(None);
            };
            let frame = Frame::parse(&report);
            if frame.cid() != self.cid {
                continue;
            }
            if let Frame::Init { cmd, .. } = frame {
                if cmd == CMD_KEEPALIVE {
                    continue;
                }
                if cmd == CMD_ERROR {
                    self.pending = false;
                    let code = report[INIT_HEADER_LEN];
                    return Err(CtapError::HidError(code));
                }
            }
            if let Some(message) = assembler.push(&frame)? {
                self.pending = false;
                return Ok(Some(message));
            }
        }
    }

    /// Send `cmd` and wait for its reply; a reply carrying another command
    /// is a protocol violation.
    pub fn transact(
        &mut self,
        cmd: u8,
        payload: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, CtapError> {
        self.send(cmd, payload)?;
        let (reply_cmd, reply) = self.receive(timeout)?.ok_or(CtapError::Timeout)?;
        if reply_cmd != cmd {
            return Err(CtapError::Protocol("reply for a different command"));
        }
        Ok(reply)
    }

    /// `CTAPHID_CANCEL` for the pending request, if any. U2F-only devices
    /// are left alone: `fido_dev_cancel` refuses them, since `CANCEL` is a
    /// CTAP2 command a U2F device may not implement.
    pub fn cancel(&mut self) -> Result<(), CtapError> {
        let pending = std::mem::replace(&mut self.pending, false);
        if !pending || !self.supports_cbor() {
            return Ok(());
        }
        for report in frame_message(self.cid, CMD_CANCEL, &[])? {
            self.device.write_report(&report)?;
        }
        Ok(())
    }
}

/// `CTAPHID_INIT` on the broadcast channel: the allocated channel ID and
/// the capability flags.
fn allocate(
    device: &mut dyn HidDevice,
    nonce: [u8; 8],
    timeout: Duration,
) -> Result<([u8; 4], u8), CtapError> {
    for report in frame_message(BROADCAST_CID, CMD_INIT, &nonce)? {
        device.write_report(&report)?;
    }
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CtapError::Timeout);
        }
        let Some(report) = device.read_report(Some(remaining))? else {
            return Err(CtapError::Timeout);
        };
        let Frame::Init {
            cid,
            cmd,
            len,
            data,
            ..
        } = Frame::parse(&report)
        else {
            continue;
        };
        if cid != BROADCAST_CID || cmd != CMD_INIT {
            continue;
        }
        if len < 17 || data[..8] != nonce {
            continue;
        }
        let cid: [u8; 4] = data[8..12].try_into().expect("four bytes");
        if cid == BROADCAST_CID || cid == [0; 4] {
            return Err(CtapError::Protocol("device allocated an invalid channel"));
        }
        return Ok((cid, data[16]));
    }
}

/// Time left before `deadline`; [`CtapError::Timeout`] once it has passed.
pub fn remaining(deadline: Instant) -> Result<Duration, CtapError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(CtapError::Timeout);
    }
    Ok(left)
}

impl Drop for CtapHidChannel {
    fn drop(&mut self) {
        // Best effort: the device may already be gone.
        let _ = self.cancel();
    }
}

#[cfg(test)]
#[path = "ctaphid_tests.rs"]
mod tests;

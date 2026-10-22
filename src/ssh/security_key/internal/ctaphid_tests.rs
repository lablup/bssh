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

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::*;

const CID: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

#[test]
fn frame_message_splits_at_the_57_and_59_byte_boundaries() {
    let one = frame_message(CID, CMD_CBOR, &[0xaa; 57]).unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(&one[0][..7], &[0x11, 0x22, 0x33, 0x44, 0x90, 0x00, 0x39]);
    assert_eq!(&one[0][7..], &[0xaa; 57]);

    let two = frame_message(CID, CMD_MSG, &[0xbb; 58]).unwrap();
    assert_eq!(two.len(), 2);
    assert_eq!(two[0][4], 0x83);
    assert_eq!(&two[1][..5], &[0x11, 0x22, 0x33, 0x44, 0x00]);
    assert_eq!(two[1][5], 0xbb);
    assert_eq!(&two[1][6..], &[0u8; 58]);

    let four = frame_message(CID, CMD_CBOR, &[0xcc; 57 + 59 * 2 + 1]).unwrap();
    assert_eq!(four.len(), 4);
    assert_eq!(
        four.iter().skip(1).map(|r| r[4]).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(four[3][5], 0xcc);
    assert_eq!(four[3][6], 0);

    let max = frame_message(CID, CMD_CBOR, &[0; MAX_MESSAGE_LEN]).unwrap();
    assert_eq!(max.len(), 129);
    assert_eq!(max[128][4], 127);
    assert_eq!(
        frame_message(CID, CMD_CBOR, &[0; MAX_MESSAGE_LEN + 1]).unwrap_err(),
        CtapError::Protocol("message too long for CTAPHID")
    );
    let empty = frame_message(CID, CMD_CANCEL, &[]).unwrap();
    assert_eq!(empty.len(), 1);
    assert_eq!(&empty[0][4..7], &[0x91, 0, 0]);
}

#[test]
fn frames_parse_back_into_init_and_continuation_packets() {
    let reports = frame_message(CID, CMD_CBOR, &[0xdd; 60]).unwrap();
    match Frame::parse(&reports[0]) {
        Frame::Init {
            cid,
            cmd,
            len,
            data,
        } => {
            assert_eq!(cid, CID);
            assert_eq!(cmd, CMD_CBOR);
            assert_eq!(len, 60);
            assert_eq!(data, &[0xdd; 57]);
        }
        other => panic!("{other:?}"),
    }
    match Frame::parse(&reports[1]) {
        Frame::Continuation { cid, seq, data } => {
            assert_eq!(cid, CID);
            assert_eq!(seq, 0);
            assert_eq!(&data[..3], &[0xdd; 3]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn assembler_reassembles_in_order_and_rejects_out_of_sequence_packets() {
    let payload = (0..200u16).map(|i| i as u8).collect::<Vec<_>>();
    let reports = frame_message(CID, CMD_CBOR, &payload).unwrap();
    assert_eq!(reports.len(), 4);
    let mut assembler = Assembler::default();
    for report in &reports[..3] {
        assert_eq!(assembler.push(&Frame::parse(report)).unwrap(), None);
    }
    assert_eq!(
        assembler.push(&Frame::parse(&reports[3])).unwrap(),
        Some((CMD_CBOR, payload.clone()))
    );

    let mut assembler = Assembler::default();
    assembler.push(&Frame::parse(&reports[0])).unwrap();
    assert_eq!(
        assembler.push(&Frame::parse(&reports[2])).unwrap_err(),
        CtapError::Protocol("continuation out of sequence")
    );
    // A continuation with nothing in progress is dropped, not an error.
    let mut assembler = Assembler::default();
    assert_eq!(assembler.push(&Frame::parse(&reports[1])).unwrap(), None);
    // A single-packet message completes on the init packet.
    let single = frame_message(CID, CMD_CBOR, &[1, 2, 3]).unwrap();
    assert_eq!(
        Assembler::default()
            .push(&Frame::parse(&single[0]))
            .unwrap(),
        Some((CMD_CBOR, vec![1, 2, 3]))
    );
}

/// A device that answers from a script, recording what was written.
#[derive(Default)]
struct ScriptedDevice {
    written: Arc<Mutex<Vec<Report>>>,
    to_read: VecDeque<Report>,
}

impl HidDevice for ScriptedDevice {
    fn write_report(&mut self, report: &Report) -> Result<(), CtapError> {
        self.written.lock().unwrap().push(*report);
        Ok(())
    }

    fn read_report(&mut self, _: Option<Duration>) -> Result<Option<Report>, CtapError> {
        Ok(self.to_read.pop_front())
    }
}

fn init_reply(nonce: [u8; 8], cid: [u8; 4], capabilities: u8) -> Report {
    let mut payload = Vec::new();
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&cid);
    payload.extend_from_slice(&[2, 1, 0, 0, capabilities]);
    frame_message(BROADCAST_CID, CMD_INIT, &payload).unwrap()[0]
}

const NONCE: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];

fn open_scripted(to_read: Vec<Report>) -> (CtapHidChannel, Arc<Mutex<Vec<Report>>>) {
    let written = Arc::new(Mutex::new(Vec::new()));
    let device = ScriptedDevice {
        written: Arc::clone(&written),
        to_read: to_read.into(),
    };
    let channel = CtapHidChannel::open(Box::new(device), NONCE).unwrap();
    (channel, written)
}

#[test]
fn open_allocates_a_channel_and_ignores_replies_to_other_nonces() {
    let (channel, written) = open_scripted(vec![
        init_reply([0; 8], [0xde, 0xad, 0xbe, 0xef], CAPABILITY_CBOR),
        init_reply(NONCE, CID, CAPABILITY_CBOR),
    ]);
    assert_eq!(channel.cid, CID);
    assert!(channel.supports_cbor());
    let written = written.lock().unwrap();
    assert_eq!(written.len(), 1);
    assert_eq!(&written[0][..4], &BROADCAST_CID);
    assert_eq!(written[0][4], CMD_INIT | 0x80);
    assert_eq!(&written[0][7..15], &NONCE);
}

#[test]
fn open_fails_on_silence_or_an_invalid_channel() {
    let silent = ScriptedDevice::default();
    assert_eq!(
        CtapHidChannel::open(Box::new(silent), NONCE).unwrap_err(),
        CtapError::Timeout
    );
    let device = ScriptedDevice {
        to_read: vec![init_reply(NONCE, BROADCAST_CID, 0)].into(),
        ..ScriptedDevice::default()
    };
    assert_eq!(
        CtapHidChannel::open(Box::new(device), NONCE).unwrap_err(),
        CtapError::Protocol("device allocated an invalid channel")
    );
    let device = ScriptedDevice {
        to_read: vec![init_reply(NONCE, CID, 0)].into(),
        ..ScriptedDevice::default()
    };
    assert!(
        !CtapHidChannel::open(Box::new(device), NONCE)
            .unwrap()
            .supports_cbor()
    );
}

#[test]
fn receive_skips_keepalives_and_other_channels_then_reassembles() {
    let reply = (0..100u8).collect::<Vec<_>>();
    let mut script = vec![init_reply(NONCE, CID, CAPABILITY_CBOR)];
    script.extend(frame_message(CID, CMD_KEEPALIVE, &[0x02]).unwrap());
    script.extend(frame_message([1, 1, 1, 1], CMD_CBOR, &[0xee; 10]).unwrap());
    script.extend(frame_message(CID, CMD_CBOR, &reply).unwrap());
    let (mut channel, written) = open_scripted(script);
    assert_eq!(
        channel
            .transact(CMD_CBOR, &[0x04], Some(Duration::from_millis(10)))
            .unwrap(),
        reply
    );
    // The request itself was framed on the allocated channel.
    let written = written.lock().unwrap();
    assert_eq!(&written[1][..5], &[0x11, 0x22, 0x33, 0x44, 0x90]);
    assert_eq!(&written[1][5..8], &[0x00, 0x01, 0x04]);
}

#[test]
fn receive_reports_error_frames_timeouts_and_mismatched_commands() {
    let mut script = vec![init_reply(NONCE, CID, CAPABILITY_CBOR)];
    script.extend(frame_message(CID, CMD_ERROR, &[0x06]).unwrap());
    let (mut channel, _) = open_scripted(script);
    assert_eq!(
        channel
            .transact(CMD_CBOR, &[0x04], Some(Duration::from_millis(10)))
            .unwrap_err(),
        CtapError::HidError(0x06)
    );
    assert!(!channel.pending, "an error frame ends the request");

    let (mut channel, written) = open_scripted(vec![init_reply(NONCE, CID, CAPABILITY_CBOR)]);
    channel.send(CMD_CBOR, &[0x04]).unwrap();
    assert_eq!(
        channel.receive(Some(Duration::from_millis(1))).unwrap(),
        None
    );
    assert!(channel.pending);
    channel.cancel().unwrap();
    assert!(!channel.pending);
    assert_eq!(written.lock().unwrap().len(), 3);
    assert_eq!(written.lock().unwrap()[2][4], CMD_CANCEL | 0x80);
    // Nothing is pending any more, so dropping the channel sends no second CANCEL.
    drop(channel);
    assert_eq!(written.lock().unwrap().len(), 3);

    let mut script = vec![init_reply(NONCE, CID, CAPABILITY_CBOR)];
    script.extend(frame_message(CID, CMD_MSG, &[0x90, 0x00]).unwrap());
    let (mut channel, _) = open_scripted(script);
    assert_eq!(
        channel
            .transact(CMD_CBOR, &[0x04], Some(Duration::from_millis(10)))
            .unwrap_err(),
        CtapError::Protocol("reply for a different command")
    );
}

#[test]
fn dropping_a_channel_with_a_pending_request_cancels_it() {
    let (mut channel, written) = open_scripted(vec![init_reply(NONCE, CID, CAPABILITY_CBOR)]);
    channel.send(CMD_CBOR, &[0x02]).unwrap();
    drop(channel);
    let written = written.lock().unwrap();
    assert_eq!(written.len(), 3);
    assert_eq!(written[2][4], CMD_CANCEL | 0x80);
}

#[test]
fn u2f_only_channels_are_never_sent_a_cancel() {
    let (mut channel, written) = open_scripted(vec![init_reply(NONCE, CID, 0)]);
    channel.send(CMD_MSG, &[0x00, 0x01]).unwrap();
    channel.cancel().unwrap();
    assert!(!channel.pending);
    drop(channel);
    assert_eq!(
        written.lock().unwrap().len(),
        2,
        "INIT and the request only"
    );

    // A CBOR device forced to U2F after a failed getInfo is treated the same.
    let (mut channel, written) = open_scripted(vec![init_reply(NONCE, CID, CAPABILITY_CBOR)]);
    channel.force_u2f();
    assert!(!channel.supports_cbor());
    channel.send(CMD_MSG, &[0x00, 0x01]).unwrap();
    drop(channel);
    assert_eq!(written.lock().unwrap().len(), 2);
}

#[test]
fn reinit_moves_to_a_new_channel_and_drops_the_old_channels_replies() {
    const NEW_CID: [u8; 4] = [0x55, 0x66, 0x77, 0x88];
    let next_nonce = [1; 8];
    let mut script = vec![init_reply(NONCE, CID, CAPABILITY_CBOR)];
    // The late reply to the abandoned request, then the new INIT reply.
    script.extend(frame_message(CID, CMD_CBOR, &[0x00, 0xa0]).unwrap());
    script.push(init_reply(next_nonce, NEW_CID, CAPABILITY_CBOR));
    let (mut channel, _) = open_scripted(script);
    channel.send(CMD_CBOR, &[0x04]).unwrap();
    channel.reinit(next_nonce, Duration::from_secs(1)).unwrap();
    assert_eq!(channel.cid, NEW_CID);
    assert!(!channel.pending, "the device abandoned the old request");
}

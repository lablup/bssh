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

//! Blocking local-terminal input forwarding for an active PTY session.

use std::time::Duration;

use tokio::sync::{mpsc, watch};

use super::constants::INPUT_POLL_TIMEOUT_MS;
use super::local_escape::{LocalAction, LocalEscapeDetector};
use super::raw_input::RawInputReader;
use crate::pty::PtyMessage;

pub(crate) fn run(
    input_tx: mpsc::Sender<PtyMessage>,
    cancel_rx: watch::Receiver<bool>,
    pending_input: Vec<u8>,
    escape_enabled: bool,
) {
    let mut reader = RawInputReader::new();
    let mut buffer = [0_u8; 1024];
    let mut escape_detector = escape_enabled.then(LocalEscapeDetector::new);

    if !pending_input.is_empty()
        && !forward_input(&input_tx, escape_detector.as_mut(), &pending_input)
    {
        return;
    }

    loop {
        if *cancel_rx.borrow() {
            break;
        }

        match reader.poll(Duration::from_millis(INPUT_POLL_TIMEOUT_MS)) {
            Ok(true) => match reader.read(&mut buffer) {
                Ok(0) => {
                    tracing::debug!("EOF received on stdin");
                    break;
                }
                Ok(read) => {
                    if !forward_input(&input_tx, escape_detector.as_mut(), &buffer[..read]) {
                        break;
                    }
                }
                Err(error) => {
                    let _ = input_tx.try_send(PtyMessage::Error(format!("Input error: {error}")));
                    break;
                }
            },
            Ok(false) => continue,
            Err(error) => {
                let _ = input_tx.try_send(PtyMessage::Error(format!("Poll error: {error}")));
                break;
            }
        }
    }
}

fn forward_input(
    input_tx: &mpsc::Sender<PtyMessage>,
    detector: Option<&mut LocalEscapeDetector>,
    bytes: &[u8],
) -> bool {
    if let Some(action) = detector.and_then(|detector| detector.process(bytes)) {
        match action {
            LocalAction::Disconnect => {
                tracing::debug!("Disconnect escape sequence detected");
                let _ = input_tx.try_send(PtyMessage::Terminate);
                false
            }
            LocalAction::Passthrough(data) => {
                input_tx.try_send(PtyMessage::LocalInput(data)).is_ok()
            }
        }
    } else {
        let data = smallvec::SmallVec::from_slice(bytes);
        input_tx.try_send(PtyMessage::LocalInput(data)).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_forwarding_preserves_control_nul_escape_and_binary_bytes() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut detector = LocalEscapeDetector::new();
        let bytes = [0x00, 0x01, 0x03, 0x04, 0x1b, 0x7f, 0x80, 0xff];

        assert!(forward_input(&tx, Some(&mut detector), &bytes));
        let PtyMessage::LocalInput(forwarded) = rx.try_recv().unwrap() else {
            panic!("raw input must produce a LocalInput message");
        };
        assert_eq!(forwarded.as_slice(), bytes);
    }

    #[test]
    fn no_pty_forwarding_preserves_ssh_escape_sequence() {
        let (tx, mut rx) = mpsc::channel(1);

        assert!(forward_input(&tx, None, b"~."));
        let PtyMessage::LocalInput(forwarded) = rx.try_recv().unwrap() else {
            panic!("no-PTY input must produce a LocalInput message");
        };
        assert_eq!(forwarded.as_slice(), b"~.");
    }
}

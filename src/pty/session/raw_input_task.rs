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
) {
    let mut reader = RawInputReader::new();
    let mut buffer = [0_u8; 1024];
    let mut escape_detector = LocalEscapeDetector::new();

    if !pending_input.is_empty() && !forward_input(&input_tx, &mut escape_detector, &pending_input)
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
                    if !forward_input(&input_tx, &mut escape_detector, &buffer[..read]) {
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
    detector: &mut LocalEscapeDetector,
    bytes: &[u8],
) -> bool {
    if let Some(action) = detector.process(bytes) {
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

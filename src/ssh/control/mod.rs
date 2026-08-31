// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Typed connection-multiplexing configuration and wire primitives.
//!
//! This module deliberately contains no CLI, dispatcher, or live SSH runtime
//! integration. It is the policy and protocol boundary those layers use.

mod config;
mod path;
mod protocol;
mod runtime;
mod socket;

pub use config::{
    ControlCommand, ControlConfigError, ControlMasterMode, ControlPersist, ControlPolicy,
};
pub use path::{
    ControlPathContext, ControlPathError, expand_control_path, unix_socket_path_capacity,
    validate_control_socket_path,
};
pub use protocol::{
    CONTROL_PROTOCOL_VERSION, ControlData, ControlDataStream, ControlMessage, ControlOperation,
    ControlProtocolError, ControlRequest, ControlResponse, ControlResponseKind,
    MAX_CONTROL_DATA_BYTES, MAX_CONTROL_FRAME_BYTES, SessionOpenRequest, read_control_message,
    write_control_message,
};
pub use runtime::{
    AttachOutcome, AttachedSession, RunningControlMaster, attach_session, prepare_attached_session,
    send_control_command, start_control_master, start_control_master_with_bootstrap_session,
};
#[cfg(unix)]
pub use socket::verify_same_user;
pub use socket::{
    ControlSocketGuard, bind_control_socket, connect_control_socket, remove_stale_control_socket,
};

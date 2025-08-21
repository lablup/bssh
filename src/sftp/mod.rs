// Copyright 2025 Lablup Inc.
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

//! SFTP client module based on russh and russh-sftp
//! 
//! This module provides a high-level SSH/SFTP client interface with support for:
//! - Multiple authentication methods (password, private key, SSH agent)
//! - Command execution
//! - File upload/download
//! - Recursive directory operations
//! - Connection pooling (future enhancement)

pub mod client;
pub mod error;

pub use client::{AuthMethod, Client, CommandResult, ServerCheckMethod};
pub use error::{Error, Result};
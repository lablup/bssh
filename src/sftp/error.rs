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

use std::io;
use std::fmt;

/// Error type for SFTP operations
#[derive(Debug)]
pub enum Error {
    /// IO error
    Io(io::Error),
    /// SSH error from russh
    Ssh(russh::Error),
    /// SFTP error from russh-sftp
    Sftp(russh_sftp::client::error::Error),
    /// Authentication failed
    AuthenticationFailed,
    /// Wrong password
    PasswordWrong,
    /// Key authentication failed
    KeyAuthFailed,
    /// Invalid key
    KeyInvalid(russh_keys::Error),
    /// Address invalid
    AddressInvalid(io::Error),
    /// Connection closed
    ConnectionClosed,
    /// Command execution failed
    CommandFailed(String),
    /// File not found
    FileNotFound(String),
    /// Permission denied
    PermissionDenied(String),
    /// Other error
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Ssh(e) => write!(f, "SSH error: {}", e),
            Error::Sftp(e) => write!(f, "SFTP error: {:?}", e),
            Error::AuthenticationFailed => write!(f, "Authentication failed"),
            Error::PasswordWrong => write!(f, "Wrong password"),
            Error::KeyAuthFailed => write!(f, "Key authentication failed"),
            Error::KeyInvalid(e) => write!(f, "Invalid key: {}", e),
            Error::AddressInvalid(e) => write!(f, "Invalid address: {}", e),
            Error::ConnectionClosed => write!(f, "Connection closed"),
            Error::CommandFailed(msg) => write!(f, "Command failed: {}", msg),
            Error::FileNotFound(path) => write!(f, "File not found: {}", path),
            Error::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            Error::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<russh::Error> for Error {
    fn from(e: russh::Error) -> Self {
        Error::Ssh(e)
    }
}

impl From<russh_sftp::client::error::Error> for Error {
    fn from(e: russh_sftp::client::error::Error) -> Self {
        Error::Sftp(e)
    }
}

impl From<russh_keys::Error> for Error {
    fn from(e: russh_keys::Error) -> Self {
        Error::KeyInvalid(e)
    }
}

/// Result type for SFTP operations
pub type Result<T> = std::result::Result<T, Error>;
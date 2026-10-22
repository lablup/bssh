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

//! The subset of CBOR (RFC 8949) that CTAP2 messages use, encoded in the
//! CTAP2 canonical form: definite lengths only, minimal integer encodings,
//! and map keys sorted by major type, then encoded length, then bytes.
//!
//! Only the value kinds CTAP2 exchanges are modelled; tags and floats are
//! rejected on input, which is what libfido2's parser does as well.

use super::CtapError;
use zeroize::{Zeroize, Zeroizing};

/// Nesting depth beyond which input is treated as hostile.
const MAX_DEPTH: usize = 16;

/// A CBOR data item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major types 0 and 1 (the negative range is limited to `i64`).
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Pairs in wire order; [`encode`] sorts them canonically.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

// Credential IDs and PIN authentication data can occur anywhere in a CBOR tree.
impl Zeroize for Value {
    fn zeroize(&mut self) {
        match self {
            Self::Bytes(bytes) => bytes.zeroize(),
            Self::Text(text) => text.zeroize(),
            Self::Array(items) => items.iter_mut().for_each(Zeroize::zeroize),
            Self::Map(pairs) => pairs.iter_mut().for_each(|(key, value)| {
                key.zeroize();
                value.zeroize();
            }),
            _ => {}
        }
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Value {
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Self::Map(pairs) => Some(pairs),
            _ => None,
        }
    }

    /// Look a key up in a map value (`None` for non-maps and missing keys).
    #[must_use]
    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
    }

    /// Look an integer key up, the common CTAP2 case.
    #[must_use]
    pub fn get_int(&self, key: i64) -> Option<&Value> {
        self.get(&Value::Int(key))
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::Text(text.to_string())
    }
}

impl From<&[u8]> for Value {
    fn from(bytes: &[u8]) -> Self {
        Self::Bytes(bytes.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

/// Encode `value` canonically.
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    if argument < 24 {
        out.push(major | argument as u8);
    } else if argument <= u64::from(u8::MAX) {
        out.push(major | 24);
        out.push(argument as u8);
    } else if argument <= u64::from(u16::MAX) {
        out.push(major | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u64::from(u32::MAX) {
        out.push(major | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(int) => {
            if *int >= 0 {
                encode_head(0, *int as u64, out);
            } else {
                encode_head(1, (-1 - *int) as u64, out);
            }
        }
        Value::Bytes(bytes) => {
            encode_head(2, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            encode_head(3, text.len() as u64, out);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            encode_head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(pairs) => {
            let mut encoded = pairs
                .iter()
                .map(|(key, value)| (Zeroizing::new(encode(key)), Zeroizing::new(encode(value))))
                .collect::<Vec<_>>();
            // CTAP2 canonical order: major type, then length, then bytes.
            // The major type is the top three bits of the first byte, so a
            // (major, len, bytes) comparison of the encoded key is exactly
            // the rule.
            encoded.sort_by(|(a, _), (b, _)| {
                (a[0] >> 5, a.len(), a.as_slice()).cmp(&(b[0] >> 5, b.len(), b.as_slice()))
            });
            encode_head(5, encoded.len() as u64, out);
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                out.extend_from_slice(&value);
            }
        }
        Value::Bool(flag) => out.push(if *flag { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
    }
}

/// Decode one item that must span the whole input.
pub fn decode(input: &[u8]) -> Result<Value, CtapError> {
    let (value, consumed) = decode_prefix(input)?;
    if consumed != input.len() {
        return Err(CtapError::Cbor("trailing bytes after item"));
    }
    Ok(value)
}

/// Decode the first item in authenticator data containing a COSE key and extensions.
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), CtapError> {
    let mut cursor = Cursor { input, offset: 0 };
    let value = cursor.item(0)?;
    Ok((value, cursor.offset))
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8], CtapError> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.input.len())
            .ok_or(CtapError::Cbor("truncated item"))?;
        let bytes = &self.input[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, CtapError> {
        Ok(self.take(1)?[0])
    }

    /// The argument of a head, or `None` for additional information 31
    /// (indefinite length), which CTAP2 forbids.
    fn argument(&mut self, additional: u8) -> Result<u64, CtapError> {
        Ok(match additional {
            0..=23 => u64::from(additional),
            24 => u64::from(self.byte()?),
            25 => u64::from(u16::from_be_bytes([self.byte()?, self.byte()?])),
            26 => {
                let bytes: [u8; 4] = self.take(4)?.try_into().expect("four bytes");
                u64::from(u32::from_be_bytes(bytes))
            }
            27 => {
                let bytes: [u8; 8] = self.take(8)?.try_into().expect("eight bytes");
                u64::from_be_bytes(bytes)
            }
            _ => return Err(CtapError::Cbor("indefinite or reserved length")),
        })
    }

    fn length(&mut self, additional: u8) -> Result<usize, CtapError> {
        let len = self.argument(additional)?;
        usize::try_from(len)
            .ok()
            .filter(|len| *len <= self.input.len())
            .ok_or(CtapError::Cbor("length exceeds input"))
    }

    fn item(&mut self, depth: usize) -> Result<Value, CtapError> {
        if depth > MAX_DEPTH {
            return Err(CtapError::Cbor("nesting too deep"));
        }
        let head = self.byte()?;
        let (major, additional) = (head >> 5, head & 0x1f);
        Ok(match major {
            0 => Value::Int(
                i64::try_from(self.argument(additional)?)
                    .map_err(|_| CtapError::Cbor("integer out of range"))?,
            ),
            1 => {
                let magnitude = self.argument(additional)?;
                let magnitude = i64::try_from(magnitude)
                    .map_err(|_| CtapError::Cbor("integer out of range"))?;
                Value::Int(-1 - magnitude)
            }
            2 => {
                let len = self.length(additional)?;
                Value::Bytes(self.take(len)?.to_vec())
            }
            3 => {
                let len = self.length(additional)?;
                let text = std::str::from_utf8(self.take(len)?)
                    .map_err(|_| CtapError::Cbor("text is not UTF-8"))?;
                Value::Text(text.to_string())
            }
            4 => {
                let len = self.length(additional)?;
                let mut items = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    items.push(self.item(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let len = self.length(additional)?;
                let mut pairs = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    let key = self.item(depth + 1)?;
                    let value = self.item(depth + 1)?;
                    if pairs.iter().any(|(existing, _)| existing == &key) {
                        return Err(CtapError::Cbor("duplicate map key"));
                    }
                    pairs.push((key, value));
                }
                Value::Map(pairs)
            }
            7 => match additional {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                _ => return Err(CtapError::Cbor("unsupported simple value or float")),
            },
            _ => return Err(CtapError::Cbor("tags are not allowed")),
        })
    }
}

#[cfg(test)]
#[path = "cbor_tests.rs"]
mod tests;

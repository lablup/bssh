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

//! Typed OpenSSH-compatible `IPQoS` policy.

use thiserror::Error;

/// A socket traffic-class value, or an explicit request to leave it unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpQosValue {
    None,
    Class(u8),
}

/// Interactive and bulk traffic classes selected by `IPQoS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpQosPolicy {
    pub interactive: IpQosValue,
    pub bulk: IpQosValue,
}

impl Default for IpQosPolicy {
    fn default() -> Self {
        // OpenSSH 10.3 defaults to EF for interactive sessions and CS0 for
        // bulk sessions (readconf.c fill_default_options()).
        Self {
            interactive: IpQosValue::Class(0xb8),
            bulk: IpQosValue::Class(0x00),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpQosParseError {
    #[error("at least one traffic class is required")]
    MissingValue,
    #[error("at most an interactive and a bulk traffic class are accepted")]
    TooManyValues,
    #[error("invalid traffic class '{0}'")]
    InvalidValue(String),
}

impl IpQosPolicy {
    pub fn parse(values: &[String]) -> Result<Self, IpQosParseError> {
        let Some(interactive) = values.first() else {
            return Err(IpQosParseError::MissingValue);
        };
        if values.len() > 2 {
            return Err(IpQosParseError::TooManyValues);
        }
        let interactive = parse_value(interactive)?;
        let bulk = values
            .get(1)
            .map_or(Ok(interactive), |value| parse_value(value))?;
        Ok(Self { interactive, bulk })
    }
}

fn parse_value(value: &str) -> Result<IpQosValue, IpQosParseError> {
    let class = match value.to_ascii_lowercase().as_str() {
        "none" => return Ok(IpQosValue::None),
        "af11" => 0x28,
        "af12" => 0x30,
        "af13" => 0x38,
        "af21" => 0x48,
        "af22" => 0x50,
        "af23" => 0x58,
        "af31" => 0x68,
        "af32" => 0x70,
        "af33" => 0x78,
        "af41" => 0x88,
        "af42" => 0x90,
        "af43" => 0x98,
        "cs0" => 0x00,
        "cs1" => 0x20,
        "cs2" => 0x40,
        "cs3" => 0x60,
        "cs4" => 0x80,
        "cs5" => 0xa0,
        "cs6" => 0xc0,
        "cs7" => 0xe0,
        "ef" => 0xb8,
        "le" => 0x04,
        "va" => 0x2c,
        // OpenSSH retains these names for compatibility but deliberately
        // leaves the system traffic class unchanged.
        "lowdelay" | "throughput" | "reliability" => return Ok(IpQosValue::None),
        _ => value
            .parse::<u8>()
            .map_err(|_| IpQosParseError::InvalidValue(value.to_string()))?,
    };
    Ok(IpQosValue::Class(class))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn parses_named_numeric_and_single_value_policies() {
        assert_eq!(
            IpQosPolicy::parse(&values(&["ef", "cs1"])),
            Ok(IpQosPolicy {
                interactive: IpQosValue::Class(0xb8),
                bulk: IpQosValue::Class(0x20),
            })
        );
        assert_eq!(
            IpQosPolicy::parse(&values(&["af21"])),
            Ok(IpQosPolicy {
                interactive: IpQosValue::Class(0x48),
                bulk: IpQosValue::Class(0x48),
            })
        );
        assert_eq!(
            IpQosPolicy::parse(&values(&["255", "0"])),
            Ok(IpQosPolicy {
                interactive: IpQosValue::Class(255),
                bulk: IpQosValue::Class(0),
            })
        );
    }

    #[test]
    fn deprecated_and_none_values_leave_the_system_class_unchanged() {
        for value in ["none", "lowdelay", "throughput", "reliability"] {
            assert_eq!(
                IpQosPolicy::parse(&values(&[value])),
                Ok(IpQosPolicy {
                    interactive: IpQosValue::None,
                    bulk: IpQosValue::None,
                })
            );
        }
    }

    #[test]
    fn rejects_missing_extra_hex_and_unknown_values() {
        assert_eq!(IpQosPolicy::parse(&[]), Err(IpQosParseError::MissingValue));
        assert_eq!(
            IpQosPolicy::parse(&values(&["ef", "cs0", "extra"])),
            Err(IpQosParseError::TooManyValues)
        );
        for value in ["0xff", "expedited", "256", "invalid"] {
            assert!(matches!(
                IpQosPolicy::parse(&values(&[value])),
                Err(IpQosParseError::InvalidValue(_))
            ));
        }
    }
}

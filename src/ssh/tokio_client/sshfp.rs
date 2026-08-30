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

//! DNSSEC-aware SSHFP lookup and trust policy.

use hickory_resolver::{
    Resolver,
    proto::{
        dnssec::Proof,
        rr::{RData, RecordType, rdata::sshfp},
    },
};
use russh::keys::{Algorithm as KeyAlgorithm, PublicKey};
use sha1::Digest as _;
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyHostKeyDnsPolicy {
    No,
    Ask,
    Yes,
}

impl VerifyHostKeyDnsPolicy {
    pub(crate) fn parse(value: &str) -> Self {
        if value.eq_ignore_ascii_case("yes") {
            Self::Yes
        } else if value.eq_ignore_ascii_case("ask") {
            Self::Ask
        } else {
            Self::No
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SshfpDecision {
    Accept,
    Continue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshfpEvidence {
    SecureMatch,
    SecureMismatch,
    InsecureMatch,
    InsecureMismatch,
    Bogus,
    NotFound,
    Unavailable,
}

pub(crate) async fn verify_sshfp(
    host: &str,
    server_key: &PublicKey,
    policy: VerifyHostKeyDnsPolicy,
) -> SshfpDecision {
    if policy == VerifyHostKeyDnsPolicy::No || host.parse::<std::net::IpAddr>().is_ok() {
        return SshfpDecision::Continue;
    }

    let evidence = lookup_sshfp(host, server_key).await;
    let decision = decide(policy, evidence);
    if decision == SshfpDecision::Accept {
        tracing::info!("Accepted host key for '{host}' from a DNSSEC-authenticated SSHFP record");
        return decision;
    }

    match evidence {
        SshfpEvidence::SecureMismatch => tracing::warn!(
            "DNSSEC-authenticated SSHFP records for '{host}' do not consistently match; falling back to known_hosts"
        ),
        SshfpEvidence::Bogus => tracing::warn!(
            "DNSSEC validation for '{host}' reported a bogus SSHFP answer; falling back to known_hosts"
        ),
        SshfpEvidence::InsecureMatch => tracing::warn!(
            "SSHFP for '{host}' matches but is in an unsigned DNS zone; it is not trusted"
        ),
        SshfpEvidence::InsecureMismatch => tracing::warn!(
            "SSHFP for '{host}' is insecure and does not match; falling back to known_hosts"
        ),
        SshfpEvidence::Unavailable => {
            tracing::warn!("SSHFP lookup for '{host}' was unavailable; falling back to known_hosts")
        }
        SshfpEvidence::SecureMatch if policy == VerifyHostKeyDnsPolicy::Ask => {
            tracing::info!(
                "SSHFP for '{host}' is DNSSEC-authenticated and matches; ask mode still requires known_hosts/TOFU confirmation"
            )
        }
        _ => {}
    }
    decision
}

async fn lookup_sshfp(host: &str, server_key: &PublicKey) -> SshfpEvidence {
    let mut builder = match Resolver::builder_tokio() {
        Ok(builder) => builder,
        Err(error) => {
            tracing::warn!("Could not load system DNS configuration for SSHFP: {error}");
            return SshfpEvidence::Unavailable;
        }
    };
    builder.options_mut().validate = true;
    builder.options_mut().try_tcp_on_error = true;
    let resolver = match builder.build() {
        Ok(resolver) => resolver,
        Err(error) => {
            tracing::warn!("Could not create DNSSEC resolver for SSHFP: {error}");
            return SshfpEvidence::Unavailable;
        }
    };

    let lookup = match resolver.lookup(host, RecordType::SSHFP).await {
        Ok(lookup) => lookup,
        Err(error) => {
            let evidence = evidence_from_lookup_error(&error);
            tracing::warn!("DNSSEC SSHFP lookup for '{host}' failed ({evidence:?}): {error}");
            return evidence;
        }
    };

    evidence_from_records(
        lookup.answers().iter().filter_map(|record| {
            let RData::SSHFP(sshfp) = &record.data else {
                return None;
            };
            Some((record.proof, sshfp))
        }),
        server_key,
    )
}

fn evidence_from_lookup_error(error: &hickory_resolver::net::NetError) -> SshfpEvidence {
    use hickory_resolver::net::{DnsError, NetError};

    match error {
        NetError::Dns(DnsError::NoRecordsFound(_)) => SshfpEvidence::NotFound,
        NetError::Dns(DnsError::Nsec {
            proof: Proof::Bogus,
            ..
        }) => SshfpEvidence::Bogus,
        NetError::Dns(DnsError::Nsec { .. }) => SshfpEvidence::NotFound,
        _ => SshfpEvidence::Unavailable,
    }
}

fn evidence_from_records<'a>(
    records: impl IntoIterator<Item = (Proof, &'a sshfp::SSHFP)>,
    server_key: &PublicKey,
) -> SshfpEvidence {
    let Some(expected_algorithm) = sshfp_algorithm(server_key.algorithm()) else {
        return SshfpEvidence::NotFound;
    };
    let Ok(key_blob) = server_key.to_bytes() else {
        return SshfpEvidence::Bogus;
    };

    let mut secure_match = false;
    let mut secure_mismatch = false;
    let mut insecure_match = false;
    let mut insecure_mismatch = false;
    for (proof, record) in records {
        if record.algorithm != expected_algorithm {
            continue;
        }
        let Some(matches) = fingerprint_matches(record, &key_blob) else {
            continue;
        };
        match proof {
            Proof::Secure => {
                secure_match |= matches;
                secure_mismatch |= !matches;
            }
            Proof::Bogus => return SshfpEvidence::Bogus,
            Proof::Insecure | Proof::Indeterminate => {
                insecure_match |= matches;
                insecure_mismatch |= !matches;
            }
        }
    }

    if secure_mismatch || (secure_match && insecure_mismatch) {
        SshfpEvidence::SecureMismatch
    } else if insecure_mismatch {
        SshfpEvidence::InsecureMismatch
    } else if secure_match {
        SshfpEvidence::SecureMatch
    } else if insecure_match {
        SshfpEvidence::InsecureMatch
    } else {
        SshfpEvidence::NotFound
    }
}
fn fingerprint_matches(record: &sshfp::SSHFP, key_blob: &[u8]) -> Option<bool> {
    let expected = match record.fingerprint_type {
        sshfp::FingerprintType::SHA1 => sha1::Sha1::digest(key_blob).to_vec(),
        sshfp::FingerprintType::SHA256 => Sha256::digest(key_blob).to_vec(),
        _ => return None,
    };
    Some(record.fingerprint == expected)
}
fn sshfp_algorithm(algorithm: KeyAlgorithm) -> Option<sshfp::Algorithm> {
    match algorithm {
        KeyAlgorithm::Rsa { .. } => Some(sshfp::Algorithm::RSA),
        KeyAlgorithm::Dsa => Some(sshfp::Algorithm::DSA),
        KeyAlgorithm::Ecdsa { .. } => Some(sshfp::Algorithm::ECDSA),
        KeyAlgorithm::Ed25519 => Some(sshfp::Algorithm::Ed25519),
        _ => None,
    }
}

fn decide(policy: VerifyHostKeyDnsPolicy, evidence: SshfpEvidence) -> SshfpDecision {
    match (policy, evidence) {
        (VerifyHostKeyDnsPolicy::Yes, SshfpEvidence::SecureMatch) => SshfpDecision::Accept,
        _ => SshfpDecision::Continue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::PrivateKey;

    fn key() -> PublicKey {
        PrivateKey::random(&mut rand::rng(), KeyAlgorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    fn record_for(key: &PublicKey, proof: Proof) -> (Proof, sshfp::SSHFP) {
        let blob = key.to_bytes().unwrap();
        (
            proof,
            sshfp::SSHFP::new(
                sshfp::Algorithm::Ed25519,
                sshfp::FingerprintType::SHA256,
                Sha256::digest(blob).to_vec(),
            ),
        )
    }

    #[test]
    fn authenticated_insecure_and_bogus_answers_have_distinct_trust() {
        assert_eq!(
            decide(VerifyHostKeyDnsPolicy::Yes, SshfpEvidence::SecureMatch),
            SshfpDecision::Accept
        );
        assert_eq!(
            decide(VerifyHostKeyDnsPolicy::Ask, SshfpEvidence::SecureMatch),
            SshfpDecision::Continue
        );
        assert_eq!(
            decide(VerifyHostKeyDnsPolicy::Yes, SshfpEvidence::InsecureMatch),
            SshfpDecision::Continue
        );
        assert_eq!(
            decide(VerifyHostKeyDnsPolicy::Ask, SshfpEvidence::Bogus),
            SshfpDecision::Continue
        );
        assert_eq!(
            decide(VerifyHostKeyDnsPolicy::Yes, SshfpEvidence::SecureMismatch),
            SshfpDecision::Continue
        );
    }

    #[test]
    fn record_fingerprints_are_checked_with_dnssec_proof() {
        let offered = key();
        let (proof, record) = record_for(&offered, Proof::Secure);
        assert_eq!(
            evidence_from_records([(proof, &record)], &offered),
            SshfpEvidence::SecureMatch
        );

        let other = key();
        let (_, mismatching) = record_for(&other, Proof::Secure);
        assert_eq!(
            evidence_from_records(
                [(Proof::Secure, &record), (Proof::Secure, &mismatching)],
                &offered,
            ),
            SshfpEvidence::SecureMismatch,
            "one related mismatch must clear an otherwise secure match"
        );

        let unsupported = sshfp::SSHFP::new(
            sshfp::Algorithm::Ed25519,
            sshfp::FingerprintType::Reserved,
            vec![0_u8; 32],
        );
        assert_eq!(
            evidence_from_records(
                [(Proof::Secure, &record), (Proof::Secure, &unsupported)],
                &offered,
            ),
            SshfpEvidence::SecureMatch,
            "unsupported fingerprint types must be ignored"
        );
        assert_eq!(
            evidence_from_records([(Proof::Insecure, &record)], &other),
            SshfpEvidence::InsecureMismatch
        );
        assert_eq!(
            evidence_from_records([(Proof::Bogus, &record)], &offered),
            SshfpEvidence::Bogus
        );
    }
    #[test]
    fn transport_timeout_and_resolver_failures_are_unavailable_not_bogus() {
        use hickory_resolver::{
            net::{DnsError, NetError},
            proto::op::ResponseCode,
        };

        for error in [
            NetError::Timeout,
            NetError::NoConnections,
            NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)),
        ] {
            assert_eq!(
                evidence_from_lookup_error(&error),
                SshfpEvidence::Unavailable
            );
            assert_eq!(
                decide(
                    VerifyHostKeyDnsPolicy::Yes,
                    evidence_from_lookup_error(&error)
                ),
                SshfpDecision::Continue
            );
        }
    }
    #[tokio::test]
    async fn numeric_targets_skip_dns_lookup_for_yes_policy() {
        let offered = key();
        for host in ["192.0.2.10", "2001:db8::10"] {
            assert_eq!(
                verify_sshfp(host, &offered, VerifyHostKeyDnsPolicy::Yes).await,
                SshfpDecision::Continue
            );
        }
    }
}

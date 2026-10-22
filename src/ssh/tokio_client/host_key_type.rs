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

//! The server's host key must have the type the key exchange negotiated.
//!
//! OpenSSH's `kex_verify_host_key` (`kex.c`) rejects a host key whose type
//! differs from the one `choose_hostkeyalg` derived from the negotiated name
//! (`sshkey_type_from_name`), and, for plain ECDSA, whose curve differs, with
//! `SSH_ERR_KEY_TYPE_MISMATCH`. Signature-algorithm names map to their key
//! type: `rsa-sha2-256` and `rsa-sha2-512` select an RSA key, and
//! `rsa-sha2-512-cert-v01@openssh.com` an RSA certificate. russh 0.64.1
//! verifies the exchange signature with whatever key the server sends, so
//! without this check a `HostKeyAlgorithms` restriction would not limit which
//! trusted key type the server may use.
//!
//! russh records the negotiated algorithm in [`russh::Names::key`] as the
//! plain key algorithm, also when a certificate was negotiated; whether a
//! certificate was negotiated is private to russh. It does, however, decide
//! from that flag how the server's blob is parsed (`client/kex.rs`): it is
//! handed to `check_server_key` as [`PublicKeyOrCertificate::Certificate`]
//! exactly when a certificate algorithm was negotiated. The certificate half
//! of the negotiated type is therefore taken from that variant, and a plain
//! key slot that carries certificate key data is refused.

use russh::keys::{Algorithm, PublicKeyOrCertificate};

/// A host key type as `sshkey_type_from_name` sees it: the key algorithm
/// and whether it is a certificate. Two types are equal when they name the
/// same kind of key; the RSA signature hash is kept only for messages.
#[derive(Debug, Clone)]
pub(crate) struct HostKeyType {
    algorithm: Algorithm,
    certificate: bool,
}

impl PartialEq for HostKeyType {
    fn eq(&self, other: &Self) -> bool {
        self.certificate == other.certificate
            && key_type_of(&self.algorithm) == key_type_of(&other.algorithm)
    }
}

impl Eq for HostKeyType {}

impl HostKeyType {
    /// The type a negotiated host-key algorithm selects. `algorithm` is the
    /// plain form russh records (`rsa-sha2-512` for
    /// `rsa-sha2-512-cert-v01@openssh.com`).
    #[must_use]
    pub(crate) fn negotiated(algorithm: &Algorithm, certificate: bool) -> Self {
        Self {
            algorithm: algorithm.clone(),
            certificate,
        }
    }

    /// The type of the key or certificate the server presented.
    #[must_use]
    pub(crate) fn presented(server_key: &PublicKeyOrCertificate) -> Self {
        match server_key {
            PublicKeyOrCertificate::Certificate(certificate) => Self {
                algorithm: certificate.public_key().algorithm(),
                certificate: true,
            },
            PublicKeyOrCertificate::PublicKey { key, .. } => Self {
                algorithm: key.algorithm(),
                certificate: key.key_data().is_certificate(),
            },
        }
    }

    /// The SSH name: `rsa-sha2-512-cert-v01@openssh.com` for a negotiated
    /// RSA certificate, `ssh-rsa` for a presented RSA key.
    fn name(&self) -> String {
        if self.certificate {
            self.algorithm.to_certificate_type()
        } else {
            self.algorithm.as_str().to_string()
        }
    }
}

/// Collapse an algorithm to the key type it names: the RSA signature hash is
/// a property of the signature, not of the key (`sshkey_type_plain`).
fn key_type_of(algorithm: &Algorithm) -> Algorithm {
    match algorithm {
        Algorithm::Rsa { .. } => Algorithm::Rsa { hash: None },
        other => other.clone(),
    }
}

/// The negotiated host-key algorithm for `check_server_key`, built from
/// what `kex_done` recorded and the form russh parsed the key in.
#[must_use]
fn negotiated_for(recorded: &Algorithm, server_key: &PublicKeyOrCertificate) -> HostKeyType {
    HostKeyType::negotiated(
        recorded,
        matches!(server_key, PublicKeyOrCertificate::Certificate(_)),
    )
}

/// [`ensure_negotiated_host_key_type`] against the algorithm `kex_done`
/// recorded. russh calls `kex_done` with the negotiated names before it hands
/// the host key to `check_server_key` (`client/mod.rs`), so a missing record
/// means that order changed, and the key is refused rather than trusted.
pub(crate) fn ensure_recorded_host_key_type(
    recorded: Option<&Algorithm>,
    server_key: &PublicKeyOrCertificate,
) -> Result<(), super::Error> {
    match recorded {
        Some(recorded) => {
            ensure_negotiated_host_key_type(&negotiated_for(recorded, server_key), server_key)
        }
        None => Err(super::Error::HostKeyTypeMismatch {
            negotiated: "(none negotiated)".to_string(),
            received: HostKeyType::presented(server_key).name(),
        }),
    }
}

/// Refuse a host key whose type differs from the negotiated one, failing
/// closed. ECDSA curves are compared for certificates as well as plain keys:
/// each curve has its own certificate algorithm name, so a server that
/// answers `ecdsa-sha2-nistp256-cert-v01@openssh.com` with a P-384
/// certificate is not presenting what was negotiated.
pub(crate) fn ensure_negotiated_host_key_type(
    negotiated: &HostKeyType,
    server_key: &PublicKeyOrCertificate,
) -> Result<(), super::Error> {
    let presented = HostKeyType::presented(server_key);
    if presented == *negotiated {
        return Ok(());
    }
    tracing::debug!(
        "host key type {} does not match negotiated host key algorithm {}",
        presented.name(),
        negotiated.name()
    );
    Err(super::Error::HostKeyTypeMismatch {
        negotiated: negotiated.name(),
        received: presented.name(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::ssh_key::public::{
        EcdsaPublicKey, Ed25519PublicKey, KeyData, SkEcdsaSha2NistP256, SkEd25519,
    };
    use russh::keys::ssh_key::{EcdsaCurve, HashAlg, PrivateKey, PublicKey};

    /// A fixed RSA public key: generating one per test is slow in debug builds.
    const RSA_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCOpiLYq9KNhwmajZJZuZeAL3OAnbikDpkxJaka6ND9mvsuBMbit7wXsGmrMPd5X0syw6S/gKen1IDJPPZq3o7gx+Uai4z8GmtVccTDrYBD84iSYNfmffsKPKbCXUGrFf1O2X+7niNZO3/g9bKz5vC7dMcsnEZMem83Zo6I5Doj399dagWWvfuFLG/VzL0NDgA5oHD3vsmhp/vnAcOu865kvdagG9stqCNiltjxows0Tt2V8DYB8335QZHl0SAbgnu3VvUDHWYAjHo7604qFe1f3/6vr9bNWqENLtDnau9qSR3cM0GNM4/YC7PLoIf10yLcIYdwJQSN8dXS72Lrm1FZ";

    fn key_data(algorithm: Algorithm) -> KeyData {
        match algorithm {
            Algorithm::Rsa { .. } => PublicKey::from_openssh(RSA_PUBLIC_KEY)
                .unwrap()
                .key_data()
                .clone(),
            Algorithm::SkEd25519 => {
                KeyData::SkEd25519(SkEd25519::new(Ed25519PublicKey([9u8; 32]), "ssh:"))
            }
            Algorithm::SkEcdsaSha2NistP256 => {
                let p256 = Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                };
                match key_data(p256) {
                    KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) => {
                        KeyData::SkEcdsaSha2NistP256(SkEcdsaSha2NistP256::new(point, "ssh:"))
                    }
                    other => panic!("unexpected P-256 key data: {other:?}"),
                }
            }
            other => PrivateKey::random(&mut rand::rng(), other)
                .unwrap()
                .public_key()
                .key_data()
                .clone(),
        }
    }

    fn plain(algorithm: Algorithm) -> PublicKeyOrCertificate {
        PublicKeyOrCertificate::PublicKey {
            key: PublicKey::new(key_data(algorithm), ""),
            hash_alg: None,
        }
    }

    fn certificate(algorithm: Algorithm) -> russh::keys::Certificate {
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mut builder =
            Builder::new_with_random_nonce(&mut rand::rng(), key_data(algorithm), 0, u64::MAX)
                .unwrap();
        builder.cert_type(CertType::Host).unwrap();
        builder.valid_principal("host.example").unwrap();
        builder.sign(&ca).unwrap()
    }

    /// Mirrors `negotiation.rs`: a plain name is parsed with
    /// `Algorithm::new`, a certificate name into the plain algorithm it
    /// contains, and the certificate flag is kept separately.
    fn negotiated(name: &str) -> HostKeyType {
        match name.strip_suffix("-cert-v01@openssh.com") {
            Some(_) => {
                let algorithm = match name {
                    "rsa-sha2-256-cert-v01@openssh.com" => Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    "rsa-sha2-512-cert-v01@openssh.com" => Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    other => Algorithm::new_certificate(other).unwrap(),
                };
                HostKeyType::negotiated(&algorithm, true)
            }
            None => HostKeyType::negotiated(&Algorithm::new(name).unwrap(), false),
        }
    }

    fn check(name: &str, server_key: &PublicKeyOrCertificate) -> Result<(), super::super::Error> {
        ensure_negotiated_host_key_type(&negotiated(name), server_key)
    }

    #[test]
    fn rsa_keys_match_every_rsa_signature_algorithm() {
        let rsa = plain(Algorithm::Rsa { hash: None });
        for name in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"] {
            check(name, &rsa).unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        let rsa_certificate =
            PublicKeyOrCertificate::Certificate(certificate(Algorithm::Rsa { hash: None }));
        for name in [
            "ssh-rsa-cert-v01@openssh.com",
            "rsa-sha2-256-cert-v01@openssh.com",
            "rsa-sha2-512-cert-v01@openssh.com",
        ] {
            check(name, &rsa_certificate).unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }

    #[test]
    fn a_key_of_another_type_is_refused() {
        let ed25519 = plain(Algorithm::Ed25519);
        let error = check("ecdsa-sha2-nistp256", &ed25519).unwrap_err();
        match &error {
            super::super::Error::HostKeyTypeMismatch {
                negotiated,
                received,
            } => {
                assert_eq!(negotiated, "ecdsa-sha2-nistp256");
                assert_eq!(received, "ssh-ed25519");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(error.to_string().contains("does not match"), "{error}");
        assert!(check("rsa-sha2-512", &ed25519).is_err());
        assert!(check("ssh-ed25519", &plain(Algorithm::Rsa { hash: None })).is_err());
    }

    #[test]
    fn ecdsa_curves_must_match_for_keys_and_certificates() {
        let p384 = Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        };
        check("ecdsa-sha2-nistp384", &plain(p384.clone())).unwrap();
        assert!(check("ecdsa-sha2-nistp256", &plain(p384.clone())).is_err());
        let certificate = PublicKeyOrCertificate::Certificate(certificate(p384));
        check("ecdsa-sha2-nistp384-cert-v01@openssh.com", &certificate).unwrap();
        assert!(check("ecdsa-sha2-nistp256-cert-v01@openssh.com", &certificate).is_err());
    }

    #[test]
    fn certificates_and_plain_keys_are_not_interchangeable() {
        let ed25519_certificate = certificate(Algorithm::Ed25519);
        let as_certificate = PublicKeyOrCertificate::Certificate(ed25519_certificate.clone());
        check("ssh-ed25519-cert-v01@openssh.com", &as_certificate).unwrap();
        // A certificate where a plain key was negotiated, in the form russh
        // would hand it over: certificate key data in the plain-key slot.
        let in_plain_slot = PublicKeyOrCertificate::PublicKey {
            key: PublicKey::new(KeyData::from(ed25519_certificate), ""),
            hash_alg: None,
        };
        let error = check("ssh-ed25519", &in_plain_slot).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ssh-ed25519-cert-v01@openssh.com"),
            "{error}"
        );
        // And the reverse: a plain key where a certificate was negotiated.
        let error = check(
            "ssh-ed25519-cert-v01@openssh.com",
            &plain(Algorithm::Ed25519),
        )
        .unwrap_err();
        match error {
            super::super::Error::HostKeyTypeMismatch {
                negotiated,
                received,
            } => {
                assert_eq!(negotiated, "ssh-ed25519-cert-v01@openssh.com");
                assert_eq!(received, "ssh-ed25519");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn security_key_types_match_only_themselves() {
        let sk_ed25519 = plain(Algorithm::SkEd25519);
        check("sk-ssh-ed25519@openssh.com", &sk_ed25519).unwrap();
        assert!(check("ssh-ed25519", &sk_ed25519).is_err());
        assert!(check("sk-ssh-ed25519@openssh.com", &plain(Algorithm::Ed25519)).is_err());

        let sk_ecdsa = plain(Algorithm::SkEcdsaSha2NistP256);
        check("sk-ecdsa-sha2-nistp256@openssh.com", &sk_ecdsa).unwrap();
        assert!(check("ecdsa-sha2-nistp256", &sk_ecdsa).is_err());
        assert!(check("sk-ssh-ed25519@openssh.com", &sk_ecdsa).is_err());

        let sk_certificate = PublicKeyOrCertificate::Certificate(certificate(Algorithm::SkEd25519));
        check("sk-ssh-ed25519-cert-v01@openssh.com", &sk_certificate).unwrap();
        assert!(check("ssh-ed25519-cert-v01@openssh.com", &sk_certificate).is_err());
        assert!(check("sk-ssh-ed25519@openssh.com", &sk_certificate).is_err());
    }

    #[test]
    fn a_key_received_before_negotiation_is_refused() {
        let key = plain(Algorithm::Ed25519);
        assert!(matches!(
            ensure_recorded_host_key_type(None, &key),
            Err(super::super::Error::HostKeyTypeMismatch { .. })
        ));
        ensure_recorded_host_key_type(Some(&Algorithm::Ed25519), &key).unwrap();
        assert!(
            ensure_recorded_host_key_type(
                Some(&Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256
                }),
                &key
            )
            .is_err()
        );
    }

    #[test]
    fn the_certificate_form_follows_the_variant_russh_parsed() {
        let recorded = Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        };
        let certificate =
            PublicKeyOrCertificate::Certificate(certificate(Algorithm::Rsa { hash: None }));
        assert_eq!(
            negotiated_for(&recorded, &certificate),
            negotiated("rsa-sha2-512-cert-v01@openssh.com")
        );
        let key = plain(Algorithm::Rsa { hash: None });
        assert_eq!(negotiated_for(&recorded, &key), negotiated("rsa-sha2-512"));
    }
}

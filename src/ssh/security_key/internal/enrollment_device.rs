// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

//! Stateful credential operations, sharing the signing channel and PIN agreement.

use super::*;
use crate::ssh::security_key::internal::cbor::{self, Value};
use crate::ssh::security_key::internal::enrollment_wire as wire;
use crate::ssh::security_key::{
    SK_FLAG_RESIDENT_KEY, SK_FLAG_USER_VERIFICATION_REQUIRED, SkAlgorithm, SkEnrollRequest,
    SkEnrollResponse, SkResidentKey,
};

impl Authenticator {
    pub(crate) fn enroll<R: rand::CryptoRng + ?Sized>(
        &mut self,
        request: &SkEnrollRequest<'_>,
        pin: Option<&str>,
        deadline: Instant,
        rng: &mut R,
    ) -> Result<SkEnrollResponse, CtapError> {
        let user = wire::user_id(request.user)?;
        let hash: [u8; 32] = Sha256::digest(request.challenge).into();
        let Some(info) = self.info.clone() else {
            return self.enroll_u2f(request, &hash, pin, deadline);
        };
        if wire::protection(request.flags).is_some()
            && !info.extensions.iter().any(|v| v == "credProtect")
        {
            return Err(CtapError::Unsupported(
                "-O resident and -O verify-required need authenticator credProtect support",
            ));
        }
        if request.flags & SK_FLAG_RESIDENT_KEY != 0 {
            if info.option("rk") != Some(true) {
                return Err(CtapError::Unsupported(
                    "-O resident requires discoverable credentials",
                ));
            }
            // Never silently replace a resident key with the same RP/user ID.
            // Enumeration verifies the PIN and detects an existing credential.
            let keys = self.resident_keys(pin, deadline, rng)?;
            if keys
                .iter()
                .any(|key| key.application == request.application && key.user_id == user)
            {
                return Err(CtapError::Protocol(
                    "resident credential already exists for application and user",
                ));
            }
        }
        let wants_uv = request.flags & SK_FLAG_USER_VERIFICATION_REQUIRED != 0;
        if pin.is_none() && wants_uv && info.option("uv") != Some(true) {
            return Err(CtapError::Status(ctap2::status::PIN_REQUIRED));
        }
        let auth = if let Some(pin) = pin {
            let (token, protocol) =
                self.enrollment_pin_token(&info, Some(request.application), 1, pin, deadline, rng)?;
            Some((
                Zeroizing::new(authenticate_with(protocol, &token, &hash)),
                protocol,
            ))
        } else if wants_uv && info.supports_permissions() {
            let (platform, secret, protocol) = self.key_agreement(&info, deadline, rng)?;
            let encoded = ctap2::encode_client_pin_get_uv_token(
                protocol.number(),
                platform.public_key(),
                (1, request.application),
            );
            let reply = Zeroizing::new(self.channel.transact(
                CMD_CBOR,
                &encoded,
                Some(remaining(deadline)?),
            )?);
            let token = secret.decrypt(&ctap2::parse_pin_token(&reply)?)?;
            Some((
                Zeroizing::new(authenticate_with(protocol, &token, &hash)),
                protocol,
            ))
        } else {
            None
        };
        let encoded = wire::make_credential(
            request,
            &hash,
            &user,
            auth.as_ref()
                .map(|(param, protocol)| (&param[..], *protocol)),
            wants_uv,
        );
        let reply = Zeroizing::new(self.channel.transact(
            CMD_CBOR,
            &encoded,
            Some(remaining(deadline)?),
        )?);
        wire::parse_created(&reply, request)
    }

    fn enrollment_pin_token<R: rand::CryptoRng + ?Sized>(
        &mut self,
        info: &AuthenticatorInfo,
        rp: Option<&str>,
        permission: i64,
        pin: &str,
        deadline: Instant,
        rng: &mut R,
    ) -> Result<(Zeroizing<Vec<u8>>, PinProtocol), CtapError> {
        let (platform, secret, protocol) = self.key_agreement(info, deadline, rng)?;
        let hash = secret.encrypt_pin_hash(pin, rng)?;
        let encoded = Zeroizing::new(ctap2::encode_client_pin_scoped_token(
            protocol.number(),
            platform.public_key(),
            &hash,
            info.supports_permissions().then_some((permission, rp)),
        ));
        let reply = Zeroizing::new(self.channel.transact(
            CMD_CBOR,
            &encoded,
            Some(remaining(deadline)?),
        )?);
        let token = secret.decrypt(&ctap2::parse_pin_token(&reply)?)?;
        if !matches!(token.len(), 16 | 32) {
            return Err(CtapError::Protocol("invalid PIN token length"));
        }
        Ok((token, protocol))
    }

    pub(crate) fn resident_keys<R: rand::CryptoRng + ?Sized>(
        &mut self,
        pin: Option<&str>,
        deadline: Instant,
        rng: &mut R,
    ) -> Result<Vec<SkResidentKey>, CtapError> {
        let info = self.info.clone().ok_or(CtapError::Unsupported(
            "-K requires CTAP2 credential management; U2F has no resident credentials",
        ))?;
        let command = if info.option("credMgmt") == Some(true) {
            0x0a
        } else if info.option("credentialMgmtPreview") == Some(true) {
            0x41
        } else {
            return Err(CtapError::Unsupported(
                "-K and -O resident require CTAP2 credential management",
            ));
        };
        let pin = pin.ok_or(CtapError::Status(ctap2::status::PIN_REQUIRED))?;
        let (token, protocol) = self.enrollment_pin_token(&info, None, 4, pin, deadline, rng)?;
        let first = match self.management(command, 2, None, Some((&token, protocol)), deadline) {
            Err(CtapError::Status(ctap2::status::NO_CREDENTIALS)) => return Ok(Vec::new()),
            result => result?,
        };
        let count = wire::count(&first, 5)?;
        let mut parties = vec![wire::relying_party(&first)?];
        // Finish RP enumeration before starting another stateful command.
        for _ in 1..count {
            let map = self.management(command, 3, None, None, deadline)?;
            let party = wire::relying_party(&map)?;
            if parties.iter().any(|(_, hash)| hash == &party.1) {
                return Err(CtapError::Protocol("duplicate resident RP"));
            }
            parties.push(party);
        }
        let mut keys: Vec<SkResidentKey> = Vec::new();
        for (application, hash) in parties {
            if !application.starts_with("ssh:") {
                continue;
            }
            let params = Value::Map(vec![(Value::Int(1), Value::from(hash.as_slice()))]);
            let first =
                self.management(command, 4, Some(params), Some((&token, protocol)), deadline)?;
            let count = wire::count(&first, 9)?;
            if keys.len() + count > wire::MAX_RESIDENT_KEYS {
                return Err(CtapError::Protocol("too many resident credentials"));
            }
            keys.push(wire::resident(&first, &application)?);
            for _ in 1..count {
                let map = self.management(command, 5, None, None, deadline)?;
                let key = wire::resident(&map, &application)?;
                if keys.iter().any(|old| {
                    old.application == key.application && old.key.key_handle == key.key.key_handle
                }) {
                    return Err(CtapError::Protocol("duplicate resident credential"));
                }
                keys.push(key);
            }
        }
        Ok(keys)
    }

    fn management(
        &mut self,
        command: u8,
        subcommand: u8,
        params: Option<Value>,
        auth: Option<(&[u8], PinProtocol)>,
        deadline: Instant,
    ) -> Result<Zeroizing<Value>, CtapError> {
        let encoded = wire::management(command, subcommand, params, auth);
        let reply = Zeroizing::new(self.channel.transact(
            CMD_CBOR,
            &encoded,
            Some(remaining(deadline)?),
        )?);
        Ok(Zeroizing::new(cbor::decode(ctap2::response_body(&reply)?)?))
    }

    fn enroll_u2f(
        &mut self,
        request: &SkEnrollRequest<'_>,
        hash: &[u8; 32],
        pin: Option<&str>,
        deadline: Instant,
    ) -> Result<SkEnrollResponse, CtapError> {
        if request.algorithm != SkAlgorithm::EcdsaSha2NistP256 {
            return Err(CtapError::Unsupported(
                "ed25519-sk requires CTAP2; U2F only supports ecdsa-sk",
            ));
        }
        if request.flags & crate::ssh::security_key::SK_FLAG_USER_PRESENCE_REQUIRED == 0 {
            return Err(CtapError::Unsupported(
                "U2F does not support -O no-touch-required",
            ));
        }
        if pin.is_some()
            || request.flags & (SK_FLAG_RESIDENT_KEY | SK_FLAG_USER_VERIFICATION_REQUIRED) != 0
        {
            return Err(CtapError::Unsupported(
                "U2F does not support PIN, -O resident or -O verify-required",
            ));
        }
        let application: [u8; 32] = Sha256::digest(request.application.as_bytes()).into();
        let mut data = Vec::from(hash.as_slice());
        data.extend(application);
        let encoded = u2f::encode_apdu(u2f::INS_REGISTER, 0, &data);
        loop {
            let reply = Zeroizing::new(self.channel.transact(
                CMD_MSG,
                &encoded,
                Some(remaining(deadline)?),
            )?);
            let (data, status) = u2f::split_status(&reply)?;
            match status {
                u2f::SW_NO_ERROR => {
                    return u2f::parse_registration(data, request.flags, &application, hash);
                }
                u2f::SW_CONDITIONS_NOT_SATISFIED => {
                    std::thread::sleep(U2F_PACE.min(remaining(deadline)?))
                }
                other => return Err(CtapError::Apdu(other)),
            }
        }
    }
}

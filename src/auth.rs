use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::PROTOCOL_VERSION;

pub const EXPECTED_ISSUER: &str = "flipple-control-plane";
pub const EXPECTED_AUDIENCE: &str = "flipple-multiplayer-relay";
pub const MAX_TICKET_LEN: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TicketHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TicketClaims {
    pub iss: String,
    pub aud: String,
    pub room_id: String,
    pub peer_id: u16,
    pub role: String,
    pub virtual_ip: String,
    pub exp: u64,
    pub jti: String,
    pub protocol_version: u8,
}

#[derive(Clone)]
pub struct TicketVerifier {
    key_id: Arc<str>,
    key: VerifyingKey,
    used_jtis: Arc<Mutex<HashMap<String, u64>>>,
}

impl TicketVerifier {
    pub fn new(key_id: impl Into<Arc<str>>, public_key: [u8; 32]) -> Result<Self> {
        Ok(Self {
            key_id: key_id.into(),
            key: VerifyingKey::from_bytes(&public_key).context("invalid Ed25519 public key")?,
            used_jtis: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn verify_once(&self, token: &str) -> Result<TicketClaims> {
        if token.len() > MAX_TICKET_LEN {
            bail!("ticket exceeds maximum length");
        }
        let mut parts = token.split('.');
        let encoded_header = parts.next().context("missing ticket header")?;
        let encoded_claims = parts.next().context("missing ticket claims")?;
        let encoded_signature = parts.next().context("missing ticket signature")?;
        if parts.next().is_some() {
            bail!("ticket contains too many segments");
        }

        let header: TicketHeader = decode_json(encoded_header).context("invalid ticket header")?;
        if header.alg != "EdDSA" || header.typ != "JWT" || header.kid != self.key_id.as_ref() {
            bail!("ticket header is not accepted");
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .context("invalid ticket signature encoding")?;
        let signature =
            Signature::from_slice(&signature_bytes).context("invalid Ed25519 signature")?;
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        self.key
            .verify(signing_input.as_bytes(), &signature)
            .context("ticket signature verification failed")?;

        let claims: TicketClaims = decode_json(encoded_claims).context("invalid ticket claims")?;
        validate_claims(&claims)?;
        let now = unix_timestamp()?;
        let mut used_jtis = self.used_jtis.lock().await;
        used_jtis.retain(|_, expires_at| *expires_at > now);
        if used_jtis.insert(claims.jti.clone(), claims.exp).is_some() {
            bail!("ticket was already consumed");
        }
        Ok(claims)
    }

    #[cfg(test)]
    async fn used_ticket_count(&self) -> usize {
        self.used_jtis.lock().await.len()
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(encoded: &str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("invalid base64url")?;
    serde_json::from_slice(&bytes).context("invalid JSON")
}

fn validate_claims(claims: &TicketClaims) -> Result<()> {
    let now = unix_timestamp()?;
    if claims.iss != EXPECTED_ISSUER || claims.aud != EXPECTED_AUDIENCE {
        bail!("ticket issuer or audience is invalid");
    }
    if claims.exp <= now || claims.exp > now + 300 {
        bail!("ticket is expired or exceeds the five-minute lifetime");
    }
    if claims.protocol_version != PROTOCOL_VERSION {
        bail!("ticket protocol version is not supported");
    }
    if claims.room_id.is_empty()
        || claims.room_id.len() > 64
        || claims.jti.is_empty()
        || claims.jti.len() > 128
    {
        bail!("ticket identifiers are invalid");
    }
    match (
        claims.role.as_str(),
        claims.peer_id,
        claims.virtual_ip.as_str(),
    ) {
        ("host", 1, "100.96.0.1") | ("guest", 2, "100.96.0.2") => Ok(()),
        _ => bail!("ticket role, peer id, and virtual IP do not match the POC contract"),
    }
}

fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub const TEST_KEY_ID: &str = "gate-a-2026-01";
    pub const TEST_SIGNING_KEY: [u8; 32] = [0x42; 32];

    pub fn verifier() -> TicketVerifier {
        let signing_key = SigningKey::from_bytes(&TEST_SIGNING_KEY);
        TicketVerifier::new(TEST_KEY_ID, signing_key.verifying_key().to_bytes()).unwrap()
    }

    pub fn sign(claims: &TicketClaims) -> String {
        let header = TicketHeader {
            alg: "EdDSA".into(),
            typ: "JWT".into(),
            kid: TEST_KEY_ID.into(),
        };
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = SigningKey::from_bytes(&TEST_SIGNING_KEY).sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::test_support::{sign, verifier};
    use super::*;

    #[tokio::test]
    async fn consumes_each_ticket_only_once() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = TicketClaims {
            iss: EXPECTED_ISSUER.into(),
            aud: EXPECTED_AUDIENCE.into(),
            room_id: "gate-a-room".into(),
            peer_id: 1,
            role: "host".into(),
            virtual_ip: "100.96.0.1".into(),
            exp: now + 120,
            jti: "single-use-ticket".into(),
            protocol_version: PROTOCOL_VERSION,
        };
        let token = sign(&claims);
        let verifier = verifier();

        assert_eq!(verifier.verify_once(&token).await.unwrap().peer_id, 1);
        assert!(
            verifier
                .verify_once(&token)
                .await
                .unwrap_err()
                .to_string()
                .contains("already consumed")
        );
    }

    #[tokio::test]
    async fn discards_consumed_ticket_ids_after_expiration() {
        let now = unix_timestamp().unwrap();
        let verifier = verifier();
        let first = TicketClaims {
            iss: EXPECTED_ISSUER.into(),
            aud: EXPECTED_AUDIENCE.into(),
            room_id: "gate-a-room".into(),
            peer_id: 1,
            role: "host".into(),
            virtual_ip: "100.96.0.1".into(),
            exp: now + 1,
            jti: "expiring-ticket".into(),
            protocol_version: PROTOCOL_VERSION,
        };
        verifier.verify_once(&sign(&first)).await.unwrap();
        assert_eq!(verifier.used_ticket_count().await, 1);

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let second = TicketClaims {
            exp: unix_timestamp().unwrap() + 120,
            jti: "fresh-ticket".into(),
            ..first
        };
        verifier.verify_once(&sign(&second)).await.unwrap();
        assert_eq!(verifier.used_ticket_count().await, 1);
    }
}

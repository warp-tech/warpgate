//! OpenID Connect Back-Channel Logout 1.0 logout tokens.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{AlgorithmFamily, DecodingKey, Header, Validation};
use openidconnect::core::CoreJsonWebKeyUse;
use openidconnect::{JsonWebKey, ProviderMetadataWithLogout, SignatureVerificationError};
use serde::Deserialize;

use crate::SsoError;
use crate::config::SsoInternalProviderConfig;

const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

const CLOCK_LEEWAY_SECONDS: u64 = 60;

// replay protection
const LOGOUT_TOKEN_MAX_AGE_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackchannelLogout {
    pub subject: Option<String>,
    pub sid: Option<String>,
}

#[derive(Deserialize)]
struct LogoutTokenClaims {
    sub: Option<String>,
    sid: Option<String>,
    iat: u64,
    #[serde(default)]
    events: HashMap<String, serde_json::Value>,
    nonce: Option<serde_json::Value>,
}

impl LogoutTokenClaims {
    /// The checks of section 2.6 that signature, `iss`, `aud` and `exp`
    /// validation leave over.
    fn into_logout(self, now: u64) -> Result<BackchannelLogout, SsoError> {
        let invalid = |reason: &str| Err(SsoError::Verification(format!("logout token {reason}")));

        // The event member is what tells a logout token apart from an ID
        // token signed with the same keys for the same audience.
        if !self
            .events
            .get(BACKCHANNEL_LOGOUT_EVENT)
            .is_some_and(serde_json::Value::is_object)
        {
            return invalid("lacks the back-channel logout event");
        }
        if self.nonce.is_some() {
            return invalid("carries a nonce");
        }
        if self.iat > now + CLOCK_LEEWAY_SECONDS
            || self.iat + LOGOUT_TOKEN_MAX_AGE_SECONDS + CLOCK_LEEWAY_SECONDS < now
        {
            return invalid("was not issued recently");
        }
        if self.sub.is_none() && self.sid.is_none() {
            return invalid("names neither a subject nor a session");
        }
        Ok(BackchannelLogout {
            subject: self.sub,
            sid: self.sid,
        })
    }
}

/// The JWKS key `header` names: by `kid`, or the only signing key when the
/// header carries none.
fn decoding_key(
    metadata: &ProviderMetadataWithLogout,
    header: &Header,
) -> Result<DecodingKey, SsoError> {
    let mut signing_keys = metadata.jwks().keys().iter().filter(|key| {
        key.key_use()
            .is_none_or(|key_use| *key_use == CoreJsonWebKeyUse::Signature)
    });
    let key = match &header.kid {
        Some(kid) => signing_keys.find(|key| key.key_id().is_some_and(|id| **id == *kid)),
        None => signing_keys
            .next()
            .filter(|_| signing_keys.next().is_none()),
    };
    let Some(key) = key else {
        return Err(SignatureVerificationError::NoMatchingKey.into());
    };
    let jwk: Jwk =
        serde_json::from_value(serde_json::to_value(key).map_err(jwk_error)?).map_err(jwk_error)?;
    Ok(DecodingKey::from_jwk(&jwk)?)
}

fn jwk_error(error: serde_json::Error) -> SsoError {
    SsoError::Verification(format!("unusable provider signing key: {error}"))
}

pub(crate) fn verify(
    config: &SsoInternalProviderConfig,
    metadata: &ProviderMetadataWithLogout,
    token: &str,
) -> Result<BackchannelLogout, SsoError> {
    let header = jsonwebtoken::decode_header(token)?;
    // A key published in a JWKS is no secret, so an HMAC "signature" with it
    // proves nothing.
    if header.alg.family() == AlgorithmFamily::Hmac {
        return Err(SsoError::Verification(
            "logout token is HMAC-signed".to_owned(),
        ));
    }
    let key = decoding_key(metadata, &header)?;

    let mut validation = Validation::new(header.alg);
    validation.leeway = CLOCK_LEEWAY_SECONDS;
    validation.set_required_spec_claims(&["iss", "aud"]);
    validation.set_issuer(&[metadata.issuer().as_str()]);
    if config.trust_unknown_audiences() {
        validation.validate_aud = false;
    } else {
        let mut audiences = vec![config.client_id().as_str().to_owned()];
        audiences.extend(
            config
                .additional_trusted_audiences()
                .cloned()
                .unwrap_or_default(),
        );
        validation.set_audience(&audiences);
    }

    let claims = jsonwebtoken::decode::<LogoutTokenClaims>(token, &key, &validation)?.claims;
    claims.into_logout(now())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn claims(value: serde_json::Value) -> LogoutTokenClaims {
        serde_json::from_value(value).unwrap()
    }

    fn valid() -> serde_json::Value {
        json!({
            "sub": "alice",
            "sid": "s1",
            "iat": NOW,
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        })
    }

    fn with(key: &str, value: serde_json::Value) -> LogoutTokenClaims {
        let mut v = valid();
        v[key] = value;
        claims(v)
    }

    #[test]
    fn accepts_a_valid_token() {
        assert_eq!(
            claims(valid()).into_logout(NOW).unwrap(),
            BackchannelLogout {
                subject: Some("alice".into()),
                sid: Some("s1".into()),
            }
        );
    }

    #[test]
    fn rejects_an_id_token() {
        let mut v = valid();
        v.as_object_mut().unwrap().remove("events");
        assert!(claims(v).into_logout(NOW).is_err());
        assert!(
            with("events", json!({ BACKCHANNEL_LOGOUT_EVENT: "x" }))
                .into_logout(NOW)
                .is_err()
        );
        assert!(with("nonce", json!("n")).into_logout(NOW).is_err());
    }

    #[test]
    fn requires_a_subject_or_session() {
        let mut v = valid();
        v.as_object_mut().unwrap().remove("sub");
        assert!(claims(v.clone()).into_logout(NOW).is_ok());
        v.as_object_mut().unwrap().remove("sid");
        assert!(claims(v).into_logout(NOW).is_err());
    }

    /// A provider publishing a freshly generated P-256 key as `k1`, and the
    /// key to sign its tokens with.
    fn provider() -> (
        SsoInternalProviderConfig,
        ProviderMetadataWithLogout,
        jsonwebtoken::EncodingKey,
    ) {
        let config = serde_json::from_value(json!({
            "type": "custom",
            "client_id": "warpgate",
            "client_secret": "secret",
            "issuer_url": "https://idp.example.com",
            "scopes": [],
        }))
        .unwrap();
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        // An uncompressed SEC1 point: 0x04, then x, then y.
        let point = key_pair.public_key_raw();
        let coordinate = |range| data_encoding::BASE64URL_NOPAD.encode(point.get(range).unwrap());
        let jwks = serde_json::from_value(json!({ "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "kid": "k1",
            "use": "sig",
            "x": coordinate(1..33),
            "y": coordinate(33..65),
        }]}))
        .unwrap();
        let key =
            jsonwebtoken::EncodingKey::from_ec_pem(key_pair.serialize_pem().as_bytes()).unwrap();
        (
            config,
            crate::metadata::tests::metadata(&json!({})).set_jwks(jwks),
            key,
        )
    }

    fn sign(key: &jsonwebtoken::EncodingKey, kid: &str, claims: &serde_json::Value) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, claims, key).unwrap()
    }

    fn signed_claims(aud: &str) -> serde_json::Value {
        let mut v = valid();
        v["iss"] = json!("https://idp.example.com");
        v["aud"] = json!(aud);
        v["iat"] = json!(now());
        v
    }

    #[test]
    fn verifies_a_signed_token() {
        let (config, metadata, key) = provider();
        let token = sign(&key, "k1", &signed_claims("warpgate"));
        assert!(verify(&config, &metadata, &token).is_ok());

        let foreign = sign(&key, "k1", &signed_claims("someone-else"));
        assert!(verify(&config, &metadata, &foreign).is_err());

        let unknown_key = sign(&key, "k2", &signed_claims("warpgate"));
        assert!(
            verify(&config, &metadata, &unknown_key)
                .unwrap_err()
                .is_unknown_signing_key()
        );

        // Another subject's claims under this token's signature.
        let mut other = signed_claims("warpgate");
        other["sub"] = json!("mallory");
        let other = sign(&key, "k1", &other);
        let (other_head, _) = other.rsplit_once('.').unwrap();
        let (_, signature) = token.rsplit_once('.').unwrap();
        let tampered = format!("{other_head}.{signature}");
        assert!(verify(&config, &metadata, &tampered).is_err());
    }

    #[test]
    fn rejects_stale_and_future_tokens() {
        let token = || claims(valid());
        assert!(token().into_logout(NOW + 300).is_ok());
        assert!(token().into_logout(NOW + 1000).is_err());
        assert!(token().into_logout(NOW - 1000).is_err());
    }
}

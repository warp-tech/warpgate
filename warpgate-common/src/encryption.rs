//! Encryption at rest
//!
//! Credentials are only decrypted immediately before use

use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use data_encoding::{BASE64, HEXLOWER};
use rand::RngExt;
use sha2::{Digest, Sha256};
use tracing::error;

use crate::helpers::rng::get_crypto_rng;
use crate::{WarpgateConfig, emit_config_warning};

const ENV_VAR: &str = "WARPGATE_ENCRYPTION_KEY";
const ENV_VAR_OLD: &str = "WARPGATE_ENCRYPTION_KEY_OLD";
const PREFIX: &str = "wgenc:v1:";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Hex characters of the key digest carried in the envelope.
const FINGERPRINT_LEN: usize = 8;

// Envelope format: PREFIX:KEY-FINGERPRINT:ENCRYPTED-DATA

type GcmNonce = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error(
        "this credential is encrypted with key {expected}, which is not among the keys configured via {ENV_VAR} ({actual:?})"
    )]
    KeyMismatch {
        expected: String,
        actual: Vec<String>,
    },
    #[error("this credential is encrypted with key {expected}, but {ENV_VAR} is not set")]
    NoKey { expected: String },
    #[error("credential could not be decrypted - the stored value is corrupt")]
    Corrupt,
    #[error("credential could not be encrypted")]
    EncryptionFailed,
}

pub struct MasterKey {
    key: [u8; KEY_LEN],
    fingerprint: String,
}

impl MasterKey {
    fn new(key: [u8; KEY_LEN]) -> Self {
        Self {
            fingerprint: HEXLOWER
                .encode(&Sha256::digest(key))
                .chars()
                .take(FINGERPRINT_LEN)
                .collect(),
            key,
        }
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(self.key))
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, EncryptionError> {
        let nonce_bytes = get_crypto_rng().random::<[u8; NONCE_LEN]>();
        let nonce = GcmNonce::from(nonce_bytes);

        let ciphertext = self
            .cipher()
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        let mut payload = nonce_bytes.to_vec();
        payload.extend_from_slice(&ciphertext);

        Ok(format!(
            "{PREFIX}{}:{}",
            self.fingerprint(),
            BASE64.encode(&payload)
        ))
    }

    pub fn decrypt(&self, value: &str) -> Result<String, EncryptionError> {
        let Some((fingerprint, payload)) = envelope_parts(value) else {
            return Ok(value.to_owned());
        };

        if fingerprint != self.fingerprint() {
            return Err(EncryptionError::KeyMismatch {
                expected: fingerprint.to_owned(),
                actual: vec![self.fingerprint().to_owned()],
            });
        }

        let (nonce_bytes, ciphertext) = payload
            .split_at_checked(NONCE_LEN)
            .ok_or(EncryptionError::Corrupt)?;
        let nonce_bytes =
            <[u8; NONCE_LEN]>::try_from(nonce_bytes).map_err(|_| EncryptionError::Corrupt)?;

        let plaintext = self
            .cipher()
            .decrypt(&GcmNonce::from(nonce_bytes), ciphertext)
            .map_err(|_| EncryptionError::Corrupt)?;

        String::from_utf8(plaintext).map_err(|_| EncryptionError::Corrupt)
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<master key {}>", self.fingerprint)
    }
}

/// All the keys a process holds - the current key and one or more old keys
pub struct Keyring {
    /// Current key for (re)encryption
    primary: Option<MasterKey>,
    /// Previous keys for decrypting old entries
    retired: Vec<MasterKey>,
}

impl Keyring {
    pub const fn primary(&self) -> Option<&MasterKey> {
        self.primary.as_ref()
    }

    /// Whether any held key has this fingerprint
    pub fn contains(&self, fingerprint: &str) -> bool {
        self.keys().any(|k| k.fingerprint() == fingerprint)
    }

    pub const fn is_empty(&self) -> bool {
        self.primary.is_none() && self.retired.is_empty()
    }

    pub const fn has_retired(&self) -> bool {
        !self.retired.is_empty()
    }

    /// iter over all keys
    fn keys(&self) -> impl Iterator<Item = &MasterKey> {
        self.primary.iter().chain(self.retired.iter())
    }

    fn fingerprints(&self) -> impl Iterator<Item = &str> {
        self.keys().map(|k| k.fingerprint())
    }

    pub fn decrypt(&self, value: &str) -> Result<String, EncryptionError> {
        let Some((fingerprint, _)) = envelope_parts(value) else {
            return Ok(value.to_owned());
        };

        let mut matched = false;
        for key in self.keys().filter(|k| k.fingerprint() == fingerprint) {
            matched = true;
            match key.decrypt(value) {
                // A fingerprint is only 32 bits, so another key can collide on it;
                // the GCM tag is what actually identifies the right key.
                Err(EncryptionError::Corrupt) => continue,
                result => return result,
            }
        }

        Err(if matched {
            EncryptionError::Corrupt
        } else if self.is_empty() {
            EncryptionError::NoKey {
                expected: fingerprint.to_owned(),
            }
        } else {
            EncryptionError::KeyMismatch {
                expected: fingerprint.to_owned(),
                actual: self.fingerprints().map(Into::into).collect(),
            }
        })
    }

    pub fn reencrypt(&self, value: &str) -> Result<String, EncryptionError> {
        let Some(primary) = self.primary() else {
            // One-way: without an active key nothing is written, and an envelope is
            // never downgraded to plaintext.
            return Ok(value.to_owned());
        };
        match envelope_parts(value) {
            None => primary.encrypt(value),
            Some((fingerprint, _)) if fingerprint == primary.fingerprint() => Ok(value.to_owned()),
            Some(_) => primary.encrypt(&self.decrypt(value)?),
        }
    }
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fingerprints = self.fingerprints().collect::<Vec<_>>().join(", ");
        write!(f, "<keyring {fingerprints}>")
    }
}

fn parse_key(raw: &str, var: &str) -> Result<MasterKey, String> {
    let Ok(decoded) = BASE64.decode(raw.as_bytes()) else {
        return Err(format!(
            "{var} is not valid base64. Generate a key with `openssl rand -base64 32`."
        ));
    };

    let Ok(key) = <[u8; KEY_LEN]>::try_from(decoded.as_slice()) else {
        return Err(format!(
            "{var} decodes to {} bytes, expected {KEY_LEN}. Generate a key with `openssl rand -base64 32`.",
            decoded.len()
        ));
    };

    Ok(MasterKey::new(key))
}

/// `old` is a comma-separated list; blank items are skipped, and keys duplicating
/// the primary or one another (by fingerprint) are dropped.
fn parse_env_keyring(primary: Option<&str>, old: Option<&str>) -> Result<Keyring, String> {
    let primary = match primary.map(str::trim).filter(|v| !v.is_empty()) {
        Some(raw) => Some(parse_key(raw, ENV_VAR)?),
        None => None,
    };

    let mut retired: Vec<MasterKey> = vec![];
    for raw in old.unwrap_or_default().split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let key = parse_key(raw, ENV_VAR_OLD)?;
        if !primary
            .iter()
            .chain(retired.iter())
            .any(|k| k.fingerprint() == key.fingerprint())
        {
            retired.push(key);
        }
    }

    Ok(Keyring { primary, retired })
}

/// keys, read from the environment and cached
pub fn env_keyring() -> &'static Keyring {
    static RING: OnceLock<Keyring> = OnceLock::new();
    RING.get_or_init(|| {
        let primary = std::env::var(ENV_VAR).ok();
        let old = std::env::var(ENV_VAR_OLD).ok();
        match parse_env_keyring(primary.as_deref(), old.as_deref()) {
            Ok(ring) => ring,
            Err(message) => {
                error!("{message}");
                std::process::exit(1);
            }
        }
    })
}

pub fn validate_encryption_config(config: &WarpgateConfig) {
    let keyring = env_keyring();
    if keyring.primary().is_none() {
        if keyring.has_retired() {
            emit_config_warning(
                    "`WARPGATE_ENCRYPTION_KEY_OLD` is set without `WARPGATE_ENCRYPTION_KEY`: existing credentials stay readable, but new credentials will be stored unencrypted.".to_owned()
                );
        } else if !config
            .store
            .database_url
            .expose_secret()
            .starts_with("sqlite:")
        {
            // This is the case where the user should have set up encryption
            emit_config_warning(
                    "Target credentials are stored unencrypted. Set the `WARPGATE_ENCRYPTION_KEY` environment variable to encrypt them at rest: https://warpgate.null.page/encryption/".to_owned()
                );
        }
    }
}
/// parse envelope into fingerprint and bytes
fn envelope_parts(value: &str) -> Option<(&str, Vec<u8>)> {
    let (fingerprint, payload) = value.strip_prefix(PREFIX)?.split_once(':')?;
    if fingerprint.len() != FINGERPRINT_LEN || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let payload = BASE64.decode(payload.as_bytes()).ok()?;
    if payload.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    Some((fingerprint, payload))
}

pub fn is_envelope(value: &str) -> bool {
    envelope_parts(value).is_some()
}

/// Encrypt if encryption is enabled and value is plaintext
pub fn idempotent_maybe_encrypt_secret(value: &str) -> Result<String, EncryptionError> {
    match env_keyring().primary() {
        Some(key) if !is_envelope(value) => key.encrypt(value),
        _ => Ok(value.to_owned()),
    }
}

/// Decrypt if encrypted, else passthrough
pub fn idempotent_maybe_decrypt(value: &str) -> Result<String, EncryptionError> {
    {
        let ring: &Keyring = env_keyring();
        ring.decrypt(value)
    }
}

/// Bring a stored value up to date in terms of encryption
pub fn maybe_reencrypt_str(value: &str) -> Result<String, EncryptionError> {
    env_keyring().reencrypt(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> MasterKey {
        MasterKey::new([seed; KEY_LEN])
    }

    #[test]
    fn round_trips() {
        let k = key(1);
        let encrypted = {
            let key: &MasterKey = &k;
            key.encrypt("hunter2")
        }
        .unwrap();
        assert_eq!(k.decrypt(&encrypted).unwrap(), "hunter2");
    }

    #[test]
    fn round_trips_empty_and_unicode() {
        let k = key(1);
        for plaintext in ["", "пароль", "a\0b"] {
            let encrypted = {
                let key: &MasterKey = &k;
                key.encrypt(plaintext)
            }
            .unwrap();
            assert_eq!(k.decrypt(&encrypted).unwrap(), plaintext);
        }
    }

    #[test]
    fn the_same_plaintext_encrypts_differently_every_time() {
        let k = key(1);
        assert_ne!(k.encrypt("hunter2").unwrap(), k.encrypt("hunter2").unwrap());
    }

    #[test]
    fn plaintext_passes_through_decryption_unchanged() {
        let k = key(1);
        for value in ["hunter2", "", "wgenc:", "wgenc:v1:nothex:zzz"] {
            assert_eq!(k.decrypt(value).unwrap(), value);
        }
    }

    /// The invariant that keeps a wrong key from destroying data: the envelope must
    /// come back byte-identical so it can be stored again untouched.
    #[test]
    fn a_wrong_key_reports_the_mismatch_and_alters_nothing() {
        let encrypted = {
            let key: &MasterKey = &key(1);
            key.encrypt("hunter2")
        }
        .unwrap();
        let err = {
            let key: &MasterKey = &key(2);
            let value: &str = &encrypted;
            key.decrypt(value)
        }
        .unwrap_err();

        let EncryptionError::KeyMismatch { expected, actual } = err else {
            panic!("expected a key mismatch");
        };
        assert_eq!(expected, key(1).fingerprint());
        assert_eq!(actual, vec![key(2).fingerprint().to_string()]);
        assert!(is_envelope(&encrypted));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let k = key(1);
        let encrypted = {
            let key: &MasterKey = &k;
            key.encrypt("hunter2")
        }
        .unwrap();
        let (head, payload) = encrypted.rsplit_once(':').unwrap();

        let mut bytes = BASE64.decode(payload.as_bytes()).unwrap();
        // Bitwise flip instead of swapping 0 and last bytes: random 12-byte GCM nonces
        // can occasionally yield bytes[0] == bytes[last], making swap a no-op and causing
        // false test failure.
        bytes[0] ^= 0xff;

        let tampered = format!("{head}:{}", BASE64.encode(&bytes));

        assert!(matches!(
            k.decrypt(&tampered),
            Err(EncryptionError::Corrupt)
        ));
    }

    #[test]
    fn is_envelope_requires_more_than_the_prefix() {
        assert!(!is_envelope("wgenc:v1:not-base64"));
        assert!(!is_envelope("wgenc:v1:abcdef12:zz!!"));
        // well-formed prefix and fingerprint, but too short to hold a nonce and a tag
        assert!(!is_envelope(&format!(
            "{PREFIX}abcdef12:{}",
            BASE64.encode(b"short")
        )));
        assert!(!is_envelope("hunter2"));
        assert!(is_envelope(&key(1).encrypt("hunter2").unwrap()));
    }

    #[test]
    fn fingerprints_distinguish_keys() {
        assert_ne!(key(1).fingerprint(), key(2).fingerprint());
        assert_eq!(key(1).fingerprint().len(), FINGERPRINT_LEN);
    }

    #[test]
    fn the_key_is_not_printable() {
        assert!(!format!("{:?}", key(1)).contains("1, 1, 1"));
    }

    fn ring(primary: Option<u8>, retired: &[u8]) -> Keyring {
        Keyring {
            primary: primary.map(key),
            retired: retired.iter().copied().map(key).collect(),
        }
    }

    fn key_b64(seed: u8) -> String {
        BASE64.encode(&[seed; KEY_LEN])
    }

    #[test]
    fn parse_keyring_handles_lists_whitespace_and_duplicates() {
        let parsed = parse_env_keyring(
            Some(&format!(" {} ", key_b64(1))),
            Some(&format!(
                " {} ,, {} , {} ",
                key_b64(2),
                key_b64(1),
                key_b64(2)
            )),
        )
        .unwrap();
        assert_eq!(
            parsed.primary().unwrap().fingerprint(),
            key(1).fingerprint()
        );
        assert_eq!(
            parsed
                .retired
                .iter()
                .map(|k| k.fingerprint())
                .collect::<Vec<_>>(),
            vec![key(2).fingerprint()]
        );

        let decrypt_only = parse_env_keyring(None, Some(&key_b64(3))).unwrap();
        assert!(decrypt_only.primary().is_none());
        assert!(decrypt_only.has_retired());

        assert!(parse_env_keyring(Some(""), None).unwrap().is_empty());
        assert!(
            parse_env_keyring(Some("%%%"), None)
                .unwrap_err()
                .contains(ENV_VAR)
        );
        assert!(
            parse_env_keyring(None, Some(&BASE64.encode(b"short")))
                .unwrap_err()
                .contains(ENV_VAR_OLD)
        );
    }

    #[test]
    fn a_retired_key_still_decrypts() {
        let encrypted = {
            let key: &MasterKey = &key(1);
            key.encrypt("hunter2")
        }
        .unwrap();
        let r = ring(Some(2), &[1]);
        assert_eq!(r.decrypt(&encrypted).unwrap(), "hunter2");
    }

    #[test]
    fn an_unknown_key_is_a_mismatch_naming_the_held_keys() {
        let encrypted = {
            let key: &MasterKey = &key(1);
            key.encrypt("hunter2")
        }
        .unwrap();
        let err = {
            let ring: &Keyring = &ring(Some(2), &[3]);
            let value: &str = &encrypted;
            ring.decrypt(value)
        }
        .unwrap_err();
        let EncryptionError::KeyMismatch { expected, actual } = err else {
            panic!("expected a key mismatch");
        };
        assert_eq!(expected, key(1).fingerprint());
        assert!(actual.contains(&key(2).fingerprint().into()));
        assert!(actual.contains(&key(3).fingerprint().into()));

        assert!(matches!(
            &ring(None, &[]).decrypt(&encrypted),
            Err(EncryptionError::NoKey { .. })
        ));
        assert_eq!(&ring(None, &[]).decrypt("plaintext").unwrap(), "plaintext");
    }

    /// A same-fingerprint wrong key (32-bit collision) must be skipped in favor of
    /// the GCM tag's verdict, and end in `Corrupt` rather than a mismatch when no
    /// candidate authenticates.
    #[test]
    fn a_colliding_fingerprint_falls_through_to_corrupt() {
        let foreign = {
            let key: &MasterKey = &key(2);
            key.encrypt("hunter2")
        }
        .unwrap();
        let forged = foreign.replace(key(2).fingerprint(), key(1).fingerprint());
        assert!(matches!(
            &ring(Some(1), &[]).decrypt(&forged),
            Err(EncryptionError::Corrupt)
        ));
    }

    #[test]
    fn reencrypt_moves_everything_to_the_primary() {
        let r = ring(Some(2), &[1]);
        let fp2 = key(2).fingerprint().to_owned();

        let from_plain = {
            let ring: &Keyring = &r;
            ring.reencrypt("hunter2")
        }
        .unwrap();
        assert!(from_plain.contains(&fp2));
        assert_eq!(r.decrypt(&from_plain).unwrap(), "hunter2");

        let old = {
            let key: &MasterKey = &key(1);
            key.encrypt("hunter2")
        }
        .unwrap();
        let rotated = {
            let ring: &Keyring = &r;
            let value: &str = &old;
            ring.reencrypt(value)
        }
        .unwrap();
        assert!(rotated.contains(&fp2));
        assert_eq!(r.decrypt(&rotated).unwrap(), "hunter2");

        let current = {
            let key: &MasterKey = &key(2);
            key.encrypt("hunter2")
        }
        .unwrap();
        assert_eq!(r.reencrypt(&current).unwrap(), current);

        let unknown = {
            let key: &MasterKey = &key(3);
            key.encrypt("hunter2")
        }
        .unwrap();
        assert!(matches!(
            r.reencrypt(&unknown),
            Err(EncryptionError::KeyMismatch { .. })
        ));
    }

    /// One-way rule: no active key means nothing is rewritten in either direction.
    #[test]
    fn reencrypt_without_a_primary_changes_nothing() {
        let r = ring(None, &[1]);
        let envelope = {
            let key: &MasterKey = &key(1);
            key.encrypt("hunter2")
        }
        .unwrap();
        for value in ["hunter2", envelope.as_str()] {
            assert_eq!(r.reencrypt(value).unwrap(), value);
        }
    }
}

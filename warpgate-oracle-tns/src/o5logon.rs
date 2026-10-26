//! Server-side 12c O5LOGON key derivation (the gateway acting as the Oracle
//! server), the counterpart of python-oracledb's client in
//! `impl/thin/messages/auth.pyx::_generate_verifier`.
//!
//! Only the crypto/derivation lives here; the TTC key/value framing that carries
//! these values is in [`crate::server_auth`]. All randomness is passed in by the
//! caller so the derivation is deterministic and testable; the Warpgate
//! integration supplies cryptographically secure random bytes. Everything that
//! takes client-supplied ciphertext returns `None` when it is malformed.

use crate::crypto::{
    aes256_cbc_decrypt_raw, aes256_cbc_encrypt, aes256_cbc_encrypt_raw, hex_upper,
    pbkdf2_hmac_sha512, sha512_prefix32,
};

/// Literal label Oracle appends to the salt when stretching the password.
pub(crate) const SPEEDY_LABEL: &[u8] = b"AUTH_PBKDF2_SPEEDY_KEY";
/// The marker the client looks for in the decrypted AUTH_SVR_RESPONSE[16..32].
const SERVER_TO_CLIENT: &[u8; 16] = b"SERVER_TO_CLIENT";

/// Per-user 12c verifier material, computed once at password-set time and
/// stored by the gateway. It never contains the plaintext password.
#[derive(Debug, Clone)]
pub struct Verifier12c {
    /// AUTH_VFR_DATA — the 16-byte salt sent to the client in phase one.
    pub vfr_data: [u8; 16],
    /// AUTH_PBKDF2_VGEN_COUNT — iterations for the password-key stretch.
    pub vgen_count: u32,
    /// AUTH_PBKDF2_CSK_SALT — salt for the combo-key derivation.
    pub csk_salt: [u8; 16],
    /// AUTH_PBKDF2_SDER_COUNT — iterations for the combo-key derivation.
    pub sder_count: u32,
    /// The 64-byte stretched password key (not reversible to the password).
    pub password_key: [u8; 64],
}

impl Verifier12c {
    /// Derive verifier material from a plaintext password (enrollment only).
    pub fn from_password(
        password: &[u8],
        vfr_data: [u8; 16],
        vgen_count: u32,
        csk_salt: [u8; 16],
        sder_count: u32,
    ) -> Self {
        let password_key = derive_password_key(password, &vfr_data, vgen_count);
        Self {
            vfr_data,
            vgen_count,
            csk_salt,
            sder_count,
            password_key,
        }
    }

    /// A stand-in verifier for a login that has no real one (an unknown user, or
    /// one without an Oracle verifier), so the client gets an ordinary challenge
    /// and the login fails only at the password check, as for a wrong password,
    /// instead of revealing up front which usernames exist. Deterministic for a
    /// given `seed` and `username`, so repeated attempts see the same salts.
    pub fn decoy(seed: &[u8; 32], username: &[u8]) -> Self {
        let salts = sha512_prefix32(&[seed, b"salts", username]);
        let (vfr, csk) = salts.split_at(16);
        // Both halves of the 32-byte hash are exactly 16 bytes.
        let vfr_data = vfr.try_into().unwrap_or_default();
        let csk_salt = csk.try_into().unwrap_or_default();
        let mut password_key = [0u8; 64];
        let (head, tail) = password_key.split_at_mut(32);
        head.copy_from_slice(&sha512_prefix32(&[seed, b"key0", username]));
        tail.copy_from_slice(&sha512_prefix32(&[seed, b"key1", username]));
        Self {
            vfr_data,
            vgen_count: 4096,
            csk_salt,
            sder_count: 3,
            password_key,
        }
    }

    /// The AES-256 key that wraps the session-key halves:
    /// SHA512(password_key || vfr_data)[..32].
    fn password_hash(&self) -> [u8; 32] {
        sha512_prefix32(&[&self.password_key, &self.vfr_data])
    }
}

/// PBKDF2-HMAC-SHA512(password, vfr_data || "AUTH_PBKDF2_SPEEDY_KEY", vgen, 64).
fn derive_password_key(password: &[u8], vfr_data: &[u8; 16], vgen_count: u32) -> [u8; 64] {
    let mut salt = Vec::with_capacity(16 + SPEEDY_LABEL.len());
    salt.extend_from_slice(vfr_data);
    salt.extend_from_slice(SPEEDY_LABEL);
    pbkdf2_hmac_sha512(password, &salt, vgen_count)
}

/// Phase one: the server picks a 48-byte `part_a` and sends the client the
/// AUTH_SESSKEY — `part_a[..32]` enciphered as two **raw** AES-CBC blocks (no
/// PKCS#7): 32 bytes / 64 hex chars, exactly what a real Oracle server sends.
/// Strict thin clients (Oracle JDBC thin, go-ora) accept only the 64- or 96-hex
/// forms. Only `part_a[..32]` feeds [`server_combo_key`].
pub fn server_sesskey(v: &Verifier12c, part_a: &[u8; 48]) -> Vec<u8> {
    let (head, _) = part_a.split_at(32);
    // 32 bytes are two whole blocks, so this is always `Some`.
    aes256_cbc_encrypt_raw(&v.password_hash(), head).unwrap_or_default()
}

/// Phase two: derive the combo key from the server's own `part_a` and the
/// client's returned AUTH_SESSKEY ciphertext (`client_sesskey_ct`).
pub fn server_combo_key(
    v: &Verifier12c,
    part_a: &[u8; 48],
    client_sesskey_ct: &[u8],
) -> Option<[u8; 32]> {
    let part_b = aes256_cbc_decrypt_raw(&v.password_hash(), client_sesskey_ct)?;
    combo_key(&part_b, part_a, &v.csk_salt, v.sder_count)
}

/// combo_key = PBKDF2(upper_hex(part_b[..32] || part_a[..32]).ascii, csk_salt,
/// sder_count, 32). Shared by both legs; either half may carry trailing padding
/// (only the first 32 bytes are used). `None` if a half is shorter than that.
pub(crate) fn combo_key(
    part_b: &[u8],
    part_a: &[u8],
    csk_salt: &[u8],
    sder_count: u32,
) -> Option<[u8; 32]> {
    let mut temp = Vec::with_capacity(64);
    temp.extend_from_slice(part_b.get(..32)?);
    temp.extend_from_slice(part_a.get(..32)?);
    let input = hex_upper(&temp).into_bytes();
    Some(pbkdf2_hmac_sha512(&input, csk_salt, sder_count))
}

/// Decrypt AUTH_PASSWORD with the combo key and return the plaintext password
/// candidate (the layout is 16 random bytes, then the password, then padding).
/// `None` if the ciphertext is malformed or carries no password.
pub fn recover_password(combo_key: &[u8; 32], auth_password_ct: &[u8]) -> Option<Vec<u8>> {
    let dec = aes256_cbc_decrypt_raw(combo_key, auth_password_ct)?;
    let body = dec.get(16..).filter(|b| !b.is_empty())?;
    Some(strip_pkcs7(body))
}

/// Confirm a recovered password really matches the stored verifier (Oracle's
/// real server-side check): re-derive the password key and compare in constant
/// time.
pub fn verify_password(v: &Verifier12c, candidate: &[u8]) -> bool {
    let derived = derive_password_key(candidate, &v.vfr_data, v.vgen_count);
    ct_eq(&derived, &v.password_key)
}

/// Build AUTH_SVR_RESPONSE: `encrypt_cbc(combo_key, nonce16 || "SERVER_TO_CLIENT")`
/// so the client finds the marker at bytes [16..32] after decrypting.
pub fn server_response(combo_key: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    let mut plain = Vec::with_capacity(32);
    plain.extend_from_slice(nonce);
    plain.extend_from_slice(SERVER_TO_CLIENT);
    aes256_cbc_encrypt(combo_key, &plain)
}

/// Check the AUTH_SVR_RESPONSE a database returned at the end of the gateway's
/// own login: it must decrypt under the combo key to a nonce followed by
/// "SERVER_TO_CLIENT", which only a party knowing the password can produce.
pub fn verify_server_response(combo_key: &[u8; 32], response_ct: &[u8]) -> bool {
    aes256_cbc_decrypt_raw(combo_key, response_ct)
        .and_then(|plain| plain.get(16..32).map(|marker| marker == SERVER_TO_CLIENT))
        .unwrap_or(false)
}

fn strip_pkcs7(b: &[u8]) -> Vec<u8> {
    let pad = b.last().map_or(0, |&p| usize::from(p));
    if (1..=16).contains(&pad)
        && let Some((body, tail)) = b.len().checked_sub(pad).map(|at| b.split_at(at))
        && tail.iter().all(|&x| usize::from(x) == pad)
    {
        return body.to_vec();
    }
    b.to_vec()
}

/// Constant-time equality for fixed-size secrets.
fn ct_eq(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |diff, (x, y)| diff | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::counting_bytes;

    /// A minimal stock-client derivation (mirrors auth.pyx `_generate_verifier`
    /// for the 12c branch), used to prove the server leg interoperates.
    struct ClientOut {
        combo_key: [u8; 32],
        sesskey_ct: Vec<u8>,
        auth_password_ct: Vec<u8>,
    }

    fn client_login(
        typed_pw: &[u8],
        vfr: &[u8; 16],
        vgen: u32,
        csk: &[u8; 16],
        sder: u32,
        server_sesskey_ct: &[u8],
        part_b: &[u8; 32],
        auth_pw_nonce: &[u8; 16],
    ) -> ClientOut {
        let password_key = derive_password_key(typed_pw, vfr, vgen);
        let cli_hash = sha512_prefix32(&[&password_key, vfr]);

        let part_a = aes256_cbc_decrypt_raw(&cli_hash, server_sesskey_ct).unwrap(); // 32 bytes
        assert_eq!(part_a.len(), part_b.len());
        let sesskey_ct = aes256_cbc_encrypt(&cli_hash, part_b);
        let combo = combo_key(part_b, &part_a, csk, sder).unwrap();
        let mut pw_plain = Vec::new();
        pw_plain.extend_from_slice(auth_pw_nonce);
        pw_plain.extend_from_slice(typed_pw);
        let auth_password_ct = aes256_cbc_encrypt(&combo, &pw_plain);
        ClientOut {
            combo_key: combo,
            sesskey_ct,
            auth_password_ct,
        }
    }

    fn setup() -> (Vec<u8>, Verifier12c, [u8; 48]) {
        let password = b"Warpgate_User_Pw!".to_vec();
        let v = Verifier12c::from_password(
            &password,
            counting_bytes(0x11),
            4096,
            counting_bytes(0x22),
            3,
        );
        (password, v, counting_bytes(0x33))
    }

    #[test]
    fn correct_password_authenticates_end_to_end() {
        let (password, v, part_a) = setup();
        let sesskey_srv = server_sesskey(&v, &part_a);
        assert_eq!(
            sesskey_srv.len(),
            32,
            "32-byte raw form (64 hex chars) — what real Oracle and strict thin clients require"
        );

        let client = client_login(
            &password,
            &v.vfr_data,
            v.vgen_count,
            &v.csk_salt,
            v.sder_count,
            &sesskey_srv,
            &[0x44; 32],
            &[0x55; 16],
        );

        let combo_srv = server_combo_key(&v, &part_a, &client.sesskey_ct).unwrap();
        assert_eq!(
            combo_srv, client.combo_key,
            "both legs derive the same combo key"
        );

        let recovered = recover_password(&combo_srv, &client.auth_password_ct).unwrap();
        assert_eq!(recovered, password, "server recovers the exact plaintext");
        assert!(verify_password(&v, &recovered), "verifier re-check passes");

        // The client accepts the server's response.
        let resp = server_response(&combo_srv, &counting_bytes(0x66));
        let dec = aes256_cbc_decrypt_raw(&client.combo_key, &resp).unwrap();
        assert_eq!(&dec[16..32], SERVER_TO_CLIENT);
        assert!(verify_server_response(&client.combo_key, &resp));
        assert!(!verify_server_response(&counting_bytes(0), &resp));
        assert!(!verify_server_response(&client.combo_key, &resp[..16]));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (_password, v, part_a) = setup();
        let sesskey_srv = server_sesskey(&v, &part_a);
        let wrong_password = b"WrongPassword123".to_vec();

        let client = client_login(
            &wrong_password,
            &v.vfr_data,
            v.vgen_count,
            &v.csk_salt,
            v.sder_count,
            &sesskey_srv,
            &[0x44; 32],
            &[0x55; 16],
        );

        let combo_srv = server_combo_key(&v, &part_a, &client.sesskey_ct).unwrap();
        assert_ne!(
            combo_srv, client.combo_key,
            "combo keys diverge on wrong pw"
        );
        let recovered = recover_password(&combo_srv, &client.auth_password_ct).unwrap_or_default();
        assert!(!verify_password(&v, &recovered), "verifier re-check fails");
    }

    #[test]
    fn enrollment_keeps_no_plaintext_and_is_reproducible() {
        let password = b"hunter2".to_vec();
        let (vfr_data, csk_salt) = (counting_bytes(1), counting_bytes(2));
        let v1 = Verifier12c::from_password(&password, vfr_data, 1000, csk_salt, 3);
        let v2 = Verifier12c::from_password(&password, vfr_data, 1000, csk_salt, 3);
        assert_eq!(v1.password_key, v2.password_key);
        // the stored key is not the password
        assert_ne!(&v1.password_key[..password.len()], password.as_slice());
    }

    #[test]
    fn decoy_is_stable_per_user_and_rejects_any_password() {
        let seed = [9u8; 32];
        let alice = b"ALICE".to_vec();
        let a = Verifier12c::decoy(&seed, &alice);
        let b = Verifier12c::decoy(&seed, &alice);
        let c = Verifier12c::decoy(&seed, b"BOB");
        assert_eq!((a.vfr_data, a.csk_salt), (b.vfr_data, b.csk_salt));
        assert_ne!(a.vfr_data, c.vfr_data);
        assert!(!verify_password(&a, &[]));
        assert!(!verify_password(&a, &alice));
    }

    #[test]
    fn malformed_client_material_is_rejected_not_panicking() {
        let (_password, v, part_a) = setup();
        let key = counting_bytes(0);
        for bad in [&[][..], &[0u8; 15][..], &[0u8; 17][..]] {
            assert!(
                server_combo_key(&v, &part_a, bad).is_none(),
                "len {}",
                bad.len()
            );
            assert!(recover_password(&key, bad).is_none(), "len {}", bad.len());
        }
        // One whole block decrypts, but is too short for a 32-byte half.
        assert!(server_combo_key(&v, &part_a, &[0u8; 16]).is_none());
        // A single block is all nonce, with no password after it.
        assert!(recover_password(&key, &[0u8; 16]).is_none());
    }
}

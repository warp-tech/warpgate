//! Client-side 12c O5LOGON derivation — the gateway acting as an Oracle *client*
//! toward the target database (the mirror of the server side in `o5logon`). It
//! follows the client half of python-oracledb `auth.pyx::_generate_verifier`:
//! from the server's phase-one parameters and the password, produce the values
//! the client sends in phase two.

use crate::crypto::{
    aes256_cbc_decrypt_raw, aes256_cbc_encrypt, pbkdf2_hmac_sha512, sha512_prefix32,
};
use crate::o5logon::{SPEEDY_LABEL, combo_key};

/// The material the client sends in AUTH phase two (binary; the request builder
/// hex-encodes these onto the wire).
#[derive(Debug, Clone)]
pub struct ClientAuth {
    /// The derived combo key (AES-256) — also used to verify AUTH_SVR_RESPONSE.
    pub combo_key: [u8; 32],
    /// AUTH_SESSKEY: the client's half of the session key (encrypted part_b).
    pub sesskey_ct: Vec<u8>,
    /// AUTH_PBKDF2_SPEEDY_KEY (80 bytes).
    pub speedy_key: Vec<u8>,
    /// AUTH_PASSWORD: the encrypted (nonce || password).
    pub auth_password: Vec<u8>,
}

/// Derive the client's phase-two response from the server's phase-one params.
///
/// `part_b`, `speedy_nonce` and `auth_pw_nonce` are random inputs supplied by
/// the caller (so the derivation is deterministic and testable); `part_b` must
/// be the same length as `server_sesskey_ct`. `None` if the server's
/// AUTH_SESSKEY is malformed or `part_b` does not match it.
#[allow(clippy::too_many_arguments)]
pub fn client_derive(
    password: &[u8],
    vfr_data: &[u8],
    vgen_count: u32,
    csk_salt: &[u8],
    sder_count: u32,
    server_sesskey_ct: &[u8],
    part_b: &[u8],
    speedy_nonce: &[u8; 16],
    auth_pw_nonce: &[u8; 16],
) -> Option<ClientAuth> {
    // 1. Stretch the password into the 64-byte password key, using the same
    //    PBKDF2 inputs as the server's enrollment (salt = vfr_data || LABEL).
    let mut key_salt = Vec::with_capacity(vfr_data.len() + SPEEDY_LABEL.len());
    key_salt.extend_from_slice(vfr_data);
    key_salt.extend_from_slice(SPEEDY_LABEL);
    let password_key: [u8; 64] = pbkdf2_hmac_sha512(password, &key_salt, vgen_count);

    // 2. The AES-256 key that wraps the session-key halves:
    //    SHA512(password_key || vfr_data)[..32].
    let cli_hash = sha512_prefix32(&[&password_key, vfr_data]);

    // 3. Recover the server's half (`part_a`) by decrypting AUTH_SESSKEY. The raw
    //    decryptor keeps padding, so `part_a.len() == server_sesskey_ct.len()`.
    let part_a = aes256_cbc_decrypt_raw(&cli_hash, server_sesskey_ct)?;

    // 4. Encrypt our own half (`part_b`) under the same key to form the client's
    //    AUTH_SESSKEY ciphertext, then truncate it to the length the server
    //    expects: python-oracledb sends `hex[:96]` (48 bytes) when part_a is 48
    //    (the 11g path), else `hex[:64]` (32 bytes, the 12c path). Sending the
    //    full padded ciphertext makes the server recover the wrong part_b.
    if part_b.len() != part_a.len() {
        return None;
    }
    let mut sesskey_ct = aes256_cbc_encrypt(&cli_hash, part_b);
    sesskey_ct.truncate(if part_a.len() == 48 { 48 } else { 32 });

    // 5. The combo key, exactly as the server side derives it.
    let combo_key = combo_key(part_b, &part_a, csk_salt, sder_count)?;

    // 6. AUTH_PBKDF2_SPEEDY_KEY: encrypt (speedy_nonce || password_key) under the
    //    combo key, keeping the first 80 bytes.
    let mut speedy_plain = Vec::with_capacity(speedy_nonce.len() + password_key.len());
    speedy_plain.extend_from_slice(speedy_nonce);
    speedy_plain.extend_from_slice(&password_key);
    let mut speedy_key = aes256_cbc_encrypt(&combo_key, &speedy_plain);
    speedy_key.truncate(80);

    // 7. AUTH_PASSWORD: encrypt (auth_pw_nonce || password) under the combo key.
    let mut pw_plain = Vec::with_capacity(auth_pw_nonce.len() + password.len());
    pw_plain.extend_from_slice(auth_pw_nonce);
    pw_plain.extend_from_slice(password);
    let auth_password = aes256_cbc_encrypt(&combo_key, &pw_plain);

    Some(ClientAuth {
        combo_key,
        sesskey_ct,
        speedy_key,
        auth_password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::o5logon;
    use crate::test_support::counting_bytes;

    const VGEN: u32 = 4096;
    const SDER: u32 = 3;

    /// The random phase-one inputs shared by the closed-loop tests. `part_a` is
    /// the server's 48-byte half; its AUTH_SESSKEY is the real-Oracle 32-byte
    /// form (part_a[..32] raw-CBC), which decrypts to 32 bytes on the client, so
    /// `part_b` is 32 bytes (a client sizes part_b to the server key length).
    struct Inputs {
        vfr_data: [u8; 16],
        csk_salt: [u8; 16],
        part_a: [u8; 48],
        part_b: [u8; 32],
        speedy_nonce: [u8; 16],
        auth_pw_nonce: [u8; 16],
    }

    fn inputs() -> Inputs {
        Inputs {
            vfr_data: counting_bytes(0x11),
            csk_salt: counting_bytes(0x22),
            part_a: counting_bytes(0x33),
            part_b: counting_bytes(0x44),
            speedy_nonce: counting_bytes(0x55),
            auth_pw_nonce: counting_bytes(0x66),
        }
    }

    /// Closed loop: the client derivation and the independent server leg agree,
    /// the server recovers the exact plaintext, and the verifier re-check passes.
    #[test]
    fn client_and_server_agree_on_correct_password() {
        let i = inputs();
        let password = b"Warpgate_User_Pw!".to_vec();
        let v = o5logon::Verifier12c::from_password(&password, i.vfr_data, VGEN, i.csk_salt, SDER);
        let server_sesskey = o5logon::server_sesskey(&v, &i.part_a);
        assert_eq!(
            server_sesskey.len(),
            32,
            "real-Oracle 32-byte AUTH_SESSKEY form"
        );
        assert_eq!(
            i.part_b.len(),
            server_sesskey.len(),
            "part_b matches the session-key ciphertext length"
        );

        let client = client_derive(
            &password,
            &i.vfr_data,
            VGEN,
            &i.csk_salt,
            SDER,
            &server_sesskey,
            &i.part_b,
            &i.speedy_nonce,
            &i.auth_pw_nonce,
        )
        .unwrap();

        // Both legs independently derive the same combo key.
        let combo_srv = o5logon::server_combo_key(&v, &i.part_a, &client.sesskey_ct).unwrap();
        assert_eq!(
            client.combo_key, combo_srv,
            "client and server combo keys agree"
        );

        // The server recovers the exact plaintext and the verifier re-check passes.
        let recovered =
            o5logon::recover_password(&client.combo_key, &client.auth_password).unwrap();
        assert_eq!(recovered, password, "server recovers the typed password");
        assert!(
            o5logon::verify_password(&v, &recovered),
            "verifier re-check passes"
        );

        // AUTH_PBKDF2_SPEEDY_KEY is truncated to exactly 80 bytes.
        assert_eq!(client.speedy_key.len(), 80, "speedy key is 80 bytes");
    }

    /// A wrong typed password makes the two combo keys diverge, so the server's
    /// verifier re-check of the recovered plaintext fails.
    #[test]
    fn wrong_password_diverges_and_fails_verification() {
        let i = inputs();
        let real_password = b"Warpgate_User_Pw!".to_vec();
        let wrong_password = b"WrongPassword123".to_vec();
        let v =
            o5logon::Verifier12c::from_password(&real_password, i.vfr_data, VGEN, i.csk_salt, SDER);
        let server_sesskey = o5logon::server_sesskey(&v, &i.part_a);

        let client = client_derive(
            &wrong_password,
            &i.vfr_data,
            VGEN,
            &i.csk_salt,
            SDER,
            &server_sesskey,
            &i.part_b,
            &i.speedy_nonce,
            &i.auth_pw_nonce,
        )
        .unwrap();

        let combo_srv = o5logon::server_combo_key(&v, &i.part_a, &client.sesskey_ct).unwrap();
        assert_ne!(
            client.combo_key, combo_srv,
            "combo keys diverge on a wrong password"
        );
        let recovered =
            o5logon::recover_password(&combo_srv, &client.auth_password).unwrap_or_default();
        assert!(
            !o5logon::verify_password(&v, &recovered),
            "verifier re-check fails for a wrong password"
        );
    }
}

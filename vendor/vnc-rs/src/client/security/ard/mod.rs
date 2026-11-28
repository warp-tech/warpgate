//! Apple Remote Desktop (ARD) authentication — RFB security type 30.
//!
//! The client and server perform an ephemeral Diffie-Hellman key agreement,
//! hash the shared secret with MD5 to derive an AES-128 key, and send the
//! credentials as a single AES-128-ECB encrypted block. The RFB session
//! itself continues unencrypted, matching the reference implementations
//! (Valence, gtk-vnc, Wireshark's dissector).

mod creds;
mod dh;

use num_bigint::BigUint;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::client::auth::AuthResult;
use crate::VncError;

/// Apple's server reports this non-standard version string instead of a legal
/// RFB version. Its presence identifies an Apple Remote Desktop server and
/// means the 3.7/3.8 security-negotiation handshake (where type 30 is offered)
/// is supported.
pub(crate) const APPLE_RFB_VERSION: &[u8; 12] = b"RFB 003.889\n";

const MAX_KEY_LEN: usize = 1024;

#[derive(Debug, Clone)]
pub(crate) struct ArdCredentials {
    pub username: String,
    pub password: String,
}

/// Perform the ARD authentication exchange after security type 30 has been
/// selected, and read the security result that follows it.
pub(crate) async fn authenticate<S>(
    stream: &mut S,
    credentials: &ArdCredentials,
) -> Result<AuthResult, VncError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Server parameters: generator, key length, prime modulus, server public key.
    let generator = BigUint::from(stream.read_u16().await?);
    let key_len = usize::from(stream.read_u16().await?);
    if key_len == 0 || key_len > MAX_KEY_LEN {
        return Err(VncError::ArdProtocol(format!(
            "key length {key_len} out of range"
        )));
    }

    let mut material = vec![0u8; key_len * 2];
    stream.read_exact(&mut material).await?;
    let prime = BigUint::from_bytes_be(&material[..key_len]);
    let server_key = BigUint::from_bytes_be(&material[key_len..]);
    dh::validate(&generator, &prime, &server_key)?;

    let (private, public) = dh::generate_keypair(&generator, &prime, key_len)?;
    let shared = dh::shared_secret(&server_key, &private, &prime);
    let key = creds::session_key(&dh::to_fixed_be(&shared, key_len)?);

    let encrypted = creds::encrypt_credentials(&credentials.username, &credentials.password, &key)?;
    stream.write_all(&encrypted).await?;
    stream
        .write_all(&dh::to_fixed_be(&public, key_len)?)
        .await?;

    stream.read_u32().await?.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    use aes::Aes128;
    use tokio::io::duplex;

    fn test_prime() -> BigUint {
        // Mersenne prime 2^521 - 1, 66 bytes: exercises key lengths above 64.
        (BigUint::from(1u8) << 521u32) - BigUint::from(1u8)
    }

    fn credentials() -> ArdCredentials {
        ArdCredentials {
            username: "vncuser".into(),
            password: "s3cret!".into(),
        }
    }

    /// Apple-side of the handshake; returns the decrypted 128-byte credential block.
    async fn serve_apple_handshake<S>(stream: &mut S, result: u32) -> Result<[u8; 128], VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let prime = test_prime();
        let key_len = prime.to_bytes_be().len();
        let generator = BigUint::from(2u8);
        let private = BigUint::from(0x1234_5678_9abc_def0u64);
        let public = generator.modpow(&private, &prime);

        stream.write_u16(2).await?;
        stream.write_u16(key_len as u16).await?;
        stream.write_all(&dh::to_fixed_be(&prime, key_len)?).await?;
        stream
            .write_all(&dh::to_fixed_be(&public, key_len)?)
            .await?;

        let mut encrypted = [0u8; 128];
        stream.read_exact(&mut encrypted).await?;
        let mut client_public = vec![0u8; key_len];
        stream.read_exact(&mut client_public).await?;

        let shared = dh::shared_secret(&BigUint::from_bytes_be(&client_public), &private, &prime);
        let key = creds::session_key(&dh::to_fixed_be(&shared, key_len)?);
        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let mut block = encrypted;
        for chunk in block.as_chunks_mut::<16>().0 {
            cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
        }

        stream.write_u32(result).await?;
        Ok(block)
    }

    async fn run_handshake(result: u32) -> (Result<AuthResult, VncError>, [u8; 128]) {
        let (mut client, mut server) = duplex(4096);
        let server_task =
            tokio::spawn(async move { serve_apple_handshake(&mut server, result).await });
        let result = authenticate(&mut client, &credentials()).await;
        let block = server_task.await.unwrap().unwrap();
        (result, block)
    }

    #[tokio::test]
    async fn handshake_encrypts_the_credentials() {
        let (result, block) = run_handshake(0).await;
        assert!(matches!(result, Ok(AuthResult::Ok)));
        assert_eq!(&block[..7], b"vncuser");
        assert_eq!(block[7], 0);
        assert_eq!(&block[64..71], b"s3cret!");
        assert_eq!(block[71], 0);
    }

    #[tokio::test]
    async fn authentication_failure_is_reported() {
        let (result, _) = run_handshake(1).await;
        assert!(matches!(result, Ok(AuthResult::Failed)));
    }

    #[tokio::test]
    async fn zero_key_length_is_rejected() {
        let (mut client, mut server) = duplex(64);
        server.write_u16(2).await.unwrap();
        server.write_u16(0).await.unwrap();
        let result = authenticate(&mut client, &credentials()).await;
        assert!(matches!(result, Err(VncError::ArdProtocol(_))));
    }

    #[tokio::test]
    async fn out_of_range_server_key_is_rejected() {
        let (mut client, mut server) = duplex(64);
        // p = 23, server key = p - 1.
        server.write_u16(5).await.unwrap();
        server.write_u16(1).await.unwrap();
        server.write_all(&[23]).await.unwrap();
        server.write_all(&[22]).await.unwrap();
        let result = authenticate(&mut client, &credentials()).await;
        assert!(matches!(result, Err(VncError::ArdProtocol(_))));
    }
}

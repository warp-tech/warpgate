//! Low-level RFB (VNC) and VeNCrypt handshake helpers.
//!
//! Warpgate acts as an RFB **server** towards the native viewer, offering VeNCrypt
//! (X.509/TLS + Plain) and Apple-DH (type 30) so the viewer authenticates with a
//! full-length `user:target` username and password; and as an RFB **client** towards
//! the backend target.
//!
//! Unfortunately the macOS native VNC client remains unsupported
//! since it only supports ARD security at RFB 003.889 which requires
//! Apple-specific server behavior after ServerInit
//!
//! RealVNC can still use ARD at a standard RFB version

use anyhow::{Context, Result, bail};
use des::Des;
use des::cipher::{BlockEncrypt, KeyInit};
use num_bigint::BigUint;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";

/// VeNCrypt sub-type: X.509 certificate based TLS, then Plain (username/password) auth.
const VENCRYPT_SUBTYPE_X509PLAIN: u32 = 262;
/// VeNCrypt protocol version we speak (major 0, minor 2).
const VENCRYPT_VERSION: [u8; 2] = [0, 2];

const MAX_STRING_LEN: usize = 4096;

/// RFB security types
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityType {
    None,
    VncAuth,
    VeNCrypt,
    AppleDh,
}

impl SecurityType {
    /// The protocol security-type code.
    const fn code(self) -> u8 {
        match self {
            Self::None => 1,
            Self::VncAuth => 2,
            Self::VeNCrypt => 19,
            Self::AppleDh => 30,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        [Self::None, Self::VncAuth, Self::VeNCrypt, Self::AppleDh]
            .into_iter()
            .find(|t| t.code() == code)
    }
}

/// Security types offered to the viewer, in preference order.
const VIEWER_SECURITY_TYPES: [SecurityType; 2] = [SecurityType::VeNCrypt, SecurityType::AppleDh];

/// RFB ProtocolVersion exchange, then offer the supported security types and read
/// the client's choice
pub async fn server_negotiate_security<S>(stream: &mut S) -> Result<SecurityType>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(RFB_VERSION).await?;
    stream.flush().await?;

    let mut client_version = [0u8; 12];
    stream
        .read_exact(&mut client_version)
        .await
        .context("reading client RFB version")?;

    debug!(
        version = %String::from_utf8_lossy(&client_version).trim_end(),
        "viewer RFB version"
    );

    let mut offer = Vec::with_capacity(1 + VIEWER_SECURITY_TYPES.len());
    offer.push(VIEWER_SECURITY_TYPES.len() as u8);
    offer.extend(VIEWER_SECURITY_TYPES.iter().map(|t| t.code()));
    stream.write_all(&offer).await?;
    stream.flush().await?;

    let selected = stream
        .read_u8()
        .await
        .context("reading selected security")?;
    debug!(selected, "viewer selected security type");

    match SecurityType::from_code(selected) {
        Some(t) if VIEWER_SECURITY_TYPES.contains(&t) => Ok(t),
        _ => bail!("viewer selected unsupported security type {selected}"),
    }
}

/// VeNCrypt sub-negotiation after the viewer selects VeNCrypt and before the TLS
/// upgrade: agree on version 0.2 and the X509Plain subtype.
pub async fn server_vencrypt_sub_negotiate<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // VeNCrypt version 0.2
    stream.write_all(&VENCRYPT_VERSION).await?;
    stream.flush().await?;
    let mut version = [0u8; 2];
    stream.read_exact(&mut version).await?;
    if version != VENCRYPT_VERSION {
        // ack failure
        stream.write_all(&[1]).await?;
        stream.flush().await?;
        bail!("unsupported VeNCrypt version {version:?}");
    }
    // ack ok
    stream.write_all(&[0]).await?;
    stream.flush().await?;

    // Offer only X509Plain
    stream.write_all(&[1]).await?; // subtype count
    stream
        .write_all(&VENCRYPT_SUBTYPE_X509PLAIN.to_be_bytes())
        .await?;
    stream.flush().await?;
    let chosen = stream
        .read_u32()
        .await
        .context("reading chosen VeNCrypt subtype")?;
    if chosen != VENCRYPT_SUBTYPE_X509PLAIN {
        stream.write_all(&[0]).await?; // refuse
        stream.flush().await?;
        bail!("viewer chose unsupported VeNCrypt subtype {chosen}");
    }
    // proceed with TLS
    stream.write_all(&[1]).await?;
    stream.flush().await?;

    Ok(())
}

mod apple_dh {
    use super::*;

    /// Returns the (username, password) the viewer supplied — the username
    /// carries the `user:target` selector, exactly like the VeNCrypt Plain path.
    pub async fn server_apple_dh_auth<S>(stream: &mut S) -> Result<(String, String)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        const APPLE_DH_PRIME_HEX: &[u8] = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";
        const APPLE_DH_GENERATOR: u16 = 2;

        let prime =
            BigUint::parse_bytes(APPLE_DH_PRIME_HEX, 16).context("parsing Apple DH prime")?;
        let generator = BigUint::from(APPLE_DH_GENERATOR);
        let key_len = prime.bits().div_ceil(8) as usize;

        // Server ephemeral keypair.
        let mut priv_bytes = vec![0u8; key_len];
        getrandom::getrandom(&mut priv_bytes).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        let server_private = BigUint::from_bytes_be(&priv_bytes) % &prime;
        let server_public = generator.modpow(&server_private, &prime);

        // Send: generator | keyLength | prime | serverPublicKey.
        let mut msg = Vec::with_capacity(4 + key_len * 2);
        msg.extend_from_slice(&APPLE_DH_GENERATOR.to_be_bytes());
        msg.extend_from_slice(&(key_len as u16).to_be_bytes());
        msg.extend_from_slice(&left_pad(&prime.to_bytes_be(), key_len));
        msg.extend_from_slice(&left_pad(&server_public.to_bytes_be(), key_len));
        stream.write_all(&msg).await?;
        stream.flush().await?;

        // Receive: 128-byte encrypted credential blob | clientPublicKey.
        let mut encrypted = [0u8; 128];
        stream
            .read_exact(&mut encrypted)
            .await
            .context("reading Apple DH credentials")?;
        let mut client_pub = vec![0u8; key_len];
        stream
            .read_exact(&mut client_pub)
            .await
            .context("reading Apple DH client key")?;

        // Shared secret -> AES-128 key = MD5(shared secret), both as key_len big-endian.
        let shared = BigUint::from_bytes_be(&client_pub).modpow(&server_private, &prime);
        let aes_key = md5_16(&left_pad(&shared.to_bytes_be(), key_len));

        // Decrypt: username in [0..64], password in [64..128], each NUL-terminated.
        let plain = aes128_ecb_decrypt(&aes_key, &encrypted)?;
        Ok((cstr(&plain[..64]), cstr(&plain[64..])))
    }

    /// Left-pad (or right-truncate) `bytes` to exactly `len` bytes, big-endian.
    fn left_pad(bytes: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        if bytes.len() >= len {
            out.copy_from_slice(&bytes[bytes.len() - len..]);
        } else {
            out[len - bytes.len()..].copy_from_slice(bytes);
        }
        out
    }

    /// Decode a fixed-width NUL-terminated C string field.
    fn cstr(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    fn md5_16(data: &[u8]) -> [u8; 16] {
        use md5::{Digest, Md5};
        let digest = Md5::digest(data);
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest);
        key
    }

    /// AES-128 ECB decryption of a whole-block buffer (the 128-byte credential blob).
    fn aes128_ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        use ecb::Decryptor;
        use ecb::cipher::block_padding::NoPadding;
        use ecb::cipher::{BlockDecryptMut, KeyInit};

        let mut buf = data.to_vec();
        let plain = Decryptor::<aes::Aes128>::new(&(*key).into())
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .map_err(|e| anyhow::anyhow!("AES-ECB decrypt: {e}"))?;
        Ok(plain.to_vec())
    }
}

pub use apple_dh::server_apple_dh_auth;

/// Reads the VeNCrypt Plain credentials (over the established TLS channel).
pub async fn server_read_plain_credentials<S>(stream: &mut S) -> Result<(String, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let user_len = stream.read_u32().await.context("reading username length")? as usize;
    let pass_len = stream.read_u32().await.context("reading password length")? as usize;
    if user_len > MAX_STRING_LEN || pass_len > MAX_STRING_LEN {
        bail!("VeNCrypt credentials too long");
    }
    let mut user = vec![0u8; user_len];
    stream.read_exact(&mut user).await?;
    let mut pass = vec![0u8; pass_len];
    stream.read_exact(&mut pass).await?;
    Ok((
        String::from_utf8_lossy(&user).into_owned(),
        String::from_utf8_lossy(&pass).into_owned(),
    ))
}

/// Writes the RFB SecurityResult to the viewer. On failure (RFB 3.8) a reason
/// string is appended.
pub async fn server_write_security_result<S>(stream: &mut S, ok: bool, reason: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if ok {
        stream.write_all(&0u32.to_be_bytes()).await?;
    } else {
        stream.write_all(&1u32.to_be_bytes()).await?;
        stream
            .write_all(&(reason.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(reason.as_bytes()).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Reads the viewer's ClientInit message (a single shared-flag byte).
pub async fn server_read_client_init<S>(stream: &mut S) -> Result<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.read_u8().await.context("reading ClientInit")
}

/// Performs the RFB **client** handshake against the backend target and returns
/// the target's ServerInit message verbatim (to be forwarded to the viewer).
pub async fn backend_handshake<S>(
    stream: &mut S,
    password: &str,
    shared_flag: u8,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ProtocolVersion
    let mut server_version = [0u8; 12];
    stream
        .read_exact(&mut server_version)
        .await
        .context("reading target RFB version")?;
    debug!(
        version = %String::from_utf8_lossy(&server_version).trim_end(),
        "backend RFB version"
    );
    // A client must never request a higher version than the server offers, so reply
    // with the lower of ours (3.8) and the target's. (Equal-length ASCII compares
    // lexicographically.) Below 3.8, "None" auth omits the SecurityResult message.
    let reply = if server_version < *RFB_VERSION {
        &server_version
    } else {
        RFB_VERSION
    };

    let target_is_gte_38 = reply >= RFB_VERSION;
    stream.write_all(reply).await?;
    stream.flush().await?;

    // Security types (RFB 3.7+)
    let count = stream
        .read_u8()
        .await
        .context("reading target security count")?;
    if count == 0 {
        let reason_len = stream.read_u32().await? as usize;
        let mut reason = vec![0u8; reason_len.min(MAX_STRING_LEN)];
        stream.read_exact(&mut reason).await.ok();
        bail!(
            "target rejected connection: {}",
            String::from_utf8_lossy(&reason)
        );
    }
    let mut types = vec![0u8; count as usize];
    stream.read_exact(&mut types).await?;
    debug!(?types, "backend security types");

    // Prefer no auth, otherwise legacy VNC Authentication.
    let chosen = [SecurityType::None, SecurityType::VncAuth]
        .into_iter()
        .find(|t| types.contains(&t.code()))
        .with_context(|| format!("target offers no supported security type: {types:?}"))?;
    debug!(chosen = chosen.code(), "chose backend security type");
    stream.write_all(&[chosen.code()]).await?;
    stream.flush().await?;

    if chosen == SecurityType::VncAuth {
        let mut challenge = [0u8; 16];
        stream.read_exact(&mut challenge).await?;
        let response = vnc_auth_response(password, &challenge);
        stream.write_all(&response).await?;
        stream.flush().await?;
    }

    // SecurityResult: always present for VNC Auth; for "None" only in RFB 3.8+.
    if chosen == SecurityType::VncAuth || target_is_gte_38 {
        let result = stream
            .read_u32()
            .await
            .context("reading target SecurityResult")?;
        if result != 0 {
            bail!("target authentication failed");
        }
    }
    debug!("backend authenticated; forwarding ClientInit");

    // ClientInit (forward the viewer's shared flag)
    stream.write_all(&[shared_flag]).await?;
    stream.flush().await?;

    // ServerInit: 2 (w) + 2 (h) + 16 (pixel format) + 4 (name length) = 24
    let mut head = [0u8; 24];
    stream
        .read_exact(&mut head)
        .await
        .context("reading ServerInit head")?;
    let name_len = u32::from_be_bytes([head[20], head[21], head[22], head[23]]) as usize;
    let mut name = vec![0u8; name_len.min(MAX_STRING_LEN)];
    stream.read_exact(&mut name).await?;

    let mut server_init = Vec::with_capacity(head.len() + name.len());
    server_init.extend_from_slice(&head);
    server_init.extend_from_slice(&name);
    Ok(server_init)
}

/// Computes the VNC Authentication DES response for a challenge.
///
/// VNC uses DES with the (max 8 byte) password as the key, with each key byte's
/// bits reversed, encrypting the 16-byte challenge as two ECB blocks.
///
/// NOTE: DES is intentional here and cannot be substituted. It is hard-wired into
/// the RFB "VNC Authentication" security type (type 2) challenge-response, which
/// is what password-protected VNC servers expect; it is *not* used to protect any
/// data in transit (the relayed session is wrapped in TLS via VeNCrypt on the
/// viewer side). Static analysers (e.g. CodeQL "weak cryptographic algorithm")
/// will flag this usage — it is a known, accepted, protocol-mandated exception.
fn vnc_auth_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (i, b) in password.bytes().take(8).enumerate() {
        key[i] = b.reverse_bits();
    }
    let cipher = Des::new(&key.into());

    let mut out = [0u8; 16];
    for chunk in 0..2 {
        let mut block_bytes = [0u8; 8];
        block_bytes.copy_from_slice(&challenge[chunk * 8..chunk * 8 + 8]);
        let mut block = block_bytes.into();
        cipher.encrypt_block(&mut block);
        out[chunk * 8..chunk * 8 + 8].copy_from_slice(&block);
    }
    out
}

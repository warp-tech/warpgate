//! Low-level RFB (VNC) and VeNCrypt handshake helpers.
//!
//! Warpgate acts as an RFB **server** towards the native viewer (offering only
//! the VeNCrypt security type with an X.509/TLS + Plain subtype, so the viewer
//! authenticates with a full-length `user:target` username and password over
//! TLS), and as an RFB **client** towards the backend target.

use anyhow::{Context, Result, bail};
use des::Des;
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";

const SECURITY_VENCRYPT: u8 = 19;
// VeNCrypt sub-type: X.509 certificate based TLS, then Plain (username/password) auth.
const VENCRYPT_SUBTYPE_X509PLAIN: u32 = 262;

const SECURITY_NONE: u8 = 1;
const SECURITY_VNC_AUTH: u8 = 2;

/// Plaintext part of the server-side VeNCrypt handshake, performed before the
/// TLS upgrade. Returns once the viewer has selected the X509Plain subtype and
/// the server has signalled it will proceed to the TLS handshake.
pub async fn server_vencrypt_pre_tls<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ProtocolVersion exchange
    stream.write_all(RFB_VERSION).await?;
    stream.flush().await?;
    let mut client_version = [0u8; 12];
    stream
        .read_exact(&mut client_version)
        .await
        .context("reading client RFB version")?;

    // Offer only VeNCrypt
    stream.write_all(&[1, SECURITY_VENCRYPT]).await?;
    stream.flush().await?;
    let selected = stream.read_u8().await.context("reading selected security")?;
    if selected != SECURITY_VENCRYPT {
        bail!("viewer did not select VeNCrypt (got {selected})");
    }

    // VeNCrypt version 0.2
    stream.write_all(&[0, 2]).await?;
    stream.flush().await?;
    let mut version = [0u8; 2];
    stream.read_exact(&mut version).await?;
    if version != [0, 2] {
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

/// Reads the VeNCrypt Plain credentials (over the established TLS channel).
pub async fn server_read_plain_credentials<S>(stream: &mut S) -> Result<(String, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let user_len = stream.read_u32().await.context("reading username length")? as usize;
    let pass_len = stream.read_u32().await.context("reading password length")? as usize;
    if user_len > 4096 || pass_len > 4096 {
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
pub async fn server_write_security_result<S>(
    stream: &mut S,
    ok: bool,
    reason: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if ok {
        stream.write_all(&0u32.to_be_bytes()).await?;
    } else {
        stream.write_all(&1u32.to_be_bytes()).await?;
        stream.write_all(&(reason.len() as u32).to_be_bytes()).await?;
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
    stream.write_all(RFB_VERSION).await?;
    stream.flush().await?;

    // Security types (RFB 3.7+)
    let count = stream.read_u8().await.context("reading target security count")?;
    if count == 0 {
        let reason_len = stream.read_u32().await? as usize;
        let mut reason = vec![0u8; reason_len.min(4096)];
        stream.read_exact(&mut reason).await.ok();
        bail!(
            "target rejected connection: {}",
            String::from_utf8_lossy(&reason)
        );
    }
    let mut types = vec![0u8; count as usize];
    stream.read_exact(&mut types).await?;

    let chosen = if types.contains(&SECURITY_NONE) {
        SECURITY_NONE
    } else if types.contains(&SECURITY_VNC_AUTH) {
        SECURITY_VNC_AUTH
    } else {
        bail!("target offers no supported security type: {types:?}");
    };
    stream.write_all(&[chosen]).await?;
    stream.flush().await?;

    if chosen == SECURITY_VNC_AUTH {
        let mut challenge = [0u8; 16];
        stream.read_exact(&mut challenge).await?;
        let response = vnc_auth_response(password, &challenge);
        stream.write_all(&response).await?;
        stream.flush().await?;
    }

    // SecurityResult (present for all types in RFB 3.8)
    let result = stream.read_u32().await.context("reading target SecurityResult")?;
    if result != 0 {
        bail!("target authentication failed");
    }

    // ClientInit (forward the viewer's shared flag)
    stream.write_all(&[shared_flag]).await?;
    stream.flush().await?;

    // ServerInit: 2 (w) + 2 (h) + 16 (pixel format) + 4 (name length) + name
    let mut head = [0u8; 20];
    stream.read_exact(&mut head).await.context("reading ServerInit head")?;
    let name_len = u32::from_be_bytes([head[16], head[17], head[18], head[19]]) as usize;
    let mut name = vec![0u8; name_len.min(4096)];
    stream.read_exact(&mut name).await?;

    let mut server_init = Vec::with_capacity(20 + name.len());
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
    let cipher = Des::new(GenericArray::from_slice(&key));

    let mut out = [0u8; 16];
    for chunk in 0..2 {
        let mut block = GenericArray::clone_from_slice(&challenge[chunk * 8..chunk * 8 + 8]);
        cipher.encrypt_block(&mut block);
        out[chunk * 8..chunk * 8 + 8].copy_from_slice(&block);
    }
    out
}

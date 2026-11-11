//! TNS packet framing over a `warpgate_tls` stream.
//!
//! Oracle TCPS is TLS from the first byte (no STARTTLS), so both legs wrap the
//! socket in [`MaybeTlsStream`] and then exchange raw TNS packets. The warpgate-oracle-tns
//! crate stays TLS-agnostic: it only ever sees the plaintext byte buffers that
//! [`read_packet`] hands it.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use warpgate_oracle_tns::packet::Header;
use warpgate_tls::{ClientTlsStream, MaybeTlsStream, ServerTlsStream};

/// The client-facing (server-leg) stream: the accepted stream `S`, upgraded to a
/// server-side TLS stream from the first byte (TCPS).
pub type ServerStream<S> = MaybeTlsStream<S, ServerTlsStream<S>>;

/// The target-facing (client-leg) stream: a TCP socket, optionally upgraded to a
/// client-side TLS stream when the target uses TCPS.
pub type TargetStream = MaybeTlsStream<TcpStream, ClientTlsStream<TcpStream>>;

/// Upper bound on one TNS packet. A packet never exceeds the negotiated SDU,
/// whose maximum is 2 MiB; the bound keeps a peer's 4-byte length field (read
/// before authentication) from making us allocate up to 4 GiB per connection.
const MAX_PACKET_LEN: usize = 4 * 1024 * 1024;

/// Read one whole TNS packet (8-byte header + body).
///
/// `large` selects the 4-byte length form used for DATA packets once the
/// handshake is complete and the negotiated version is >= 315; the
/// CONNECT/ACCEPT handshake uses the 2-byte form (`large = false`). Ported from
/// a peer's length field is bounded by [`MAX_PACKET_LEN`].
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R, large: bool) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 8];
    r.read_exact(&mut header).await?;
    let hdr = Header::parse(&header, large).map_err(io::Error::other)?;
    let total = hdr.length as usize;
    if total < 8 {
        return Err(io::Error::other("short TNS packet"));
    }
    if total > MAX_PACKET_LEN {
        return Err(io::Error::other(format!(
            "TNS packet too large ({total} bytes)"
        )));
    }
    let mut buf = vec![0u8; total];
    let (head, body) = buf.split_at_mut(header.len());
    head.copy_from_slice(&header);
    r.read_exact(body).await?;
    Ok(buf)
}

/// The TTC message-type byte of a DATA packet (payload offset 0 == packet offset
/// 10): 1 = PROTOCOL, 2 = DATATYPE, 3 = FUNCTION.
pub fn ttc_type(pkt: &[u8]) -> Option<u8> {
    pkt.get(10).copied()
}

/// The TTC function-code byte of a FUNCTION DATA packet (packet offset 11):
/// 118 = AUTH phase one, 115 = AUTH phase two.
pub fn ttc_func(pkt: &[u8]) -> Option<u8> {
    pkt.get(11).copied()
}

/// Cryptographically-random fixed-size byte array (part_a, nonces).
pub fn random_fixed<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    for x in &mut b {
        *x = rand::random();
    }
    b
}

/// Cryptographically-random byte vector of a runtime length (part_b, which must
/// match the server's session-key ciphertext length).
pub fn random_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

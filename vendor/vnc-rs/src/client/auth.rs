use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::security;
use crate::{VncError, VncVersion};

/// Warpgate fork: cap for RFB failure-reason strings. Comparable to the Warpgate VNC
/// server's `MAX_STRING_LEN`. See PATCHES.md.
const MAX_REASON_LEN: usize = 4096;

/// Warpgate fork: read a U32-length-prefixed RFB failure-reason string, rejecting an
/// over-`MAX_REASON_LEN` length before allocating. Upstream read these with
/// `read_to_string` (to EOF), letting a hostile target stream forever. See PATCHES.md.
pub(super) async fn read_reason_string<S>(reader: &mut S) -> Result<String, VncError>
where
    S: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len > MAX_REASON_LEN {
        return Err(VncError::General(format!(
            "VNC failure reason too long ({len} bytes)"
        )));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum SecurityType {
    Invalid = 0,
    None = 1,
    VncAuth = 2,
    RA2 = 5,
    RA2ne = 6,
    Tight = 16,
    Ultra = 17,
    Tls = 18,
    VeNCrypt = 19,
    GtkVncSasl = 20,
    Md5Hash = 21,
    ColinDeanXvp = 22,
}

impl TryFrom<u8> for SecurityType {
    type Error = VncError;
    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 | 1 | 2 | 5 | 6 | 16 | 17 | 18 | 19 | 20 | 21 | 22 => {
                Ok(unsafe { std::mem::transmute::<u8, SecurityType>(num) })
            }
            invalid => Err(VncError::InvalidSecurityTyep(invalid)),
        }
    }
}

impl From<SecurityType> for u8 {
    fn from(e: SecurityType) -> Self {
        e as u8
    }
}

impl SecurityType {
    pub(super) async fn read<S>(reader: &mut S, version: &VncVersion) -> Result<Vec<Self>, VncError>
    where
        S: AsyncRead + Unpin,
    {
        match version {
            VncVersion::RFB33 => {
                let security_type = reader.read_u32().await?;
                let security_type = (security_type as u8).try_into()?;
                if let SecurityType::Invalid = security_type {
                    return Err(VncError::General(read_reason_string(reader).await?));
                }
                Ok(vec![security_type])
            }
            _ => {
                // +--------------------------+-------------+--------------------------+
                // | No. of bytes             | Type        | Description              |
                // |                          | [Value]     |                          |
                // +--------------------------+-------------+--------------------------+
                // | 1                        | U8          | number-of-security-types |
                // | number-of-security-types | U8 array    | security-types           |
                // +--------------------------+-------------+--------------------------+
                let num = reader.read_u8().await?;

                if num == 0 {
                    return Err(VncError::General(read_reason_string(reader).await?));
                }
                let mut sec_types = vec![];
                for _ in 0..num {
                    sec_types.push(reader.read_u8().await?.try_into()?);
                }
                tracing::trace!("Server supported security type: {:?}", sec_types);
                Ok(sec_types)
            }
        }
    }

    pub(super) async fn write<S>(&self, writer: &mut S) -> Result<(), VncError>
    where
        S: AsyncWrite + Unpin,
    {
        writer.write_all(&[(*self).into()]).await?;
        Ok(())
    }
}

#[allow(dead_code)]
#[repr(u32)]
pub(super) enum AuthResult {
    Ok = 0,
    Failed = 1,
}

// Warpgate fork: the SecurityResult word comes straight off an untrusted target socket.
// Upstream `transmute`d any u32 into this 2-variant enum — instant UB for values != 0/1.
// Validate with a plain match instead. See PATCHES.md.
impl TryFrom<u32> for AuthResult {
    type Error = VncError;
    fn try_from(num: u32) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(AuthResult::Ok),
            1 => Ok(AuthResult::Failed),
            other => Err(VncError::General(format!(
                "Unknown VNC SecurityResult value: {other}"
            ))),
        }
    }
}

impl From<AuthResult> for u32 {
    fn from(e: AuthResult) -> Self {
        e as u32
    }
}

pub(super) struct AuthHelper {
    challenge: [u8; 16],
    key: [u8; 8],
}

impl AuthHelper {
    pub(super) async fn read<S>(reader: &mut S, credential: &str) -> Result<Self, VncError>
    where
        S: AsyncRead + Unpin,
    {
        let mut challenge = [0; 16];
        reader.read_exact(&mut challenge).await?;

        let credential_len = credential.len();
        let mut key = [0u8; 8];
        for (i, key_i) in key.iter_mut().enumerate() {
            let c = if i < credential_len {
                credential.as_bytes()[i]
            } else {
                0
            };
            let mut cs = 0u8;
            for j in 0..8 {
                cs |= ((c >> j) & 1) << (7 - j)
            }
            *key_i = cs;
        }

        Ok(Self { challenge, key })
    }

    pub(super) async fn write<S>(&self, writer: &mut S) -> Result<(), VncError>
    where
        S: AsyncWrite + Unpin,
    {
        let encrypted = security::des::encrypt(&self.challenge, &self.key);
        writer.write_all(&encrypted).await?;
        Ok(())
    }

    pub(super) async fn finish<S>(self, reader: &mut S) -> Result<AuthResult, VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = reader.read_u32().await?;
        result.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_result_try_from_validates() {
        assert!(matches!(AuthResult::try_from(0), Ok(AuthResult::Ok)));
        assert!(matches!(AuthResult::try_from(1), Ok(AuthResult::Failed)));
        assert!(AuthResult::try_from(2).is_err());
        assert!(AuthResult::try_from(u32::MAX).is_err());
    }

    #[tokio::test]
    async fn read_reason_string_rejects_over_cap() {
        let buf = u32::MAX.to_be_bytes();
        let mut reader: &[u8] = &buf;
        assert!(read_reason_string(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn read_reason_string_reads_in_cap() {
        let mut data = Vec::new();
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(b"hello");
        let mut reader: &[u8] = &data;
        let s = read_reason_string(&mut reader).await.unwrap();
        assert_eq!(s, "hello");
    }
}

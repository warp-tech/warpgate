use super::security;
use crate::{VncError, VncVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    AppleArd = 30,
}

impl TryFrom<u8> for SecurityType {
    type Error = VncError;
    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(Self::Invalid),
            1 => Ok(Self::None),
            2 => Ok(Self::VncAuth),
            5 => Ok(Self::RA2),
            6 => Ok(Self::RA2ne),
            16 => Ok(Self::Tight),
            17 => Ok(Self::Ultra),
            18 => Ok(Self::Tls),
            19 => Ok(Self::VeNCrypt),
            20 => Ok(Self::GtkVncSasl),
            21 => Ok(Self::Md5Hash),
            22 => Ok(Self::ColinDeanXvp),
            30 => Ok(Self::AppleArd),
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
                if security_type > 2 {
                    return Err(VncError::ConnectError);
                }
                let security_type = (security_type as u8).try_into()?;
                if let SecurityType::Invalid = security_type {
                    let err_msg = crate::limits::string(reader, crate::limits::MAX_NAME).await?;
                    return Err(VncError::General(err_msg));
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
                    let err_msg = crate::limits::string(reader, crate::limits::MAX_NAME).await?;
                    return Err(VncError::General(err_msg));
                }
                let mut sec_types = vec![];
                for _ in 0..num {
                    // Ignore unfamiliar advertised mechanisms; only choose a known one.
                    if let Ok(kind) = reader.read_u8().await?.try_into() {
                        sec_types.push(kind);
                    }
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

impl TryFrom<u32> for AuthResult {
    type Error = VncError;

    fn try_from(num: u32) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Failed),
            _ => Err(VncError::General(format!(
                "Unknown authentication result: {num}"
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

    #[tokio::test]
    async fn authentication_result_is_checked() {
        for status in [0_u32, 1, 2, 256, u32::MAX] {
            let (mut server, mut client) = tokio::io::duplex(4);
            server.write_all(&status.to_be_bytes()).await.unwrap();
            let auth = AuthHelper {
                challenge: [0; 16],
                key: [0; 8],
            };

            let result = auth.finish(&mut client).await;
            match status {
                0 => assert!(matches!(result, Ok(AuthResult::Ok))),
                1 => assert!(matches!(result, Ok(AuthResult::Failed))),
                _ => assert!(matches!(result, Err(VncError::General(_)))),
            }
        }
    }
}

#[cfg(test)]
mod negotiation_tests {
    use super::*;

    #[tokio::test]
    async fn security_values_are_not_narrowed_and_unknown_offers_are_skipped() {
        for value in [3_u32, 257, 258, u32::MAX] {
            assert!(
                SecurityType::read(&mut value.to_be_bytes().as_slice(), &VncVersion::RFB33)
                    .await
                    .is_err()
            );
        }
        let mut offers = &[3, 250, 2, 1][..];
        assert_eq!(
            SecurityType::read(&mut offers, &VncVersion::RFB38)
                .await
                .unwrap(),
            vec![SecurityType::VncAuth, SecurityType::None]
        );
        assert!(offers.is_empty());
        let mut unknown = &[1, 250][..];
        assert!(SecurityType::read(&mut unknown, &VncVersion::RFB38)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn failure_reason_uses_its_length_and_rejects_oversized_payloads() {
        for version in [VncVersion::RFB33, VncVersion::RFB37, VncVersion::RFB38] {
            let mut bytes = if version == VncVersion::RFB33 {
                vec![0; 4]
            } else {
                vec![0]
            };
            bytes.extend(2_u32.to_be_bytes());
            bytes.extend(b"noNEXT");
            let mut input = bytes.as_slice();
            assert!(matches!(SecurityType::read(&mut input, &version).await,
                Err(VncError::General(reason)) if reason == "no"));
            assert_eq!(input, b"NEXT");
            let mut bytes = if version == VncVersion::RFB33 {
                vec![0; 4]
            } else {
                vec![0]
            };
            bytes.extend(u32::MAX.to_be_bytes());
            assert!(matches!(
                SecurityType::read(&mut bytes.as_slice(), &version).await,
                Err(VncError::General(_))
            ));
        }
    }
}

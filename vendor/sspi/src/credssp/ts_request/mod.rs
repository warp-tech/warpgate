#[cfg(test)]
mod test;

use core::fmt;
use std::io::{self, Read};

use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1, OctetStringAsn1};
use picky_krb::constants::cred_ssp::TS_PASSWORD_CREDS;
use picky_krb::credssp::{TsCredentials, TsPasswordCreds};
use widestring::Utf16String;

use super::CredSspMode;
use crate::utf16string::ZeroizedUtf16String;
use crate::{AuthIdentityBuffers, CredentialsBuffers, Error, ErrorKind, Utf16StringExt, ber};

pub(super) const TS_REQUEST_VERSION: u32 = 6;

pub(super) const NONCE_SIZE: usize = 32;
const NONCE_FIELD_LEN: u16 = 36;

/// Used for communication in the CredSSP [client](struct.CredSspServer.html)
/// and [server](struct.CredSspServer.html). It's a top-most structure that
/// they use.
///
/// # MSDN
///
/// * [TSRequest](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
#[derive(Debug, Clone)]
pub struct TsRequest {
    /// Specifies the supported version of the CredSSP protocol.
    pub version: u32,
    /// Contains the SPNEGO tokens or NTLM messages that are passed between the client
    /// and server.
    pub nego_tokens: Option<Vec<u8>>,
    /// Contains the user's credentials that are delegated to the server.
    pub auth_info: Option<Vec<u8>>,
    /// Used to assure that the public key that is used by the server during
    /// the TLS handshake belongs to the target server and not to a man-in-the-middle.
    pub pub_key_auth: Option<Vec<u8>>,
    /// If the SPNEGO exchange fails on the server, this field is used to send
    /// the failure code to the client.
    pub error_code: Option<NStatusCode>,
    /// An array of cryptographically random bytes used to provide sufficient
    /// entropy during hash computation.
    pub client_nonce: Option<[u8; NONCE_SIZE]>,
}

impl Default for TsRequest {
    fn default() -> Self {
        Self {
            version: TS_REQUEST_VERSION,
            nego_tokens: None,
            auth_info: None,
            pub_key_auth: None,
            error_code: None,
            client_nonce: None,
        }
    }
}

impl TsRequest {
    /// Returns a length of the 'TsRequest' buffer length
    ///
    /// # Arguments
    ///
    /// * `stream` - an input stream
    pub fn read_length(mut stream: impl Read) -> io::Result<usize> {
        let ts_request_len =
            ber::read_sequence_tag(&mut stream).map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;

        Ok(usize::from(ber::sizeof_sequence(ts_request_len)))
    }

    /// Creates a `TsRequest` structure from a raw array.
    ///
    /// # Arguments
    ///
    /// * `buffer` - the array of bytes
    pub fn from_buffer(buffer: &[u8]) -> io::Result<TsRequest> {
        let mut stream = io::Cursor::new(buffer);

        if buffer.len() < TsRequest::read_length(&mut stream)? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Incomplete buffer"));
        }

        ber::read_contextual_tag(&mut stream, 0, ber::Pc::Construct)?;

        let version = ber::read_integer(&mut stream)? as u32;

        let nego_tokens = if ber::read_contextual_tag_or_unwind(&mut stream, 1, ber::Pc::Construct)?.is_some() {
            ber::read_sequence_tag(&mut stream)?;
            ber::read_sequence_tag(&mut stream)?;
            ber::read_contextual_tag(&mut stream, 0, ber::Pc::Construct)?;
            let length = ber::read_octet_string_tag(&mut stream)?;
            let mut nego_tokens = vec![0x00; length as usize];
            stream.read_exact(&mut nego_tokens)?;

            Some(nego_tokens)
        } else {
            None
        };

        let auth_info = if ber::read_contextual_tag_or_unwind(&mut stream, 2, ber::Pc::Construct)?.is_some() {
            let length = ber::read_octet_string_tag(&mut stream)?;
            let mut auth_info = vec![0x00; length as usize];
            stream.read_exact(&mut auth_info)?;

            Some(auth_info)
        } else {
            None
        };

        let pub_key_auth = if ber::read_contextual_tag_or_unwind(&mut stream, 3, ber::Pc::Construct)?.is_some() {
            let length = ber::read_octet_string_tag(&mut stream)?;
            let mut pub_key_auth = vec![0x00; length as usize];
            stream.read_exact(&mut pub_key_auth)?;

            Some(pub_key_auth)
        } else {
            None
        };

        let error_code =
            if version >= 3 && ber::read_contextual_tag_or_unwind(&mut stream, 4, ber::Pc::Construct)?.is_some() {
                let read_error_code = ber::read_integer(&mut stream)?;
                let error_code = read_error_code as u32;

                Some(NStatusCode(error_code))
            } else {
                None
            };

        let client_nonce =
            if version >= 5 && ber::read_contextual_tag_or_unwind(&mut stream, 5, ber::Pc::Construct)?.is_some() {
                let length = ber::read_octet_string_tag(&mut stream)?;
                if length != NONCE_SIZE as u16 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Got ClientNonce with invalid length: {length}"),
                    ));
                }

                let mut client_nonce = [0x00; NONCE_SIZE];
                stream.read_exact(&mut client_nonce)?;

                Some(client_nonce)
            } else {
                None
            };

        Ok(TsRequest {
            version,
            nego_tokens,
            auth_info,
            pub_key_auth,
            error_code,
            client_nonce,
        })
    }

    /// Encodes the `TsRequest` to be ready to be sent to the TLS stream.
    ///
    /// # Arguments
    ///
    /// * `buffer` - an output buffer
    pub fn encode_ts_request(&self, mut buffer: impl io::Write) -> io::Result<()> {
        let len = self.ts_request_len();

        ber::write_sequence_tag(&mut buffer, len)?;
        /* [0] version */
        ber::write_contextual_tag(&mut buffer, 0, 3, ber::Pc::Construct)?;
        ber::write_integer(&mut buffer, self.version)?;

        /* [1] negoTokens (NegoData) */
        if let Some(ref nego_tokens) = self.nego_tokens {
            ber::write_contextual_tag(
                &mut buffer,
                1,
                ber::sizeof_sequence(ber::sizeof_sequence(ber::sizeof_sequence_octet_string(
                    nego_tokens.len() as u16,
                ))),
                ber::Pc::Construct,
            )?;
            ber::write_sequence_tag(
                &mut buffer,
                ber::sizeof_sequence(ber::sizeof_sequence_octet_string(nego_tokens.len() as u16)),
            )?; /* SEQUENCE OF NegoDataItem */
            ber::write_sequence_tag(&mut buffer, ber::sizeof_sequence_octet_string(nego_tokens.len() as u16))?; /* NegoDataItem */
            ber::write_sequence_octet_string(&mut buffer, 0, nego_tokens)?; /* OCTET STRING */
        }

        /* [2] authInfo (OCTET STRING) */
        if let Some(ref auth_info) = self.auth_info {
            ber::write_sequence_octet_string(&mut buffer, 2, auth_info)?;
        }

        /* [3] pubKeyAuth (OCTET STRING) */
        if let Some(ref pub_key_auth) = self.pub_key_auth {
            ber::write_sequence_octet_string(&mut buffer, 3, pub_key_auth)?;
        }

        /* [4] errorCode (INTEGER) */
        match self.error_code {
            Some(error_code) if self.version >= 3 => {
                let (error_code_len, _) = get_error_code_len(self.version, self.error_code);
                ber::write_contextual_tag(&mut buffer, 4, error_code_len, ber::Pc::Construct)?;
                ber::write_integer(&mut buffer, error_code.0)?;
            }
            _ => {}
        }

        /* [5] clientNonce (OCTET STRING) */
        if self.version >= 5
            && let Some(client_nonce) = self.client_nonce.as_ref()
        {
            ber::write_sequence_octet_string(&mut buffer, 5, client_nonce)?;
        }

        Ok(())
    }

    pub fn buffer_len(&self) -> u16 {
        ber::sizeof_sequence(self.ts_request_len())
    }

    pub fn check_error(&self) -> crate::Result<()> {
        match self.error_code {
            Some(error_code) if error_code != NStatusCode::SUCCESS => Err(Error::new_with_nstatus(
                ErrorKind::InvalidToken,
                "CredSSP server returned an error status",
                error_code,
            )),
            _ => Ok(()),
        }
    }

    fn ts_request_len(&self) -> u16 {
        let (error_code_len, error_code_context_len) = get_error_code_len(self.version, self.error_code);
        let client_nonce_len = if self.client_nonce.is_some() && self.version >= 5 {
            NONCE_FIELD_LEN
        } else {
            0
        };
        let fields_len = get_nego_tokens_len(&self.nego_tokens)
            + get_field_len(&self.pub_key_auth)
            + get_field_len(&self.auth_info)
            + client_nonce_len
            + error_code_context_len
            + error_code_len;

        fields_len + ber::sizeof_integer(2) + ber::sizeof_contextual_tag(3)
    }
}

#[instrument(ret, level = "debug")]
#[cfg(feature = "scard")]
fn write_smart_card_credentials(credentials: &crate::SmartCardIdentityBuffers) -> crate::Result<Vec<u8>> {
    use picky_asn1::wrapper::{ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, Optional};
    use picky_krb::constants::cred_ssp::AT_KEYEXCHANGE;
    use picky_krb::credssp::{TsCspDataDetail, TsSmartCardCreds};

    let smart_card_creds = TsSmartCardCreds {
        pin: ExplicitContextTag0::from(OctetStringAsn1::from(credentials.pin.as_ref().0.to_bytes_le())),
        csp_data: ExplicitContextTag1::from(TsCspDataDetail {
            key_spec: ExplicitContextTag0::from(IntegerAsn1::from(vec![AT_KEYEXCHANGE])),
            card_name: Optional::from(
                credentials
                    .card_name
                    .as_ref()
                    .map(|name| ExplicitContextTag1::from(OctetStringAsn1::from(name.as_ref().to_bytes_le()))),
            ),
            reader_name: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(
                credentials.reader_name.to_bytes_le(),
            )))),
            container_name: Optional::from(
                credentials
                    .container_name
                    .as_ref()
                    .map(|name| ExplicitContextTag3::from(OctetStringAsn1::from(name.as_ref().to_bytes_le()))),
            ),
            csp_name: Optional::from(Some(ExplicitContextTag4::from(OctetStringAsn1::from(
                credentials.csp_name.to_bytes_le(),
            )))),
        }),
        user_hint: Optional::from(None),
        domain_hint: Optional::from(None),
    };

    Ok(picky_asn1_der::to_vec(&smart_card_creds)?)
}

#[instrument(level = "trace", ret)]
pub fn write_ts_credentials(credentials: &CredentialsBuffers, cred_ssp_mode: CredSspMode) -> crate::Result<Vec<u8>> {
    let (creds_type, encoded_credentials) = match credentials {
        CredentialsBuffers::AuthIdentity(creds) => {
            (TS_PASSWORD_CREDS, write_password_credentials(creds, cred_ssp_mode)?)
        }
        #[cfg(feature = "scard")]
        CredentialsBuffers::SmartCard(creds) => (
            picky_krb::constants::cred_ssp::TS_SMART_CARD_CREDS,
            write_smart_card_credentials(creds)?,
        ),
        CredentialsBuffers::Keytab(_) => {
            return Err(Error::new(
                ErrorKind::UnsupportedPreAuth,
                "keytab credentials are not supported in CredSSP",
            ));
        }
    };

    let ts_creds = TsCredentials {
        cred_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![creds_type])),
        credentials: ExplicitContextTag1::from(OctetStringAsn1::from(encoded_credentials)),
    };

    Ok(picky_asn1_der::to_vec(&ts_creds)?)
}

#[instrument(ret, level = "debug")]
fn write_password_credentials(credentials: &AuthIdentityBuffers, cred_ssp_mode: CredSspMode) -> io::Result<Vec<u8>> {
    let empty_identity = AuthIdentityBuffers::default();
    let identity = match cred_ssp_mode {
        CredSspMode::WithCredentials => credentials,
        CredSspMode::CredentialLess => &empty_identity,
    };

    let ts_credentials_len = sizeof_ts_credentials(identity);
    let ts_credentials_sequence_len = ber::sizeof_sequence(ts_credentials_len);
    let password_credentials_len = sizeof_ts_password_creds(identity);

    let mut buffer = Vec::with_capacity(ts_credentials_sequence_len as usize);

    /* TSPasswordCreds (SEQUENCE) */
    ber::write_sequence_tag(&mut buffer, password_credentials_len)?;
    /* [0] domainName (OCTET STRING) */
    ber::write_sequence_octet_string(&mut buffer, 0, identity.domain.as_bytes_le())?;
    /* [1] userName (OCTET STRING) */
    ber::write_sequence_octet_string(&mut buffer, 1, identity.user.as_bytes_le())?;
    /* [2] password (OCTET STRING) */
    ber::write_sequence_octet_string(&mut buffer, 2, identity.password.as_ref().0.as_bytes_le())?;

    Ok(buffer)
}

fn read_password_credentials(data: impl AsRef<[u8]>) -> crate::Result<AuthIdentityBuffers> {
    let password_creds: TsPasswordCreds = picky_asn1_der::from_bytes(data.as_ref())?;

    let TsPasswordCreds {
        domain_name,
        user_name,
        password,
    } = password_creds;

    Ok(AuthIdentityBuffers {
        user: Utf16String::from_bytes_le(user_name.0.0)?,
        domain: Utf16String::from_bytes_le(domain_name.0.0)?,
        password: ZeroizedUtf16String::from_bytes_le(password.0.0)?.into(),
    })
}

pub fn read_ts_credentials(mut buffer: impl Read) -> crate::Result<CredentialsBuffers> {
    let ts_credentials: TsCredentials = picky_asn1_der::from_reader(&mut buffer)?;

    match ts_credentials.cred_type.0.0.first() {
        Some(&TS_PASSWORD_CREDS) => Ok(CredentialsBuffers::AuthIdentity(read_password_credentials(
            &ts_credentials.credentials.0.0,
        )?)),
        Some(&picky_krb::constants::cred_ssp::TS_SMART_CARD_CREDS) => Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "Reading of the TsSmartCard credentials is not supported yet",
        )),
        Some(cred_type) => Err(Error::new(
            ErrorKind::InvalidToken,
            format!("Invalid or unsupported TsCredentials::cred_type value: {cred_type}"),
        )),
        None => Err(Error::new(
            ErrorKind::InvalidToken,
            "TsCredentials::cred_type field is empty",
        )),
    }
}

fn sizeof_ts_credentials(identity: &AuthIdentityBuffers) -> u16 {
    ber::sizeof_integer(1)
        + ber::sizeof_contextual_tag(ber::sizeof_integer(1))
        + ber::sizeof_sequence_octet_string(ber::sizeof_sequence(sizeof_ts_password_creds(identity)))
}

fn sizeof_ts_password_creds(identity: &AuthIdentityBuffers) -> u16 {
    ber::sizeof_sequence_octet_string(identity.domain.as_bytes_le().len() as u16)
        + ber::sizeof_sequence_octet_string(identity.user.as_bytes_le().len() as u16)
        + ber::sizeof_sequence_octet_string(identity.password.as_ref().0.as_bytes_le().len() as u16)
}

fn get_nego_tokens_len(nego_tokens: &Option<Vec<u8>>) -> u16 {
    match nego_tokens {
        Some(nego_tokens) => {
            let nego_len = nego_tokens.len() as u16;
            let mut len = ber::sizeof_octet_string(nego_len);
            len += ber::sizeof_contextual_tag(len);
            len += ber::sizeof_sequence_tag(len);
            len += ber::sizeof_sequence_tag(len);
            len += ber::sizeof_contextual_tag(len);

            len
        }
        None => 0,
    }
}

fn get_error_code_len(version: u32, error_code: impl Into<Option<NStatusCode>>) -> (u16, u16) {
    match error_code.into() {
        Some(error_code) if version >= 3 && version != 5 => {
            let len = ber::sizeof_integer(error_code.0);
            let context_len = ber::sizeof_contextual_tag(len);

            (len, context_len)
        }
        _ => (0, 0),
    }
}

fn get_field_len(field: &Option<Vec<u8>>) -> u16 {
    match field {
        Some(field) => {
            let field_len = field.len() as u16;
            let mut len = ber::sizeof_octet_string(field_len);
            len += ber::sizeof_contextual_tag(len);

            len
        }
        None => 0,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NStatusCode(pub u32);

impl NStatusCode {
    pub const SUCCESS: Self = Self(0x0000_0000);
    pub const NO_QUOTAS_FOR_ACCOUNT: Self = Self(0x0000_010d);
    pub const NO_LOGON_SERVERS: Self = Self(0xc000_005e);
    pub const NO_SUCH_LOGON_SESSION: Self = Self(0xc000_005f);
    pub const NO_SUCH_PRIVILEGE: Self = Self(0xc000_0060);
    pub const PRIVILEGE_NOT_HELD: Self = Self(0xc000_0061);
    pub const INVALID_ACCOUNT_NAME: Self = Self(0xc000_0062);
    pub const USER_EXISTS: Self = Self(0xc000_0063);
    pub const NO_SUCH_USER: Self = Self(0xc000_0064);
    pub const GROUP_EXISTS: Self = Self(0xc000_0065);
    pub const NO_SUCH_GROUP: Self = Self(0xc000_0066);
    pub const MEMBER_IN_GROUP: Self = Self(0xc000_0067);
    pub const MEMBER_NOT_IN_GROUP: Self = Self(0xc000_0068);
    pub const LAST_ADMIN: Self = Self(0xc000_0069);
    pub const WRONG_PASSWORD: Self = Self(0xc000_006a);
    pub const ILL_FORMED_PASSWORD: Self = Self(0xc000_006b);
    pub const PASSWORD_RESTRICTION: Self = Self(0xc000_006c);
    pub const LOGON_FAILURE: Self = Self(0xc000_006d);
    pub const ACCOUNT_RESTRICTION: Self = Self(0xc000_006e);
    pub const INVALID_LOGON_HOURS: Self = Self(0xc000_006f);
    pub const INVALID_WORKSTATION: Self = Self(0xc000_0070);
    pub const PASSWORD_EXPIRED: Self = Self(0xc000_0071);
    pub const ACCOUNT_DISABLED: Self = Self(0xc000_0072);
    pub const IO_TIMEOUT: Self = Self(0xc000_00b5);
    pub const NOT_LOGON_PROCESS: Self = Self(0xc000_00ed);
    pub const LOGON_SESSION_EXISTS: Self = Self(0xc000_00ee);
    pub const BAD_LOGON_SESSION_STATE: Self = Self(0xc000_0104);
    pub const LOGON_SESSION_COLLISION: Self = Self(0xc000_0105);
    pub const INVALID_LOGON_TYPE: Self = Self(0xc000_010b);
    pub const SPECIAL_ACCOUNT: Self = Self(0xc000_0124);
    pub const TOKEN_ALREADY_IN_USE: Self = Self(0xc000_012b);
    pub const LOGON_SERVER_CONFLICT: Self = Self(0xc000_0132);
    pub const TIME_DIFFERENCE_AT_DC: Self = Self(0xc000_0133);
    pub const MEMBER_NOT_IN_ALIAS: Self = Self(0xc000_0152);
    pub const MEMBER_IN_ALIAS: Self = Self(0xc000_0153);
    pub const LOGON_NOT_GRANTED: Self = Self(0xc000_0155);
    pub const LOGON_TYPE_NOT_GRANTED: Self = Self(0xc000_015b);
    pub const TRANSACTION_TIMED_OUT: Self = Self(0xc000_0210);
    pub const PASSWORD_MUST_CHANGE: Self = Self(0xc000_0224);
    pub const ACCOUNT_LOCKED_OUT: Self = Self(0xc000_0234);
    pub const INSUFFICIENT_LOGON_INFO: Self = Self(0xc000_0250);
    pub const SMARTCARD_LOGON_REQUIRED: Self = Self(0xc000_02fa);
    pub const CTX_LOGON_DISABLED: Self = Self(0xc00a_0037);

    pub fn name(self) -> Option<&'static str> {
        let name = match self {
            Self::SUCCESS => "STATUS_SUCCESS",
            Self::NO_QUOTAS_FOR_ACCOUNT => "STATUS_NO_QUOTAS_FOR_ACCOUNT",
            Self::NO_LOGON_SERVERS => "STATUS_NO_LOGON_SERVERS",
            Self::NO_SUCH_LOGON_SESSION => "STATUS_NO_SUCH_LOGON_SESSION",
            Self::NO_SUCH_PRIVILEGE => "STATUS_NO_SUCH_PRIVILEGE",
            Self::PRIVILEGE_NOT_HELD => "STATUS_PRIVILEGE_NOT_HELD",
            Self::INVALID_ACCOUNT_NAME => "STATUS_INVALID_ACCOUNT_NAME",
            Self::USER_EXISTS => "STATUS_USER_EXISTS",
            Self::NO_SUCH_USER => "STATUS_NO_SUCH_USER",
            Self::GROUP_EXISTS => "STATUS_GROUP_EXISTS",
            Self::NO_SUCH_GROUP => "STATUS_NO_SUCH_GROUP",
            Self::MEMBER_IN_GROUP => "STATUS_MEMBER_IN_GROUP",
            Self::MEMBER_NOT_IN_GROUP => "STATUS_MEMBER_NOT_IN_GROUP",
            Self::LAST_ADMIN => "STATUS_LAST_ADMIN",
            Self::WRONG_PASSWORD => "STATUS_WRONG_PASSWORD",
            Self::ILL_FORMED_PASSWORD => "STATUS_ILL_FORMED_PASSWORD",
            Self::PASSWORD_RESTRICTION => "STATUS_PASSWORD_RESTRICTION",
            Self::LOGON_FAILURE => "STATUS_LOGON_FAILURE",
            Self::ACCOUNT_RESTRICTION => "STATUS_ACCOUNT_RESTRICTION",
            Self::INVALID_LOGON_HOURS => "STATUS_INVALID_LOGON_HOURS",
            Self::INVALID_WORKSTATION => "STATUS_INVALID_WORKSTATION",
            Self::PASSWORD_EXPIRED => "STATUS_PASSWORD_EXPIRED",
            Self::ACCOUNT_DISABLED => "STATUS_ACCOUNT_DISABLED",
            Self::IO_TIMEOUT => "STATUS_IO_TIMEOUT",
            Self::NOT_LOGON_PROCESS => "STATUS_NOT_LOGON_PROCESS",
            Self::LOGON_SESSION_EXISTS => "STATUS_LOGON_SESSION_EXISTS",
            Self::BAD_LOGON_SESSION_STATE => "STATUS_BAD_LOGON_SESSION_STATE",
            Self::LOGON_SESSION_COLLISION => "STATUS_LOGON_SESSION_COLLISION",
            Self::INVALID_LOGON_TYPE => "STATUS_INVALID_LOGON_TYPE",
            Self::SPECIAL_ACCOUNT => "STATUS_SPECIAL_ACCOUNT",
            Self::TOKEN_ALREADY_IN_USE => "STATUS_TOKEN_ALREADY_IN_USE",
            Self::LOGON_SERVER_CONFLICT => "STATUS_LOGON_SERVER_CONFLICT",
            Self::TIME_DIFFERENCE_AT_DC => "STATUS_TIME_DIFFERENCE_AT_DC",
            Self::MEMBER_NOT_IN_ALIAS => "STATUS_MEMBER_NOT_IN_ALIAS",
            Self::MEMBER_IN_ALIAS => "STATUS_MEMBER_IN_ALIAS",
            Self::LOGON_NOT_GRANTED => "STATUS_LOGON_NOT_GRANTED",
            Self::LOGON_TYPE_NOT_GRANTED => "STATUS_LOGON_TYPE_NOT_GRANTED",
            Self::TRANSACTION_TIMED_OUT => "STATUS_TRANSACTION_TIMED_OUT",
            Self::PASSWORD_MUST_CHANGE => "STATUS_PASSWORD_MUST_CHANGE",
            Self::ACCOUNT_LOCKED_OUT => "STATUS_ACCOUNT_LOCKED_OUT",
            Self::INSUFFICIENT_LOGON_INFO => "STATUS_INSUFFICIENT_LOGON_INFO",
            Self::SMARTCARD_LOGON_REQUIRED => "STATUS_SMARTCARD_LOGON_REQUIRED",
            Self::CTX_LOGON_DISABLED => "STATUS_CTX_LOGON_DISABLED",
            _ => return None,
        };

        Some(name)
    }
}

impl fmt::Debug for NStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NStatusCode({:#x})", self.0)
    }
}

impl fmt::Display for NStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
            write!(f, "{name} [{:#x}]", self.0)
        } else {
            write!(f, "NSTATUS code {:#x}", self.0)
        }
    }
}

#[cfg(target_os = "windows")]
impl TryFrom<windows::core::HRESULT> for NStatusCode {
    type Error = &'static str;

    fn try_from(hresult: windows::core::HRESULT) -> Result<Self, Self::Error> {
        // More info: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/0642cb2f-2075-4469-918c-4441e69c548a
        const NSTATUS_BIT: i32 = 0x1000_0000;

        if hresult.0 & NSTATUS_BIT != 0 {
            #[expect(
                clippy::as_conversions,
                reason = "casting via `as` is correct here (all we care about is bit pattern of nstatus"
            )]
            Ok(NStatusCode((hresult.0 & !NSTATUS_BIT) as u32))
        } else {
            Err("HRESULT does not represent NStatusCode")
        }
    }
}

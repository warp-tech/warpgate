use std::fmt;
use std::ops::Not;

use picky_krb::crypto::CipherSuite;

use crate::utf16string::ZeroizedUtf16String;
use crate::{Error, Secret, Utf16String, Utf16StringExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsernameError {
    MixedFormat,
}

impl std::error::Error for UsernameError {}

impl fmt::Display for UsernameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsernameError::MixedFormat => write!(f, "mixed username format"),
        }
    }
}

/// Enumeration of the supported [User Name Formats].
///
/// [User Name Formats]: https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UserNameFormat {
    /// [User principal name] (UPN) format is used to specify an Internet-style name, such as UserName@Example.Microsoft.com.
    ///
    /// [User principal name]: https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats#user-principal-name
    UserPrincipalName,
    /// The [down-level logon name] format is used to specify a domain and a user account in that domain, for example, DOMAIN\UserName.
    ///
    /// [down-level logon name]: https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats#down-level-logon-name
    DownLevelLogonName,
}

/// A username formatted as either UPN or Down-Level Logon Name
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Username {
    value: String,
    format: UserNameFormat,
    sep_idx: Option<usize>,
}

/// A format-tagged, borrowed view into the components of a [`Username`].
///
/// Unlike the (deprecated) [`Username::domain_name`] accessor, each variant only exposes the
/// components that are actually meaningful for its [`UserNameFormat`]. This makes it impossible to
/// mistake a UPN suffix for a NetBIOS domain name (or vice versa): the [`UserPrincipalNameParts`]
/// arm has no "domain" component at all, only a suffix.
///
/// Matching is exhaustive over the two [User Name Formats], so callers are forced to handle both.
///
/// A `UsernameParts` can only be obtained from [`Username::parts`]; the variant payloads are opaque
/// (accessor-only, not constructible outside this crate), so a view can never be forged into an
/// inconsistent state.
///
/// [User Name Formats]: https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UsernameParts<'a> {
    /// [User principal name] components, e.g. `account_name@suffix`.
    ///
    /// [User principal name]: https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats#user-principal-name
    UserPrincipalName(UserPrincipalNameParts<'a>),
    /// [Down-level logon name] components, e.g. `netbios_domain\account_name`.
    ///
    /// [Down-level logon name]: https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats#down-level-logon-name
    DownLevelLogonName(DownLevelLogonNameParts<'a>),
}

/// The components of a [user principal name](UsernameParts::UserPrincipalName).
///
/// Obtained via [`Username::parts`]; the components are opaque and exposed through accessors only,
/// so this type can never be constructed with inconsistent fields.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UserPrincipalNameParts<'a> {
    account_name: &'a str,
    suffix: &'a str,
    upn: &'a str,
}

impl<'a> UserPrincipalNameParts<'a> {
    /// The account name, i.e. the part before the `@`.
    pub fn account_name(&self) -> &'a str {
        self.account_name
    }

    /// The UPN suffix, i.e. the part after the `@`. This is *not* a NetBIOS domain name.
    pub fn suffix(&self) -> &'a str {
        self.suffix
    }

    /// The complete user principal name (`account_name@suffix`), borrowed as-is.
    ///
    /// For a UPN, this whole string is what identifies the user (e.g. it is used verbatim as the
    /// NT-ENTERPRISE client name in Kerberos), unlike a down-level logon name where only
    /// `account_name` does. Prefer this over reconstructing the string from `account_name`/`suffix`
    /// or reaching for [`Username::inner`].
    pub fn upn(&self) -> &'a str {
        self.upn
    }
}

/// The components of a [down-level logon name](UsernameParts::DownLevelLogonName).
///
/// Obtained via [`Username::parts`]; the components are opaque and exposed through accessors only,
/// so this type can never be constructed with inconsistent fields.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DownLevelLogonNameParts<'a> {
    account_name: &'a str,
    netbios_domain: Option<&'a str>,
}

impl<'a> DownLevelLogonNameParts<'a> {
    /// The account name, i.e. the part after the `\` (or the whole value when there is no separator).
    pub fn account_name(&self) -> &'a str {
        self.account_name
    }

    /// The NetBIOS domain name, i.e. the part before the `\`, or `None` when the value has no separator.
    pub fn netbios_domain(&self) -> Option<&'a str> {
        self.netbios_domain
    }
}

impl UsernameParts<'_> {
    /// Compares two username views for equality, ignoring ASCII case.
    ///
    /// Equality is *format-aware*: a [`UsernameParts::UserPrincipalName`] and a
    /// [`UsernameParts::DownLevelLogonName`] are never equal, even if their account names and their
    /// UPN suffix / NetBIOS domain happen to match case-insensitively. Because the format is part of
    /// the comparison, a UPN suffix is only ever compared against another UPN suffix, and a NetBIOS
    /// domain only ever against another NetBIOS domain: the two can never be conflated.
    pub fn eq_ignore_ascii_case(&self, other: &UsernameParts<'_>) -> bool {
        match (self, other) {
            (UsernameParts::UserPrincipalName(lhs), UsernameParts::UserPrincipalName(rhs)) => {
                // `upn` is fully determined by `account_name` and `suffix`, so it needs no comparison.
                lhs.account_name.eq_ignore_ascii_case(rhs.account_name) && lhs.suffix.eq_ignore_ascii_case(rhs.suffix)
            }
            (UsernameParts::DownLevelLogonName(lhs), UsernameParts::DownLevelLogonName(rhs)) => {
                let domains_equal = match (lhs.netbios_domain, rhs.netbios_domain) {
                    (Some(lhs_domain), Some(rhs_domain)) => lhs_domain.eq_ignore_ascii_case(rhs_domain),
                    (None, None) => true,
                    _ => false,
                };

                lhs.account_name.eq_ignore_ascii_case(rhs.account_name) && domains_equal
            }
            // Different formats are distinct identities.
            _ => false,
        }
    }
}

impl Username {
    /// Builds a user principal name from an account name and an UPN suffix
    pub fn new_upn(account_name: &str, upn_suffix: &str) -> Result<Self, UsernameError> {
        // NOTE: AD usernames may contain `@`
        if account_name.contains(['\\']) {
            return Err(UsernameError::MixedFormat);
        }

        if upn_suffix.contains(['\\', '@']) {
            return Err(UsernameError::MixedFormat);
        }

        Ok(Self {
            value: format!("{account_name}@{upn_suffix}"),
            format: UserNameFormat::UserPrincipalName,
            sep_idx: Some(account_name.len()),
        })
    }

    /// Builds a down-level logon name from an account name and a NetBIOS domain name
    pub fn new_down_level_logon_name(account_name: &str, netbios_domain_name: &str) -> Result<Self, UsernameError> {
        if account_name.contains(['\\', '@']) {
            return Err(UsernameError::MixedFormat);
        }

        if netbios_domain_name.contains(['\\', '@']) {
            return Err(UsernameError::MixedFormat);
        }

        // An empty NetBIOS domain means "no domain": represent it accurately as a separator-less
        // down-level logon name (`netbios_domain == None`) rather than a distinct `Some("")`.
        if netbios_domain_name.is_empty() {
            return Ok(Self {
                value: account_name.to_owned(),
                format: UserNameFormat::DownLevelLogonName,
                sep_idx: None,
            });
        }

        Ok(Self {
            value: format!("{netbios_domain_name}\\{account_name}"),
            format: UserNameFormat::DownLevelLogonName,
            sep_idx: Some(netbios_domain_name.len()),
        })
    }

    /// Attempts to guess the right name format for the account name/domain combo
    ///
    /// If no netbios domain name is provided, or if it is an empty string, the username will
    /// be parsed as either a user principal name or a down-level logon name.
    ///
    /// It falls back to a down-level logon name when the format can’t be guessed.
    pub fn new(account_name: &str, netbios_domain_name: Option<&str>) -> Result<Self, UsernameError> {
        match netbios_domain_name {
            Some(netbios_domain_name) if !netbios_domain_name.is_empty() => {
                Self::new_down_level_logon_name(account_name, netbios_domain_name)
            }
            _ => Self::parse(account_name),
        }
    }

    /// Parses the value in order to find if the value is a user principal name or a down-level logon name
    ///
    /// If there is no `\` or `@` separator, the value is considered to be a down-level logon name with
    /// an empty NetBIOS domain.
    pub fn parse(value: &str) -> Result<Self, UsernameError> {
        match (value.split_once('\\'), value.rsplit_once('@')) {
            (None, None) => Ok(Self {
                value: value.to_owned(),
                format: UserNameFormat::DownLevelLogonName,
                sep_idx: None,
            }),
            (Some((netbios_domain_name, account_name)), _) => {
                Self::new_down_level_logon_name(account_name, netbios_domain_name)
            }
            (_, Some((account_name, upn_suffix))) => Self::new_upn(account_name, upn_suffix),
        }
    }

    /// Returns the internal representation, as-is
    pub fn inner(&self) -> &str {
        &self.value
    }

    /// Returns the [`UserNameFormat`] for this username
    pub fn format(&self) -> UserNameFormat {
        self.format
    }

    /// Returns a format-tagged, borrowed view into the components of the username.
    ///
    /// Prefer this over [`Username::domain_name`]: matching on the returned [`UsernameParts`]
    /// forces both user name formats to be handled explicitly and prevents confusing a UPN
    /// suffix with a NetBIOS domain name.
    pub fn parts(&self) -> UsernameParts<'_> {
        match self.format {
            UserNameFormat::UserPrincipalName => {
                // A user principal name is always built with a separator (the `@`).
                let idx = self.sep_idx.expect("a UPN always has an `@` separator");
                UsernameParts::UserPrincipalName(UserPrincipalNameParts {
                    account_name: &self.value[..idx],
                    suffix: &self.value[idx + 1..],
                    upn: &self.value,
                })
            }
            UserNameFormat::DownLevelLogonName => match self.sep_idx {
                Some(idx) => UsernameParts::DownLevelLogonName(DownLevelLogonNameParts {
                    account_name: &self.value[idx + 1..],
                    netbios_domain: Some(&self.value[..idx]),
                }),
                None => UsernameParts::DownLevelLogonName(DownLevelLogonNameParts {
                    account_name: &self.value,
                    netbios_domain: None,
                }),
            },
        }
    }

    /// May return an UPN suffix or NetBIOS domain name depending on the internal format
    #[allow(
        clippy::deprecated_semver,
        reason = "`<next-version>` placeholder filled in at release time"
    )]
    #[deprecated(
        since = "<next-version>",
        note = "conflates UPN suffix with NetBIOS domain; match on `Username::parts()` instead — see https://github.com/Devolutions/sspi-rs/issues/708"
    )]
    pub fn domain_name(&self) -> Option<&str> {
        self.sep_idx.map(|idx| match self.format {
            UserNameFormat::UserPrincipalName => &self.value[idx + 1..],
            UserNameFormat::DownLevelLogonName => &self.value[..idx],
        })
    }

    /// Returns the account name
    pub fn account_name(&self) -> &str {
        if let Some(idx) = self.sep_idx {
            match self.format {
                UserNameFormat::UserPrincipalName => &self.value[..idx],
                UserNameFormat::DownLevelLogonName => &self.value[idx + 1..],
            }
        } else {
            &self.value
        }
    }

    /// Compares two usernames for equality, ignoring ASCII case.
    ///
    /// This is a case-insensitive counterpart to the (case-sensitive) [`PartialEq`] implementation,
    /// matching Windows' case-insensitive treatment of account and domain names. Usernames of
    /// different [formats](UserNameFormat) are never equal (see [`UsernameParts::eq_ignore_ascii_case`]).
    pub fn eq_ignore_ascii_case(&self, other: &Username) -> bool {
        self.parts().eq_ignore_ascii_case(&other.parts())
    }
}

/// Allows you to pass a particular user name and password to the run-time library for the purpose of authentication
///
/// # MSDN
///
/// * [SEC_WINNT_AUTH_IDENTITY_W structure](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_w)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthIdentity {
    pub username: Username,
    pub password: Secret<String>,
}

/// Client credentials backed by a pre-derived Kerberos long-term key.
///
/// Unlike [`AuthIdentity`], no password is supplied: the raw long-term key
/// (as stored in a keytab) is used directly to encrypt the PA-ENC-TIMESTAMP
/// pre-authentication value and to decrypt the AS-REP, skipping the
/// string-to-key derivation. This is the credential a service uses when it
/// acts as a Kerberos *client* (e.g. inter-service authentication) without a
/// human password.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeytabIdentity {
    /// Client principal, e.g. `"svc@REALM"` or `"svc/host@REALM"`.
    pub principal: Username,
    /// Raw long-term key bytes for `key_enctype`.
    pub key: Secret<Vec<u8>>,
    /// Kerberos encryption type of `key` (e.g. aes256-cts-hmac-sha1-96).
    pub key_enctype: CipherSuite,
}

/// Auth identity buffers for password-based logon.
#[derive(Clone, Eq, PartialEq, Default)]
pub struct AuthIdentityBuffers {
    /// Username.
    ///
    /// Must be UTF-16 encoded.
    pub user: Utf16String,
    /// Domain.
    ///
    /// Must be UTF-16 encoded.
    pub domain: Utf16String,
    /// Password.
    ///
    /// Must be UTF-16 encoded.
    ///
    /// If the password is an NT hash, it should be prefixed with [`NTLM_HASH_PREFIX`](crate::NTLM_HASH_PREFIX) followed by the hash in hexadecimal format.
    ///
    /// See [`NtlmHash`](crate::NtlmHash) for more details.
    pub password: Secret<ZeroizedUtf16String>,
}

impl AuthIdentityBuffers {
    /// Creates a new [AuthIdentityBuffers] object based on provided credentials.
    ///
    /// Provided credentials must be UTF-16 encoded.
    pub fn new(user: Utf16String, domain: Utf16String, password: Utf16String) -> Self {
        Self {
            user,
            domain,
            password: ZeroizedUtf16String(password).into(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.user.is_empty()
    }

    /// Creates a new [AuthIdentityBuffers] object based on UTF-8 credentials.
    ///
    /// It converts the provided credentials to UTF-16 byte vectors automatically.
    pub fn from_utf8(user: &str, domain: &str, password: &str) -> Self {
        Self {
            user: user.into(),
            domain: domain.into(),
            password: ZeroizedUtf16String(Utf16String::from(password)).into(),
        }
    }

    /// Creates a new [AuthIdentityBuffers] object based on UTF-8 username and domain, and NT hash for the password.
    pub fn from_utf8_with_hash(user: &str, domain: &str, nt_hash: &crate::NtlmHash) -> Self {
        Self {
            user: user.into(),
            domain: domain.into(),
            password: ZeroizedUtf16String(Utf16String::from(nt_hash.to_sspi_password())).into(),
        }
    }
}

impl fmt::Debug for AuthIdentityBuffers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthIdentityBuffers {{ user: 0x")?;
        self.user
            .as_bytes_le()
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02X}"))?;
        write!(f, ", domain: 0x")?;
        self.domain
            .as_bytes_le()
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02X}"))?;
        write!(f, ", password: {:?} }}", self.password)?;

        Ok(())
    }
}

impl From<AuthIdentity> for AuthIdentityBuffers {
    fn from(credentials: AuthIdentity) -> Self {
        let password: &str = credentials.password.as_ref().as_ref();

        // Encode the username so that it round-trips back to the same format through
        // `TryFrom<&AuthIdentityBuffers>` (which parses `user` and treats `domain` as a NetBIOS
        // domain). A UPN is stored whole in `user` with an empty `domain` (parsing recovers the UPN
        // via its `@`), while a down-level logon name keeps the `(account_name, netbios_domain)` split.
        let (user, domain) = match credentials.username.parts() {
            UsernameParts::UserPrincipalName(parts) => (parts.upn(), ""),
            UsernameParts::DownLevelLogonName(parts) => {
                (parts.account_name(), parts.netbios_domain().unwrap_or_default())
            }
        };

        Self {
            user: user.into(),
            domain: domain.into(),
            password: ZeroizedUtf16String(password.into()).into(),
        }
    }
}

impl TryFrom<&AuthIdentityBuffers> for AuthIdentity {
    type Error = UsernameError;

    fn try_from(credentials_buffers: &AuthIdentityBuffers) -> Result<Self, Self::Error> {
        let account_name = credentials_buffers.user.to_string();

        let domain_name = credentials_buffers
            .domain
            .is_empty()
            .not()
            .then(|| credentials_buffers.domain.to_string());

        let username = Username::new(&account_name, domain_name.as_deref())?;
        let password = credentials_buffers.password.as_ref().as_ref().to_string().into();

        Ok(Self { username, password })
    }
}

impl TryFrom<AuthIdentityBuffers> for AuthIdentity {
    type Error = UsernameError;

    fn try_from(credentials_buffers: AuthIdentityBuffers) -> Result<Self, Self::Error> {
        AuthIdentity::try_from(&credentials_buffers)
    }
}

#[cfg(feature = "scard")]
mod scard_credentials {
    #[cfg(not(target_arch = "wasm32"))]
    use std::path::PathBuf;

    use picky::key::PrivateKey;
    use picky_asn1_der::Asn1DerError;
    use picky_asn1_x509::Certificate;

    use crate::secret::SecretPrivateKey;
    use crate::utf16string::ZeroizedUtf16String;
    use crate::{Error, ErrorKind, NonEmpty, Secret, Utf16String};

    /// DER-encoded x509 certificate.
    #[derive(Clone, Eq, PartialEq, Debug)]
    pub struct CertificateRaw(Vec<u8>);

    impl AsRef<[u8]> for CertificateRaw {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    impl TryFrom<Vec<u8>> for CertificateRaw {
        type Error = Asn1DerError;

        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            let _: Certificate = picky_asn1_der::from_bytes(value.as_ref())?;
            Ok(Self(value))
        }
    }

    impl From<CertificateRaw> for Vec<u8> {
        fn from(value: CertificateRaw) -> Self {
            value.0
        }
    }

    impl TryFrom<&Certificate> for CertificateRaw {
        type Error = Asn1DerError;

        fn try_from(value: &Certificate) -> Result<Self, Self::Error> {
            picky_asn1_der::to_vec(value).map(Self)
        }
    }

    impl TryFrom<Certificate> for CertificateRaw {
        type Error = Asn1DerError;

        fn try_from(value: Certificate) -> Result<Self, Self::Error> {
            Self::try_from(&value)
        }
    }

    impl From<&CertificateRaw> for Certificate {
        fn from(value: &CertificateRaw) -> Self {
            picky_asn1_der::from_bytes(&value.0).expect("value.0 is convertible to Certificate (checked on creation)")
        }
    }

    impl From<CertificateRaw> for Certificate {
        fn from(value: CertificateRaw) -> Self {
            Self::from(&value)
        }
    }

    /// Smart card type.
    #[derive(Clone, Eq, PartialEq, Debug)]
    pub enum SmartCardType {
        /// Emulated smart card.
        ///
        /// No real device is used. All smart card functionality is emulated using the [winscard] crate.
        Emulated {
            /// Emulated smart card PIN code.
            ///
            /// This is smart card PIN code, not the PIN code provided by the user.
            scard_pin: Secret<Vec<u8>>,
        },
        #[cfg(not(target_arch = "wasm32"))]
        /// System-provided smart card.
        ///
        /// Real smart card device in use.
        SystemProvided {
            /// Path to the PKCS11 module.
            pkcs11_module_path: PathBuf,
        },
        /// System-provided smart card, but the Windows native API will be used for accessing smart card.
        ///
        /// Available only on Windows.
        #[cfg(target_os = "windows")]
        WindowsNative,
    }

    /// Represents raw data needed for smart card authentication
    #[derive(Clone, Eq, PartialEq, Debug)]
    pub struct SmartCardIdentityBuffers {
        /// UTF-16 encoded username
        pub username: Utf16String,
        /// DER-encoded X509 certificate
        pub certificate: CertificateRaw,
        /// UTF-16 encoded smart card name
        pub card_name: Option<NonEmpty<Utf16String>>,
        /// UTF-16 encoded smart card reader name
        pub reader_name: Utf16String,
        /// UTF-16 encoded smart card key container name
        pub container_name: Option<NonEmpty<Utf16String>>,
        /// UTF-16 encoded smart card CSP name
        pub csp_name: Utf16String,
        /// UTF-16 encoded smart card PIN code
        pub pin: Secret<ZeroizedUtf16String>,
        /// UTF-16 string with PEM-encoded RSA 2048-bit private key
        pub private_key_pem: Option<NonEmpty<Utf16String>>,
        /// Smart card type.
        pub scard_type: SmartCardType,
    }

    /// Represents data needed for smart card authentication
    #[derive(Debug, Clone, PartialEq)]
    pub struct SmartCardIdentity {
        /// Username
        pub username: String,
        /// X509 certificate
        pub certificate: Certificate,
        /// Smart card reader name
        pub reader_name: String,
        /// Smart card name
        pub card_name: Option<String>,
        /// Smart card key container name
        pub container_name: Option<String>,
        /// Smart card CSP name
        pub csp_name: String,
        /// ASCII encoded mart card PIN code
        pub pin: Secret<Vec<u8>>,
        /// RSA 2048-bit private key
        pub private_key: Option<SecretPrivateKey>,
        /// Smart card type.
        pub scard_type: SmartCardType,
    }

    impl TryFrom<SmartCardIdentity> for SmartCardIdentityBuffers {
        type Error = Error;

        fn try_from(value: SmartCardIdentity) -> Result<Self, Self::Error> {
            let private_key = if let Some(key) = value.private_key {
                NonEmpty::new(Utf16String::from(key.as_ref().to_pem_str().map_err(|e| {
                    Error::new(
                        ErrorKind::InternalError,
                        format!("Unable to serialize a smart card private key: {e}"),
                    )
                })?))
            } else {
                None
            };

            Ok(Self {
                certificate: value.certificate.try_into()?,
                reader_name: value.reader_name.into(),
                pin: ZeroizedUtf16String(String::from_utf8_lossy(value.pin.as_ref()).as_ref().into()).into(),
                username: value.username.into(),
                card_name: value.card_name.and_then(|value| NonEmpty::new(value.into())),
                container_name: value.container_name.and_then(|value| NonEmpty::new(value.into())),
                csp_name: value.csp_name.into(),
                private_key_pem: private_key,
                scard_type: value.scard_type,
            })
        }
    }

    impl TryFrom<&SmartCardIdentityBuffers> for SmartCardIdentity {
        type Error = Error;

        fn try_from(value: &SmartCardIdentityBuffers) -> Result<Self, Self::Error> {
            let private_key = if let Some(key) = &value.private_key_pem {
                let pem_string = key.as_ref().to_string();

                Some(SecretPrivateKey::new(PrivateKey::from_pem_str(&pem_string).map_err(
                    |e| {
                        Error::new(
                            ErrorKind::InternalError,
                            format!("Unable to create a PrivateKey from a PEM string: {e}"),
                        )
                    },
                )?))
            } else {
                None
            };

            Ok(Self {
                certificate: Certificate::from(&value.certificate),
                reader_name: value.reader_name.to_string(),
                pin: value.pin.as_ref().0.to_string().into_bytes().into(),
                username: value.username.to_string(),
                card_name: value.card_name.as_ref().map(NonEmpty::as_ref).map(ToString::to_string),
                container_name: value
                    .container_name
                    .as_ref()
                    .map(NonEmpty::as_ref)
                    .map(ToString::to_string),
                csp_name: value.csp_name.to_string(),
                private_key,
                scard_type: value.scard_type.clone(),
            })
        }
    }
}

#[cfg(feature = "scard")]
pub use self::scard_credentials::{CertificateRaw, SmartCardIdentity, SmartCardIdentityBuffers, SmartCardType};

/// Generic enum that encapsulates raw credentials for any type of authentication
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum CredentialsBuffers {
    /// Raw auth identity buffers for the password based authentication
    AuthIdentity(AuthIdentityBuffers),
    #[cfg(feature = "scard")]
    /// Raw smart card identity buffers for the smart card based authentication
    SmartCard(SmartCardIdentityBuffers),
    /// Pre-derived Kerberos long-term key for keytab-based client authentication
    Keytab(KeytabIdentity),
}

impl CredentialsBuffers {
    pub fn into_auth_identity(self) -> Option<AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
            _ => None,
        }
    }

    pub fn to_auth_identity(&self) -> Option<AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity.clone()),
            _ => None,
        }
    }

    pub fn as_auth_identity(&self) -> Option<&AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
            _ => None,
        }
    }

    pub fn as_mut_auth_identity(&mut self) -> Option<&mut AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
            _ => None,
        }
    }
}

/// Generic enum that encapsulates credentials for any type of authentication
#[derive(Clone, PartialEq, Debug)]
pub enum Credentials {
    /// Auth identity for the password based authentication
    AuthIdentity(AuthIdentity),
    /// Smart card identity for the smart card based authentication
    #[cfg(feature = "scard")]
    SmartCard(Box<SmartCardIdentity>),
    /// Pre-derived Kerberos long-term key for keytab-based client authentication
    Keytab(KeytabIdentity),
}

impl Credentials {
    pub fn to_auth_identity(&self) -> Option<AuthIdentity> {
        match self {
            Credentials::AuthIdentity(identity) => Some(identity.clone()),
            _ => None,
        }
    }

    pub fn auth_identity(self) -> Option<AuthIdentity> {
        match self {
            Credentials::AuthIdentity(identity) => Some(identity),
            _ => None,
        }
    }
}

#[cfg(feature = "scard")]
impl From<SmartCardIdentity> for Credentials {
    fn from(value: SmartCardIdentity) -> Self {
        Self::SmartCard(Box::new(value))
    }
}

impl From<AuthIdentity> for Credentials {
    fn from(value: AuthIdentity) -> Self {
        Self::AuthIdentity(value)
    }
}

impl From<KeytabIdentity> for Credentials {
    fn from(value: KeytabIdentity) -> Self {
        Self::Keytab(value)
    }
}

impl TryFrom<Credentials> for CredentialsBuffers {
    type Error = Error;

    fn try_from(value: Credentials) -> Result<Self, Self::Error> {
        Ok(match value {
            Credentials::AuthIdentity(identity) => Self::AuthIdentity(identity.into()),
            #[cfg(feature = "scard")]
            Credentials::SmartCard(identity) => Self::SmartCard((*identity).try_into()?),
            Credentials::Keytab(identity) => Self::Keytab(identity),
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn username_format_conversion() {
        proptest!(|(value in "[a-zA-Z0-9.]{1,3}@?\\\\?[a-zA-Z0-9.]{1,3}@?\\\\?[a-zA-Z0-9.]{1,3}")| {
            let res = Username::parse(&value);
            prop_assume!(res.is_ok());
            let initial_username = res.unwrap();
            assert_eq!(initial_username.inner(), value);

            // The "domain-ish" component, whatever its format-specific meaning is.
            let domain = match initial_username.parts() {
                UsernameParts::UserPrincipalName(upn) => Some(upn.suffix()),
                UsernameParts::DownLevelLogonName(dlln) => dlln.netbios_domain(),
            };

            if let Some(domain) = domain {
                let reconstructed_upn = Username::new_upn(initial_username.account_name(), domain).expect("UPN");
                assert_eq!(reconstructed_upn.account_name(), initial_username.account_name());
                assert_eq!(
                    reconstructed_upn.parts(),
                    UsernameParts::UserPrincipalName(UserPrincipalNameParts {
                        account_name: initial_username.account_name(),
                        suffix: domain,
                        upn: reconstructed_upn.inner(),
                    })
                );
            }

            // A down-level user name can't contain a @ in the account name
            if !initial_username.account_name().contains('@') {
                let netbios_name = Username::new(initial_username.account_name(), domain).expect("NetBIOS");
                assert_eq!(netbios_name.format(), UserNameFormat::DownLevelLogonName);
                assert_eq!(netbios_name.account_name(), initial_username.account_name());
                let netbios_domain = match netbios_name.parts() {
                    UsernameParts::DownLevelLogonName(dlln) => dlln.netbios_domain(),
                    UsernameParts::UserPrincipalName(_) => unreachable!("constructed as a down-level logon name"),
                };
                assert_eq!(netbios_domain, domain);
            }
        })
    }

    fn check_round_trip_property(username: &Username) {
        let round_trip = Username::parse(username.inner()).expect("round-trip parse");
        assert_eq!(*username, round_trip);
    }

    #[test]
    fn upn_round_trip() {
        proptest!(|(account_name in "[a-zA-Z0-9@.]{1,3}", domain_name in "[a-z0-9.]{1,3}")| {
            let username = Username::new_upn(&account_name, &domain_name).expect("UPN");

            assert_eq!(username.account_name(), account_name);
            assert_eq!(username.format(), UserNameFormat::UserPrincipalName);
            assert_eq!(
                username.parts(),
                UsernameParts::UserPrincipalName(UserPrincipalNameParts {
                    account_name: &account_name,
                    suffix: &domain_name,
                    upn: username.inner(),
                })
            );

            check_round_trip_property(&username);
        })
    }

    #[test]
    fn down_level_logon_name_round_trip() {
        proptest!(|(account_name in "[a-zA-Z0-9.]{1,3}", domain_name in "[A-Z0-9.]{1,3}")| {
            let username = Username::new_down_level_logon_name(&account_name, &domain_name).expect("down-level logon name");

            assert_eq!(username.account_name(), account_name);
            assert_eq!(username.format(), UserNameFormat::DownLevelLogonName);
            assert_eq!(
                username.parts(),
                UsernameParts::DownLevelLogonName(DownLevelLogonNameParts {
                    account_name: &account_name,
                    netbios_domain: Some(&domain_name),
                })
            );

            check_round_trip_property(&username);
        })
    }

    #[test]
    fn down_level_logon_name_without_domain_parts() {
        // When a bare name (no `\` and no `@`) is parsed, it is a down-level logon name with no
        // NetBIOS domain: the `netbios_domain` field must be `None`.
        proptest!(|(account_name in "[a-zA-Z0-9.]{1,3}")| {
            let username = Username::parse(&account_name).expect("parse");

            assert_eq!(username.account_name(), account_name);
            assert_eq!(username.format(), UserNameFormat::DownLevelLogonName);
            assert_eq!(
                username.parts(),
                UsernameParts::DownLevelLogonName(DownLevelLogonNameParts {
                    account_name: &account_name,
                    netbios_domain: None,
                })
            );

            check_round_trip_property(&username);
        })
    }

    #[test]
    fn eq_ignore_ascii_case_matches_within_format() {
        // UPNs that differ only by ASCII case are equal.
        let upn = Username::new_upn("Alice", "Example.COM").expect("upn");
        let upn_other_case = Username::new_upn("alice", "example.com").expect("upn");
        assert!(upn.eq_ignore_ascii_case(&upn_other_case));

        // Down-level logon names that differ only by ASCII case are equal.
        let dlln = Username::new_down_level_logon_name("Bob", "EXAMPLE").expect("dlln");
        let dlln_other_case = Username::new_down_level_logon_name("bob", "example").expect("dlln");
        assert!(dlln.eq_ignore_ascii_case(&dlln_other_case));

        // Bare down-level logon names (no NetBIOS domain) compare on the account name only.
        let bare = Username::parse("Carol").expect("parse");
        let bare_other_case = Username::parse("carol").expect("parse");
        assert!(bare.eq_ignore_ascii_case(&bare_other_case));
    }

    #[test]
    fn eq_ignore_ascii_case_distinguishes_components_and_formats() {
        // Different account names are not equal.
        let alice = Username::new_upn("alice", "example.com").expect("upn");
        let bob = Username::new_upn("bob", "example.com").expect("upn");
        assert!(!alice.eq_ignore_ascii_case(&bob));

        // A present NetBIOS domain never equals an absent one.
        let with_domain = Username::new_down_level_logon_name("alice", "EXAMPLE").expect("dlln");
        let without_domain = Username::parse("alice").expect("parse");
        assert!(!with_domain.eq_ignore_ascii_case(&without_domain));

        // A UPN and a down-level logon name are distinct identities even with matching components:
        // the UPN suffix must never be conflated with the NetBIOS domain across formats.
        let upn = Username::new_upn("alice", "example").expect("upn");
        let dlln = Username::new_down_level_logon_name("alice", "example").expect("dlln");
        assert!(!upn.eq_ignore_ascii_case(&dlln));
    }

    #[test]
    fn auth_identity_buffers_round_trip_preserves_format() {
        // Converting to `AuthIdentityBuffers` and back must preserve the user name format: a UPN
        // must not silently degrade into a down-level logon name.
        for username in [
            Username::new_upn("alice", "example.com").expect("upn"),
            Username::new_upn("bob@dept", "example.com").expect("upn with @ in account name"),
            Username::new_down_level_logon_name("carol", "EXAMPLE").expect("dlln"),
            // An empty NetBIOS domain is normalized to a separator-less down-level logon name.
            Username::new_down_level_logon_name("erin", "").expect("dlln without domain"),
            Username::parse("dave").expect("bare name"),
        ] {
            let identity = AuthIdentity {
                username: username.clone(),
                password: String::new().into(),
            };

            let buffers = AuthIdentityBuffers::from(identity);
            let round_trip = AuthIdentity::try_from(&buffers).expect("round-trip");

            assert_eq!(round_trip.username, username);
            assert_eq!(round_trip.username.format(), username.format());
        }
    }

    #[test]
    fn empty_netbios_domain_is_normalized_to_no_domain() {
        // An empty NetBIOS domain means "no domain": it must not produce a distinct `Some("")` view
        // that would compare unequal to a separator-less down-level logon name.
        let empty_domain = Username::new_down_level_logon_name("alice", "").expect("dlln without domain");
        let bare = Username::parse("alice").expect("parse");

        assert_eq!(empty_domain, bare);
        assert_eq!(empty_domain.inner(), "alice");
        assert!(matches!(
            empty_domain.parts(),
            UsernameParts::DownLevelLogonName(dlln) if dlln.netbios_domain().is_none()
        ));
        assert!(empty_domain.eq_ignore_ascii_case(&bare));
    }
}

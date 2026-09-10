use std::fmt;

/// The prefix used to identify NT hash credentials in password fields
pub const NTLM_HASH_PREFIX: &str = "$NTLM$:";

/// Represents an NT hash (16 bytes) used for NT Hash authentication
///
/// This type provides type safety and validation for NT hashes.
///
/// It can be parsed from hex strings and used to create [`AuthIdentityBuffers`](crate::AuthIdentityBuffers) with [`AuthIdentityBuffers::from_utf8_with_hash`](crate::AuthIdentityBuffers::from_utf8_with_hash).
///
/// # Example
///
/// ```
/// use sspi::ntlm::NtlmHash;
///
/// // Parse from hex string.
/// let hash = "8119935C5F7FA5F57135620C8073AACA".parse::<NtlmHash>().unwrap();
///
/// // Use with AuthIdentityBuffers.
/// use sspi::AuthIdentityBuffers;
/// let creds = AuthIdentityBuffers::from_utf8_with_hash("username", "DOMAIN", &hash);
/// ```
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NtlmHash([u8; 16]);

impl NtlmHash {
    /// Creates a new NtlmHash from a byte array.
    #[inline]
    pub fn from_bytes(hash: [u8; 16]) -> Self {
        Self(hash)
    }

    /// Attempts to create an NtlmHash from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `NtlmHashError::ByteLength` if the slice is not exactly 16 bytes long.
    #[inline]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, NtlmHashError> {
        NtlmHash::try_from(bytes)
    }

    /// Attempts to create an NtlmHash from a hex string.
    ///
    /// # Errors
    ///
    /// Returns `NtlmHashError::StringLength` if the string is not exactly 32 characters long.
    ///
    /// Returns `NtlmHashError::Hex` if the string contains invalid hex characters.
    #[inline]
    pub fn try_from_hex_str(s: impl AsRef<str>) -> Result<Self, NtlmHashError> {
        NtlmHash::try_from(s.as_ref())
    }

    /// Returns a reference to the hash bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Converts the NT hash to the password format expected by sspi when constructing [`AuthIdentityBuffers`](crate::AuthIdentityBuffers).
    ///
    /// Called internally during [`AuthIdentityBuffers::from_utf8_with_hash`](crate::AuthIdentityBuffers::from_utf8_with_hash).
    pub(crate) fn to_sspi_password(self) -> String {
        let mut hex = String::with_capacity(self.0.len() * 2);
        for byte in &self.0 {
            hex.push_str(&format!("{byte:02x}"));
        }

        format!("{NTLM_HASH_PREFIX}{hex}")
    }
}

impl From<[u8; 16]> for NtlmHash {
    fn from(value: [u8; 16]) -> Self {
        NtlmHash(value)
    }
}

// Parses NT hash from hex string. Required for compatibility with clap.
impl std::str::FromStr for NtlmHash {
    type Err = NtlmHashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NtlmHash::try_from(s)
    }
}

impl TryFrom<&str> for NtlmHash {
    type Error = NtlmHashError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(NtlmHashError::StringLength);
        }

        let mut hash = [0u8; 16];
        for i in 0..16 {
            let hex_byte = &value[(i * 2)..(i * 2 + 2)];
            hash[i] = u8::from_str_radix(hex_byte, 16).map_err(|_| NtlmHashError::Hex)?;
        }

        Ok(NtlmHash(hash))
    }
}

impl TryFrom<&[u8]> for NtlmHash {
    type Error = NtlmHashError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 16 {
            return Err(NtlmHashError::ByteLength);
        }

        let mut hash = [0u8; 16];
        hash.copy_from_slice(value);

        Ok(NtlmHash(hash))
    }
}

/// Errors that can occur when parsing or creating an NT hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NtlmHashError {
    /// Invalid string length for NTLM hash (must be 32-character hex string).
    StringLength,
    /// Invalid byte length for NTLM hash (must be 16 bytes).
    ByteLength,
    /// Invalid hex string.
    Hex,
}

impl std::error::Error for NtlmHashError {}

impl fmt::Display for NtlmHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtlmHashError::StringLength => {
                write!(f, "invalid length: expected 32-character hex string for NTLM hash")
            }
            NtlmHashError::ByteLength => write!(f, "invalid length: expected 16 bytes for NTLM hash"),
            NtlmHashError::Hex => write!(f, "invalid hex string for NTLM hash"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ntlm_hash_from_hex_string() {
        // Test valid 32-character hex string
        let hash_str = "32ed87bdb5fdc5e9cba88547376818d4";
        let result: Result<NtlmHash, _> = hash_str.try_into();
        assert!(result.is_ok());

        let hash = result.unwrap();
        assert_eq!(hash.as_bytes().len(), 16);
    }

    #[test]
    fn test_ntlm_hash_from_bytes() {
        let bytes = [
            0x32, 0xed, 0x87, 0xbd, 0xb5, 0xfd, 0xc5, 0xe9, 0xcb, 0xa8, 0x85, 0x47, 0x37, 0x68, 0x18, 0xd4,
        ];

        let result: Result<NtlmHash, _> = bytes.as_slice().try_into();
        assert!(result.is_ok());

        let hash = result.unwrap();
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_ntlm_hash_invalid_hex_length() {
        // Too short
        let hash_str = "32ed87bdb5fdc5e9cba885473768";
        let result: Result<NtlmHash, _> = hash_str.try_into();
        assert!(result.is_err());

        // Too long
        let hash_str = "32ed87bdb5fdc5e9cba88547376818d4ff";
        let result: Result<NtlmHash, _> = hash_str.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_ntlm_hash_invalid_hex_characters() {
        let hash_str = "32ed87bdb5fdc5e9cba88547376818zz";
        let result: Result<NtlmHash, _> = hash_str.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_ntlm_hash_invalid_byte_length() {
        let bytes = [0x32, 0xed, 0x87, 0xbd, 0xb5];
        let result: Result<NtlmHash, _> = bytes.as_slice().try_into();
        assert!(result.is_err());

        // Invalid length
        let invalid_len: Result<NtlmHash, _> = "32ed87bd".try_into();
        assert!(invalid_len.is_err());

        let empty: Result<NtlmHash, _> = "".try_into();
        assert!(empty.is_err());
    }

    #[test]
    fn test_ntlm_hash_case_insensitive() {
        let lowercase = "32ed87bdb5fdc5e9cba88547376818d4";
        let uppercase = "32ED87BDB5FDC5E9CBA88547376818D4";
        let mixed = "32Ed87BdB5FdC5e9CbA88547376818D4";

        let hash1: NtlmHash = lowercase.try_into().unwrap();
        let hash2: NtlmHash = uppercase.try_into().unwrap();
        let hash3: NtlmHash = mixed.try_into().unwrap();

        assert_eq!(hash1.as_bytes(), hash2.as_bytes());
        assert_eq!(hash2.as_bytes(), hash3.as_bytes());
    }

    #[test]
    fn test_ntlm_hash_to_sspi_password() {
        let hash_str = "32ed87bdb5fdc5e9cba88547376818d4";
        let hash: NtlmHash = hash_str.parse().unwrap();
        let sspi_password = hash.to_sspi_password();
        assert_eq!(
            sspi_password,
            format!("{NTLM_HASH_PREFIX}{}", "32ed87bdb5fdc5e9cba88547376818d4")
        );
    }
}

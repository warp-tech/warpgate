use std::ops::Not;

pub use widestring::error::Utf16Error;
pub use widestring::{U16CStr, U16CString, Utf16Str, Utf16String};
use zeroize::Zeroize;

use crate::{Error, ErrorKind};

fn bytes_le_to_vec_u16(bytes: impl AsRef<[u8]>) -> Result<Vec<u16>, Error> {
    let bytes = bytes.as_ref();

    if bytes.len() % 2 != 0 {
        return Err(Error::new(ErrorKind::InvalidParameter, "UTF-16 error: lone byte"));
    }

    Ok(bytes
        .chunks(2)
        .map(|c| u16::from_le_bytes(c.try_into().expect("c is 2 bytes, checked earlier")))
        .collect())
}

pub trait Utf16StringExt: Sized {
    /// Constructs new string from [`u8`] slice of UTF-16 data.
    ///
    /// # Errors
    ///
    /// This function will return an error if `bytes` has an odd number of elements.
    ///
    /// This function will return an error if `bytes` contains an invalid UTF-16 character (lone surrogate).
    fn from_bytes_le(bytes: impl AsRef<[u8]>) -> Result<Self, Error>;

    /// Constructs new string from [`u8`] slice of UTF-16 data.
    /// Unlike [`Utf16StringExt::from_bytes_le`], truncates at the first null character.
    ///
    /// # Errors
    ///
    /// This function will return an error if `bytes` has an odd number of elements.
    ///
    /// This function will return an error if `bytes` contains an invalid UTF-16 character (lone surrogate).
    fn from_bytes_le_truncate(bytes: impl AsRef<[u8]>) -> Result<Self, Error>;

    /// Constructs new string from [`u8`] slice of UTF-8 data.
    ///
    /// # Errors
    ///
    /// This function will return an error if `bytes` contains an invalid UTF-8 character.
    fn from_utf8_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error>;

    /// Converts a string into a vector of its elements, appending nul byte to the end.
    fn into_vec_with_nul(self) -> Vec<u16>;

    /// Returns reference to internal buffer as &[u8], assuming the little endianness.
    fn as_bytes_le(&self) -> &[u8];

    /// Returns internal buffer as Vec<u8>, assuming the little endianness.
    fn to_bytes_le(&self) -> Vec<u8> {
        self.as_bytes_le().to_vec()
    }

    /// # Safety
    ///
    /// Behavior is undefined is any of the following conditions are violated:
    ///
    /// - `ptr` must be a [valid], null-terminated C string.
    ///
    /// # Panics
    ///
    /// This function panics if `ptr` is null.
    unsafe fn from_pcwstr(ptr: *const u16) -> Result<Utf16String, Utf16Error>;
}

impl Utf16StringExt for Utf16String {
    fn from_bytes_le(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let buffer = bytes_le_to_vec_u16(bytes)?;

        Ok(Utf16String::from_vec(buffer)?)
    }

    fn from_bytes_le_truncate(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let mut buffer = bytes_le_to_vec_u16(bytes)?;

        let new_len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());

        buffer.truncate(new_len);

        Ok(Utf16String::from_vec(buffer)?)
    }

    fn from_utf8_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let bytes = bytes.as_ref();
        let str = std::str::from_utf8(bytes).map_err(Error::from)?;
        Ok(Self::from_str(str))
    }

    fn as_bytes_le(&self) -> &[u8] {
        let slice: &[u16] = self.as_ref();
        bytemuck::cast_slice(slice)
    }

    fn into_vec_with_nul(self) -> Vec<u16> {
        let mut vec = self.into_vec();
        vec.push(0);
        vec
    }

    unsafe fn from_pcwstr(ptr: *const u16) -> Result<Utf16String, Utf16Error> {
        // SAFETY: `s` must be valid null-terminated C string (upheld by the caller).
        let cstr = unsafe { U16CStr::from_ptr_str(ptr) };

        Ok(Utf16Str::from_ucstr(cstr)?.to_owned())
    }
}

pub trait U16CStringExt: Sized {
    /// Constructs new string from [`u8`] slice of UTF-16 data, truncating at the first nul terminator.
    ///
    /// The input is not validated for lone surrogates or other ill-formed UTF-16 sequences;
    /// use [`Utf16StringExt::from_bytes_le`] if strict UTF-16 validity is required.
    ///
    /// # Errors
    ///
    /// This function will return an error if `bytes` has an odd number of elements.
    fn from_bytes_le_truncate(bytes: impl AsRef<[u8]>) -> Result<Self, Error>;

    /// Constructs new string from [`u8`] slice of UTF-8 data.
    ///
    /// The string will be scanned for nul values, which are invalid anywhere except the final character.
    ///
    /// # Errors
    ///
    /// This function will return an error if `bytes` contains an invalid UTF-8 character.
    ///
    /// This function will return an error if `bytes` contains a nul value anywhere except the final position.
    fn from_utf8_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error>;

    /// Returns reference to internal buffer (excluding nul byte) as &[u8], assuming the native endianness.
    fn as_bytes(&self) -> &[u8];

    /// Returns reference to internal buffer (including nul byte) as &[u8], assuming the native endianness.
    fn as_bytes_with_nul(&self) -> &[u8];

    /// Returns internal buffer as Vec<u8> (excluding nul byte), assuming the native endianness.
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Returns internal buffer as Vec<u8> (including nul byte), assuming the native endianness.
    fn to_bytes_with_nul(&self) -> Vec<u8> {
        self.as_bytes_with_nul().to_vec()
    }
}

impl U16CStringExt for U16CString {
    fn from_bytes_le_truncate(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let buffer = bytes_le_to_vec_u16(bytes)?;

        Ok(U16CString::from_vec_truncate(buffer))
    }

    fn from_utf8_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let bytes = bytes.as_ref();
        let str = std::str::from_utf8(bytes).map_err(Error::from)?;

        Ok(Self::from_str(str)?)
    }

    fn as_bytes(&self) -> &[u8] {
        let slice = self.as_slice();
        bytemuck::cast_slice(slice)
    }

    fn as_bytes_with_nul(&self) -> &[u8] {
        let slice = self.as_slice_with_nul();
        bytemuck::cast_slice(slice)
    }
}

/// A UTF-16 string wrapper that supports explicit zeroization of sensitive data.
///
/// Wrap authentication credentials or other sensitive values in this type and call
/// [`Zeroize::zeroize`] on the value before it is dropped to overwrite the in-memory
/// buffer with zeroes.
///
/// # Note
/// This type does not implement `ZeroizeOnDrop`; the caller is responsible for
/// calling `.zeroize()` before the value goes out of scope if automatic erasure is required.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ZeroizedUtf16String(pub Utf16String);

impl ZeroizedUtf16String {
    pub fn from_bytes_le(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(Self(Utf16String::from_bytes_le(bytes)?))
    }

    pub fn from_bytes_le_truncate(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(Self(Utf16String::from_bytes_le_truncate(bytes)?))
    }
}

impl Zeroize for ZeroizedUtf16String {
    fn zeroize(&mut self) {
        // SAFETY:
        // - The mutable borrow is safe. The `.as_mut_slice` requires to keep it UTF-16 valid.
        //   The 0x0000 is a valid UTF-16 code unit, so we can zeroize the buffer safely without breaking the UTF-16 validity.
        let buffer = unsafe { self.0.as_mut_slice() };
        buffer.zeroize();
    }
}

impl AsRef<Utf16Str> for ZeroizedUtf16String {
    fn as_ref(&self) -> &Utf16Str {
        self.0.as_ref()
    }
}

#[derive(Zeroize, Clone, Eq, PartialEq, Default, Debug)]
pub struct NonEmpty<T: AsRef<Utf16Str>>(T);

impl<T: AsRef<Utf16Str>> NonEmpty<T> {
    pub fn new(value: T) -> Option<NonEmpty<T>> {
        value.as_ref().is_empty().not().then(|| Self(value))
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: AsRef<Utf16Str>> AsRef<T> for NonEmpty<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

#[cfg(test)]
mod tests {

    use widestring::U16CString;

    use super::{Utf16String, Utf16StringExt};
    use crate::{ErrorKind, NonEmpty, U16CStringExt};

    #[test]
    fn utf16_from_bytes_le_lone_byte() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x00,
        ];

        let result = Utf16String::from_bytes_le(bytes);

        assert!(result.is_err());
        assert_eq!(
            result.expect_err("result is err").error_type,
            ErrorKind::InvalidParameter
        );
    }

    #[test]
    fn utf16_from_bytes_le_lone_surrogate() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x00, 0xd8,
        ];

        let result = Utf16String::from_bytes_le(bytes);

        assert!(result.is_err());
        assert_eq!(
            result.expect_err("result is err").error_type,
            ErrorKind::InvalidParameter
        );
    }

    #[test]
    fn utf16_from_bytes_le_valid_bytes() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00,
        ];

        let result = Utf16String::from_bytes_le(bytes);

        assert!(result.is_ok());
        assert_eq!(result.expect("result is ok"), "El Psy Congroo");
    }

    #[test]
    fn utf16_from_bytes_le_roundtrip() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00,
        ];

        let result = Utf16String::from_bytes_le(bytes);

        assert!(result.is_ok());
        assert_eq!(result.as_ref().expect("result is ok").as_bytes_le(), bytes);
        assert_eq!(result.as_ref().expect("result is ok").as_bytes_le(), Vec::from(bytes));
    }

    #[test]
    fn utf16_from_bytes_le_truncate_lone_byte() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x00,
        ];

        let result = Utf16String::from_bytes_le_truncate(bytes);

        assert!(result.is_err());
        assert_eq!(
            result.expect_err("result is err").error_type,
            ErrorKind::InvalidParameter
        );
    }

    #[test]
    fn utf16_from_bytes_le_truncate_lone_surrogate() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x00, 0xd8,
        ];

        let result = Utf16String::from_bytes_le_truncate(bytes);

        assert!(result.is_err());
        assert_eq!(
            result.expect_err("result is err").error_type,
            ErrorKind::InvalidParameter
        );
    }

    #[test]
    fn utf16_from_bytes_le_truncate_no_null() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00,
        ];

        let result = Utf16String::from_bytes_le_truncate(bytes);

        assert!(result.is_ok());
        assert_eq!(result.expect("result is ok"), "El Psy Congroo");
    }

    #[test]
    fn utf16_from_bytes_le_truncate_null() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x00, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00,
        ];

        let result = Utf16String::from_bytes_le_truncate(bytes);

        assert!(result.is_ok());
        assert_eq!(result.expect("result is ok"), "El Psy");
    }

    #[test]
    fn utf16_from_utf8_bytes_valid() {
        let result = Utf16String::from_utf8_bytes(b"El Psy Congroo");
        assert!(result.is_ok());
        assert_eq!(result.expect("result is ok").to_string(), "El Psy Congroo");
    }

    #[test]
    fn utf16_from_utf8_bytes_invalid_utf8() {
        let result = Utf16String::from_utf8_bytes(b"\xFF\xFE");
        assert!(result.is_err());
    }

    #[test]
    fn utf16_into_vec_with_nul() {
        let s = Utf16String::from_str("42");
        let vec = s.into_vec_with_nul();
        assert_eq!(vec.last(), Some(&0u16));
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn u16c_from_bytes_le_truncate_lone_byte() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x00,
        ];

        let result = U16CString::from_bytes_le_truncate(bytes);

        assert!(result.is_err());
        assert_eq!(
            result.expect_err("result is err").error_type,
            ErrorKind::InvalidParameter
        );
    }

    #[test]
    fn u16c_from_bytes_le_truncate_lone_surrogate() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x00, 0xd8,
        ];

        let result = U16CString::from_bytes_le_truncate(bytes);

        assert!(result.is_ok());
    }

    #[test]
    fn u16c_from_bytes_le_roundtrip() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00,
        ];

        let result = U16CString::from_bytes_le_truncate(bytes).expect("succeeds");

        assert_eq!(result.as_bytes(), bytes);
        assert_eq!(result.to_bytes(), Vec::from(bytes));
    }

    #[test]
    fn u16c_from_bytes_le_null_terminated_roundtrip() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x00, 0x00, 0x42, 0x00,
        ];

        let result = U16CString::from_bytes_le_truncate(bytes).expect("succeeds");

        let bytes = &bytes[..bytes.len() - 4];

        assert_eq!(result.as_bytes(), bytes);
        assert_eq!(result.to_bytes(), Vec::from(bytes));
    }

    #[test]
    fn u16c_from_utf8_bytes_valid() {
        let result = U16CString::from_utf8_bytes(b"El Psy Congroo");
        assert!(result.is_ok());
    }

    #[test]
    fn u16c_from_utf8_bytes_embedded_nul() {
        // Nul anywhere except final position must be rejected.
        let result = U16CString::from_utf8_bytes(b"El\x00Psy Congroo");
        assert!(result.is_err());
    }

    #[test]
    fn u16c_from_utf8_bytes_invalid_utf8() {
        let result = U16CString::from_utf8_bytes(b"\xFF\xFE");
        assert!(result.is_err());
    }

    #[test]
    fn u16c_bytes_with_nul() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x00, 0x00,
        ];

        let result = U16CString::from_bytes_le_truncate(bytes).expect("succeeds");

        assert_eq!(result.as_bytes_with_nul(), bytes);
        assert_eq!(result.to_bytes_with_nul(), Vec::from(bytes));
    }

    #[test]
    fn non_empty_empty() {
        let test_str = "";

        let string = NonEmpty::new(Utf16String::from_str(test_str));
        assert!(string.is_none());
    }

    #[test]
    fn non_empty_non_empty() {
        let test_string = Utf16String::from_str("non empty test string");

        let string = NonEmpty::new(test_string.clone());

        assert!(string.is_some());
        let string = string.expect("string is some");

        assert_eq!(string.0, test_string);
        assert_eq!(string.into_inner(), test_string);
    }
}

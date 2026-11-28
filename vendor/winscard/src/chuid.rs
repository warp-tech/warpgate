use alloc::format;
use alloc::vec::Vec;

use time::{Duration, OffsetDateTime, format_description};
use uuid::Uuid;

use crate::{Error, ErrorKind, WinScardResult, tlv_tags};

// CHUID will always have a fixed length when excluding optional fields and asymmetric signature
pub(crate) const CHUID_LENGTH: usize = 61;

// The CHUID has to be encoded manually because for some weird reason all nested tags use the SIMPLE-TLV encoding.
// This makes it impossible to encode this particular object using iso7816_tlv crate (or any other BER-TLV crate out there)
pub(crate) fn build_chuid(card_id: Uuid) -> WinScardResult<[u8; CHUID_LENGTH]> {
    // We do this by hand, because iso7816_tlv uses Vecs when constructing a new TLV value
    // By avoiding using Tlv::new(), we can avoid allocating a new Vec for each TLV value and use slices instead
    let mut chuid = Vec::with_capacity(CHUID_LENGTH);
    let data_length = 0x3B;
    chuid.extend_from_slice(&[tlv_tags::DATA, data_length]);
    let fasc_n_length = 0x19;
    chuid.extend_from_slice(&[tlv_tags::FASC_N, fasc_n_length]);
    // The FASC-N number is encoded using the BCD 4-Bit decimal format with odd parity as per https://www.idmanagement.gov/docs/pacs-tig-scepacs.pdf
    // The unencoded value is (whitespaces were added for readability): SS 9999 FS 9999 FS 999999 FS 0 FS 1 FS 0000000000 3 0000 1 ES LRC
    // The Agency Code is set to 9999 as stated in section 6.4
    // The system code and credential number can both be set to any number
    chuid.extend_from_slice(&[
        0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10,
        0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb,
    ]);
    let guid_length = 0x10;
    chuid.extend_from_slice(&[tlv_tags::GUID, guid_length]);
    // Section 3.4.1 of https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
    //
    // This GUID identifies the smart card: the smart card minidriver uses it as the card
    // identifier (and derives the key container name from it). So, it must be stable.
    chuid.extend_from_slice(card_id.as_bytes());
    let expiration_date_length = 0x8;
    chuid.extend_from_slice(&[tlv_tags::EXPIRATION_DATE, expiration_date_length]);
    // Section 3.1.2 of https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
    let year_from_today = OffsetDateTime::now_utc() + Duration::weeks(48);
    let expiration_date_format = format_description::parse_borrowed::<2>("[year][month][day]").map_err(|e| {
        Error::new(
            ErrorKind::InternalError,
            format!("error while trying to parse the date format: {e}"),
        )
    })?;
    let expiration_date = year_from_today.format(&expiration_date_format).map_err(|e| {
        Error::new(
            ErrorKind::InternalError,
            format!("error while trying to format a date: {e}"),
        )
    })?;
    chuid.extend_from_slice(expiration_date.as_bytes());
    // both ISSUER_SIGNATURE and EDC don't have any value and both have a length of 0
    chuid.extend_from_slice(&[tlv_tags::ISSUER_SIGNATURE, 0x0]);
    chuid.extend_from_slice(&[tlv_tags::ERROR_DETECTION_CODE, 0x0]);
    // won't fail, as chuid is of fixed length
    Ok(chuid.try_into().unwrap())
}

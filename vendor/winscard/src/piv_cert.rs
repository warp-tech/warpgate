use alloc::vec::Vec;

use iso7816_tlv::simple::{Tag, Tlv};

use crate::ber_tlv::ber_tlv_length_encoding;
use crate::{WinScardResult, tlv_tags};

// The X.509 Certificate for PIV Authentication has to be encoded manually because for some weird reason all nested tags use the SIMPLE-TLV encoding.
// This makes it impossible to encode this particular object using iso7816_tlv crate (or any other BER-TLV crate out there)
pub(crate) fn build_auth_cert(auth_cert: Vec<u8>) -> WinScardResult<Vec<u8>> {
    // SIMPLE-TLV encoding
    // We do use Tlv::new() here to avoid calculating SIMPLE-TLV length ourselves (as a certificate is most certainly > 254 bytes in length)
    let certificate = Tlv::new(Tag::try_from(tlv_tags::CERTIFICATE)?, auth_cert)?.to_vec();
    let cert_info_length = 0x01;
    // 0x00 indicates that the certificate is uncompressed
    // NIST.SP.800-73-4, Part 1, Appendix A, table 39
    let cert_info_value = 0x00;
    let cert_info = &[tlv_tags::CERT_INFO, cert_info_length, cert_info_value];
    // NIST.SP.800-73-4, Part 1, Appendix A, table 10
    let edc_length = 0x00;
    let edc = &[tlv_tags::ERROR_DETECTION_CODE, edc_length];
    let data_value_len = certificate.len() + cert_info.len() + edc.len();
    // BER-TLV encoding of the data_value_len
    let encoded_data_value_len = ber_tlv_length_encoding(data_value_len);
    let mut result: Vec<u8> = Vec::with_capacity(1 + encoded_data_value_len.len() + data_value_len);
    result.extend_from_slice(&[tlv_tags::DATA]);
    result.extend_from_slice(&encoded_data_value_len);
    result.extend_from_slice(&certificate);
    result.extend_from_slice(cert_info);
    result.extend_from_slice(edc);
    Ok(result)
}

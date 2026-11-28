use alloc::vec;
use alloc::vec::Vec;

/// Encodes the length in BER encoding.
pub fn ber_tlv_length_encoding(length: usize) -> Vec<u8> {
    // ISO/IEC 7816-4, Section 5.2.2.2
    if length <= 0x7F {
        // length consists of 1 byte
        vec![length.try_into().unwrap()]
    } else {
        // if the length is > 0x7F, it consists of N consecutive bytes, where N is the first 7 lower bits of the first byte in the sequence
        let mut len_bytes: Vec<_> = length.to_be_bytes().into_iter().skip_while(|x| *x == 0).collect();
        // add the first byte that indicates how many consecutive bytes represent the object's actual length
        len_bytes.insert(
            0,
            0x80 | u8::try_from(len_bytes.len()).expect("length bytes amount < u8::MAX"),
        );
        len_bytes
    }
}

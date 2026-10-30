use std::string::FromUtf16Error;

pub fn read_utf16_string(utf16_payload: &[u8], utf16_size_hint: Option<usize>) -> Result<String, FromUtf16Error> {
    let mut trimmed_utf16: Vec<u16> = if let Some(size_hint) = utf16_size_hint {
        Vec::with_capacity(size_hint)
    } else {
        Vec::with_capacity(utf16_payload.len() / 2)
    };

    for chunk in utf16_payload.chunks_exact(2) {
        let code_unit = u16::from_le_bytes([chunk[0], chunk[1]]);

        // Stop reading at the null terminator
        if code_unit == 0 {
            break;
        }

        trimmed_utf16.push(code_unit);
    }

    String::from_utf16(&trimmed_utf16)
}

pub fn null_terminated_utf16_encoded_len(utf8: &str) -> usize {
    utf8.encode_utf16().count() * 2 + 2
}

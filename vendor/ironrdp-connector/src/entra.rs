//! RDS AAD Auth messages exchanged inside authenticated TLS.
//!
//! Token acquisition and proof-of-possession signing belong to the caller.
//! See [MS-RDPBCGR] sections 2.2.18 and 5.4.5.4.1.
//! Windows `termsrv` frames these JSON messages as NUL-terminated strings on the wire.
//! Framing and message parsing are property-tested in `ironrdp-testsuite-core` rather than fuzzed in
//! `ironrdp-fuzzing`, which does not depend on `ironrdp-connector`.
//!
//! [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/

use ironrdp_core::{DecodeResult, WriteBuf, other_err};
use ironrdp_pdu::PduHint;
use serde_json::Value;

use crate::{ConnectorResult, Written, custom_err, reason_err};

// Local resource limit, not a protocol-defined maximum.
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct EntraJsonHint;

pub(crate) const ENTRA_JSON_HINT: EntraJsonHint = EntraJsonHint;

impl PduHint for EntraJsonHint {
    fn find_size(&self, bytes: &[u8]) -> DecodeResult<Option<(bool, usize)>> {
        let capped = &bytes[..bytes.len().min(MAX_MESSAGE_SIZE)];
        let offset = json_whitespace_len(capped);
        let mut stream = serde_json::Deserializer::from_slice(&capped[offset..]).into_iter::<Value>();
        match stream.next() {
            Some(Ok(Value::Object(_))) => {
                let mut end = offset + stream.byte_offset();
                if bytes.get(end) == Some(&0) {
                    end += 1;
                }
                Ok(Some((true, end)))
            }
            Some(Ok(_)) => Err(other_err!("EntraAuth", "expected a JSON object")),
            Some(Err(e)) if !e.is_eof() => Err(other_err!("EntraAuth", "invalid JSON message")),
            _ if MAX_MESSAGE_SIZE <= bytes.len() => Err(other_err!("EntraAuth", "JSON message exceeds size limit")),
            _ => Ok(None),
        }
    }
}

#[derive(Debug)]
pub(crate) struct EntraPostAuthX224Hint;

pub(crate) const ENTRA_POST_AUTH_X224_HINT: EntraPostAuthX224Hint = EntraPostAuthX224Hint;

impl PduHint for EntraPostAuthX224Hint {
    fn find_size(&self, bytes: &[u8]) -> DecodeResult<Option<(bool, usize)>> {
        let whitespace_len = json_whitespace_len(bytes);
        let Some((is_complete, pdu_len)) = ironrdp_pdu::X224_HINT.find_size(&bytes[whitespace_len..])? else {
            return Ok(None);
        };
        Ok(Some((is_complete, whitespace_len + pdu_len)))
    }
}

pub(crate) fn skip_json_whitespace(bytes: &[u8]) -> &[u8] {
    &bytes[json_whitespace_len(bytes)..]
}

fn json_whitespace_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0))
        .count()
}

pub(crate) fn server_nonce(input: &[u8]) -> ConnectorResult<String> {
    let value = message(input)?;
    let nonce = value
        .get("ts_nonce")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| reason_err!("EntraAuth", "missing or invalid server nonce"))?;
    Ok(nonce.to_owned())
}

pub(crate) fn authentication_result(input: &[u8]) -> ConnectorResult<u32> {
    let value = message(input)?;
    let result = value
        .get("authentication_result")
        .ok_or_else(|| reason_err!("EntraAuth", "missing authentication result"))?;
    // The specification illustrates a quoted integer; accept JSON integers too.
    let code = if let Some(s) = result.as_str() {
        s.parse::<i64>().ok()
    } else {
        result.as_i64()
    }
    .ok_or_else(|| reason_err!("EntraAuth", "invalid authentication result"))?;
    if let Ok(code) = u32::try_from(code) {
        Ok(code)
    } else {
        let signed = i32::try_from(code)
            .map_err(|_| reason_err!("EntraAuth", "authentication result is outside the 32-bit range"))?;
        Ok(u32::from_ne_bytes(signed.to_ne_bytes()))
    }
}

fn message(input: &[u8]) -> ConnectorResult<Value> {
    if MAX_MESSAGE_SIZE < input.len() {
        return Err(reason_err!("EntraAuth", "JSON message exceeds size limit"));
    }
    let start = json_whitespace_len(input);
    let trimmed = &input[start..];
    let trimmed = trimmed.strip_suffix(&[0]).unwrap_or(trimmed);
    let value: Value = serde_json::from_slice(trimmed).map_err(|e| custom_err!("invalid Entra JSON message", e))?;
    if !value.is_object() {
        return Err(reason_err!("EntraAuth", "expected a JSON object"));
    }
    Ok(value)
}

pub(crate) fn write_assertion(assertion: &str, output: &mut WriteBuf) -> ConnectorResult<Written> {
    if MAX_MESSAGE_SIZE < assertion.len() {
        return Err(reason_err!("EntraAuth", "RDP assertion exceeds size limit"));
    }
    let mut parts = assertion.split('.');
    for _ in 0..3 {
        let part = parts
            .next()
            .filter(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            })
            .ok_or_else(|| reason_err!("EntraAuth", "expected a compact JWS RDP assertion"))?;
        if part.len() % 4 == 1 {
            return Err(reason_err!("EntraAuth", "invalid Base64URL assertion segment"));
        }
    }
    if parts.next().is_some() {
        return Err(reason_err!("EntraAuth", "expected three compact JWS segments"));
    }
    let mut message = serde_json::to_vec(&serde_json::json!({ "rdp_assertion": assertion }))
        .map_err(|e| custom_err!("encoding RDP assertion", e))?;
    // Windows `termsrv` requires the RDS AAD JSON message to be NUL-terminated on the wire.
    message.push(0);
    if MAX_MESSAGE_SIZE < message.len() {
        return Err(reason_err!("EntraAuth", "JSON message exceeds size limit"));
    }
    let written = Written::from_size(message.len())?;
    output.write_slice(&message);
    Ok(written)
}

use std::io;

use der_parser::parse_der;
use num_bigint::BigUint;

pub(crate) fn encrypt_with_public_key(message: &[u8], public_key_der: &[u8]) -> io::Result<Vec<u8>> {
    let (_, der_object) = parse_der(public_key_der).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unable to parse public key from DER: {err:?}"),
        )
    })?;

    let der_object_sequence = der_object.as_sequence().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unable to extract a sequence from the DER object: {err:?}"),
        )
    })?;

    if der_object_sequence.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DER object sequence is empty",
        ));
    }

    let n = der_object_sequence[0].as_slice().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unable to extract a slice from public key modulus sequence: {err:?}"),
        )
    })?;

    let e = der_object_sequence[1].as_slice().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unable to extract a slice from public key exponent sequence: {err:?}"),
        )
    })?;

    let n = BigUint::from_bytes_be(n);
    let e = BigUint::from_bytes_be(e);
    let m = BigUint::from_bytes_le(message);
    let c = m.modpow(&e, &n);

    let mut result = c.to_bytes_le();
    result.resize(result.len() + 8, 0u8);

    Ok(result)
}

use num_bigint::BigUint;

use crate::VncError;

/// Reject degenerate Diffie-Hellman values before doing any modular arithmetic.
pub(super) fn validate(g: &BigUint, p: &BigUint, peer: &BigUint) -> Result<(), VncError> {
    let one = BigUint::from(1u8);
    if p <= &one || g <= &one || g >= p {
        return Err(VncError::ArdProtocol(
            "invalid Diffie-Hellman generator or modulus".into(),
        ));
    }
    let p_minus_one = p - &one;
    if peer <= &one || peer >= &p_minus_one {
        return Err(VncError::ArdProtocol(
            "Diffie-Hellman peer key out of range".into(),
        ));
    }
    Ok(())
}

/// Generate an ephemeral private key in `[2, p - 2]` and the matching public key.
pub(super) fn generate_keypair(
    g: &BigUint,
    p: &BigUint,
    key_len: usize,
) -> Result<(BigUint, BigUint), VncError> {
    let mut random = vec![0u8; key_len];
    getrandom::getrandom(&mut random)
        .map_err(|e| VncError::General(format!("ARD: no randomness available: {e}")))?;
    let private = BigUint::from_bytes_be(&random) % (p - BigUint::from(3u8)) + BigUint::from(2u8);
    let public = g.modpow(&private, p);
    Ok((private, public))
}

pub(super) fn shared_secret(peer: &BigUint, private: &BigUint, p: &BigUint) -> BigUint {
    peer.modpow(private, p)
}

/// Fixed-length big-endian representation, left-padded with zeros.
pub(super) fn to_fixed_be(value: &BigUint, key_len: usize) -> Result<Vec<u8>, VncError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > key_len {
        return Err(VncError::ArdProtocol(
            "Diffie-Hellman value exceeds the negotiated key length".into(),
        ));
    }
    let mut out = vec![0u8; key_len];
    out[key_len - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_length_serialization_pads_and_rejects_overflow() {
        assert_eq!(
            to_fixed_be(&BigUint::from(0x0102u32), 4).unwrap(),
            [0, 0, 1, 2]
        );
        assert!(to_fixed_be(&(BigUint::from(1u8) << 32u32), 4).is_err());
    }

    #[test]
    fn key_exchange_agrees_on_the_shared_secret() {
        // Mersenne prime 2^127 - 1.
        let p = (BigUint::from(1u8) << 127u32) - BigUint::from(1u8);
        let g = BigUint::from(2u8);
        let (a_private, a_public) = generate_keypair(&g, &p, 16).unwrap();
        let (b_private, b_public) = generate_keypair(&g, &p, 16).unwrap();
        assert_eq!(g.modpow(&a_private, &p), a_public);
        assert_eq!(
            shared_secret(&b_public, &a_private, &p),
            shared_secret(&a_public, &b_private, &p)
        );
    }

    #[test]
    fn degenerate_values_are_rejected() {
        let p = BigUint::from(23u8);
        let g = BigUint::from(5u8);
        for peer in [BigUint::from(0u8), BigUint::from(1u8), p.clone() - 1u8] {
            assert!(validate(&g, &p, &peer).is_err());
        }
        assert!(validate(&BigUint::from(1u8), &p, &BigUint::from(4u8)).is_err());
        assert!(validate(&p, &p, &BigUint::from(4u8)).is_err());
        assert!(validate(&g, &p, &BigUint::from(4u8)).is_ok());
    }
}

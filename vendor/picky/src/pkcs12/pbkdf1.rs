use crate::pkcs12::Pkcs12HashAlgorithm;

pub enum Pbkdf1Usage {
    Key,
    Iv,
    Mac,
}

impl Pbkdf1Usage {
    fn to_id_byte(&self) -> u8 {
        match self {
            Pbkdf1Usage::Key => 1,
            Pbkdf1Usage::Iv => 2,
            Pbkdf1Usage::Mac => 3,
        }
    }
}

/// PBKDF1 implementation for PKCS#12 as defined in [RFC](https://datatracker.ietf.org/doc/html/rfc7292#appendix-B.2)
pub fn pbkdf1(
    hash: Pkcs12HashAlgorithm,
    password: &[u8],
    salt: &[u8],
    kdf_iterations: usize,
    usage: Pbkdf1Usage,
    output_size: usize,
) -> Vec<u8> {
    let u = hash.pbkdf1_u_bits() / 8;
    let v = hash.pbkdf1_v_bits() / 8;

    let hash_round = match hash {
        Pkcs12HashAlgorithm::Sha1 => pbkdf1_hash_round::<sha1::Sha1>,
        Pkcs12HashAlgorithm::Sha224 => pbkdf1_hash_round::<sha2::Sha224>,
        Pkcs12HashAlgorithm::Sha256 => pbkdf1_hash_round::<sha2::Sha256>,
        Pkcs12HashAlgorithm::Sha384 => pbkdf1_hash_round::<sha2::Sha384>,
        Pkcs12HashAlgorithm::Sha512 => pbkdf1_hash_round::<sha2::Sha512>,
    };

    // Construct "diversifier" string
    let d = vec![usage.to_id_byte(); v];

    let expanded_length = |len: usize| v * len.div_ceil(v);

    // Expand salt and password length to multiple of V
    let expanded_salt = salt.iter().cycle().take(expanded_length(salt.len()));
    let expanded_password = password.iter().cycle().take(expanded_length(password.len()));

    // I = S || P
    let mut key_material: Vec<u8> = expanded_salt.chain(expanded_password).cloned().collect();

    let c = output_size.div_ceil(u);

    let mut output: Vec<u8> = vec![];

    // Temporary buffer for key blocks produced by SHA1
    let mut key_block = vec![];

    let mut b = vec![];

    for _ in 1..c {
        hash_round(&d, &key_material, kdf_iterations, &mut key_block);
        output.extend_from_slice(&key_block);

        // Create concatenated string B of length V
        b.clear();
        b.extend(key_block.iter().cycle().take(v).copied());

        // Pretty convoluted operation which is defined in RFC as follows:
        //
        // C.  Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
        // blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
        // setting I_j=(I_j+B+1) mod 2^v for each j.
        //
        // Implementation of this part has been borrowed from [p12 crate](https://github.com/hjiayz/p12)
        let b_iter = b.iter().rev().cycle().take(key_material.len());
        let i_b_iter = key_material.iter_mut().rev().zip(b_iter);
        let mut inc = 1u8;
        for (i3, (ii, bi)) in i_b_iter.enumerate() {
            if (i3 % v) == 0 {
                inc = 1;
            }
            let (ii2, inc2) = ii.overflowing_add(*bi);
            let (ii3, inc3) = ii2.overflowing_add(inc);
            inc = (inc2 || inc3) as u8;
            *ii = ii3;
        }
    }

    hash_round(&d, &key_material, kdf_iterations, &mut key_block);
    output.extend_from_slice(&key_block);

    // Truncate to output_size
    output.resize(output_size, 0);
    output
}

fn pbkdf1_hash_round<H: digest::Digest + digest::FixedOutputReset>(
    d: &[u8],
    i: &[u8],
    iterations: usize,
    output_buffer: &mut Vec<u8>,
) {
    let mut hasher = H::new();
    output_buffer.clear();
    output_buffer.extend_from_slice(d);
    output_buffer.extend_from_slice(i);

    for _ in 0..iterations {
        digest::Digest::update(&mut hasher, &output_buffer);
        let hash = hasher.finalize_reset();
        output_buffer.clear();
        output_buffer.extend_from_slice(&hash[..]);
    }
}

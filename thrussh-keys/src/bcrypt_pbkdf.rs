// From the rust-crypto project.

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::blowfish::*;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use sha2::{Sha512, Digest};

fn bcrypt_hash(hpass: &[u8], hsalt: &[u8], output: &mut [u8; 32]) {
    let mut bf = Blowfish::init_state();
    bf.salted_expand_key(hsalt, hpass);

    for _ in 0..64 {
        bf.expand_key(hsalt);
        bf.expand_key(hpass);
    }

    // b"OxychromaticBlowfishSwatDynamite"
    let mut buf: [u32; 8] = [
        1333295459, 1752330093, 1635019107, 1114402679, 1718186856, 1400332660, 1148808801,
        1835627621,
    ];
    let mut i = 0;
    while i < 8 {
        for _ in 0..64 {
            let (l, r) = bf.encrypt(buf[i], buf[i + 1]);
            buf[i] = l;
            buf[i + 1] = r;
        }
        i += 2
    }

    for i in 0..8 {
        LittleEndian::write_u32(&mut output[i * 4..(i + 1) * 4], buf[i]);
    }
}

pub fn bcrypt_pbkdf(password: &[u8], salt: &[u8], rounds: u32, output: &mut [u8]) {
    assert!(password.len() > 0);
    assert!(salt.len() > 0);
    assert!(rounds > 0);
    assert!(output.len() > 0);
    assert!(output.len() <= 1024);

    let nblocks = (output.len() + 31) / 32;

    let hpass = {
        let mut hasher = Sha512::new();
        hasher.update(password);
        hasher.finalize()
    };

    for block in 1..(nblocks + 1) {
        let mut count = [0u8; 4];
        let mut out = [0u8; 32];
        BigEndian::write_u32(&mut count, block as u32);

        let mut hasher = Sha512::new();
        hasher.update(salt);
        hasher.update(&count);
        let hsalt = hasher.finalize();

        bcrypt_hash(hpass.as_ref(), hsalt.as_ref(), &mut out);
        let mut tmp = out;

        for _ in 1..rounds {
            let mut hasher = sha2::Sha512::new();
            hasher.update(&tmp);
            let hsalt = hasher.finalize();

            bcrypt_hash(hpass.as_ref(), hsalt.as_ref(), &mut tmp);
            for i in 0..out.len() {
                out[i] ^= tmp[i];
            }

            for i in 0..out.len() {
                let idx = i * nblocks + (block - 1);
                if idx < output.len() {
                    output[idx] = out[i];
                }
            }
        }
    }
}

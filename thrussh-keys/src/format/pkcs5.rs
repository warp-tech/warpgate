use super::{pkcs_unpad, Encryption};
use crate::key;
use crate::Error;

use aes::*;
use block_modes::block_padding::NoPadding;
use block_modes::BlockMode;
type Aes128Cbc = block_modes::Cbc<Aes128, NoPadding>;

/// Decode a secret key in the PKCS#5 format, possible deciphering it
/// using the supplied password.
#[cfg(feature = "openssl")]
pub fn decode_pkcs5(
    secret: &[u8],
    password: Option<&str>,
    enc: Encryption,
) -> Result<key::KeyPair, Error> {
    if let Some(pass) = password {
        let sec = match enc {
            Encryption::Aes128Cbc(ref iv) => {
                let mut c = md5::Context::new();
                c.consume(pass.as_bytes());
                c.consume(&iv[..8]);
                let md5 = c.compute();

                let c = Aes128Cbc::new_from_slices(&md5.0, &iv[..]).unwrap();
                let mut dec = secret.to_vec();
                c.decrypt(&mut dec).unwrap();
                pkcs_unpad(&mut dec);
                dec
            }
            Encryption::Aes256Cbc(_) => unimplemented!(),
        };
        super::decode_rsa(&sec)
    } else {
        Err(Error::KeyIsEncrypted)
    }
}

extern crate libc;
#[macro_use] extern crate lazy_static;
use libc::c_ulonglong;
use libsodium_sys::*;

lazy_static!{
    static ref SODIUM: i32 = unsafe { sodium_init() };
}

pub mod chacha20 {
    use super::*;
    pub const NONCE_BYTES: usize = 8;
    pub const KEY_BYTES: usize = 32;
    pub struct Nonce(pub [u8; NONCE_BYTES]);
    pub struct Key(pub [u8; KEY_BYTES]);
    pub fn chacha20_xor(c: &mut [u8], n: &Nonce, k: &Key) {
        lazy_static::initialize(&super::SODIUM);
        unsafe {
            crypto_stream_chacha20_xor(
                c.as_mut_ptr(),
                c.as_ptr(),
                c.len() as c_ulonglong,
                n.0.as_ptr(),
                k.0.as_ptr(),
            );
        }
    }

    pub fn chacha20_xor_ic(c: &mut [u8], n: &Nonce, ic: u64, k: &Key) {
        lazy_static::initialize(&super::SODIUM);
        unsafe {
            crypto_stream_chacha20_xor_ic(
                c.as_mut_ptr(),
                c.as_ptr(),
                c.len() as c_ulonglong,
                n.0.as_ptr(),
                ic,
                k.0.as_ptr(),
            );
        }
    }
}

pub mod poly1305 {
    use super::*;
    pub const KEY_BYTES: usize = 32;
    pub const TAG_BYTES: usize = 16;
    pub struct Key(pub [u8; KEY_BYTES]);
    pub struct Tag(pub [u8; TAG_BYTES]);
    pub fn poly1305_auth(m: &[u8], key: &Key) -> Tag {
        lazy_static::initialize(&super::SODIUM);
        let mut tag = Tag([0; TAG_BYTES]);
        unsafe {
            crypto_onetimeauth(
                tag.0.as_mut_ptr(),
                m.as_ptr(),
                m.len() as c_ulonglong,
                key.0.as_ptr(),
            );
        }
        tag
    }
    pub fn poly1305_verify(tag: &[u8], m: &[u8], key: &Key) -> bool {
        lazy_static::initialize(&super::SODIUM);
        if tag.len() != TAG_BYTES {
            false
        } else {
            unsafe {
                crypto_onetimeauth_verify(
                    tag.as_ptr(),
                    m.as_ptr(),
                    m.len() as c_ulonglong,
                    key.0.as_ptr(),
                ) == 0
            }
        }
    }
}

pub mod ed25519 {
    use super::*;
    pub const PUBLICKEY_BYTES: usize = 32;
    pub const SECRETKEY_BYTES: usize = 64;
    pub const SIGNATURE_BYTES: usize = 64;

    /// Ed25519 public key.
    #[derive(Debug, PartialEq, Eq)]
    pub struct PublicKey {
        /// Actual key
        pub key: [u8; PUBLICKEY_BYTES],
    }

    impl PublicKey {
        pub fn new_zeroed() -> Self {
            PublicKey {
                key: [0; PUBLICKEY_BYTES],
            }
        }
    }

    /// Ed25519 secret key.
    #[derive(Clone)]
    pub struct SecretKey {
        /// Actual key
        pub key: [u8; SECRETKEY_BYTES],
    }

    impl SecretKey {
        pub fn new_zeroed() -> Self {
            SecretKey {
                key: [0; SECRETKEY_BYTES],
            }
        }
    }

    pub struct Signature(pub [u8; SIGNATURE_BYTES]);

    /// Generate a key pair.
    pub fn keypair() -> (PublicKey, SecretKey) {
        unsafe {
            lazy_static::initialize(&super::SODIUM);
            let mut pk = PublicKey {
                key: [0; PUBLICKEY_BYTES],
            };
            let mut sk = SecretKey {
                key: [0; SECRETKEY_BYTES],
            };
            crypto_sign_keypair(pk.key.as_mut_ptr(), sk.key.as_mut_ptr());
            (pk, sk)
        }
    }

    /// Verify a signature, `sig` could as well be a `Signature`.
    pub fn verify_detached(sig: &[u8], m: &[u8], pk: &PublicKey) -> bool {
        lazy_static::initialize(&super::SODIUM);
        if sig.len() == SIGNATURE_BYTES {
            unsafe {
                crypto_sign_verify_detached(
                    sig.as_ptr(),
                    m.as_ptr(),
                    m.len() as c_ulonglong,
                    pk.key.as_ptr(),
                ) == 0
            }
        } else {
            false
        }
    }

    /// Sign a message with a secret key.
    pub fn sign_detached(m: &[u8], sk: &SecretKey) -> Signature {
        lazy_static::initialize(&super::SODIUM);
        let mut sig = Signature([0; SIGNATURE_BYTES]);
        let mut sig_len = 0;
        unsafe {
            crypto_sign_detached(
                sig.0.as_mut_ptr(),
                &mut sig_len,
                m.as_ptr(),
                m.len() as c_ulonglong,
                sk.key.as_ptr(),
            );
        }
        sig
    }
}

pub mod aes256gcm {
    use super::*;
    pub const NONCE_BYTES: usize = crypto_aead_aes256gcm_NPUBBYTES as usize;
    pub const KEY_BYTES: usize = crypto_aead_aes256gcm_KEYBYTES as usize;
    pub const TAG_BYTES: usize = crypto_aead_aes256gcm_ABYTES as usize;
    pub struct Key(pub [u8; KEY_BYTES]);
    pub struct Nonce(pub [u8; NONCE_BYTES]);
    pub struct Tag(pub [u8; TAG_BYTES]);

    pub fn aes256gcm_encrypt(ciphertext: &mut [u8], tag: &mut [u8], message: &[u8], ad: &[u8], nonce: &Nonce, key: &Key) -> bool {
        lazy_static::initialize(&super::SODIUM);
        if tag.len() != TAG_BYTES {
            false
        } else {
            unsafe {
                let ret = crypto_aead_aes256gcm_encrypt_detached(
                    ciphertext.as_mut_ptr(),
                    tag.as_mut_ptr(),
                    std::ptr::null_mut(),
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                    ad.as_ptr(),
                    ad.len() as c_ulonglong,
                    std::ptr::null_mut(),
                    nonce.0.as_ptr(),
                    key.0.as_ptr(),
                );
                ret == 0
            }
        }
    }

    pub fn aes256gcm_decrypt(message: &mut [u8], tag: &[u8], ciphertext: &[u8], ad: &[u8], nonce: &Nonce, key: &Key) -> bool {
        lazy_static::initialize(&super::SODIUM);
        if tag.len() != TAG_BYTES {
            false
        } else {
            unsafe {
                crypto_aead_aes256gcm_decrypt_detached(
                    message.as_mut_ptr(),
                    std::ptr::null_mut(),
                    ciphertext.as_ptr(),
                    ciphertext.len() as c_ulonglong,
                    tag.as_ptr(),
                    ad.as_ptr(),
                    ad.len() as c_ulonglong,
                    nonce.0.as_ptr(),
                    key.0.as_ptr(),
                ) == 0
            }
        }
    }
}

pub mod scalarmult {
    use super::*;
    pub const BYTES: usize = 32;

    #[derive(Debug)]
    pub struct Scalar(pub [u8; BYTES]);
    #[derive(Debug)]
    pub struct GroupElement(pub [u8; BYTES]);

    pub fn scalarmult_base(n: &Scalar) -> GroupElement {
        lazy_static::initialize(&super::SODIUM);
        let mut q = GroupElement([0; BYTES]);
        unsafe {
            crypto_scalarmult_curve25519_base(q.0.as_mut_ptr(), n.0.as_ptr());
        }
        q
    }

    pub fn scalarmult(n: &Scalar, p: &GroupElement) -> GroupElement {
        lazy_static::initialize(&super::SODIUM);
        let mut q = GroupElement([0; BYTES]);
        unsafe {
            crypto_scalarmult_curve25519(q.0.as_mut_ptr(), n.0.as_ptr(), p.0.as_ptr());
        }
        q
    }
}

pub mod random {
    use libc::c_void;
    use libsodium_sys::randombytes_buf;

    pub fn randombytes(buf: &mut [u8]) {
        unsafe {
            randombytes_buf(buf.as_mut_ptr() as *mut c_void, buf.len());
        }
    }
}

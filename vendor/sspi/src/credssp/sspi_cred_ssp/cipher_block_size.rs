use rustls::CipherSuite;

// [Block Size and Padding](https://www.rfc-editor.org/rfc/rfc3826#section-3.1.1.3)
// The block size of the AES cipher is 128 bits
const AES_BLOCK_SIZE: u32 = 16;

// [Data Size](https://www.rfc-editor.org/rfc/rfc1851#section-1.3)
// The 3DES algorithm operates on blocks of eight octets. This often requires padding after
// the end of the unencrypted payload data.
const DES_BLOCK_SIZE: u32 = 8;

use crate::{Error, ErrorKind, Result};

pub(super) fn get_cipher_block_size(cipher: CipherSuite) -> Result<u32> {
    match cipher {
        // Block ciphers
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA => Ok(DES_BLOCK_SIZE),
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA => Ok(DES_BLOCK_SIZE),
        CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256 => Ok(AES_BLOCK_SIZE),
        CipherSuite::TLS13_AES_256_GCM_SHA384 => Ok(AES_BLOCK_SIZE),
        // Stream ciphers
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Ok(0),
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => Ok(0),
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => Ok(0),
        CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => Ok(0),
        CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => Ok(0),
        CipherSuite::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => Ok(0),
        CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => Ok(0),
        CipherSuite::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => Ok(0),
        CipherSuite::TLS_RSA_WITH_RC4_128_SHA => Ok(0),
        CipherSuite::TLS_RSA_WITH_RC4_128_MD5 => Ok(0),
        CipherSuite::TLS_RSA_EXPORT1024_WITH_RC4_56_SHA => Ok(0),
        CipherSuite::TLS_RSA_EXPORT_WITH_RC4_40_MD5 => Ok(0),
        // Unsupported ciphers or others
        cipher => Err(Error::new(
            ErrorKind::InternalError,
            format!("can not get block size of cipher: {cipher:?}"),
        )),
    }
}

mod rc4;

use std::io;

use hmac::KeyInit;
use md4::Md4;
use md5::{Digest as _, Md5};
pub(crate) use rc4::Rc4;
use sha2::Sha256;

use crate::channel_bindings::ChannelBindings;

pub(crate) const HASH_SIZE: usize = 16;

const SHA256_SIZE: usize = 32;

pub(crate) fn compute_md4(data: &[u8]) -> [u8; HASH_SIZE] {
    use md4::Digest as _;

    let mut context = Md4::new();
    let mut result = [0x00; HASH_SIZE];
    context.update(data);
    result.clone_from_slice(&context.finalize());

    result
}

pub(crate) fn compute_md5(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut context = Md5::new();
    let mut result = [0x00; HASH_SIZE];
    context.update(data);
    result.clone_from_slice(&context.finalize());

    result
}

pub(crate) fn compute_md5_channel_bindings_hash(channel_bindings: &ChannelBindings) -> [u8; HASH_SIZE] {
    let mut context = Md5::new();
    let mut result = [0x00; HASH_SIZE];

    let initiator_len = channel_bindings.initiator.len() as u32;
    context.update(channel_bindings.initiator_addr_type.to_le_bytes());
    context.update(initiator_len.to_le_bytes());
    context.update(&channel_bindings.initiator);

    let acceptor_len = channel_bindings.acceptor.len() as u32;
    context.update(channel_bindings.acceptor_addr_type.to_le_bytes());
    context.update(acceptor_len.to_le_bytes());
    context.update(&channel_bindings.acceptor);

    let application_data_len = channel_bindings.application_data.len() as u32;
    context.update(application_data_len.to_le_bytes());
    context.update(&channel_bindings.application_data);

    result.clone_from_slice(&context.finalize());

    result
}

pub(crate) fn compute_sha256(data: &[u8]) -> [u8; SHA256_SIZE] {
    let mut context = Sha256::new();
    let mut result = [0x00; SHA256_SIZE];
    context.update(data);
    result.clone_from_slice(&context.finalize());

    result
}

pub(crate) fn compute_hmac_md5(key: &[u8], input: &[u8]) -> io::Result<[u8; HASH_SIZE]> {
    use hmac::Mac as _;

    let mut mac = hmac::Hmac::<Md5>::new_from_slice(key)
        .map_err(|e| io::Error::other(format!("Failed to compute hmac md5: {e}")))?;
    let mut result = [0x00; HASH_SIZE];
    mac.update(input);
    result.clone_from_slice(&mac.finalize().into_bytes());

    Ok(result)
}

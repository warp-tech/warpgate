// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use crate::sshbuffer::SSHBuffer;
use crate::Error;
use byteorder::{BigEndian, ByteOrder};
use std::num::Wrapping;
use tokio::io::{AsyncRead, AsyncReadExt};
pub mod chacha20poly1305;
pub mod aes256gcm;
pub mod clear;

pub struct Cipher {
    pub name: Name,
    pub key_len: usize,
    pub nonce_len: usize,
    pub make_opening_cipher: fn(key: &[u8], nonce: &[u8]) -> OpeningCipher,
    pub make_sealing_cipher: fn(key: &[u8], nonce: &[u8]) -> SealingCipher,
}

pub enum OpeningCipher {
    Clear(clear::Key),
    Chacha20Poly1305(chacha20poly1305::OpeningKey),
    AES256GCM(aes256gcm::OpeningKey),
}

impl<'a> OpeningCipher {
    fn as_opening_key(&self) -> &dyn OpeningKey {
        match *self {
            OpeningCipher::Clear(ref key) => key,
            OpeningCipher::Chacha20Poly1305(ref key) => key,
            OpeningCipher::AES256GCM(ref key) => key,
        }
    }
}

pub enum SealingCipher {
    Clear(clear::Key),
    Chacha20Poly1305(chacha20poly1305::SealingKey),
    AES256GCM(aes256gcm::SealingKey),
}

impl<'a> SealingCipher {
    fn as_sealing_key(&'a self) -> &'a dyn SealingKey {
        match *self {
            SealingCipher::Clear(ref key) => key,
            SealingCipher::Chacha20Poly1305(ref key) => key,
            SealingCipher::AES256GCM(ref key) => key,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

pub struct CipherPair {
    pub local_to_remote: SealingCipher,
    pub remote_to_local: OpeningCipher,
}

impl std::fmt::Debug for CipherPair {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        Ok(())
    }
}

pub const CLEAR_PAIR: CipherPair = CipherPair {
    local_to_remote: SealingCipher::Clear(clear::Key),
    remote_to_local: OpeningCipher::Clear(clear::Key),
};

pub trait OpeningKey {
    fn decrypt_packet_length(&self, seqn: u32, encrypted_packet_length: [u8; 4]) -> [u8; 4];

    fn tag_len(&self) -> usize;

    fn open<'a>(
        &self,
        seqn: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error>;
}

pub trait SealingKey {
    fn padding_length(&self, plaintext: &[u8]) -> usize;

    fn fill_padding(&self, padding_out: &mut [u8]);

    fn tag_len(&self) -> usize;

    fn seal(&self, seqn: u32, plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]);
}

pub async fn read<'a, R: AsyncRead + Unpin>(
    stream: &'a mut R,
    buffer: &'a mut SSHBuffer,
    pair: &'a CipherPair,
) -> Result<usize, Error> {
    if buffer.len == 0 {
        let mut len = [0; 4];
        stream.read_exact(&mut len).await?;
        debug!("reading, len = {:?}", len);
        {
            let key = pair.remote_to_local.as_opening_key();
            let seqn = buffer.seqn.0;
            buffer.buffer.clear();
            buffer.buffer.extend(&len);
            debug!("reading, seqn = {:?}", seqn);
            let len = key.decrypt_packet_length(seqn, len);
            buffer.len = BigEndian::read_u32(&len) as usize + key.tag_len();
            debug!("reading, clear len = {:?}", buffer.len);
        }
    }
    buffer.buffer.resize(buffer.len + 4);
    debug!("read_exact {:?}", buffer.len + 4);
    stream.read_exact(&mut buffer.buffer[4..]).await?;
    debug!("read_exact done");
    let key = pair.remote_to_local.as_opening_key();
    let seqn = buffer.seqn.0;
    let ciphertext_len = buffer.buffer.len() - key.tag_len();
    let (ciphertext, tag) = buffer.buffer.split_at_mut(ciphertext_len);
    let plaintext = key.open(seqn, ciphertext, tag)?;

    let padding_length = plaintext[0] as usize;
    debug!("reading, padding_length {:?}", padding_length);
    let plaintext_end = plaintext
        .len()
        .checked_sub(padding_length)
        .ok_or(Error::IndexOutOfBounds)?;

    // Sequence numbers are on 32 bits and wrap.
    // https://tools.ietf.org/html/rfc4253#section-6.4
    buffer.seqn += Wrapping(1);
    buffer.len = 0;

    // Remove the padding
    buffer.buffer.resize(plaintext_end + 4);

    Ok(plaintext_end + 4)
}

impl CipherPair {
    pub fn write(&self, payload: &[u8], buffer: &mut SSHBuffer) {
        // https://tools.ietf.org/html/rfc4253#section-6
        //
        // The variables `payload`, `packet_length` and `padding_length` refer
        // to the protocol fields of the same names.
        debug!("writing, seqn = {:?}", buffer.seqn.0);
        let key = self.local_to_remote.as_sealing_key();

        let padding_length = key.padding_length(payload);
        debug!("padding length {:?}", padding_length);
        let packet_length = PADDING_LENGTH_LEN + payload.len() + padding_length;
        debug!("packet_length {:?}", packet_length);
        let offset = buffer.buffer.len();

        // Maximum packet length:
        // https://tools.ietf.org/html/rfc4253#section-6.1
        assert!(packet_length <= std::u32::MAX as usize);
        buffer.buffer.push_u32_be(packet_length as u32);

        assert!(padding_length <= std::u8::MAX as usize);
        buffer.buffer.push(padding_length as u8);
        buffer.buffer.extend(payload);
        key.fill_padding(buffer.buffer.resize_mut(padding_length));
        buffer.buffer.resize_mut(key.tag_len());

        let (plaintext, tag) =
            buffer.buffer[offset..].split_at_mut(PACKET_LENGTH_LEN + packet_length);

        key.seal(buffer.seqn.0, plaintext, tag);

        buffer.bytes += payload.len();
        // Sequence numbers are on 32 bits and wrap.
        // https://tools.ietf.org/html/rfc4253#section-6.4
        buffer.seqn += Wrapping(1);
    }
}

pub const PACKET_LENGTH_LEN: usize = 4;

const MINIMUM_PACKET_LEN: usize = 16;

const PADDING_LENGTH_LEN: usize = 1;

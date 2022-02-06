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

use crate::Error;

#[derive(Debug)]
pub struct Key;

impl super::OpeningKey for Key {
    fn decrypt_packet_length(&self, _seqn: u32, packet_length: [u8; 4]) -> [u8; 4] {
        packet_length
    }

    fn tag_len(&self) -> usize {
        0
    }

    fn open<'a>(
        &self,
        _seqn: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        debug_assert_eq!(tag.len(), 0); // self.tag_len());
        Ok(&ciphertext_in_plaintext_out[4..])
    }
}

impl super::SealingKey for Key {
    // Cleartext packets (including lengths) must be multiple of 8 in
    // length.
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 8;
        let padding_len = block_size - ((5 + payload.len()) % block_size);
        if padding_len < 4 {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        // Since the packet is unencrypted anyway, there's no advantage to
        // randomizing the padding, so avoid possibly leaking extra RNG state
        // by padding with zeros.
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize {
        0
    }

    fn seal(&self, _seqn: u32, _plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]) {
        debug_assert_eq!(tag_out.len(), self.tag_len());
    }
}

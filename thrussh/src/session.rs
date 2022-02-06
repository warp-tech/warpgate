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
use crate::{auth, cipher, kex, msg, negotiation};
use crate::{Channel, ChannelId, Disconnect, Limits};
use byteorder::{BigEndian, ByteOrder};
use cryptovec::CryptoVec;
use std::collections::HashMap;
use std::num::Wrapping;
use std::sync::Arc;
use thrussh_keys::encoding::Encoding;

#[derive(Debug)]
pub(crate) struct Encrypted {
    pub state: EncryptedState,

    // It's always Some, except when we std::mem::replace it temporarily.
    pub exchange: Option<Exchange>,
    pub kex: kex::Algorithm,
    pub key: usize,
    pub mac: Option<&'static str>,
    pub session_id: crate::Sha256Hash,
    pub rekey: Option<Kex>,
    pub channels: HashMap<ChannelId, Channel>,
    pub last_channel_id: Wrapping<u32>,
    pub wants_reply: bool,
    pub write: CryptoVec,
    pub write_cursor: usize,
    pub last_rekey: std::time::Instant,
    pub server_compression: crate::compression::Compression,
    pub client_compression: crate::compression::Compression,
    pub compress: crate::compression::Compress,
    pub decompress: crate::compression::Decompress,
    pub compress_buffer: CryptoVec,
}

pub(crate) struct CommonSession<Config> {
    pub auth_user: String,
    pub config: Config,
    pub encrypted: Option<Encrypted>,
    pub auth_method: Option<auth::Method>,
    pub write_buffer: SSHBuffer,
    pub kex: Option<Kex>,
    pub cipher: Arc<cipher::CipherPair>,
    pub wants_reply: bool,
    pub disconnected: bool,
    pub buffer: CryptoVec,
}

impl<C> CommonSession<C> {
    pub fn newkeys(&mut self, newkeys: NewKeys) {
        if let Some(ref mut enc) = self.encrypted {
            enc.exchange = Some(newkeys.exchange);
            enc.kex = newkeys.kex;
            enc.key = newkeys.key;
            enc.mac = newkeys.names.mac;
            self.cipher = Arc::new(newkeys.cipher);
        }
    }

    pub fn encrypted(&mut self, state: EncryptedState, newkeys: NewKeys) {
        self.encrypted = Some(Encrypted {
            exchange: Some(newkeys.exchange),
            kex: newkeys.kex,
            key: newkeys.key,
            mac: newkeys.names.mac,
            session_id: newkeys.session_id,
            state,
            rekey: None,
            channels: HashMap::new(),
            last_channel_id: Wrapping(1),
            wants_reply: false,
            write: CryptoVec::new(),
            write_cursor: 0,
            last_rekey: std::time::Instant::now(),
            server_compression: newkeys.names.server_compression,
            client_compression: newkeys.names.client_compression,
            compress: crate::compression::Compress::None,
            compress_buffer: CryptoVec::new(),
            decompress: crate::compression::Decompress::None,
        });
        self.cipher = Arc::new(newkeys.cipher);
    }

    /// Send a disconnect message.
    pub fn disconnect(&mut self, reason: Disconnect, description: &str, language_tag: &str) {
        let disconnect = |buf: &mut CryptoVec| {
            push_packet!(buf, {
                buf.push(msg::DISCONNECT);
                buf.push_u32_be(reason as u32);
                buf.extend_ssh_string(description.as_bytes());
                buf.extend_ssh_string(language_tag.as_bytes());
            });
        };
        if !self.disconnected {
            self.disconnected = true;
            if let Some(ref mut enc) = self.encrypted {
                disconnect(&mut enc.write)
            } else {
                disconnect(&mut self.write_buffer.buffer)
            }
        }
    }

    /// Send a single byte message onto the channel.
    pub fn byte(&mut self, channel: ChannelId, msg: u8) {
        if let Some(ref mut enc) = self.encrypted {
            enc.byte(channel, msg)
        }
    }
}

impl Encrypted {
    pub fn byte(&mut self, channel: ChannelId, msg: u8) {
        if let Some(channel) = self.channels.get(&channel) {
            push_packet!(self.write, {
                self.write.push(msg);
                self.write.push_u32_be(channel.recipient_channel);
            });
        }
    }

    /*
    pub fn authenticated(&mut self) {
        self.server_compression.init_compress(&mut self.compress);
        self.state = EncryptedState::Authenticated;
    }
    */

    pub fn eof(&mut self, channel: ChannelId) {
        self.byte(channel, msg::CHANNEL_EOF);
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if let Some(ref channel) = self.channels.get(&channel) {
            channel.sender_window_size as usize
        } else {
            0
        }
    }

    pub fn adjust_window_size(&mut self, channel: ChannelId, data: &[u8], target: u32) -> bool {
        debug!("adjust_window_size");
        if let Some(ref mut channel) = self.channels.get_mut(&channel) {
            debug!("channel {:?}", channel);
            // Ignore extra data.
            // https://tools.ietf.org/html/rfc4254#section-5.2
            if data.len() as u32 <= channel.sender_window_size {
                channel.sender_window_size -= data.len() as u32;
            }
            if channel.sender_window_size < target / 2 {
                debug!(
                    "sender_window_size {:?}, target {:?}",
                    channel.sender_window_size, target
                );
                push_packet!(self.write, {
                    self.write.push(msg::CHANNEL_WINDOW_ADJUST);
                    self.write.push_u32_be(channel.recipient_channel);
                    self.write.push_u32_be(target - channel.sender_window_size);
                });
                channel.sender_window_size = target;
                return true;
            }
        }
        false
    }

    pub fn flush_pending(&mut self, channel: ChannelId) -> usize {
        let mut pending_size = 0;
        if let Some(channel) = self.channels.get_mut(&channel) {
            while let Some((buf, a, from)) = channel.pending_data.pop_front() {
                let size = Self::data_noqueue(&mut self.write, channel, &buf, from);
                pending_size += size;
                if from + size < buf.len() {
                    channel.pending_data.push_front((buf, a, from + size));
                    break;
                }
            }
        }
        pending_size
    }

    pub fn flush_all_pending(&mut self) {
        for (_, channel) in self.channels.iter_mut() {
            while let Some((buf, a, from)) = channel.pending_data.pop_front() {
                let size = Self::data_noqueue(&mut self.write, channel, &buf, from);
                if from + size < buf.len() {
                    channel.pending_data.push_front((buf, a, from + size));
                    break;
                }
            }
        }
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
        if let Some(channel) = self.channels.get(&channel) {
            !channel.pending_data.is_empty()
        } else {
            false
        }
    }

    /// Push the largest amount of `&buf0[from..]` that can fit into
    /// the window, dividing it into packets if it is too large, and
    /// return the length that was written.
    fn data_noqueue(
        write: &mut CryptoVec,
        channel: &mut Channel,
        buf0: &[u8],
        from: usize,
    ) -> usize {
        let mut buf = if buf0.len() as u32 > from as u32 + channel.recipient_window_size {
            &buf0[from..from + channel.recipient_window_size as usize]
        } else {
            &buf0[from..]
        };
        let buf_len = buf.len();

        while buf.len() > 0 {
            // Compute the length we're allowed to send.
            let off = std::cmp::min(buf.len(), channel.recipient_maximum_packet_size as usize);
            push_packet!(write, {
                write.push(msg::CHANNEL_DATA);
                write.push_u32_be(channel.recipient_channel);
                write.extend_ssh_string(&buf[..off]);
            });
            debug!(
                "buffer: {:?} {:?}",
                write.len(),
                channel.recipient_window_size
            );
            channel.recipient_window_size -= off as u32;
            buf = &buf[off..]
        }
        debug!("buf.len() = {:?}, buf_len = {:?}", buf.len(), buf_len);
        buf_len
    }

    pub fn data(&mut self, channel: ChannelId, buf0: CryptoVec) {
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() || self.rekey.is_some() {
                channel.pending_data.push_back((buf0, None, 0));
                return;
            }
            let buf_len = Self::data_noqueue(&mut self.write, channel, &buf0, 0);
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, None, buf_len))
            }
        }
    }

    pub fn extended_data(&mut self, channel: ChannelId, ext: u32, buf0: CryptoVec) {
        use std::ops::Deref;
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() {
                channel.pending_data.push_back((buf0, Some(ext), 0));
                return;
            }
            let mut buf = if buf0.len() as u32 > channel.recipient_window_size {
                &buf0[0..channel.recipient_window_size as usize]
            } else {
                &buf0
            };
            let buf_len = buf.len();

            while buf.len() > 0 {
                // Compute the length we're allowed to send.
                let off = std::cmp::min(buf.len(), channel.recipient_maximum_packet_size as usize);
                push_packet!(self.write, {
                    self.write.push(msg::CHANNEL_EXTENDED_DATA);
                    self.write.push_u32_be(channel.recipient_channel);
                    self.write.push_u32_be(ext);
                    self.write.extend_ssh_string(&buf[..off]);
                });
                debug!("buffer: {:?}", self.write.deref().len());
                channel.recipient_window_size -= off as u32;
                buf = &buf[off..]
            }
            debug!("buf.len() = {:?}, buf_len = {:?}", buf.len(), buf_len);
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, Some(ext), buf_len))
            }
        }
    }

    pub fn flush(
        &mut self,
        limits: &Limits,
        cipher: &cipher::CipherPair,
        write_buffer: &mut SSHBuffer,
    ) -> bool {
        // If there are pending packets (and we've not started to rekey), flush them.
        {
            while self.write_cursor < self.write.len() {
                // Read a single packet, encrypt and send it.
                let len = BigEndian::read_u32(&self.write[self.write_cursor..]) as usize;
                let packet = self
                    .compress
                    .compress(
                        &self.write[(self.write_cursor + 4)..(self.write_cursor + 4 + len)],
                        &mut self.compress_buffer,
                    )
                    .unwrap();
                cipher.write(packet, write_buffer);
                self.write_cursor += 4 + len
            }
        }
        if self.write_cursor >= self.write.len() {
            // If all packets have been written, clear.
            self.write_cursor = 0;
            self.write.clear();
        }
        let now = std::time::Instant::now();
        let dur = now.duration_since(self.last_rekey);
        write_buffer.bytes >= limits.rekey_write_limit || dur >= limits.rekey_time_limit
    }
    pub fn new_channel_id(&mut self) -> ChannelId {
        self.last_channel_id += Wrapping(1);
        while self
            .channels
            .contains_key(&ChannelId(self.last_channel_id.0))
        {
            self.last_channel_id += Wrapping(1)
        }
        ChannelId(self.last_channel_id.0)
    }
    pub fn new_channel(&mut self, window_size: u32, maxpacket: u32) -> ChannelId {
        loop {
            self.last_channel_id += Wrapping(1);
            if let std::collections::hash_map::Entry::Vacant(vacant_entry) =
                self.channels.entry(ChannelId(self.last_channel_id.0))
            {
                vacant_entry.insert(Channel {
                    recipient_channel: 0,
                    sender_channel: ChannelId(self.last_channel_id.0),
                    sender_window_size: window_size,
                    recipient_window_size: 0,
                    sender_maximum_packet_size: maxpacket,
                    recipient_maximum_packet_size: 0,
                    confirmed: false,
                    wants_reply: false,
                    pending_data: std::collections::VecDeque::new(),
                });
                return ChannelId(self.last_channel_id.0);
            }
        }
    }
}

#[derive(Debug)]
pub enum EncryptedState {
    WaitingServiceRequest { sent: bool, accepted: bool },
    WaitingAuthRequest(auth::AuthRequest),
    InitCompression,
    Authenticated,
}

#[derive(Debug)]
pub struct Exchange {
    pub client_id: CryptoVec,
    pub server_id: CryptoVec,
    pub client_kex_init: CryptoVec,
    pub server_kex_init: CryptoVec,
    pub client_ephemeral: CryptoVec,
    pub server_ephemeral: CryptoVec,
}

impl Exchange {
    pub fn new() -> Self {
        Exchange {
            client_id: CryptoVec::new(),
            server_id: CryptoVec::new(),
            client_kex_init: CryptoVec::new(),
            server_kex_init: CryptoVec::new(),
            client_ephemeral: CryptoVec::new(),
            server_ephemeral: CryptoVec::new(),
        }
    }
}

#[derive(Debug)]
pub enum Kex {
    /// Version number sent. `algo` and `sent` tell wether kexinit has
    /// been received, and sent, respectively.
    KexInit(KexInit),

    /// Algorithms have been determined, the DH algorithm should run.
    KexDh(KexDh),

    /// The kex has run.
    KexDhDone(KexDhDone),

    /// The DH is over, we've sent the NEWKEYS packet, and are waiting
    /// the NEWKEYS from the other side.
    NewKeys(NewKeys),
}

#[derive(Debug)]
pub struct KexInit {
    pub algo: Option<negotiation::Names>,
    pub exchange: Exchange,
    pub session_id: Option<crate::Sha256Hash>,
    pub sent: bool,
}

impl KexInit {
    pub fn received_rekey(
        ex: Exchange,
        algo: negotiation::Names,
        session_id: &crate::Sha256Hash,
    ) -> Self {
        let mut kexinit = KexInit {
            exchange: ex,
            algo: Some(algo),
            sent: false,
            session_id: Some(session_id.clone()),
        };
        kexinit.exchange.client_kex_init.clear();
        kexinit.exchange.server_kex_init.clear();
        kexinit.exchange.client_ephemeral.clear();
        kexinit.exchange.server_ephemeral.clear();
        kexinit
    }

    pub fn initiate_rekey(ex: Exchange, session_id: &crate::Sha256Hash) -> Self {
        let mut kexinit = KexInit {
            exchange: ex,
            algo: None,
            sent: true,
            session_id: Some(session_id.clone()),
        };
        kexinit.exchange.client_kex_init.clear();
        kexinit.exchange.server_kex_init.clear();
        kexinit.exchange.client_ephemeral.clear();
        kexinit.exchange.server_ephemeral.clear();
        kexinit
    }
}

#[derive(Debug)]
pub struct KexDh {
    pub exchange: Exchange,
    pub names: negotiation::Names,
    pub key: usize,
    pub session_id: Option<crate::Sha256Hash>,
}

#[derive(Debug)]
pub struct KexDhDone {
    pub exchange: Exchange,
    pub kex: kex::Algorithm,
    pub key: usize,
    pub session_id: Option<crate::Sha256Hash>,
    pub names: negotiation::Names,
}

impl KexDhDone {
    pub fn compute_keys(
        self,
        hash: crate::Sha256Hash,
        is_server: bool,
    ) -> Result<NewKeys, crate::Error> {
        let session_id = if let Some(session_id) = self.session_id {
            session_id
        } else {
            hash.clone()
        };
        // Now computing keys.
        let c = self
            .kex
            .compute_keys(&session_id, &hash, self.names.cipher, is_server)?;
        Ok(NewKeys {
            exchange: self.exchange,
            names: self.names,
            kex: self.kex,
            key: self.key,
            cipher: c,
            session_id: session_id,
            received: false,
            sent: false,
        })
    }
}

#[derive(Debug)]
pub struct NewKeys {
    pub exchange: Exchange,
    pub names: negotiation::Names,
    pub kex: kex::Algorithm,
    pub key: usize,
    pub cipher: cipher::CipherPair,
    pub session_id: crate::Sha256Hash,
    pub received: bool,
    pub sent: bool,
}

use super::*;
use crate::cipher::CipherPair;
use crate::key::PubKey;
use crate::negotiation::Select;
use crate::{kex, msg, negotiation};
use std::cell::RefCell;
use thrussh_keys::encoding::{Encoding, Reader};

thread_local! {
    static HASH_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

impl KexInit {
    pub fn server_parse(
        mut self,
        config: &Config,
        cipher: &CipherPair,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<Kex, Error> {
        if buf[0] == msg::KEXINIT {
            let algo = {
                // read algorithms from packet.
                self.exchange.client_kex_init.extend(buf);
                super::negotiation::Server::read_kex(buf, &config.preferred)?
            };
            if !self.sent {
                self.server_write(config, cipher, write_buffer)?
            }
            let mut key = 0;
            while key < config.keys.len() && config.keys[key].name() != algo.key.as_ref() {
                key += 1
            }
            let next_kex = if key < config.keys.len() {
                Kex::KexDh(KexDh {
                    exchange: self.exchange,
                    key: key,
                    names: algo,
                    session_id: self.session_id,
                })
            } else {
                return Err(Error::UnknownKey.into());
            };

            Ok(next_kex)
        } else {
            Ok(Kex::KexInit(self))
        }
    }

    pub fn server_write(
        &mut self,
        config: &Config,
        cipher: &CipherPair,
        write_buffer: &mut SSHBuffer,
    ) -> Result<(), Error> {
        self.exchange.server_kex_init.clear();
        negotiation::write_kex(&config.preferred, &mut self.exchange.server_kex_init)?;
        debug!("server kex init: {:?}", &self.exchange.server_kex_init[..]);
        self.sent = true;
        cipher.write(&self.exchange.server_kex_init, write_buffer);
        Ok(())
    }
}

impl KexDh {
    pub fn parse(
        mut self,
        config: &Config,
        cipher: &CipherPair,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<Kex, Error> {
        if self.names.ignore_guessed {
            // If we need to ignore this packet.
            self.names.ignore_guessed = false;
            Ok(Kex::KexDh(self))
        } else {
            // Else, process it.
            assert!(buf[0] == msg::KEX_ECDH_INIT);
            let mut r = buf.reader(1);
            self.exchange.client_ephemeral.extend(r.read_string()?);
            let kex = kex::Algorithm::server_dh(self.names.kex, &mut self.exchange, buf)?;
            // Then, we fill the write buffer right away, so that we
            // can output it immediately when the time comes.
            let kexdhdone = KexDhDone {
                exchange: self.exchange,
                kex: kex,
                key: self.key,
                names: self.names,
                session_id: self.session_id,
            };
            let hash: Result<_, Error> = HASH_BUF.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                buffer.clear();
                debug!("server kexdhdone.exchange = {:?}", kexdhdone.exchange);
                let hash = kexdhdone.kex.compute_exchange_hash(
                    &config.keys[kexdhdone.key],
                    &kexdhdone.exchange,
                    &mut buffer,
                )?;
                debug!("exchange hash: {:?}", hash);
                buffer.clear();
                buffer.push(msg::KEX_ECDH_REPLY);
                config.keys[kexdhdone.key].push_to(&mut buffer);
                // Server ephemeral
                buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
                // Hash signature
                debug!("signing with key {:?}", kexdhdone.key);
                debug!("hash: {:?}", hash);
                debug!("key: {:?}", config.keys[kexdhdone.key]);
                config.keys[kexdhdone.key].add_signature(&mut buffer, &hash)?;
                cipher.write(&buffer, write_buffer);
                cipher.write(&[msg::NEWKEYS], write_buffer);
                Ok(hash)
            });

            Ok(Kex::NewKeys(kexdhdone.compute_keys(hash?, true)?))
        }
    }
}

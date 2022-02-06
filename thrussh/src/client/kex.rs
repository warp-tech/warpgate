use super::*;
use crate::cipher::CipherPair;
use crate::negotiation;
use crate::negotiation::Select;

use crate::kex;

impl KexInit {
    pub fn client_parse(
        mut self,
        config: &Config,
        cipher: &CipherPair,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<KexDhDone, Error> {
        debug!("client parse {:?} {:?}", buf.len(), buf);
        let algo = {
            // read algorithms from packet.
            debug!("extending {:?}", &self.exchange.server_kex_init[..]);
            self.exchange.server_kex_init.extend(buf);
            super::negotiation::Client::read_kex(buf, &config.preferred)?
        };
        debug!("algo = {:?}", algo);
        debug!("write = {:?}", &write_buffer.buffer[..]);
        if !self.sent {
            self.client_write(config, cipher, write_buffer)?
        }

        // This function is called from the public API.
        //
        // In order to simplify the public API, we reuse the
        // self.exchange.client_kex buffer to send an extra packet,
        // then truncate that buffer. Without that, we would need an
        // extra buffer.
        let i0 = self.exchange.client_kex_init.len();
        debug!("i0 = {:?}", i0);
        let kex = kex::Algorithm::client_dh(
            algo.kex,
            &mut self.exchange.client_ephemeral,
            &mut self.exchange.client_kex_init,
        )?;

        cipher.write(&self.exchange.client_kex_init[i0..], write_buffer);
        self.exchange.client_kex_init.resize(i0);

        debug!("moving to kexdhdone, exchange = {:?}", self.exchange);
        Ok(KexDhDone {
            exchange: self.exchange,
            names: algo,
            kex: kex,
            key: 0,
            session_id: self.session_id,
        })
    }

    pub fn client_write(
        &mut self,
        config: &Config,
        cipher: &CipherPair,
        write_buffer: &mut SSHBuffer,
    ) -> Result<(), Error> {
        self.exchange.client_kex_init.clear();
        negotiation::write_kex(&config.preferred, &mut self.exchange.client_kex_init)?;
        self.sent = true;
        cipher.write(&self.exchange.client_kex_init, write_buffer);
        Ok(())
    }
}

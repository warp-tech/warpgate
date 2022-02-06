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
use super::super::*;
use super::*;
use auth::*;
use byteorder::{BigEndian, ByteOrder};
use msg;
use negotiation;
use negotiation::Select;
use std::cell::RefCell;
use thrussh_keys::encoding::{Encoding, Position, Reader};
use thrussh_keys::key;
use thrussh_keys::key::Verify;
use tokio::time::Instant;

impl Session {
    /// Returns false iff a request was rejected.
    pub(in crate) async fn server_read_encrypted<H: Handler>(
        mut self,
        handler: &mut Option<H>,
        buf: &[u8],
    ) -> Result<Self, H::Error> {
        debug!(
            "server_read_encrypted, buf = {:?}",
            &buf[..buf.len().min(20)]
        );
        // Either this packet is a KEXINIT, in which case we start a key re-exchange.

        let mut enc = self.common.encrypted.as_mut().unwrap();
        if buf[0] == msg::KEXINIT {
            debug!("Received rekeying request");
            // If we're not currently rekeying, but `buf` is a rekey request
            if let Some(Kex::KexInit(kexinit)) = enc.rekey.take() {
                enc.rekey = Some(kexinit.server_parse(
                    self.common.config.as_ref(),
                    &self.common.cipher,
                    buf,
                    &mut self.common.write_buffer,
                )?);
            } else if let Some(exchange) = enc.exchange.take() {
                let kexinit = KexInit::received_rekey(
                    exchange,
                    negotiation::Server::read_kex(buf, &self.common.config.as_ref().preferred)?,
                    &enc.session_id,
                );
                enc.rekey = Some(kexinit.server_parse(
                    self.common.config.as_ref(),
                    &mut self.common.cipher,
                    buf,
                    &mut self.common.write_buffer,
                )?);
            }
            self.flush()?;
            return Ok(self);
        }

        match enc.rekey.take() {
            Some(Kex::KexDh(kexdh)) => {
                enc.rekey = Some(kexdh.parse(
                    self.common.config.as_ref(),
                    &self.common.cipher,
                    buf,
                    &mut self.common.write_buffer,
                )?);
                self.flush()?;
                return Ok(self);
            }
            Some(Kex::NewKeys(newkeys)) => {
                if buf[0] != msg::NEWKEYS {
                    return Err(Error::Kex.into());
                }
                self.common.write_buffer.bytes = 0;
                enc.last_rekey = std::time::Instant::now();

                // Ok, NEWKEYS received, now encrypted.
                enc.flush_all_pending();
                let mut pending = std::mem::replace(&mut self.pending_reads, Vec::new());
                for p in pending.drain(..) {
                    self = self.process_packet(handler, &p).await?
                }
                self.pending_reads = pending;
                self.pending_len = 0;
                self.common.newkeys(newkeys);
                self.flush()?;
                return Ok(self);
            }
            Some(Kex::KexInit(k)) => {
                enc.rekey = Some(Kex::KexInit(k));
                self.pending_len += buf.len() as u32;
                if self.pending_len > 2 * self.target_window_size {
                    return Err(Error::Pending.into())
                }
                self.pending_reads.push(CryptoVec::from_slice(buf));
                return Ok(self);
            }
            rek => {
                debug!("rek = {:?}", rek);
                enc.rekey = rek
            },
        }
        self.process_packet(handler, buf).await
    }

    async fn process_packet<H: Handler>(
        mut self,
        handler: &mut Option<H>,
        buf: &[u8],
    ) -> Result<Self, H::Error> {
        let instant = tokio::time::Instant::now() + self.common.config.auth_rejection_time;
        let mut enc = self.common.encrypted.as_mut().unwrap();
        // If we've successfully read a packet.
        match enc.state {
            EncryptedState::WaitingServiceRequest {
                ref mut accepted, ..
            } if buf[0] == msg::SERVICE_REQUEST => {
                let mut r = buf.reader(1);
                let request = r.read_string().map_err(crate::Error::from)?;
                debug!("request: {:?}", std::str::from_utf8(request));
                if request == b"ssh-userauth" {
                    let auth_request = server_accept_service(
                        self.common.config.as_ref().auth_banner,
                        self.common.config.as_ref().methods,
                        &mut enc.write,
                    );
                    *accepted = true;
                    enc.state = EncryptedState::WaitingAuthRequest(auth_request);
                }
                Ok(self)
            }
            EncryptedState::WaitingAuthRequest(_) if buf[0] == msg::USERAUTH_REQUEST => {
                enc.server_read_auth_request(instant, handler, buf, &mut self.common.auth_user)
                    .await?;
                if let EncryptedState::InitCompression = enc.state {
                    enc.client_compression.init_decompress(&mut enc.decompress);
                }
                Ok(self)
            }
            EncryptedState::WaitingAuthRequest(ref mut auth)
                if buf[0] == msg::USERAUTH_INFO_RESPONSE =>
            {
                if read_userauth_info_response(
                    instant,
                    handler,
                    &mut enc.write,
                    auth,
                    &mut self.common.auth_user,
                    buf,
                )
                .await?
                {
                    if let EncryptedState::InitCompression = enc.state {
                        enc.client_compression.init_decompress(&mut enc.decompress);
                    }
                }
                Ok(self)
            }
            EncryptedState::InitCompression => {
                enc.server_compression.init_compress(&mut enc.compress);
                enc.state = EncryptedState::Authenticated;
                self.server_read_authenticated(handler, buf).await
            }
            EncryptedState::Authenticated => self.server_read_authenticated(handler, buf).await,
            _ => Ok(self),
        }
    }
}

fn server_accept_service(
    banner: Option<&str>,
    methods: MethodSet,
    buffer: &mut CryptoVec,
) -> AuthRequest {
    push_packet!(buffer, {
        buffer.push(msg::SERVICE_ACCEPT);
        buffer.extend_ssh_string(b"ssh-userauth");
    });

    if let Some(ref banner) = banner {
        push_packet!(buffer, {
            buffer.push(msg::USERAUTH_BANNER);
            buffer.extend_ssh_string(banner.as_bytes());
            buffer.extend_ssh_string(b"");
        })
    }

    AuthRequest {
        methods: methods,
        partial_success: false, // not used immediately anway.
        current: None,
        rejection_count: 0,
    }
}

impl Encrypted {
    /// Returns false iff the request was rejected.
    async fn server_read_auth_request<H: Handler>(
        &mut self,
        until: Instant,
        handler: &mut Option<H>,
        buf: &[u8],
        auth_user: &mut String,
    ) -> Result<(), H::Error> {
        // https://tools.ietf.org/html/rfc4252#section-5
        let mut r = buf.reader(1);
        let user = r.read_string().map_err(crate::Error::from)?;
        let user = std::str::from_utf8(user).map_err(crate::Error::from)?;
        let service_name = r.read_string().map_err(crate::Error::from)?;
        let method = r.read_string().map_err(crate::Error::from)?;
        debug!(
            "name: {:?} {:?} {:?}",
            user,
            std::str::from_utf8(service_name),
            std::str::from_utf8(method)
        );

        if service_name == b"ssh-connection" {
            if method == b"password" {
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                auth_user.clear();
                auth_user.push_str(user);
                r.read_byte().map_err(crate::Error::from)?;
                let password = r.read_string().map_err(crate::Error::from)?;
                let password = std::str::from_utf8(password).map_err(crate::Error::from)?;
                let handler_ = handler.take().unwrap();
                let (handler_, auth) = handler_.auth_password(user, password).await?;
                *handler = Some(handler_);
                if let Auth::Accept = auth {
                    server_auth_request_success(&mut self.write);
                    self.state = EncryptedState::InitCompression;
                } else {
                    auth_user.clear();
                    auth_request.methods = auth_request.methods - MethodSet::PASSWORD;
                    auth_request.partial_success = false;
                    reject_auth_request(until, &mut self.write, auth_request).await;
                }
                Ok(())
            } else if method == b"publickey" {
                self.server_read_auth_request_pk(until, handler, buf, auth_user, user, r)
                    .await
            } else if method == b"keyboard-interactive" {
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                auth_user.clear();
                auth_user.push_str(user);
                let _ = r.read_string().map_err(crate::Error::from)?; // language_tag, deprecated.
                let submethods = std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                    .map_err(crate::Error::from)?;
                debug!("{:?}", submethods);
                auth_request.current = Some(CurrentRequest::KeyboardInteractive {
                    submethods: submethods.to_string(),
                });
                let h = handler.take().unwrap();
                let (h, auth) = h.auth_keyboard_interactive(user, submethods, None).await?;
                *handler = Some(h);
                if reply_userauth_info_response(until, auth_request, &mut self.write, auth).await? {
                    self.state = EncryptedState::InitCompression
                }
                Ok(())
            } else {
                // Other methods of the base specification are insecure or optional.
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                reject_auth_request(until, &mut self.write, auth_request).await;
                Ok(())
            }
        } else {
            // Unknown service
            Err(Error::Inconsistent.into())
        }
    }
}

thread_local! {
    static SIGNATURE_BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

impl Encrypted {
    async fn server_read_auth_request_pk<'a, H: Handler>(
        &mut self,
        until: Instant,
        handler: &mut Option<H>,
        buf: &[u8],
        auth_user: &mut String,
        user: &str,
        mut r: Position<'a>,
    ) -> Result<(), H::Error> {
        let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state {
            a
        } else {
            unreachable!()
        };
        let is_real = r.read_byte().map_err(crate::Error::from)?;
        let pubkey_algo = r.read_string().map_err(crate::Error::from)?;
        let pubkey_key = r.read_string().map_err(crate::Error::from)?;
        debug!("algo: {:?}, key: {:?}", pubkey_algo, pubkey_key);
        match key::PublicKey::parse(pubkey_algo, pubkey_key) {
            Ok(mut pubkey) => {
                debug!("is_real = {:?}", is_real);

                if is_real != 0 {
                    let pos0 = r.position;
                    let sent_pk_ok = if let Some(CurrentRequest::PublicKey { sent_pk_ok, .. }) =
                        auth_request.current
                    {
                        sent_pk_ok
                    } else {
                        false
                    };

                    let signature = r.read_string().map_err(crate::Error::from)?;
                    debug!("signature = {:?}", signature);
                    let mut s = signature.reader(0);
                    let algo_ = s.read_string().map_err(crate::Error::from)?;
                    pubkey.set_algorithm(algo_);
                    debug!("algo_: {:?}", algo_);
                    let sig = s.read_string().map_err(crate::Error::from)?;
                    let init = &buf[0..pos0];

                    let is_valid = if sent_pk_ok && user == auth_user {
                        true
                    } else if auth_user.len() == 0 {
                        auth_user.clear();
                        auth_user.push_str(user);
                        let h = handler.take().unwrap();
                        let (h, auth) = h.auth_publickey(user, &pubkey).await?;
                        *handler = Some(h);
                        auth == Auth::Accept
                    } else {
                        false
                    };
                    if is_valid {
                        let session_id = self.session_id.as_ref();
                        if SIGNATURE_BUFFER.with(|buf| {
                            let mut buf = buf.borrow_mut();
                            buf.clear();
                            buf.extend_ssh_string(session_id);
                            buf.extend(init);
                            // Verify signature.
                            pubkey.verify_client_auth(&buf, sig)
                        }) {
                            debug!("signature verified");
                            server_auth_request_success(&mut self.write);
                            self.state = EncryptedState::InitCompression;
                        } else {
                            debug!("signature wrong");
                            reject_auth_request(until, &mut self.write, auth_request).await;
                        }
                    } else {
                        reject_auth_request(until, &mut self.write, auth_request).await;
                    }
                    Ok(())
                } else {
                    auth_user.clear();
                    auth_user.push_str(user);
                    let h = handler.take().unwrap();
                    let (h, auth) = h.auth_publickey(user, &pubkey).await?;
                    *handler = Some(h);
                    if auth == Auth::Accept {
                        let mut public_key = CryptoVec::new();
                        public_key.extend(pubkey_key);

                        let mut algo = CryptoVec::new();
                        algo.extend(pubkey_algo);
                        debug!("pubkey_key: {:?}", pubkey_key);
                        push_packet!(self.write, {
                            self.write.push(msg::USERAUTH_PK_OK);
                            self.write.extend_ssh_string(&pubkey_algo);
                            self.write.extend_ssh_string(&pubkey_key);
                        });

                        auth_request.current = Some(CurrentRequest::PublicKey {
                            key: public_key,
                            algo: algo,
                            sent_pk_ok: true,
                        });
                    } else {
                        debug!("signature wrong");
                        auth_request.partial_success = false;
                        auth_user.clear();
                        reject_auth_request(until, &mut self.write, auth_request).await;
                    }
                    Ok(())
                }
            }
            Err(e) => {
                if let thrussh_keys::Error::CouldNotReadKey = e {
                    reject_auth_request(until, &mut self.write, auth_request).await;
                    Ok(())
                } else {
                    Err(crate::Error::from(e).into())
                }
            }
        }
    }
}

async fn reject_auth_request(
    until: Instant,
    write: &mut CryptoVec,
    auth_request: &mut AuthRequest,
) {
    debug!("rejecting {:?}", auth_request);
    push_packet!(write, {
        write.push(msg::USERAUTH_FAILURE);
        write.extend_list(auth_request.methods);
        write.push(if auth_request.partial_success { 1 } else { 0 });
    });
    auth_request.current = None;
    auth_request.rejection_count += 1;
    debug!("packet pushed");
    tokio::time::sleep_until(until).await
}

fn server_auth_request_success(buffer: &mut CryptoVec) {
    push_packet!(buffer, {
        buffer.push(msg::USERAUTH_SUCCESS);
    })
}

async fn read_userauth_info_response<H: Handler>(
    until: Instant,
    handler: &mut Option<H>,
    write: &mut CryptoVec,
    auth_request: &mut AuthRequest,
    user: &mut String,
    b: &[u8],
) -> Result<bool, H::Error> {
    if let Some(CurrentRequest::KeyboardInteractive { ref submethods }) = auth_request.current {
        let mut r = b.reader(1);
        let n = r.read_u32().map_err(crate::Error::from)?;
        let response = Response { pos: r, n: n };
        let h = handler.take().unwrap();
        let (h, auth) = h
            .auth_keyboard_interactive(user, submethods, Some(response))
            .await?;
        *handler = Some(h);
        reply_userauth_info_response(until, auth_request, write, auth)
            .await
            .map_err(|e| H::Error::from(crate::Error::from(e)))
    } else {
        reject_auth_request(until, write, auth_request).await;
        Ok(false)
    }
}

async fn reply_userauth_info_response(
    until: Instant,
    auth_request: &mut AuthRequest,
    write: &mut CryptoVec,
    auth: Auth,
) -> Result<bool, Error> {
    match auth {
        Auth::Accept => {
            server_auth_request_success(write);
            Ok(true)
        }
        Auth::Reject => {
            auth_request.partial_success = false;
            reject_auth_request(until, write, auth_request).await;
            Ok(false)
        }
        Auth::Partial {
            name,
            instructions,
            prompts,
        } => {
            push_packet!(write, {
                write.push(msg::USERAUTH_INFO_REQUEST);
                write.extend_ssh_string(name.as_bytes());
                write.extend_ssh_string(instructions.as_bytes());
                write.extend_ssh_string(b""); // lang, should be empty
                write.push_u32_be(prompts.len() as u32);
                for &(ref a, b) in prompts.iter() {
                    write.extend_ssh_string(a.as_bytes());
                    write.push(if b { 1 } else { 0 });
                }
            });
            Ok(false)
        }
        Auth::UnsupportedMethod => unreachable!(),
    }
}

impl Session {
    async fn server_read_authenticated<H: Handler>(
        mut self,
        handler: &mut Option<H>,
        buf: &[u8],
    ) -> Result<Self, H::Error> {
        debug!(
            "authenticated buf = {:?}",
            &buf[..std::cmp::min(buf.len(), 100)]
        );
        match buf[0] {
            msg::CHANNEL_OPEN => self.server_handle_channel_open(handler, buf).await,
            msg::CHANNEL_CLOSE => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.channels.remove(&channel_num);
                }
                debug!("handler.channel_close {:?}", channel_num);
                let h = handler.take().unwrap();
                let (h, s) = h.channel_close(channel_num, self).await?;
                *handler = Some(h);
                Ok(s)
            }
            msg::CHANNEL_EOF => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                debug!("handler.channel_eof {:?}", channel_num);
                let h = handler.take().unwrap();
                let (h, s) = h.channel_eof(channel_num, self).await?;
                *handler = Some(h);
                Ok(s)
            }
            msg::CHANNEL_EXTENDED_DATA | msg::CHANNEL_DATA => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);

                let ext = if buf[0] == msg::CHANNEL_DATA {
                    None
                } else {
                    Some(r.read_u32().map_err(crate::Error::from)?)
                };
                debug!("handler.data {:?} {:?}", ext, channel_num);
                let data = r.read_string().map_err(crate::Error::from)?;
                let target = self.target_window_size;

                let mut h = handler.take().unwrap();
                if let Some(ref mut enc) = self.common.encrypted {
                    if enc.adjust_window_size(channel_num, data, target) {
                        let window = h.adjust_window(channel_num, self.target_window_size);
                        if window > 0 {
                            self.target_window_size = window
                        }
                    }
                }
                self.flush()?;
                let (h, s) = if let Some(ext) = ext {
                    h.extended_data(channel_num, ext, &data, self).await?
                } else {
                    h.data(channel_num, &data, self).await?
                };
                *handler = Some(h);
                Ok(s)
            }

            msg::CHANNEL_WINDOW_ADJUST => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                let amount = r.read_u32().map_err(crate::Error::from)?;
                let mut new_value = 0;
                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(channel) = enc.channels.get_mut(&channel_num) {
                        channel.recipient_window_size += amount;
                        new_value = channel.recipient_window_size;
                    } else {
                        return Err(Error::WrongChannel.into());
                    }
                }
                debug!("handler.window_adjusted {:?}", channel_num);
                let h = handler.take().unwrap();
                let (h, s) = h
                    .window_adjusted(channel_num, new_value as usize, self)
                    .await?;
                *handler = Some(h);
                Ok(s)
            }

            msg::CHANNEL_REQUEST => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                let req_type = r.read_string().map_err(crate::Error::from)?;
                let wants_reply = r.read_byte().map_err(crate::Error::from)?;
                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(channel) = enc.channels.get_mut(&channel_num) {
                        channel.wants_reply = wants_reply != 0;
                    }
                }
                match req_type {
                    b"pty-req" => {
                        let term =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let col_width = r.read_u32().map_err(crate::Error::from)?;
                        let row_height = r.read_u32().map_err(crate::Error::from)?;
                        let pix_width = r.read_u32().map_err(crate::Error::from)?;
                        let pix_height = r.read_u32().map_err(crate::Error::from)?;
                        let mut modes = [(Pty::TTY_OP_END, 0); 130];
                        let mut i = 0;
                        {
                            let mode_string = r.read_string().map_err(crate::Error::from)?;
                            while 5 * i < mode_string.len() {
                                let code = mode_string[5 * i];
                                if code == 0 {
                                    break;
                                }
                                let num = BigEndian::read_u32(&mode_string[5 * i + 1..]);
                                debug!("code = {:?}", code);
                                if let Some(code) = Pty::from_u8(code) {
                                    modes[i] = (code, num);
                                } else {
                                    info!("pty-req: unknown pty code {:?}", code);
                                }
                                i += 1
                            }
                        }
                        debug!("handler.pty_request {:?}", channel_num);
                        let h = handler.take().unwrap();
                        let (h, s) = h
                            .pty_request(
                                channel_num,
                                term,
                                col_width,
                                row_height,
                                pix_width,
                                pix_height,
                                &modes[0..i],
                                self,
                            )
                            .await?;
                        *handler = Some(h);
                        Ok(s)
                    }
                    b"x11-req" => {
                        let single_connection = r.read_byte().map_err(crate::Error::from)? != 0;
                        let x11_auth_protocol =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let x11_auth_cookie =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let x11_screen_number = r.read_u32().map_err(crate::Error::from)?;
                        debug!("handler.x11_request {:?}", channel_num);
                        let h = handler.take().unwrap();
                        let (h, s) = h
                            .x11_request(
                                channel_num,
                                single_connection,
                                x11_auth_protocol,
                                x11_auth_cookie,
                                x11_screen_number,
                                self,
                            )
                            .await?;
                        *handler = Some(h);
                        Ok(s)
                    }
                    b"env" => {
                        let env_variable =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let env_value =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        debug!("handler.env_request {:?}", channel_num);
                        let h = handler.take().unwrap();
                        let (h, s) = h
                            .env_request(channel_num, env_variable, env_value, self)
                            .await?;
                        *handler = Some(h);
                        Ok(s)
                    }
                    b"shell" => {
                        debug!("handler.shell_request {:?}", channel_num);
                        let h = handler.take().unwrap();
                        let (h, s) = h.shell_request(channel_num, self).await?;
                        *handler = Some(h);
                        Ok(s)
                    }
                    b"exec" => {
                        let req = r.read_string().map_err(crate::Error::from)?;
                        debug!("handler.exec_request {:?}", channel_num);
                        let h = handler.take().unwrap();
                        let (h, s) = h.exec_request(channel_num, req, self).await?;
                        *handler = Some(h);
                        debug!("executed");
                        Ok(s)
                    }
                    b"subsystem" => {
                        let name =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        debug!("handler.subsystem_request {:?}", channel_num);
                        let h = handler.take().unwrap();
                        let (h, s) = h.subsystem_request(channel_num, name, self).await?;
                        *handler = Some(h);
                        Ok(s)
                    }
                    b"window-change" => {
                        let col_width = r.read_u32().map_err(crate::Error::from)?;
                        let row_height = r.read_u32().map_err(crate::Error::from)?;
                        let pix_width = r.read_u32().map_err(crate::Error::from)?;
                        let pix_height = r.read_u32().map_err(crate::Error::from)?;
                        debug!("handler.window_change {:?}", channel_num);
                        let h = handler.take().unwrap();
                        let (h, s) = h
                            .window_change_request(
                                channel_num,
                                col_width,
                                row_height,
                                pix_width,
                                pix_height,
                                self,
                            )
                            .await?;
                        *handler = Some(h);
                        Ok(s)
                    }
                    b"signal" => {
                        let signal_name =
                            Sig::from_name(r.read_string().map_err(crate::Error::from)?)?;
                        debug!("handler.signal {:?} {:?}", channel_num, signal_name);
                        let h = handler.take().unwrap();
                        let (h, s) = h.signal(channel_num, signal_name, self).await?;
                        *handler = Some(h);
                        Ok(s)
                    }
                    x => {
                        warn!("unknown channel request {}", String::from_utf8_lossy(x));
                        self.channel_failure(channel_num);
                        Ok(self)
                    }
                }
            }
            msg::GLOBAL_REQUEST => {
                let mut r = buf.reader(1);
                let req_type = r.read_string().map_err(crate::Error::from)?;
                self.common.wants_reply = r.read_byte().map_err(crate::Error::from)? != 0;
                match req_type {
                    b"tcpip-forward" => {
                        let address =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let port = r.read_u32().map_err(crate::Error::from)?;
                        debug!("handler.tcpip_forward {:?} {:?}", address, port);
                        let h = handler.take().unwrap();
                        let (h, mut s, result) = h.tcpip_forward(address, port, self).await?;
                        *handler = Some(h);
                        if let Some(ref mut enc) = s.common.encrypted {
                            if result {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
                            } else {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                            }
                        }
                        Ok(s)
                    }
                    b"cancel-tcpip-forward" => {
                        let address =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let port = r.read_u32().map_err(crate::Error::from)?;
                        debug!("handler.cancel_tcpip_forward {:?} {:?}", address, port);
                        let h = handler.take().unwrap();
                        let (h, mut s, result) =
                            h.cancel_tcpip_forward(address, port, self).await?;
                        *handler = Some(h);
                        if let Some(ref mut enc) = s.common.encrypted {
                            if result {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
                            } else {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                            }
                        }
                        Ok(s)
                    }
                    _ => {
                        if let Some(ref mut enc) = self.common.encrypted {
                            push_packet!(enc.write, {
                                enc.write.push(msg::REQUEST_FAILURE);
                            });
                        }
                        Ok(self)
                    }
                }
            }
            m => {
                debug!("unknown message received: {:?}", m);
                Ok(self)
            }
        }
    }

    async fn server_handle_channel_open<H: Handler>(
        mut self,
        handler: &mut Option<H>,
        buf: &[u8],
    ) -> Result<Self, H::Error> {
        // https://tools.ietf.org/html/rfc4254#section-5.1
        let mut r = buf.reader(1);
        let typ = r.read_string().map_err(crate::Error::from)?;
        let sender = r.read_u32().map_err(crate::Error::from)?;
        let window = r.read_u32().map_err(crate::Error::from)?;
        let maxpacket = r.read_u32().map_err(crate::Error::from)?;

        let sender_channel = if let Some(ref mut enc) = self.common.encrypted {
            enc.new_channel_id()
        } else {
            unreachable!()
        };
        let channel = Channel {
            recipient_channel: sender,

            // "sender" is the local end, i.e. we're the sender, the remote is the recipient.
            sender_channel: sender_channel,

            recipient_window_size: window,
            sender_window_size: self.common.config.window_size,
            recipient_maximum_packet_size: maxpacket,
            sender_maximum_packet_size: self.common.config.maximum_packet_size,
            confirmed: true,
            wants_reply: false,
            pending_data: std::collections::VecDeque::new(),
        };
        match typ {
            b"session" => {
                self.confirm_channel_open(channel);
                let h = handler.take().unwrap();
                let (h, s) = h.channel_open_session(sender_channel, self).await?;
                *handler = Some(h);
                Ok(s)
            }
            b"x11" => {
                self.confirm_channel_open(channel);
                let a = std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                    .map_err(crate::Error::from)?;
                let b = r.read_u32().map_err(crate::Error::from)?;
                let h = handler.take().unwrap();
                let (h, s) = h.channel_open_x11(sender_channel, a, b, self).await?;
                *handler = Some(h);
                Ok(s)
            }
            b"direct-tcpip" => {
                self.confirm_channel_open(channel);
                let a = std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                    .map_err(crate::Error::from)?;
                let b = r.read_u32().map_err(crate::Error::from)?;
                let c = std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                    .map_err(crate::Error::from)?;
                let d = r.read_u32().map_err(crate::Error::from)?;
                let h = handler.take().unwrap();
                let (h, s) = h
                    .channel_open_direct_tcpip(sender_channel, a, b, c, d, self)
                    .await?;
                *handler = Some(h);
                Ok(s)
            }
            t => {
                debug!("unknown channel type: {:?}", t);
                if let Some(ref mut enc) = self.common.encrypted {
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN_FAILURE);
                        enc.write.push_u32_be(sender);
                        enc.write.push_u32_be(3); // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
                        enc.write.extend_ssh_string(b"Unknown channel type");
                        enc.write.extend_ssh_string(b"en");
                    });
                }
                Ok(self)
            }
        }
    }
    fn confirm_channel_open(&mut self, channel: Channel) {
        if let Some(ref mut enc) = self.common.encrypted {
            server_confirm_channel_open(&mut enc.write, &channel, self.common.config.as_ref());
            enc.channels.insert(channel.sender_channel, channel);
        }
    }
}

fn server_confirm_channel_open(buffer: &mut CryptoVec, channel: &Channel, config: &Config) {
    push_packet!(buffer, {
        buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
        buffer.push_u32_be(channel.recipient_channel); // remote channel number.
        buffer.push_u32_be(channel.sender_channel.0); // our channel number.
        buffer.push_u32_be(config.window_size);
        buffer.push_u32_be(config.maximum_packet_size);
    });
}

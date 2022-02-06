use super::*;

impl Session {
    pub fn channel_open_session(&mut self) -> Result<ChannelId, Error> {
        let result = if let Some(ref mut enc) = self.common.encrypted {
            match enc.state {
                EncryptedState::Authenticated => {
                    let sender_channel = enc.new_channel(
                        self.common.config.window_size,
                        self.common.config.maximum_packet_size,
                    );
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(b"session");

                        // sender channel id.
                        enc.write.push_u32_be(sender_channel.0);

                        // window.
                        enc.write
                            .push_u32_be(self.common.config.as_ref().window_size);

                        // max packet size.
                        enc.write
                            .push_u32_be(self.common.config.as_ref().maximum_packet_size);
                    });
                    sender_channel
                }
                _ => return Err(Error::NotAuthenticated.into()),
            }
        } else {
            return Err(Error::Inconsistent.into());
        };
        Ok(result)
    }

    pub fn channel_open_x11(
        &mut self,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        let result = if let Some(ref mut enc) = self.common.encrypted {
            match enc.state {
                EncryptedState::Authenticated => {
                    let sender_channel = enc.new_channel(
                        self.common.config.window_size,
                        self.common.config.maximum_packet_size,
                    );
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(b"x11");

                        // sender channel id.
                        enc.write.push_u32_be(sender_channel.0);

                        // window.
                        enc.write
                            .push_u32_be(self.common.config.as_ref().window_size);

                        // max packet size.
                        enc.write
                            .push_u32_be(self.common.config.as_ref().maximum_packet_size);

                        enc.write.extend_ssh_string(originator_address.as_bytes());
                        enc.write.push_u32_be(originator_port); // sender channel id.
                    });
                    sender_channel
                }
                _ => return Err(Error::NotAuthenticated.into()),
            }
        } else {
            return Err(Error::Inconsistent.into());
        };
        Ok(result)
    }

    pub fn channel_open_direct_tcpip(
        &mut self,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        let result = if let Some(ref mut enc) = self.common.encrypted {
            match enc.state {
                EncryptedState::Authenticated => {
                    let sender_channel = enc.new_channel(
                        self.common.config.window_size,
                        self.common.config.maximum_packet_size,
                    );
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(b"direct-tcpip");

                        // sender channel id.
                        enc.write.push_u32_be(sender_channel.0);

                        // window.
                        enc.write
                            .push_u32_be(self.common.config.as_ref().window_size);

                        // max packet size.
                        enc.write
                            .push_u32_be(self.common.config.as_ref().maximum_packet_size);

                        enc.write.extend_ssh_string(host_to_connect.as_bytes());
                        enc.write.push_u32_be(port_to_connect); // sender channel id.
                        enc.write.extend_ssh_string(originator_address.as_bytes());
                        enc.write.push_u32_be(originator_port); // sender channel id.
                    });
                    sender_channel
                }
                _ => return Err(Error::NotAuthenticated.into()),
            }
        } else {
            return Err(Error::Inconsistent.into());
        };
        Ok(result)
    }

    pub fn request_pty(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: &[(Pty, u32)],
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"pty-req");
                    enc.write.push(if want_reply { 1 } else { 0 });

                    enc.write.extend_ssh_string(term.as_bytes());
                    enc.write.push_u32_be(col_width);
                    enc.write.push_u32_be(row_height);
                    enc.write.push_u32_be(pix_width);
                    enc.write.push_u32_be(pix_height);

                    enc.write.push_u32_be((1 + 5 * terminal_modes.len()) as u32);
                    for &(code, value) in terminal_modes {
                        enc.write.push(code as u8);
                        enc.write.push_u32_be(value)
                    }
                    // 0 code (to terminate the list)
                    enc.write.push(0);
                });
            }
        }
    }

    pub fn request_x11(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        single_connection: bool,
        x11_authentication_protocol: &str,
        x11_authentication_cookie: &str,
        x11_screen_number: u32,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"x11-req");
                    enc.write.push(if want_reply { 1 } else { 0 });
                    enc.write.push(if single_connection { 1 } else { 0 });
                    enc.write
                        .extend_ssh_string(x11_authentication_protocol.as_bytes());
                    enc.write
                        .extend_ssh_string(x11_authentication_cookie.as_bytes());
                    enc.write.push_u32_be(x11_screen_number);
                });
            }
        }
    }

    pub fn set_env(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        variable_name: &str,
        variable_value: &str,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"env");
                    enc.write.push(if want_reply { 1 } else { 0 });
                    enc.write.extend_ssh_string(variable_name.as_bytes());
                    enc.write.extend_ssh_string(variable_value.as_bytes());
                });
            }
        }
    }

    pub fn request_shell(&mut self, want_reply: bool, channel: ChannelId) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"shell");
                    enc.write.push(if want_reply { 1 } else { 0 });
                });
            }
        }
    }

    pub fn exec(&mut self, channel: ChannelId, want_reply: bool, command: &str) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"exec");
                    enc.write.push(if want_reply { 1 } else { 0 });
                    enc.write.extend_ssh_string(command.as_bytes());
                });
                return;
            }
        }
        error!("exec");
    }

    pub fn signal(&mut self, channel: ChannelId, signal: Sig) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"signal");
                    enc.write.push(0);
                    enc.write.extend_ssh_string(signal.name().as_bytes());
                });
            }
        }
    }

    pub fn request_subsystem(&mut self, want_reply: bool, channel: ChannelId, name: &str) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"subsystem");
                    enc.write.push(if want_reply { 1 } else { 0 });
                    enc.write.extend_ssh_string(name.as_bytes());
                });
            }
        }
    }

    pub fn window_change(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"window-change");
                    enc.write.push(0); // this packet never wants reply
                    enc.write.push_u32_be(col_width);
                    enc.write.push_u32_be(row_height);
                    enc.write.push_u32_be(pix_width);
                    enc.write.push_u32_be(pix_height);
                });
            }
        }
    }

    pub fn tcpip_forward(&mut self, want_reply: bool, address: &str, port: u32) {
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"tcpip-forward");
                enc.write.push(if want_reply { 1 } else { 0 });
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
    }

    pub fn cancel_tcpip_forward(&mut self, want_reply: bool, address: &str, port: u32) {
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"cancel-tcpip-forward");
                enc.write.push(if want_reply { 1 } else { 0 });
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
    }

    pub fn data(&mut self, channel: ChannelId, data: CryptoVec) {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.data(channel, data)
        } else {
            unreachable!()
        }
    }

    pub fn eof(&mut self, channel: ChannelId) {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.eof(channel)
        } else {
            unreachable!()
        }
    }

    pub fn extended_data(&mut self, channel: ChannelId, ext: u32, data: CryptoVec) {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.extended_data(channel, ext, data)
        } else {
            unreachable!()
        }
    }

    pub fn disconnect(&mut self, reason: Disconnect, description: &str, language_tag: &str) {
        self.common.disconnect(reason, description, language_tag);
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
        if let Some(ref enc) = self.common.encrypted {
            enc.has_pending_data(channel)
        } else {
            false
        }
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if let Some(ref enc) = self.common.encrypted {
            enc.sender_window_size(channel)
        } else {
            0
        }
    }
}

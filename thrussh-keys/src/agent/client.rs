use super::msg;
use super::Constraint;
use crate::encoding::{Encoding, Reader};
use crate::key;
use crate::key::{PublicKey, SignatureHash};
use crate::Error;
use byteorder::{BigEndian, ByteOrder};
use cryptovec::CryptoVec;
use tokio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SSH agent client.
pub struct AgentClient<S: AsyncRead + AsyncWrite> {
    stream: S,
    buf: CryptoVec,
}

// https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.1
impl<S: AsyncRead + AsyncWrite + Unpin> AgentClient<S> {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub fn connect(stream: S) -> Self {
        AgentClient {
            stream,
            buf: CryptoVec::new(),
        }
    }
}

#[cfg(unix)]
impl AgentClient<tokio::net::UnixStream> {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub async fn connect_uds<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        Ok(AgentClient {
            stream,
            buf: CryptoVec::new(),
        })
    }

    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub async fn connect_env() -> Result<Self, Error> {
        let var = if let Ok(var) = std::env::var("SSH_AUTH_SOCK") {
            var
        } else {
            return Err(Error::EnvVar("SSH_AUTH_SOCK"));
        };
        match Self::connect_uds(var).await {
            Err(Error::IO(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => Err(Error::BadAuthSock),
            owise => owise
        }
    }
}

#[cfg(not(unix))]
impl AgentClient<tokio::net::TcpStream> {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub async fn connect_env() -> Result<Self, Error> {
        Err(Error::AgentFailure)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AgentClient<S> {
    async fn read_response(&mut self) -> Result<(), Error> {
        // Writing the message
        self.stream.write_all(&self.buf).await?;
        self.stream.flush().await?;

        // Reading the length
        self.buf.clear();
        self.buf.resize(4);
        self.stream.read_exact(&mut self.buf).await?;

        // Reading the rest of the buffer
        let len = BigEndian::read_u32(&self.buf) as usize;
        self.buf.clear();
        self.buf.resize(len);
        self.stream.read_exact(&mut self.buf).await?;

        Ok(())
    }

    /// Send a key to the agent, with a (possibly empty) slice of
    /// constraints to apply when using the key to sign.
    pub async fn add_identity(
        &mut self,
        key: &key::KeyPair,
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_IDENTITY)
        } else {
            self.buf.push(msg::ADD_ID_CONSTRAINED)
        }
        match *key {
            key::KeyPair::Ed25519(ref secret) => {
                self.buf.extend_ssh_string(b"ssh-ed25519");
                let public = &secret.key[32..];
                self.buf.extend_ssh_string(public);
                self.buf.push_u32_be(64);
                self.buf.extend(&secret.key);
                self.buf.extend_ssh_string(b"");
            }
            #[cfg(feature = "openssl")]
            key::KeyPair::RSA { ref key, .. } => {
                self.buf.extend_ssh_string(b"ssh-rsa");
                self.buf.extend_ssh_mpint(&key.n().to_vec());
                self.buf.extend_ssh_mpint(&key.e().to_vec());
                self.buf.extend_ssh_mpint(&key.d().to_vec());
                if let Some(iqmp) = key.iqmp() {
                    self.buf.extend_ssh_mpint(&iqmp.to_vec());
                } else {
                    let mut ctx = openssl::bn::BigNumContext::new()?;
                    let mut iqmp = openssl::bn::BigNum::new()?;
                    iqmp.mod_inverse(key.p().unwrap(), key.q().unwrap(), &mut ctx)?;
                    self.buf.extend_ssh_mpint(&iqmp.to_vec());
                }
                self.buf.extend_ssh_mpint(&key.p().unwrap().to_vec());
                self.buf.extend_ssh_mpint(&key.q().unwrap().to_vec());
                self.buf.extend_ssh_string(b"");
            }
        }
        if !constraints.is_empty() {
            self.buf.push_u32_be(constraints.len() as u32);
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        self.buf.push(msg::CONSTRAIN_LIFETIME);
                        self.buf.push_u32_be(seconds)
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions {
                        ref name,
                        ref details,
                    } => {
                        self.buf.push(msg::CONSTRAIN_EXTENSION);
                        self.buf.extend_ssh_string(name);
                        self.buf.extend_ssh_string(details);
                    }
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_response().await?;
        Ok(())
    }

    /// Add a smart card to the agent, with a (possibly empty) set of
    /// constraints to apply when signing.
    pub async fn add_smartcard_key(
        &mut self,
        id: &str,
        pin: &[u8],
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_SMARTCARD_KEY)
        } else {
            self.buf.push(msg::ADD_SMARTCARD_KEY_CONSTRAINED)
        }
        self.buf.extend_ssh_string(id.as_bytes());
        self.buf.extend_ssh_string(pin);
        if !constraints.is_empty() {
            self.buf.push_u32_be(constraints.len() as u32);
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        self.buf.push(msg::CONSTRAIN_LIFETIME);
                        self.buf.push_u32_be(seconds)
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions {
                        ref name,
                        ref details,
                    } => {
                        self.buf.push(msg::CONSTRAIN_EXTENSION);
                        self.buf.extend_ssh_string(name);
                        self.buf.extend_ssh_string(details);
                    }
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Lock the agent, making it refuse to sign until unlocked.
    pub async fn lock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::LOCK);
        self.buf.extend_ssh_string(passphrase);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Unlock the agent, allowing it to sign again.
    pub async fn unlock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::UNLOCK);
        self.buf.extend_ssh_string(passphrase);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Ask the agent for a list of the currently registered secret
    /// keys.
    pub async fn request_identities(&mut self) -> Result<Vec<PublicKey>, Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REQUEST_IDENTITIES);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);

        self.read_response().await?;
        debug!("identities: {:?}", &self.buf[..]);
        let mut keys = Vec::new();
        if self.buf[0] == msg::IDENTITIES_ANSWER {
            let mut r = self.buf.reader(1);
            let n = r.read_u32()?;
            for _ in 0..n {
                let key = r.read_string()?;
                let _ = r.read_string()?;
                let mut r = key.reader(0);
                let t = r.read_string()?;
                debug!("t = {:?}", std::str::from_utf8(t));
                match t {
                    #[cfg(feature = "openssl")]
                    b"ssh-rsa" => {
                        let e = r.read_mpint()?;
                        let n = r.read_mpint()?;
                        use openssl::bn::BigNum;
                        use openssl::pkey::PKey;
                        use openssl::rsa::Rsa;
                        keys.push(PublicKey::RSA {
                            key: key::OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                                BigNum::from_slice(n)?,
                                BigNum::from_slice(e)?,
                            )?)?),
                            hash: SignatureHash::SHA2_512,
                        })
                    }
                    b"ssh-ed25519" => {
                        let mut p = key::ed25519::PublicKey::new_zeroed();
                        p.key.clone_from_slice(r.read_string()?);
                        keys.push(PublicKey::Ed25519(p))
                    }
                    t => {
                        info!("Unsupported key type: {:?}", std::str::from_utf8(t))
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Ask the agent to sign the supplied piece of data.
    pub fn sign_request(
        mut self,
        public: &key::PublicKey,
        mut data: CryptoVec,
    ) -> impl futures::Future<Output = (Self, Result<CryptoVec, Error>)> {
        debug!("sign_request: {:?}", data);
        let hash = self.prepare_sign_request(public, &data);
        async move {
            let resp = self.read_response().await;
            debug!("resp = {:?}", &self.buf[..]);
            if let Err(e) = resp {
                return (self, Err(e));
            }

            if !self.buf.is_empty() && self.buf[0] == msg::SIGN_RESPONSE {
                let resp = self.write_signature(hash, &mut data);
                if let Err(e) = resp {
                    return (self, Err(e));
                }
                (self, Ok(data))
            } else if self.buf[0] == msg::FAILURE {
                (self, Err(Error::AgentFailure))
            } else {
                debug!("self.buf = {:?}", &self.buf[..]);
                (self, Ok(data))
            }
        }
    }

    fn prepare_sign_request(&mut self, public: &key::PublicKey, data: &[u8]) -> u32 {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::SIGN_REQUEST);
        key_blob(public, &mut self.buf);
        self.buf.extend_ssh_string(data);
        debug!("public = {:?}", public);
        let hash = match public {
            #[cfg(feature = "openssl")]
            PublicKey::RSA { hash, .. } => match hash {
                SignatureHash::SHA2_256 => 2,
                SignatureHash::SHA2_512 => 4,
                SignatureHash::SHA1 => 0,
            },
            _ => 0,
        };
        self.buf.push_u32_be(hash);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        hash
    }

    fn write_signature(&self, hash: u32, data: &mut CryptoVec) -> Result<(), Error> {
        let mut r = self.buf.reader(1);
        let mut resp = r.read_string()?.reader(0);
        let t = resp.read_string()?;
        if (hash == 2 && t == b"rsa-sha2-256") || (hash == 4 && t == b"rsa-sha2-512") || hash == 0 {
            let sig = resp.read_string()?;
            data.push_u32_be((t.len() + sig.len() + 8) as u32);
            data.extend_ssh_string(t);
            data.extend_ssh_string(sig);
        }
        Ok(())
    }

    /// Ask the agent to sign the supplied piece of data.
    pub fn sign_request_base64(
        mut self,
        public: &key::PublicKey,
        data: &[u8],
    ) -> impl futures::Future<Output = (Self, Result<String, Error>)> {
        debug!("sign_request: {:?}", data);
        self.prepare_sign_request(public, data);
        async move {
            let resp = self.read_response().await;
            if let Err(e) = resp {
                return (self, Err(e));
            }

            if !self.buf.is_empty() && self.buf[0] == msg::SIGN_RESPONSE {
                let base64 = data_encoding::BASE64_NOPAD.encode(&self.buf[1..]);
                (self, Ok(base64))
            } else {
                (self, Ok(String::new()))
            }
        }
    }

    /// Ask the agent to sign the supplied piece of data, and return a `Signature`.
    pub fn sign_request_signature(
        mut self,
        public: &key::PublicKey,
        data: &[u8],
    ) -> impl futures::Future<Output = (Self, Result<crate::signature::Signature, Error>)> {
        debug!("sign_request: {:?}", data);
        self.prepare_sign_request(public, data);

        async move {
            if let Err(e) = self.read_response().await {
                return (self, Err(e));
            }
            if !self.buf.is_empty() && self.buf[0] == msg::SIGN_RESPONSE {
                let as_sig = |buf: &CryptoVec| -> Result<crate::signature::Signature, Error> {
                    let mut r = buf.reader(1);
                    let mut resp = r.read_string()?.reader(0);
                    let typ = resp.read_string()?;
                    let sig = resp.read_string()?;
                    use crate::signature::Signature;
                    match typ {
                        b"rsa-sha2-256" => Ok(Signature::RSA {
                            bytes: sig.to_vec(),
                            hash: SignatureHash::SHA2_256,
                        }),
                        b"rsa-sha2-512" => Ok(Signature::RSA {
                            bytes: sig.to_vec(),
                            hash: SignatureHash::SHA2_512,
                        }),
                        b"ssh-ed25519" => {
                            let mut sig_bytes = [0; 64];
                            sig_bytes.clone_from_slice(sig);
                            Ok(Signature::Ed25519(crate::signature::SignatureBytes(
                                sig_bytes,
                            )))
                        }
                        _ => Err(Error::UnknownSignatureType {
                            sig_type: std::str::from_utf8(typ).unwrap_or("").to_string(),
                        }),
                    }
                };
                let sig = as_sig(&self.buf);
                (self, sig)
            } else {
                (self, Err(Error::AgentProtocolError))
            }
        }
    }

    /// Ask the agent to remove a key from its memory.
    pub async fn remove_identity(&mut self, public: &key::PublicKey) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_IDENTITY);
        key_blob(public, &mut self.buf);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Ask the agent to remove a smartcard from its memory.
    pub async fn remove_smartcard_key(&mut self, id: &str, pin: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_SMARTCARD_KEY);
        self.buf.extend_ssh_string(id.as_bytes());
        self.buf.extend_ssh_string(pin);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Ask the agent to forget all known keys.
    pub async fn remove_all_identities(&mut self) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_ALL_IDENTITIES);
        BigEndian::write_u32(&mut self.buf[0..], 5);
        self.read_response().await?;
        Ok(())
    }

    /// Send a custom message to the agent.
    pub async fn extension(&mut self, typ: &[u8], ext: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::EXTENSION);
        self.buf.extend_ssh_string(typ);
        self.buf.extend_ssh_string(ext);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Ask the agent what extensions about supported extensions.
    pub async fn query_extension(&mut self, typ: &[u8], mut ext: CryptoVec) -> Result<bool, Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::EXTENSION);
        self.buf.extend_ssh_string(typ);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[0..], len as u32);
        self.read_response().await?;

        let mut r = self.buf.reader(1);
        ext.extend(r.read_string()?);

        Ok(!self.buf.is_empty() && self.buf[0] == msg::SUCCESS)
    }
}

fn key_blob(public: &key::PublicKey, buf: &mut CryptoVec) {
    match *public {
        #[cfg(feature = "openssl")]
        PublicKey::RSA { ref key, .. } => {
            buf.extend(&[0, 0, 0, 0]);
            let len0 = buf.len();
            buf.extend_ssh_string(b"ssh-rsa");
            let rsa = key.0.rsa().unwrap();
            buf.extend_ssh_mpint(&rsa.e().to_vec());
            buf.extend_ssh_mpint(&rsa.n().to_vec());
            let len1 = buf.len();
            BigEndian::write_u32(&mut buf[5..], (len1 - len0) as u32);
        }
        PublicKey::Ed25519(ref p) => {
            buf.extend(&[0, 0, 0, 0]);
            let len0 = buf.len();
            buf.extend_ssh_string(b"ssh-ed25519");
            buf.extend_ssh_string(&p.key[0..]);
            let len1 = buf.len();
            BigEndian::write_u32(&mut buf[5..], (len1 - len0) as u32);
        }
    }
}

use russh_keys::key::KeyPair;
use russh_keys::PublicKeyBase64;

pub trait PublicKeyAsOpenSSH {
    fn as_openssh(&self) -> String;
}

impl PublicKeyAsOpenSSH for KeyPair {
    fn as_openssh(&self) -> String {
        let mut buf = String::new();
        buf.push_str(self.name());
        buf.push(' ');
        buf.push_str(&self.public_key_base64().replace("\r\n", ""));
        buf
    }
}

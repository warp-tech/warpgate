use russh::keys::PrivateKey;
use russh::keys::PublicKeyBase64;

pub trait PublicKeyAsOpenSSH {
    fn as_openssh(&self) -> String;
}

impl PublicKeyAsOpenSSH for PrivateKey {
    fn as_openssh(&self) -> String {
        let mut buf = String::new();
        buf.push_str(self.algorithm().as_str());
        buf.push(' ');
        buf.push_str(&self.public_key_base64());
        buf
    }
}

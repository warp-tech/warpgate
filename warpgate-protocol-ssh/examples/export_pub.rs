use russh;
use warpgate_protocol_ssh::helpers::PublicKeyAsOpenSSH;

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let key = russh::keys::load_secret_key(path, None).unwrap();
    println!("{}", key.as_openssh());
}

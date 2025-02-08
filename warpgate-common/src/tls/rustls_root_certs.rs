use once_cell::sync::Lazy;
use rustls::RootCertStore;

#[allow(clippy::expect_used)]
pub static ROOT_CERT_STORE: Lazy<RootCertStore> = Lazy::new(|| {
    let mut roots = RootCertStore::empty();
    for cert in
        rustls_native_certs::load_native_certs().expect("could not load root TLS certificates")
    {
        roots.add(cert).expect("could not add root TLS certificate");
    }
    roots
});

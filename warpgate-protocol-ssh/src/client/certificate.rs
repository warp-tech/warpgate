//! Certificates a secret backend's SSH CA signs per connection, and what is
//! checked on them before one is offered to a target.

use std::sync::Arc;
use std::time::Duration;

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey};
use tracing::warn;
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{SshTargetCertificateAuth, UserSessionId, WarpgateError};
use warpgate_core::SecretBackendRegistry;

use super::ConnectionError;

/// The longest a session certificate may be valid for; a backstop against a
/// role whose `max_ttl` is far longer than a session credential should live.
const MAX_CERTIFICATE_LIFETIME: Duration = Duration::from_hours(24);

/// `warpgate:<username>:<session id>`, which the target's sshd logs verbatim
/// and which is what makes a proxied session attributable to a person from the
/// target side alone.
pub(super) fn key_id(username: Option<&str>, session: UserSessionId) -> String {
    let who = username.map_or_else(|| "unattributed".to_owned(), key_id_field);
    format!("warpgate:{who}:{session}")
}

/// A username as it may appear in the key ID. Readers split the ID on colons,
/// so a colon in the name would shift every field; percent-encoded rather than
/// replaced so that two names cannot collide.
fn key_id_field(name: &str) -> String {
    name.replace('%', "%25").replace(':', "%3A")
}

/// A key pair generated for this attempt alone and the certificate the backend
/// signed for it, refused if it is not what was asked for.
pub(super) async fn issue(
    backends: &SecretBackendRegistry,
    auth: &SshTargetCertificateAuth,
    principal: &str,
    key_id: &str,
) -> Result<(Arc<PrivateKey>, Certificate), ConnectionError> {
    let key = Arc::new(
        PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
            .map_err(russh::keys::Error::from)?,
    );
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(russh::keys::Error::from)?;

    let signed_key = backends
        .sign_ssh_key(
            &auth.backend,
            &auth.mount,
            &auth.role,
            &public_key,
            principal,
            key_id,
        )
        .await
        .map_err(WarpgateError::from)?;
    let certificate = Certificate::from_openssh(&signed_key).map_err(russh::keys::Error::from)?;

    if let Some(reason) = mismatch(&certificate, key.public_key(), principal, key_id) {
        warn!(key_id, reason, "Refusing the issued certificate");
        return Err(ConnectionError::CertificateRefusedLocally(reason));
    }
    Ok((key, certificate))
}

/// Why an issued certificate must not be offered to the target, if any reason.
///
/// The issuer is a second gate, not a trusted party: every field that was asked
/// for is checked against what came back. What was not asked for is the
/// signing role's decision, except a `force-command`: writing a role is a lower
/// bar than signing with it, and a command planted there would run under the
/// connecting user's own key ID.
fn mismatch(
    certificate: &Certificate,
    key: &PublicKey,
    principal: &str,
    key_id: &str,
) -> Option<String> {
    if certificate.key_id() != key_id {
        return Some("the certificate carries a key ID other than the one requested".to_owned());
    }
    if certificate.cert_type() != CertType::User {
        return Some(
            "the issuer returned a host certificate rather than a user certificate".to_owned(),
        );
    }
    if certificate.public_key() != key.key_data() {
        return Some(
            "the issuer signed a key other than the one generated for this session".to_owned(),
        );
    }
    // Exactly the requested account: Vault returns the requested set or refuses,
    // so any other name is another account the target would accept this
    // certificate for (CVE-2024-7594, CVE-2026-35414).
    let principals = certificate.valid_principals();
    if principals.len() != 1 || principals.first().is_none_or(|only| only != principal) {
        return Some(format!(
            "the certificate names {principals:?} rather than only the target account {principal:?}"
        ));
    }
    // `u64::MAX` is OpenSSH's "never expires" sentinel; `valid_before_time()`
    // reports it as a real instant, so it is checked on the raw field.
    if certificate.valid_before() == u64::MAX {
        return Some("the certificate never expires, which is not a session credential".to_owned());
    }
    match certificate
        .valid_before_time()
        .map(|at| at.duration_since(std::time::SystemTime::now()))
    {
        None => {
            return Some("the certificate has an unrepresentable expiry time".to_owned());
        }
        Some(Err(_)) => {
            return Some(
                "the certificate has already expired; check the clock on this host".to_owned(),
            );
        }
        Some(Ok(lifetime)) if lifetime > MAX_CERTIFICATE_LIFETIME => {
            return Some(format!(
                "the certificate is valid for {} hours, far longer than a session credential should be",
                lifetime.as_secs() / 3600
            ));
        }
        Some(Ok(_)) => {}
    }
    if certificate.critical_options().contains_key("force-command") {
        return Some(
            "the certificate carries a force-command, which would run under the user's own key ID"
                .to_owned(),
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey};
    use warpgate_common::helpers::rng::get_crypto_rng;

    use super::{MAX_CERTIFICATE_LIFETIME, key_id_field, mismatch};

    const PRINCIPAL: &str = "root";
    const KEY_ID: &str = "warpgate:alice:0e6d1f4c";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    struct Issued {
        certificate: Certificate,
        key: PublicKey,
    }

    /// A certificate over a fresh key, signed by a throwaway CA.
    fn issued(
        valid_after: u64,
        valid_before: u64,
        critical: &[(&str, &str)],
        extensions: &[(&str, &str)],
    ) -> Issued {
        let ca = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519).unwrap();
        let subject = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519).unwrap();
        let mut builder = Builder::new_with_random_nonce(
            &mut get_crypto_rng(),
            subject.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();
        builder.cert_type(CertType::User).unwrap();
        builder.key_id(KEY_ID).unwrap();
        builder.valid_principal(PRINCIPAL).unwrap();
        for (name, value) in critical {
            builder.critical_option(*name, *value).unwrap();
        }
        for (name, value) in extensions {
            builder.extension(*name, *value).unwrap();
        }
        Issued {
            certificate: builder.sign(&ca).unwrap(),
            key: subject.public_key().clone(),
        }
    }

    fn fresh() -> Issued {
        issued(now() - 60, now() + 300, &[], &[])
    }

    fn verdict(issued: &Issued) -> Option<String> {
        mismatch(&issued.certificate, &issued.key, PRINCIPAL, KEY_ID)
    }

    #[test]
    fn test_matching_certificate_is_accepted() {
        assert_eq!(verdict(&fresh()), None);
    }

    #[test]
    fn test_request_mismatches_are_refused() {
        let issued = fresh();
        let other = fresh();
        let check = |key: &PublicKey, principal, key_id| {
            mismatch(&issued.certificate, key, principal, key_id).unwrap()
        };
        assert!(check(&issued.key, PRINCIPAL, "warpgate:bob:1").contains("key ID"));
        assert!(check(&other.key, PRINCIPAL, KEY_ID).contains("signed a key other"));
        assert!(check(&issued.key, "deploy", KEY_ID).contains("target account"));
    }

    #[test]
    fn test_validity_window_is_bounded() {
        let window = |before| verdict(&issued(now() - 60, before, &[], &[]));
        assert!(window(u64::MAX).unwrap().contains("never expires"));
        assert!(window(u64::MAX - 1).unwrap().contains("unrepresentable"));
        assert!(
            verdict(&issued(now() - 600, now() - 300, &[], &[]))
                .unwrap()
                .contains("already expired")
        );
        let bound = MAX_CERTIFICATE_LIFETIME.as_secs();
        assert!(window(now() + bound + 3600).unwrap().contains("far longer"));
        assert_eq!(window(now() + bound - 60), None);
    }

    /// Only a forced command is Warpgate's business; the rest of what a role
    /// puts on a certificate is the role's.
    #[test]
    fn test_forced_command_is_refused_and_other_options_are_the_roles() {
        let forced = issued(
            now() - 60,
            now() + 300,
            &[("force-command", "/bin/sh")],
            &[],
        );
        assert!(verdict(&forced).unwrap().contains("force-command"));

        let restricted = issued(
            now() - 60,
            now() + 300,
            &[("source-address", "10.0.0.0/8")],
            &[("permit-pty", ""), ("permit-port-forwarding", "")],
        );
        assert_eq!(verdict(&restricted), None);
    }

    #[test]
    fn test_key_id_field_keeps_names_distinct() {
        assert_eq!(key_id_field("alice"), "alice");
        assert_eq!(key_id_field("root:admin"), "root%3Aadmin");
        assert_ne!(key_id_field("root:admin"), key_id_field("root%3Aadmin"));
    }
}

use bytes::Bytes;
use poem_openapi::Enum;
use russh::keys::Algorithm;
use sea_orm::entity::prelude::{DeriveActiveEnum, EnumIter};
use sea_orm::sea_query::StringLen;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Secret, UserCertificateCredential};

#[derive(
    Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum,
)]
pub enum CredentialKind {
    #[serde(rename = "password")]
    Password,
    #[serde(rename = "publickey")]
    PublicKey,
    #[serde(rename = "certificate")]
    Certificate,
    #[serde(rename = "otp")]
    Totp,
    #[serde(rename = "sso")]
    Sso,
    #[serde(rename = "web")]
    WebUserApproval,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ApprovalKind {
    /// User approval: is a credential and part of auth policy, approved by user themselves in their browser session, pre-auth
    #[sea_orm(string_value = "user")]
    User,
    /// Admin approval: a target property, not a credential, approved by an admin user, post-auth
    #[sea_orm(string_value = "admin")]
    Admin,
}

/// "Remember decision" scope for approvals
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum, EnumIter, DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ApprovalScope {
    #[sea_orm(string_value = "once")]
    Once,
    #[sea_orm(string_value = "target")]
    Target,
    #[sea_orm(string_value = "all_targets")]
    AllTargets,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCredential {
    Otp(Secret<String>),
    Password(Secret<String>),
    PublicKey {
        kind: Algorithm,
        public_key_bytes: Bytes,
    },
    Certificate {
        certificate_pem: Secret<String>,
    },
    Sso {
        provider: String,
        email: String,
    },
    WebUserApproval,
}

impl AuthCredential {
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::Password { .. } => CredentialKind::Password,
            Self::PublicKey { .. } => CredentialKind::PublicKey,
            Self::Certificate { .. } => CredentialKind::Certificate,
            Self::Otp { .. } => CredentialKind::Totp,
            Self::Sso { .. } => CredentialKind::Sso,
            Self::WebUserApproval => CredentialKind::WebUserApproval,
        }
    }

    pub fn safe_description(&self) -> String {
        match self {
            Self::Password { .. } => "password".to_string(),
            Self::PublicKey { .. } => "public key".to_string(),
            Self::Certificate { .. } => "client certificate".to_string(),
            Self::Otp { .. } => "one-time password".to_string(),
            Self::Sso { provider, .. } => format!("SSO ({provider})"),
            Self::WebUserApproval => "in-browser auth".to_string(),
        }
    }
}

/// Identifies the *stored* credential that a submitted one matched, so a later
/// authentication can be recognised as having used the same one.
///
/// Built only from a credential's stored verifier — an Argon2 PHC string, an
/// OpenSSH public key — never from what the client submitted. That is the whole
/// point of the type: these identifiers end up in the approval rows, and a
/// digest of a submitted *password* would put a second, far cheaper
/// representation of it in the same database the Argon2 hash lives in. Anyone
/// holding a dump already has the verifier, so this tells them nothing new.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoredCredentialId([u8; 32]);

impl StoredCredentialId {
    /// `verifier` must be the stored side of the credential, never the client's
    /// submission — see the type docs.
    #[must_use]
    pub fn of_stored_verifier(verifier: &[u8]) -> Self {
        Self(sha256(verifier))
    }

    const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The credential kinds that exist as a stored row.
///
/// Deliberately not [`CredentialKind`]: an in-browser approval has no row and
/// so no id, and `{ kind: WebUserApproval, id }` must not be a pair anyone can
/// write. Certificates have a table but no submission path yet — add the
/// variant when one exists and the compiler will ask for its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoredCredentialKind {
    Password,
    PublicKey,
    Totp,
    Sso,
}

impl StoredCredentialKind {
    pub const fn kind(self) -> CredentialKind {
        match self {
            Self::Password => CredentialKind::Password,
            Self::PublicKey => CredentialKind::PublicKey,
            Self::Totp => CredentialKind::Totp,
            Self::Sso => CredentialKind::Sso,
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PublicKey => "public key",
            Self::Totp => "one-time password",
            Self::Sso => "SSO",
        }
    }
}

/// The stored credential a submission was verified against: which row, and what
/// that row held at the time.
///
/// Both halves, because they answer different questions. The id distinguishes
/// two rows that hold identical material — two users enrolling the same public
/// key, or one user with two TOTP devices. The verifier notices when a row's
/// material is *replaced*: the admin endpoints for public keys and SSO update
/// in place, keeping the id, so an id-only identity would carry a remembered
/// approval across a key rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoredCredential {
    kind: StoredCredentialKind,
    id: Uuid,
    verifier: StoredCredentialId,
}

impl StoredCredential {
    /// `verifier` is the row's own material — see [`StoredCredentialId`].
    #[must_use]
    pub const fn new(kind: StoredCredentialKind, id: Uuid, verifier: StoredCredentialId) -> Self {
        Self { kind, id, verifier }
    }

    pub const fn kind(&self) -> StoredCredentialKind {
        self.kind
    }

    /// Pushes a byte encoding of this credential's identity, for hashing into a
    /// digest of a whole authentication.
    ///
    /// Every part is fixed-width — a tag, a 16-byte uuid, a 32-byte digest — so
    /// the concatenation is unambiguous without length framing. Restore the
    /// framing if a variable-length part is ever added.
    pub(crate) fn write_canonical_bytes(&self, out: &mut Vec<u8>) {
        // Written out rather than `kind as u8`: this digest is persisted in
        // approval rows, so reordering the enum must not renumber it.
        out.push(match self.kind {
            StoredCredentialKind::Password => 1,
            StoredCredentialKind::PublicKey => 2,
            StoredCredentialKind::Totp => 3,
            StoredCredentialKind::Sso => 4,
        });
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(self.verifier.bytes());
    }
}

/// A credential that passed validation, by identity rather than by value.
///
/// One value replaces what used to be two index-parallel vectors — the
/// submission and the stored credential it matched — so the two cannot drift.
/// Nothing here is secret, so an auth state that lives for the whole auth
/// timeout no longer holds a plaintext password or one-time code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidCredential {
    Stored(StoredCredential),
    /// The user approving in their own browser. There is no stored row to point
    /// at — the act of approving *is* the credential — so none can be attached.
    WebUserApproval,
}

impl ValidCredential {
    #[must_use]
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::Stored(credential) => credential.kind().kind(),
            Self::WebUserApproval => CredentialKind::WebUserApproval,
        }
    }

    /// The stored row this asserts, where there is one.
    ///
    /// The projection a remember-by key is built through, so "an approval is
    /// not part of the key it is remembered under" holds by type rather than by
    /// a filter someone has to remember to write.
    #[must_use]
    pub const fn stored(&self) -> Option<&StoredCredential> {
        match self {
            Self::Stored(credential) => Some(credential),
            Self::WebUserApproval => None,
        }
    }

    /// How an accepted credential appears in the `Authenticated` audit event.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Stored(credential) => {
                format!("{} ({})", credential.kind.description(), credential.id)
            }
            Self::WebUserApproval => "in-browser auth".to_string(),
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl From<UserCertificateCredential> for AuthCredential {
    fn from(cred: UserCertificateCredential) -> Self {
        Self::Certificate {
            certificate_pem: cred.certificate_pem,
        }
    }
}

impl From<AuthCredential> for Option<UserCertificateCredential> {
    fn from(cred: AuthCredential) -> Self {
        match cred {
            AuthCredential::Certificate { certificate_pem } => {
                Some(UserCertificateCredential { certificate_pem })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::StoredCredentials;

    fn digest(credential: StoredCredential) -> String {
        #[allow(clippy::expect_used)]
        StoredCredentials::new(vec![credential])
            .expect("non-empty")
            .digest()
    }

    fn base() -> StoredCredential {
        StoredCredential::new(
            StoredCredentialKind::Password,
            Uuid::from_u128(1),
            StoredCredentialId::of_stored_verifier(b"stored"),
        )
    }

    /// The digest *is* the comparison a remembered approval is matched by, so a
    /// part of a credential's identity that doesn't reach it is a part two
    /// different credentials may differ in and still share a grant.
    ///
    /// The destructuring is the point: adding a field to `StoredCredential`
    /// stops this compiling until someone says what it does to the digest.
    #[test]
    fn every_part_of_a_stored_credential_reaches_the_digest() {
        let StoredCredential { kind, id, verifier } = base();
        let _ = (kind, id, verifier);

        for altered in [
            StoredCredential::new(StoredCredentialKind::Sso, id, verifier),
            StoredCredential::new(kind, Uuid::from_u128(2), verifier),
            StoredCredential::new(
                kind,
                id,
                StoredCredentialId::of_stored_verifier(b"replaced"),
            ),
        ] {
            assert_ne!(digest(base()), digest(altered), "{altered:?}");
        }
    }

    /// Both halves earn their place, and each catches what the other cannot:
    /// the id separates two rows holding identical material, and the verifier
    /// notices a row whose material was replaced in place — which the admin
    /// public-key and SSO endpoints do, keeping the id.
    #[test]
    fn the_id_and_the_material_each_catch_what_the_other_misses() {
        let same_material_different_row = StoredCredential::new(
            StoredCredentialKind::Password,
            Uuid::from_u128(2),
            StoredCredentialId::of_stored_verifier(b"stored"),
        );
        assert_ne!(digest(base()), digest(same_material_different_row));

        let same_row_replaced_material = StoredCredential::new(
            StoredCredentialKind::Password,
            Uuid::from_u128(1),
            StoredCredentialId::of_stored_verifier(b"rotated"),
        );
        assert_ne!(digest(base()), digest(same_row_replaced_material));
    }

    /// Every kind must encode distinctly, or two credentials of different kinds
    /// sharing an id and material would be one credential to the digest.
    #[test]
    fn every_stored_kind_encodes_distinctly() {
        use std::collections::HashSet;

        let kinds = [
            StoredCredentialKind::Password,
            StoredCredentialKind::PublicKey,
            StoredCredentialKind::Totp,
            StoredCredentialKind::Sso,
        ];
        // Exhaustive by construction: a new variant fails to compile here.
        for kind in kinds {
            let _: () = match kind {
                StoredCredentialKind::Password
                | StoredCredentialKind::PublicKey
                | StoredCredentialKind::Totp
                | StoredCredentialKind::Sso => (),
            };
        }

        let digests: HashSet<_> = kinds
            .into_iter()
            .map(|kind| {
                digest(StoredCredential::new(
                    kind,
                    Uuid::nil(),
                    StoredCredentialId::of_stored_verifier(b""),
                ))
            })
            .collect();
        assert_eq!(digests.len(), kinds.len());
    }
}

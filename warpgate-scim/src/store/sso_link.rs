//! Keeps one SSO credential per provisioning provider in step with the user's
//! primary SCIM email, so a provisioned user can log in through the identity
//! provider's OIDC straight away.

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;
use warpgate_common::audit::{AuditEvent, CredentialChangedVia};
use warpgate_db_entities::{SsoCredential, User};

use crate::protocol::ScimError;

/// Makes the user's SSO credentials for `provider` exactly `email` (or none).
/// Other SSO credentials of that provider on the user are replaced: for the
/// provisioning provider, SCIM is the source of the identity.
pub async fn reconcile(
    db: &DatabaseConnection,
    user: &User::Model,
    provider: &str,
    email: Option<&str>,
) -> Result<(), ScimError> {
    let existing = SsoCredential::Entity::find()
        .filter(SsoCredential::Column::UserId.eq(user.id))
        .filter(SsoCredential::Column::Provider.eq(provider))
        .all(db)
        .await?;

    let mut kept = false;
    for credential in existing {
        if email == Some(credential.email.as_str()) && !kept {
            kept = true;
            continue;
        }
        let gone = credential.email.clone();
        SsoCredential::Entity::delete_by_id(credential.id)
            .exec(db)
            .await?;
        credential_event(user, gone, false);
    }

    if let Some(email) = email
        && !kept
    {
        SsoCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user.id),
            provider: Set(Some(provider.to_owned())),
            email: Set(email.to_owned()),
        }
        .insert(db)
        .await?;
        credential_event(user, email.to_owned(), true);
    }
    Ok(())
}

fn credential_event(user: &User::Model, email: String, created: bool) {
    let (user_id, username) = (user.id, user.username.clone());
    let credential_type = "sso".to_owned();
    let via = CredentialChangedVia::Scim;
    let actor_user_id = Uuid::nil();
    if created {
        AuditEvent::CredentialCreated {
            credential_type,
            credential_name: Some(email),
            via,
            user_id,
            username,
            actor_user_id,
        }
        .emit();
    } else {
        AuditEvent::CredentialDeleted {
            credential_type,
            credential_name: Some(email),
            via,
            user_id,
            username,
            actor_user_id,
        }
        .emit();
    }
}

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::Utc;
use data_encoding::BASE64;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::auth::{
    AllCredentialsPolicy, AnySingleCredentialPolicy, AuthCredential, CredentialKind,
    CredentialPolicy, PerProtocolCredentialPolicy,
};
use warpgate_common::helpers::hash::verify_password_hash;
use warpgate_common::helpers::otp::verify_totp;
use warpgate_common::{
    Role, Target, User, UserAuthCredential, UserPasswordCredential, UserPublicKeyCredential,
    UserSsoCredential, UserTotpCredential, WarpgateError,
};
use warpgate_db_entities as entities;

use super::ConfigProvider;

pub struct DatabaseConfigProvider {
    db: Arc<Mutex<DatabaseConnection>>,
}

impl DatabaseConfigProvider {
    pub async fn new(db: &Arc<Mutex<DatabaseConnection>>) -> Self {
        Self { db: db.clone() }
    }
}

impl ConfigProvider for DatabaseConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<User>, WarpgateError> {
        let db = self.db.lock().await;

        let users = entities::User::Entity::find()
            .order_by_asc(entities::User::Column::Username)
            .all(&*db)
            .await?;

        let users: Result<Vec<User>, _> = users.into_iter().map(|t| t.try_into()).collect();

        Ok(users?)
    }

    async fn list_targets(&mut self) -> Result<Vec<Target>, WarpgateError> {
        let db = self.db.lock().await;

        let targets = entities::Target::Entity::find()
            .order_by_asc(entities::Target::Column::Name)
            .all(&*db)
            .await?;

        let targets: Result<Vec<Target>, _> = targets.into_iter().map(|t| t.try_into()).collect();

        Ok(targets?)
    }

    async fn get_credential_policy(
        &mut self,
        username: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError> {
        let db = self.db.lock().await;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(None);
        };

        let user = user_model.load_details(&db).await?;

        let supported_credential_types: HashSet<CredentialKind> = user
            .credentials
            .iter()
            .map(|x| x.kind())
            .filter(|x| supported_credential_types.contains(x))
            .collect();
        let default_policy = Box::new(AnySingleCredentialPolicy {
            supported_credential_types: supported_credential_types.clone(),
        }) as Box<dyn CredentialPolicy + Sync + Send>;

        if let Some(req) = user.credential_policy.clone() {
            let mut policy = PerProtocolCredentialPolicy {
                default: default_policy,
                protocols: HashMap::new(),
            };

            if let Some(p) = req.http {
                policy.protocols.insert(
                    "HTTP",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.mysql {
                policy.protocols.insert(
                    "MySQL",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.postgres {
                policy.protocols.insert(
                    "PostgreSQL",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.ssh {
                policy.protocols.insert(
                    "SSH",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types,
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }

            Ok(Some(
                Box::new(policy) as Box<dyn CredentialPolicy + Sync + Send>
            ))
        } else {
            Ok(Some(default_policy))
        }
    }

    async fn username_for_sso_credential(
        &mut self,
        client_credential: &AuthCredential,
    ) -> Result<Option<String>, WarpgateError> {
        let db = self.db.lock().await;

        let AuthCredential::Sso {
            provider: client_provider,
            email: client_email,
        } = client_credential
        else {
            return Ok(None);
        };

        let Some(cred) = entities::SsoCredential::Entity::find()
            .filter(
                entities::SsoCredential::Column::Email.eq(client_email).and(
                    entities::SsoCredential::Column::Provider
                        .eq(client_provider)
                        .or(entities::SsoCredential::Column::Provider.is_null()),
                ),
            )
            .one(&*db)
            .await?
        else {
            return Ok(None);
        };

        let user = cred.find_related(entities::User::Entity).one(&*db).await?;

        Ok(user.map(|x| x.username))
    }

    async fn validate_credential(
        &mut self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<bool, WarpgateError> {
        let db = self.db.lock().await;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        let user_details = user_model.load_details(&db).await?;

        match client_credential {
            AuthCredential::PublicKey {
                kind,
                public_key_bytes,
            } => {
                let base64_bytes = BASE64.encode(public_key_bytes);
                let openssh_public_key = format!("{kind} {base64_bytes}");
                debug!(
                    username = &user_details.username[..],
                    "Client key: {}", openssh_public_key
                );

                return Ok(user_details
                    .credentials
                    .iter()
                    .any(|credential| match credential {
                        UserAuthCredential::PublicKey(UserPublicKeyCredential {
                            key: ref user_key,
                        }) => &openssh_public_key == user_key.expose_secret(),
                        _ => false,
                    }));
            }
            AuthCredential::Password(client_password) => {
                return Ok(user_details
                    .credentials
                    .iter()
                    .any(|credential| match credential {
                        UserAuthCredential::Password(UserPasswordCredential {
                            hash: ref user_password_hash,
                        }) => verify_password_hash(
                            client_password.expose_secret(),
                            user_password_hash.expose_secret(),
                        )
                        .unwrap_or_else(|e| {
                            error!(
                                username = &user_details.username[..],
                                "Error verifying password hash: {}", e
                            );
                            false
                        }),
                        _ => false,
                    }))
            }
            AuthCredential::Otp(client_otp) => {
                return Ok(user_details
                    .credentials
                    .iter()
                    .any(|credential| match credential {
                        UserAuthCredential::Totp(UserTotpCredential {
                            key: ref user_otp_key,
                        }) => verify_totp(client_otp.expose_secret(), user_otp_key),
                        _ => false,
                    }))
            }
            AuthCredential::Sso {
                provider: client_provider,
                email: client_email,
            } => {
                for credential in user_details.credentials.iter() {
                    if let UserAuthCredential::Sso(UserSsoCredential {
                        ref provider,
                        ref email,
                    }) = credential
                    {
                        if provider.as_ref().unwrap_or(client_provider) == client_provider
                            && email == client_email
                        {
                            return Ok(true);
                        }
                    }
                }
                return Ok(false);
            }
            _ => return Err(WarpgateError::InvalidCredentialType),
        }
    }

    async fn authorize_target(
        &mut self,
        username: &str,
        target_name: &str,
    ) -> Result<bool, WarpgateError> {
        let db = self.db.lock().await;

        let target_model = entities::Target::Entity::find()
            .filter(entities::Target::Column::Name.eq(target_name))
            .one(&*db)
            .await?;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        let Some(target_model) = target_model else {
            warn!("Selected target not found: {}", target_name);
            return Ok(false);
        };

        let target_roles: HashSet<String> = target_model
            .find_related(entities::Role::Entity)
            .all(&*db)
            .await?
            .into_iter()
            .map(Into::<Role>::into)
            .map(|x| x.name)
            .collect();

        let user_roles: HashSet<String> = user_model
            .find_related(entities::Role::Entity)
            .all(&*db)
            .await?
            .into_iter()
            .map(Into::<Role>::into)
            .map(|x| x.name)
            .collect();

        let intersect = user_roles.intersection(&target_roles).count() > 0;

        Ok(intersect)
    }

    async fn apply_sso_role_mappings(
        &mut self,
        username: &str,
        managed_role_names: Option<Vec<String>>,
        assigned_role_names: Vec<String>,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        let user = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await
            .map_err(WarpgateError::from)?
            .ok_or_else(|| WarpgateError::UserNotFound(username.into()))?;

        let managed_role_names = match managed_role_names {
            Some(x) => x,
            None => entities::Role::Entity::find()
                .all(&*db)
                .await?
                .into_iter()
                .map(|x| x.name)
                .collect(),
        };

        for role_name in managed_role_names.into_iter() {
            let role = entities::Role::Entity::find()
                .filter(entities::Role::Column::Name.eq(role_name.clone()))
                .one(&*db)
                .await
                .map_err(WarpgateError::from)?
                .ok_or_else(|| WarpgateError::RoleNotFound(role_name.clone()))?;

            let assignment = entities::UserRoleAssignment::Entity::find()
                .filter(entities::UserRoleAssignment::Column::UserId.eq(user.id))
                .filter(entities::UserRoleAssignment::Column::RoleId.eq(role.id))
                .one(&*db)
                .await
                .map_err(WarpgateError::from)?;

            match (assignment, assigned_role_names.contains(&role_name)) {
                (None, true) => {
                    info!("Adding role {role_name} for user {username} (from SSO)");
                    let values = entities::UserRoleAssignment::ActiveModel {
                        user_id: Set(user.id),
                        role_id: Set(role.id),
                        ..Default::default()
                    };

                    values.insert(&*db).await.map_err(WarpgateError::from)?;
                }
                (Some(assignment), false) => {
                    info!("Removing role {role_name} for user {username} (from SSO)");
                    assignment.delete(&*db).await.map_err(WarpgateError::from)?;
                }
                _ => (),
            }
        }

        Ok(())
    }

    async fn update_public_key_last_used(
        &self,
        credential: Option<AuthCredential>,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        let Some(AuthCredential::PublicKey {
            kind,
            public_key_bytes,
        }) = credential
        else {
            error!("Invalid or missing public key credential");
            return Err(WarpgateError::InvalidCredentialType);
        };

        // Encode public key and match it against the database
        let base64_bytes = data_encoding::BASE64.encode(&public_key_bytes);
        let openssh_public_key = format!("{kind} {base64_bytes}");

        debug!(
            "Attempting to update last_used for public key: {}",
            openssh_public_key
        );

        // Find the public key credential
        let public_key_credential = entities::PublicKeyCredential::Entity::find()
            .filter(
                entities::PublicKeyCredential::Column::OpensshPublicKey
                    .eq(openssh_public_key.clone()),
            )
            .one(&*db)
            .await?;

        let Some(public_key_credential) = public_key_credential else {
            warn!(
                "Public key not found in the database: {}",
                openssh_public_key
            );
            return Ok(()); // Gracefully return if the key is not found
        };

        // Update the `last_used` (last used) timestamp
        let mut active_model: entities::PublicKeyCredential::ActiveModel =
            public_key_credential.into();
        active_model.last_used = Set(Some(Utc::now()));

        active_model.update(&*db).await.map_err(|e| {
            error!("Failed to update last_used for public key: {:?}", e);
            WarpgateError::DatabaseError(e)
        })?;

        Ok(())
    }

    async fn validate_api_token(&mut self, token: &str) -> Result<Option<User>, WarpgateError> {
        let db = self.db.lock().await;
        let Some(ticket) = entities::ApiToken::Entity::find()
            .filter(
                entities::ApiToken::Column::Secret
                    .eq(token)
                    .and(entities::ApiToken::Column::Expiry.gt(Utc::now())),
            )
            .one(&*db)
            .await?
        else {
            return Ok(None);
        };

        let Some(user) = ticket
            .find_related(entities::User::Entity)
            .one(&*db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState);
        };

        Ok(Some(user.try_into()?))
    }
}

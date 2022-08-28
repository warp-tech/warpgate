use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use data_encoding::BASE64;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter, QueryOrder};
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::auth::{
    AllCredentialsPolicy, AnySingleCredentialPolicy, AuthCredential, CredentialKind,
    CredentialPolicy, PerProtocolCredentialPolicy,
};
use warpgate_common::helpers::hash::verify_password_hash;
use warpgate_common::helpers::otp::verify_totp;
use warpgate_common::{
    Role as RoleConfig, Target as TargetConfig, User, UserAuthCredential, WarpgateConfig,
    WarpgateError,
};
use warpgate_db_entities::{Role, Target};

use super::ConfigProvider;
use crate::UserSnapshot;

pub struct DatabaseConfigProvider {
    db: Arc<Mutex<DatabaseConnection>>,
    config: Arc<Mutex<WarpgateConfig>>,
}

impl DatabaseConfigProvider {
    pub async fn new(
        db: &Arc<Mutex<DatabaseConnection>>,
        config: &Arc<Mutex<WarpgateConfig>>,
    ) -> Self {
        Self {
            db: db.clone(),
            config: config.clone(),
        }
    }
}

#[async_trait]
impl ConfigProvider for DatabaseConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<UserSnapshot>, WarpgateError> {
        Ok(self
            .config
            .lock()
            .await
            .store
            .users
            .iter()
            .map(UserSnapshot::new)
            .collect::<Vec<_>>())
    }

    async fn list_targets(&mut self) -> Result<Vec<TargetConfig>, WarpgateError> {
        let db = self.db.lock().await;

        let targets = Target::Entity::find()
            .order_by_asc(Target::Column::Name)
            .all(&*db)
            .await?;

        let targets: Result<Vec<TargetConfig>, _> =
            targets.into_iter().map(|t| t.try_into()).collect();

        Ok(targets?)
    }

    async fn get_credential_policy(
        &mut self,
        username: &str,
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError> {
        let user = {
            self.config
                .lock()
                .await
                .store
                .users
                .iter()
                .find(|x| x.username == username)
                .map(User::to_owned)
        };
        let Some(user) = user else {
            error!("Selected user not found: {}", username);
            return Ok(None);
        };

        let supported_credential_types: HashSet<CredentialKind> =
            user.credentials.iter().map(|x| x.kind()).collect();
        let default_policy = Box::new(AnySingleCredentialPolicy {
            supported_credential_types: supported_credential_types.clone(),
        }) as Box<dyn CredentialPolicy + Sync + Send>;

        if let Some(req) = user.require {
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
        let AuthCredential::Sso { provider: client_provider, email : client_email} = client_credential else {
            return Ok(None);
        };

        Ok(self
            .config
            .lock()
            .await
            .store
            .users
            .iter()
            .find(|x| {
                for cred in x.credentials.iter() {
                    if let UserAuthCredential::Sso { provider, email } = cred {
                        if provider.as_ref().unwrap_or(client_provider) == client_provider
                            && email == client_email
                        {
                            return true;
                        }
                    }
                }
                false
            })
            .map(|x| x.username.clone()))
    }

    async fn validate_credential(
        &mut self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<bool, WarpgateError> {
        let user = {
            self.config
                .lock()
                .await
                .store
                .users
                .iter()
                .find(|x| x.username == username)
                .map(User::to_owned)
        };
        let Some(user) = user else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        match client_credential {
            AuthCredential::PublicKey {
                kind,
                public_key_bytes,
            } => {
                let base64_bytes = BASE64.encode(public_key_bytes);

                let client_key = format!("{} {}", kind, base64_bytes);
                debug!(username = &user.username[..], "Client key: {}", client_key);

                return Ok(user.credentials.iter().any(|credential| match credential {
                    UserAuthCredential::PublicKey { key: ref user_key } => {
                        &client_key == user_key.expose_secret()
                    }
                    _ => false,
                }));
            }
            AuthCredential::Password(client_password) => {
                return Ok(user.credentials.iter().any(|credential| match credential {
                    UserAuthCredential::Password {
                        hash: ref user_password_hash,
                    } => verify_password_hash(
                        client_password.expose_secret(),
                        user_password_hash.expose_secret(),
                    )
                    .unwrap_or_else(|e| {
                        error!(
                            username = &user.username[..],
                            "Error verifying password hash: {}", e
                        );
                        false
                    }),
                    _ => false,
                }))
            }
            AuthCredential::Otp(client_otp) => {
                return Ok(user.credentials.iter().any(|credential| match credential {
                    UserAuthCredential::Totp {
                        key: ref user_otp_key,
                    } => verify_totp(client_otp.expose_secret(), user_otp_key),
                    _ => false,
                }))
            }
            AuthCredential::Sso {
                provider: client_provider,
                email: client_email,
            } => {
                for credential in user.credentials.iter() {
                    if let UserAuthCredential::Sso {
                        ref provider,
                        ref email,
                    } = credential
                    {
                        if provider.as_ref().unwrap_or(client_provider) == client_provider {
                            return Ok(email == client_email);
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
        let config = self.config.lock().await;
        let user = config
            .store
            .users
            .iter()
            .find(|x| x.username == username)
            .map(User::to_owned);

        let db = self.db.lock().await;

        let target_model: Option<Target::Model> = Target::Entity::find()
            .order_by_desc(Target::Column::Name)
            .filter(Target::Column::Name.eq(target_name))
            .one(&*db)
            .await?;

        let Some(user) = user else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        let Some(target_model) = target_model else {
            warn!("Selected target not found: {}", target_name);
            return Ok(false);
        };

        let target_roles: HashSet<String> = target_model
            .find_related(Role::Entity)
            .all(&*db)
            .await?
            .into_iter()
            .map(Into::<RoleConfig>::into)
            .map(|x| x.name)
            .collect();

        let user_roles: HashSet<String> = Role::Entity::find()
            .filter(Role::Column::Name.is_in(user.roles))
            .all(&*db)
            .await?
            .into_iter()
            .map(Into::<RoleConfig>::into)
            .map(|x| x.name)
            .collect();

        let intersect = user_roles.intersection(&target_roles).count() > 0;

        Ok(intersect)
    }
}

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use data_encoding::BASE64_MIME;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Ticket;

use super::ConfigProvider;
use crate::auth::{
    AuthCredential, AuthState, CredentialKind, CredentialPolicy, CredentialPolicyResponse,
};
use crate::helpers::hash::verify_password_hash;
use crate::helpers::otp::verify_totp;
use crate::{
    AuthResult, ProtocolName, Target, User, UserAuthCredential, UserSnapshot, WarpgateConfig,
    WarpgateError,
};

pub struct FileConfigProvider {
    db: Arc<Mutex<DatabaseConnection>>,
    config: Arc<Mutex<WarpgateConfig>>,
}

impl FileConfigProvider {
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
impl ConfigProvider for FileConfigProvider {
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

    async fn list_targets(&mut self) -> Result<Vec<Target>, WarpgateError> {
        Ok(self
            .config
            .lock()
            .await
            .store
            .targets
            .iter()
            .map(|x| x.to_owned())
            .collect::<Vec<_>>())
    }

    async fn authorize(
        &mut self,
        username: &str,
        credentials: &[AuthCredential],
        protocol: ProtocolName,
    ) -> Result<AuthResult, WarpgateError> {
        if credentials.is_empty() {
            return Ok(AuthResult::Rejected);
        }

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
            return Ok(AuthResult::Rejected);
        };

        let mut valid_credentials = vec![];

        for client_credential in credentials {
            match client_credential {
                AuthCredential::PublicKey {
                    kind,
                    public_key_bytes,
                } => {
                    let mut base64_bytes = BASE64_MIME.encode(public_key_bytes);
                    base64_bytes.pop();
                    base64_bytes.pop();

                    let client_key = format!("{} {}", kind, base64_bytes);
                    debug!(username = &user.username[..], "Client key: {}", client_key);

                    if let Some(credential) =
                        user.credentials.iter().find(|credential| match credential {
                            UserAuthCredential::PublicKey { key: ref user_key } => {
                                &client_key == user_key.expose_secret()
                            }
                            _ => false,
                        })
                    {
                        valid_credentials.push((client_credential, credential))
                    }
                }
                AuthCredential::Password(client_password) => {
                    match user.credentials.iter().find(|credential| match credential {
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
                    }) {
                        Some(credential) => valid_credentials.push((client_credential, credential)),
                        None => return Ok(AuthResult::Rejected),
                    }
                }
                AuthCredential::Otp(client_otp) => {
                    match user.credentials.iter().find(|credential| match credential {
                        UserAuthCredential::Totp {
                            key: ref user_otp_key,
                        } => verify_totp(client_otp.expose_secret(), user_otp_key),
                        _ => false,
                    }) {
                        Some(credential) => valid_credentials.push((client_credential, credential)),
                        None => return Ok(AuthResult::Rejected),
                    }
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
                                if email == client_email {
                                    valid_credentials.push((client_credential, credential))
                                } else {
                                    return Ok(AuthResult::Rejected);
                                }
                            }
                        }
                    }
                }
            }
        }

        if valid_credentials.is_empty() {
            warn!(
                username = &user.username[..],
                "Client credentials did not match"
            );
        }

        let mut state = AuthState::new(user.username.clone(), protocol.to_string(), user.require);

        for pair in valid_credentials.into_iter() {
            state.add_valid_credential(pair.0.clone());
        }

        Ok(state.verify())
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
        let target = config.store.targets.iter().find(|x| x.name == target_name);

        let Some(user) = user else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        let Some(target) = target else {
            warn!("Selected target not found: {}", target_name);
            return Ok(false);
        };

        let user_roles = user
            .roles
            .iter()
            .map(|x| config.store.roles.iter().find(|y| &y.name == x))
            .filter_map(|x| x.to_owned())
            .collect::<HashSet<_>>();
        let target_roles = target
            .allow_roles
            .iter()
            .map(|x| config.store.roles.iter().find(|y| &y.name == x))
            .filter_map(|x| x.to_owned())
            .collect::<HashSet<_>>();

        let intersect = user_roles.intersection(&target_roles).count() > 0;

        Ok(intersect)
    }

    async fn consume_ticket(&mut self, ticket_id: &Uuid) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;
        let ticket = Ticket::Entity::find_by_id(*ticket_id).one(&*db).await?;
        let Some(ticket) = ticket else {
            return Err(WarpgateError::InvalidTicket(*ticket_id));
        };

        if let Some(uses_left) = ticket.uses_left {
            let mut model: Ticket::ActiveModel = ticket.into();
            model.uses_left = Set(Some(uses_left - 1));
            model.update(&*db).await?;
        }

        Ok(())
    }
}

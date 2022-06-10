use super::ConfigProvider;
use crate::helpers::hash::verify_password_hash;
use crate::helpers::otp::verify_totp;
use crate::{
    AuthCredential, AuthResult, Target, User, UserAuthCredential, UserSnapshot, WarpgateConfig,
};
use anyhow::Result;
use async_trait::async_trait;
use data_encoding::BASE64_MIME;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Ticket;

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

fn credential_is_type(c: &UserAuthCredential, k: &str) -> bool {
    match c {
        UserAuthCredential::Password { .. } => k == "password",
        UserAuthCredential::PublicKey { .. } => k == "publickey",
        UserAuthCredential::TOTP { .. } => k == "otp",
    }
}

#[async_trait]
impl ConfigProvider for FileConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<UserSnapshot>> {
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

    async fn list_targets(&mut self) -> Result<Vec<Target>> {
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
    ) -> Result<AuthResult> {
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

                    for credential in user.credentials.iter() {
                        if let UserAuthCredential::PublicKey { key: ref user_key } = credential {
                            if &client_key == user_key.expose_secret() {
                                valid_credentials.push(credential);
                                break;
                            }
                        }
                    }
                }
                AuthCredential::Password(client_password) => {
                    for credential in user.credentials.iter() {
                        if let UserAuthCredential::Password {
                            hash: ref user_password_hash,
                        } = credential
                        {
                            match verify_password_hash(
                                client_password.expose_secret(),
                                user_password_hash.expose_secret(),
                            ) {
                                Ok(true) => {
                                    valid_credentials.push(credential);
                                    break;
                                }
                                Ok(false) => continue,
                                Err(e) => {
                                    error!(
                                        username = &user.username[..],
                                        "Error verifying password hash: {}", e
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                }
                AuthCredential::OTP(client_otp) => {
                    for credential in user.credentials.iter() {
                        if let UserAuthCredential::TOTP {
                            key: ref user_otp_key,
                        } = credential
                        {
                            if verify_totp(client_otp.expose_secret(), user_otp_key) {
                                valid_credentials.push(credential);
                                break;
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

        match user.require {
            Some(ref required_kinds) => {
                let mut remaining_required_kinds = HashSet::new();
                remaining_required_kinds.extend(required_kinds);
                for kind in required_kinds {
                    if valid_credentials
                        .iter()
                        .any(|x| credential_is_type(x, kind))
                    {
                        remaining_required_kinds.remove(kind);
                    }
                }
                if remaining_required_kinds.is_empty() {
                    return Ok(AuthResult::Accepted {
                        username: user.username.clone(),
                    });
                } else if remaining_required_kinds.contains(&"otp".to_string()) {
                    return Ok(AuthResult::OTPNeeded);
                } else {
                    return Ok(AuthResult::Rejected);
                }
            }
            None => Ok(if !valid_credentials.is_empty() {
                AuthResult::Accepted {
                    username: user.username.clone(),
                }
            } else {
                AuthResult::Rejected
            }),
        }
    }

    async fn authorize_target(&mut self, username: &str, target_name: &str) -> Result<bool> {
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
            error!("Selected target not found: {}", target_name);
            return Ok(false);
        };

        let user_roles = user
            .roles
            .iter()
            .map(|x| config.store.roles.iter().find(|y| &y.name == x))
            .filter(|x| x.is_some())
            .map(|x| x.unwrap().to_owned())
            .collect::<HashSet<_>>();
        let target_roles = target
            .allow_roles
            .iter()
            .map(|x| config.store.roles.iter().find(|y| &y.name == x))
            .filter(|x| x.is_some())
            .map(|x| x.unwrap().to_owned())
            .collect::<HashSet<_>>();

        let intersect = user_roles.intersection(&target_roles).count() > 0;

        Ok(intersect)
    }

    async fn consume_ticket(&mut self, ticket_id: &Uuid) -> Result<()> {
        let db = self.db.lock().await;
        let ticket = Ticket::Entity::find_by_id(*ticket_id).one(&*db).await?;
        let Some(ticket) = ticket else {
            anyhow::bail!("Ticket not found: {}", ticket_id);
        };

        if let Some(uses_left) = ticket.uses_left {
            let mut model: Ticket::ActiveModel = ticket.into();
            model.uses_left = Set(Some(uses_left - 1));
            model.update(&*db).await?;
        }

        Ok(())
    }
}

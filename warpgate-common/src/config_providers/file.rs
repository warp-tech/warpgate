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
use crate::helpers::hash::verify_password_hash;
use crate::helpers::otp::verify_totp;
use crate::{
    AuthCredential, AuthResult, ProtocolName, Target, User, UserAuthCredential, UserSnapshot,
    WarpgateConfig, WarpgateError,
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

fn credential_is_type(c: &UserAuthCredential, k: &str) -> bool {
    match c {
        UserAuthCredential::Password { .. } => k == "password",
        UserAuthCredential::PublicKey { .. } => k == "publickey",
        UserAuthCredential::Totp { .. } => k == "otp",
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
                        valid_credentials.push(credential)
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
                        Some(credential) => valid_credentials.push(credential),
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
                        Some(credential) => valid_credentials.push(credential),
                        None => return Ok(AuthResult::Rejected),
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

        if let Some(ref policy) = user.require {
            let required_kinds = match protocol {
                "SSH" => &policy.ssh,
                "HTTP" => &policy.http,
                "MySQL" => &policy.mysql,
                _ => {
                    error!(%protocol, "Unkown protocol");
                    return Ok(AuthResult::Rejected);
                }
            };
            if let Some(required_kinds) = required_kinds {
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
                    return Ok(AuthResult::OtpNeeded);
                } else {
                    return Ok(AuthResult::Rejected);
                }
            }
        }

        Ok(if !valid_credentials.is_empty() {
            AuthResult::Accepted {
                username: user.username.clone(),
            }
        } else {
            AuthResult::Rejected
        })
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

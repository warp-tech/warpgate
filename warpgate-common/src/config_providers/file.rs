use anyhow::Result;
use async_trait::async_trait;
use data_encoding::BASE64_MIME;
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, ActiveModelTrait};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Ticket;

use crate::hash::verify_password_hash;
use crate::{
    AuthCredential, AuthResult, TargetSnapshot, User, UserAuthCredential,
    UserSnapshot, WarpgateConfig,
};

use super::ConfigProvider;

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

    async fn authorize_user(
        &mut self,
        selector: &str,
        credentials: &Vec<AuthCredential>,
    ) -> Result<AuthResult> {
        if credentials.is_empty() {
            return Ok(AuthResult::Rejected);
        }

        let user = {
            self.config
                .lock()
                .await
                .users
                .iter()
                .find(|x| x.username == selector)
                .map(User::to_owned)
        };
        let Some(user) = user else {
            error!("Selected user not found: {}", selector);
            return Ok(AuthResult::Rejected);
        };

        let mut valid_credentials = vec![];

        for client_credential in credentials {
            if let AuthCredential::PublicKey {
                kind,
                public_key_bytes,
            } = client_credential
            {
                let mut base64_bytes = BASE64_MIME.encode(public_key_bytes);
                base64_bytes.pop();
                base64_bytes.pop();

                let client_key = format!("{} {}", kind, base64_bytes);
                debug!(username=%user.username, "Client key: {}", client_key);

                for credential in user.credentials.iter() {
                    if let UserAuthCredential::PublicKey { key: ref user_key } =
                        credential
                    {
                        if &client_key == user_key {
                            valid_credentials.push(credential);
                            break;
                        }
                    }
                }
            }
        }

        for client_credential in credentials {
            if let AuthCredential::Password(client_password) = client_credential
            {
                for credential in user.credentials.iter() {
                    if let UserAuthCredential::Password {
                        password: ref user_password_hash,
                    } = credential
                    {
                        match verify_password_hash(
                            client_password,
                            user_password_hash,
                        ) {
                            Ok(true) => {
                                valid_credentials.push(credential);
                                break;
                            }
                            Ok(false) => continue,
                            Err(e) => {
                                error!(username=%user.username, "Error verifying password hash: {}", e);
                                continue;
                            }
                        }
                    }
                }
            }
        }

        if valid_credentials.len() > 0 {
            match user.require {
                Some(ref required_kinds) => {
                    for kind in required_kinds {
                        if !valid_credentials
                            .iter()
                            .any(|x| credential_is_type(x, kind))
                        {
                            return Ok(AuthResult::Rejected);
                        }
                    }
                    return Ok(AuthResult::Accepted {
                        username: user.username.clone(),
                        via_ticket: None,
                    });
                }
                None => {
                    return Ok(AuthResult::Accepted {
                        username: user.username.clone(),
                        via_ticket: None,
                    })
                }
            }
        }

        warn!(username=%user.username, "Client credentials did not match");
        Ok(AuthResult::Rejected)
    }
}

fn credential_is_type(c: &UserAuthCredential, k: &str) -> bool {
    match c {
        UserAuthCredential::Password { .. } => k == "password",
        UserAuthCredential::PublicKey { .. } => k == "publickey",
    }
}

#[async_trait]
impl ConfigProvider for FileConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<UserSnapshot>> {
        Ok(self
            .config
            .lock()
            .await
            .users
            .iter()
            .map(UserSnapshot::new)
            .collect::<Vec<_>>())
    }

    async fn list_targets(&mut self) -> Result<Vec<TargetSnapshot>> {
        Ok(self
            .config
            .lock()
            .await
            .targets
            .iter()
            .map(TargetSnapshot::new)
            .collect::<Vec<_>>())
    }

    async fn authorize(
        &mut self,
        selector: &str,
        credentials: &Vec<AuthCredential>,
    ) -> Result<AuthResult> {
        if selector
            .to_string()
            .starts_with(crate::consts::TICKET_SELECTOR_PREFIX)
        {
            let ticket_secret =
                &selector[crate::consts::TICKET_SELECTOR_PREFIX.len()..];
            let ticket = {
                let db = self.db.lock().await;
                Ticket::Entity::find()
                    .filter(Ticket::Column::Secret.eq(ticket_secret))
                    .one(&*db)
                    .await?
            };
            match ticket {
                Some(ticket) => {
                    if let Some(0) = ticket.uses_left {
                        warn!("Ticket is used up: {}", &selector);
                        return Ok(AuthResult::Rejected);
                    }

                    if let Some(datetime) = ticket.expiry {
                        if datetime < chrono::Utc::now() {
                            warn!("Ticket has expired: {}", &selector);
                            return Ok(AuthResult::Rejected);
                        }
                    }

                    return Ok(AuthResult::Accepted {
                        username: ticket.username.clone(),
                        via_ticket: Some(ticket.into()),
                    });
                }
                None => {
                    warn!("Ticket not found: {}", &selector);
                    return Ok(AuthResult::Rejected);
                }
            }
        } else {
            self.authorize_user(selector, credentials).await
        }
    }

    async fn authorize_target(
        &mut self,
        username: &str,
        target_name: &str,
    ) -> Result<bool> {
        let config = self.config.lock().await;
        let user = config
            .users
            .iter()
            .find(|x| x.username == username)
            .map(User::to_owned);
        let target = config.targets.iter().find(|x| x.name == target_name);

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
            .map(|x| config.roles.iter().find(|y| &y.name == x))
            .filter(|x| x.is_some())
            .map(|x| x.unwrap().to_owned())
            .collect::<HashSet<_>>();
        let target_roles = target
            .roles
            .iter()
            .map(|x| config.roles.iter().find(|y| &y.name == x))
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

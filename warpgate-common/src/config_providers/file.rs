use anyhow::Result;
use async_trait::async_trait;
use data_encoding::BASE64_MIME;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;

use crate::hash::verify_password_hash;
use crate::{AuthCredential, AuthResult, User, UserAuthCredential, WarpgateConfig};

use super::ConfigProvider;

pub struct FileConfigProvider {
    config: Arc<Mutex<WarpgateConfig>>,
}

impl FileConfigProvider {
    pub async fn new(config: &Arc<Mutex<WarpgateConfig>>) -> Self {
        Self {
            config: config.clone(),
        }
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
    async fn authorize_user(
        &mut self,
        username: &str,
        credentials: &Vec<AuthCredential>,
    ) -> Result<AuthResult> {
        let user = {
            self.config
                .lock()
                .await
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
            if let AuthCredential::PublicKey {
                kind,
                public_key_bytes,
            } = client_credential
            {
                let mut base64_bytes = BASE64_MIME.encode(public_key_bytes);
                base64_bytes.pop();
                base64_bytes.pop();

                let client_key = format!("{} {}", kind, base64_bytes);
                debug!(%username, "Client key: {}", client_key);

                for credential in user.credentials.iter() {
                    if let UserAuthCredential::PublicKey { key: ref user_key } = credential {
                        if &client_key == user_key {
                            valid_credentials.push(credential);
                            break;
                        }
                    }
                }
            }
        }

        for client_credential in credentials {
            if let AuthCredential::Password(client_password) = client_credential {
                for credential in user.credentials.iter() {
                    if let UserAuthCredential::Password { password: ref user_password_hash } = credential {
                        match verify_password_hash(client_password, user_password_hash) {
                            Ok(true) => {
                                valid_credentials.push(credential);
                                break;
                            },
                            Ok(false) => continue,
                            Err(e) => {
                                error!(%username, "Error verifying password hash: {}", e);
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
                        if !valid_credentials.iter().any(|x| credential_is_type(x, kind)) {
                            return Ok(AuthResult::Rejected);
                        }
                    }
                    return Ok(AuthResult::Accepted);
                },
                None => return Ok(AuthResult::Accepted)
            }
        }

        warn!(%username, "Client credentials did not match");
        Ok(AuthResult::Rejected)
    }
}

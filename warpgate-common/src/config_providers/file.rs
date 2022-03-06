use anyhow::Result;
use async_trait::async_trait;

use crate::{AuthCredential, AuthResult};

use super::ConfigProvider;

pub struct FileConfigProvider {

}

#[async_trait]
impl ConfigProvider for FileConfigProvider {
    async fn authorize_user(&mut self, username: &str, credentials: Vec<AuthCredential>) -> Result<AuthResult> {
        Ok(AuthResult::Accepted)
    }
}

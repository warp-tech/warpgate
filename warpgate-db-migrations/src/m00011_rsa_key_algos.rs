use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, Set};
use sea_orm_migration::prelude::*;

use crate::m00009_credential_models::public_key_credential as PKC;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00011_rsa_key_algos"
    }
}

/// Re-save all keys so that rsa-sha2-* gets replaced with ssh-rsa
/// since ssh-keys never serializes key type as rsa-sha2-*
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        let creds = PKC::Entity::find().all(connection).await?;
        for cred in creds.into_iter() {
            let parsed = russh_keys::PublicKey::from_openssh(&cred.openssh_public_key)
                .map_err(|e| DbErr::Custom(format!("Failed to parse public key: {e}")))?;
            let serialized = parsed
                .to_openssh()
                .map_err(|e| DbErr::Custom(format!("Failed to serialize public key: {e}")))?;
            let am = PKC::ActiveModel {
                openssh_public_key: Set(serialized),
                ..cred.into_active_model()
            };
            am.update(connection).await?;
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

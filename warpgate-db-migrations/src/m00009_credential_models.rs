use credential_enum::UserAuthCredential;
use sea_orm::{ActiveModelTrait, EntityTrait, Schema, Set};
use sea_orm_migration::prelude::*;
use tracing::error;
use uuid::Uuid;

use super::m00008_users::user as User;

pub mod otp_credential {
    use sea_orm::entity::prelude::*;
    use sea_orm::sea_query::ForeignKeyAction;
    use uuid::Uuid;

    use crate::m00008_users::user as User;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "credentials_otp")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub secret_key: Vec<u8>,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        User,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::User => Entity::belongs_to(User::Entity)
                    .from(Column::UserId)
                    .to(User::Column::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod password_credential {
    use sea_orm::entity::prelude::*;
    use sea_orm::sea_query::ForeignKeyAction;
    use uuid::Uuid;

    use crate::m00008_users::user as User;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "credentials_password")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub argon_hash: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        User,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::User => Entity::belongs_to(User::Entity)
                    .from(Column::UserId)
                    .to(User::Column::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

mod public_key_credential {
    use sea_orm::entity::prelude::*;
    use sea_orm::sea_query::ForeignKeyAction;
    use uuid::Uuid;

    use crate::m00008_users::user as User;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "credentials_public_key")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub openssh_public_key: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        User,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::User => Entity::belongs_to(User::Entity)
                    .from(Column::UserId)
                    .to(User::Column::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

mod sso_credential {
    use sea_orm::entity::prelude::*;
    use sea_orm::sea_query::ForeignKeyAction;
    use uuid::Uuid;

    use crate::m00008_users::user as User;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "credentials_sso")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub provider: Option<String>,
        pub email: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        User,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::User => Entity::belongs_to(User::Entity)
                    .from(Column::UserId)
                    .to(User::Column::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

mod credential_enum {
    use serde::{Deserialize, Serialize};

    mod serde_base64_secret {
        use serde::Serializer;

        mod serde_base64 {
            use data_encoding::BASE64;
            use serde::{Deserialize, Serializer};

            pub fn serialize<S: Serializer, B: AsRef<[u8]>>(
                bytes: B,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&BASE64.encode(bytes.as_ref()))
            }

            pub fn deserialize<'de, D: serde::Deserializer<'de>, B: From<Vec<u8>>>(
                deserializer: D,
            ) -> Result<B, D::Error> {
                let s = String::deserialize(deserializer)?;
                Ok(BASE64
                    .decode(s.as_bytes())
                    .map_err(serde::de::Error::custom)?
                    .into())
            }
        }

        pub fn serialize<S: Serializer>(
            secret: &Vec<u8>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serde_base64::serialize(secret, serializer)
        }

        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<u8>, D::Error> {
            let inner = serde_base64::deserialize(deserializer)?;
            Ok(inner)
        }
    }

    #[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
    #[serde(tag = "type")]
    pub enum UserAuthCredential {
        #[serde(rename = "password")]
        Password(UserPasswordCredential),
        #[serde(rename = "publickey")]
        PublicKey(UserPublicKeyCredential),
        #[serde(rename = "otp")]
        Totp(UserTotpCredential),
        #[serde(rename = "sso")]
        Sso(UserSsoCredential),
    }

    #[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
    pub struct UserPasswordCredential {
        pub hash: String,
    }
    #[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
    pub struct UserPublicKeyCredential {
        pub key: String,
    }
    #[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
    pub struct UserTotpCredential {
        #[serde(with = "serde_base64_secret")]
        pub key: Vec<u8>,
    }
    #[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
    pub struct UserSsoCredential {
        pub provider: Option<String>,
        pub email: String,
    }
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00009_credential_models"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let db = manager.get_connection();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(otp_credential::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(password_credential::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(public_key_credential::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(sso_credential::Entity))
            .await?;

        let users = User::Entity::find().all(db).await?;
        for user in users {
            #[allow(clippy::unwrap_used)]
            let Ok(credentials) =
                serde_json::from_value::<Vec<UserAuthCredential>>(user.credentials.clone())
            else {
                error!(
                    "Failed to parse credentials for user {}, value was {:?}",
                    user.id, user.credentials
                );
                continue;
            };
            for credential in credentials {
                match credential {
                    UserAuthCredential::Password(password) => {
                        let model = password_credential::ActiveModel {
                            id: Set(Uuid::new_v4()),
                            user_id: Set(user.id),
                            argon_hash: Set(password.hash),
                        };
                        model.insert(db).await?;
                    }
                    UserAuthCredential::PublicKey(key) => {
                        let model = public_key_credential::ActiveModel {
                            id: Set(Uuid::new_v4()),
                            user_id: Set(user.id),
                            openssh_public_key: Set(key.key),
                        };
                        model.insert(db).await?;
                    }
                    UserAuthCredential::Sso(sso) => {
                        let model = sso_credential::ActiveModel {
                            id: Set(Uuid::new_v4()),
                            user_id: Set(user.id),
                            provider: Set(sso.provider),
                            email: Set(sso.email),
                        };
                        model.insert(db).await?;
                    }
                    UserAuthCredential::Totp(totp) => {
                        let model = otp_credential::ActiveModel {
                            id: Set(Uuid::new_v4()),
                            user_id: Set(user.id),
                            secret_key: Set(totp.key),
                        };
                        model.insert(db).await?;
                    }
                }
            }
        }

        manager
            .alter_table(
                Table::alter()
                    .table(User::Entity)
                    .drop_column(User::Column::Credentials)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        panic!("This migration is irreversible");
    }
}

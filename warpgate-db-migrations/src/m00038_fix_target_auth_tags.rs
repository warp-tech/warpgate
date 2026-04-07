use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use sea_orm_migration::prelude::*;

mod target {
    use sea_orm::entity::prelude::*;

    #[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
    #[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
    pub enum TargetKind {
        #[sea_orm(string_value = "http")]
        Http,
        #[sea_orm(string_value = "kubernetes")]
        Kubernetes,
        #[sea_orm(string_value = "mysql")]
        MySql,
        #[sea_orm(string_value = "postgres")]
        Postgres,
        #[sea_orm(string_value = "ssh")]
        Ssh,
        #[sea_orm(string_value = "web_admin")]
        WebAdmin,
    }

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "targets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        pub kind: TargetKind,
        pub options: serde_json::Value,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00038_fix_target_auth_tags"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        let targets = target::Entity::find().all(db).await?;

        for t in targets {
            let Some(options_obj) = t.options.as_object() else {
                continue;
            };

            let Some(auth) = options_obj.get("auth").and_then(|v| v.as_object()) else {
                continue;
            };

            // Skip if auth already has a kind tag
            if auth.contains_key("kind") {
                continue;
            }

            let kind_value = match t.kind {
                target::TargetKind::Ssh => {
                    if auth.contains_key("password") {
                        "password"
                    } else {
                        "publickey"
                    }
                }
                target::TargetKind::Kubernetes => {
                    if auth.contains_key("token") {
                        "token"
                    } else {
                        "certificate"
                    }
                }
                _ => continue,
            };

            let mut new_options = options_obj.clone();
            let mut new_auth = auth.clone();
            new_auth.insert(
                "kind".to_string(),
                serde_json::Value::String(kind_value.to_string()),
            );
            new_options.insert("auth".to_string(), serde_json::Value::Object(new_auth));

            let mut model: target::ActiveModel = t.into();
            model.options = Set(serde_json::Value::Object(new_options));
            model.update(db).await?;
        }

        Ok(())
    }

    #[allow(clippy::panic, reason = "dev only")]
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        panic!("This migration is irreversible");
    }
}

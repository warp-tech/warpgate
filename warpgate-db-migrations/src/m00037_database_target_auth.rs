use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use sea_orm_migration::prelude::*;
use tracing::error;

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
        "m00037_database_target_auth"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        let targets = target::Entity::find().all(db).await?;

        for t in targets {
            let is_db_target = matches!(
                t.kind,
                target::TargetKind::MySql | target::TargetKind::Postgres
            );
            if !is_db_target {
                continue;
            }

            let Some(options_obj) = t.options.as_object() else {
                error!(target_id = %t.id, "Target options is not a JSON object, skipping");
                continue;
            };

            // Options are wrapped under a protocol key, e.g. {"mysql": {"password": "...", ...}}
            let kind_key = match t.kind {
                target::TargetKind::MySql => "mysql",
                target::TargetKind::Postgres => "postgres",
                _ => continue,
            };

            let Some(proto_obj) = options_obj.get(kind_key).and_then(|v| v.as_object()) else {
                error!(target_id = %t.id, "Target options missing protocol key, skipping");
                continue;
            };

            if proto_obj.contains_key("auth") {
                // Skip already migrated entries (this can happen in m00042)
                continue;
            }

            let mut new_proto = proto_obj.clone();

            // Extract the old password field
            let password = new_proto.remove("password");

            // Build the new auth object
            let auth = match password {
                Some(serde_json::Value::String(pw)) => serde_json::json!({
                    "kind": "password",
                    "password": pw
                }),
                _ => serde_json::json!({
                    "kind": "password"
                }),
            };

            new_proto.insert("auth".to_string(), auth);

            let mut new_options = options_obj.clone();
            new_options.insert(kind_key.to_string(), serde_json::Value::Object(new_proto));

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

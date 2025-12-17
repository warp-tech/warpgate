use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;
use warpgate_tls::TlsMode;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "ldap_servers")]
#[oai(rename = "LdapServer")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub name: String,
    pub host: String,
    pub port: i32,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_filter: String,
    pub base_dns: serde_json::Value,
    pub tls_mode: String,
    pub tls_verify: bool,
    pub enabled: bool,
    pub auto_link_sso_users: bool,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub username_attribute: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl TryFrom<&Model> for warpgate_ldap::LdapConfig {
    type Error = serde_json::Error;

    fn try_from(server: &Model) -> Result<Self, Self::Error> {
        let base_dns: Vec<String> = serde_json::from_value(server.base_dns.clone())?;

        Ok(Self {
            host: server.host.clone(),
            port: server.port as u16,
            bind_dn: server.bind_dn.clone(),
            bind_password: server.bind_password.clone(),
            tls_mode: TlsMode::from(server.tls_mode.as_str()),
            tls_verify: server.tls_verify,
            base_dns,
            user_filter: server.user_filter.clone(),
            username_attribute: server
                .username_attribute
                .as_str()
                .try_into()
                .unwrap_or(warpgate_ldap::LdapUsernameAttribute::Cn),
        })
    }
}

impl TryFrom<Model> for warpgate_ldap::LdapConfig {
    type Error = serde_json::Error;

    fn try_from(server: Model) -> Result<Self, Self::Error> {
        Self::try_from(&server)
    }
}

use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

// Permissions on admin roles. All fields are simple bools. The naming here matches the
// permission list defined in the admin UI and in the code elsewhere.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "admin_roles")]
#[oai(rename = "AdminRole")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,

    // permissions
    pub targets_create: bool,
    pub targets_edit: bool,
    pub targets_delete: bool,

    pub users_create: bool,
    pub users_edit: bool,
    pub users_delete: bool,

    pub access_roles_create: bool,
    pub access_roles_edit: bool,
    pub access_roles_delete: bool,
    pub access_roles_assign: bool,

    pub sessions_view: bool,
    pub sessions_terminate: bool,

    pub recordings_view: bool,

    pub tickets_create: bool,
    pub tickets_delete: bool,

    pub config_edit: bool,

    pub admin_roles_manage: bool,

    pub ticket_requests_manage: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::UserAdminRoleAssignment::Entity")]
    UserAdminRoleAssignment,
}

impl Related<super::User::Entity> for Entity {
    fn to() -> RelationDef {
        super::UserAdminRoleAssignment::Relation::User.def()
    }

    fn via() -> Option<RelationDef> {
        Some(
            super::UserAdminRoleAssignment::Relation::AdminRole
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for warpgate_common::AdminRole {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            description: model.description,
            targets_create: model.targets_create,
            targets_edit: model.targets_edit,
            targets_delete: model.targets_delete,
            users_create: model.users_create,
            users_edit: model.users_edit,
            users_delete: model.users_delete,
            access_roles_create: model.access_roles_create,
            access_roles_edit: model.access_roles_edit,
            access_roles_delete: model.access_roles_delete,
            access_roles_assign: model.access_roles_assign,
            sessions_view: model.sessions_view,
            sessions_terminate: model.sessions_terminate,
            recordings_view: model.recordings_view,
            tickets_create: model.tickets_create,
            tickets_delete: model.tickets_delete,
            config_edit: model.config_edit,
            admin_roles_manage: model.admin_roles_manage,
            ticket_requests_manage: model.ticket_requests_manage,
        }
    }
}

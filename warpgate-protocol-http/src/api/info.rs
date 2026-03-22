use anyhow::Context;
use poem::session::Session;
use poem::web::Data;
use poem::Request;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter};
use serde::Serialize;
use warpgate_common::version::warpgate_version;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::{AuthenticatedRequestContext, SessionAuthorization};
use warpgate_core::ConfigProvider;
use warpgate_db_entities::{AdminRole, LdapServer, Parameters, User};

use crate::common::{is_user_admin, SessionExt};

pub struct Api;

#[derive(Serialize, Object)]
pub struct PortsInfo {
    ssh: Option<u16>,
    http: Option<u16>,
    mysql: Option<u16>,
    postgres: Option<u16>,
    kubernetes: Option<u16>,
}

#[derive(Serialize, Object, Debug)]
pub struct SetupState {
    has_targets: bool,
    has_users: bool,
}

impl SetupState {
    pub fn completed(&self) -> bool {
        self.has_targets && self.has_users
    }
}

#[derive(Serialize, Object, Default)]
pub struct AdminPermissions {
    targets_create: bool,
    targets_edit: bool,
    targets_delete: bool,

    users_create: bool,
    users_edit: bool,
    users_delete: bool,

    access_roles_create: bool,
    access_roles_edit: bool,
    access_roles_delete: bool,
    access_roles_assign: bool,

    sessions_view: bool,
    sessions_terminate: bool,

    recordings_view: bool,

    tickets_create: bool,
    tickets_delete: bool,

    config_edit: bool,
    admin_roles_manage: bool,
}

#[derive(Serialize, Object)]
pub struct Info {
    version: Option<String>,
    username: Option<String>,
    selected_target: Option<String>,
    external_host: Option<String>,
    ports: PortsInfo,
    minimize_password_login: bool,
    authorized_via_ticket: bool,
    authorized_via_sso_with_single_logout: bool,
    own_credential_management_allowed: bool,
    has_ldap: bool,
    setup_state: Option<SetupState>,
    admin_permissions: Option<AdminPermissions>,
}

#[derive(ApiResponse)]
enum InstanceInfoResponse {
    #[oai(status = 200)]
    Ok(Json<Info>),
}

#[OpenApi]
impl Api {
    #[oai(path = "/info", method = "get", operation_id = "get_info")]
    async fn api_get_info(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        auth_ctx: Option<Data<&AuthenticatedRequestContext>>,
    ) -> poem::Result<InstanceInfoResponse> {
        let config = ctx.services.config.lock().await;
        let external_host = config
            .construct_external_url(Some(req), None)
            .ok()
            .as_ref()
            .and_then(|x| x.host())
            .map(|x| x.to_string());

        let parameters = {
            Parameters::Entity::get(&*ctx.services.db.lock().await)
                .await
                .context("loading parameters")?
        };

        let setup_state = {
            let (users, targets) = {
                let mut p = ctx.services.config_provider.lock().await;
                let users = p.list_users().await?;
                let targets = p.list_targets().await?;
                (users, targets)
            };
            let user_is_admin = if let Some(ctx) = &auth_ctx {
                is_user_admin(ctx).await?
            } else {
                false
            };
            if user_is_admin {
                let state = SetupState {
                    has_targets: targets.len() > 1,
                    has_users: users.len() > 1,
                };
                if !state.completed() {
                    Some(state)
                } else {
                    None
                }
            } else {
                None
            }
        };

        let has_ldap = LdapServer::Entity::find()
            .one(&*ctx.services.db.lock().await)
            .await
            .context("loading LDAP servers")?
            .is_some();

        // compute admin permissions (only if authenticated)
        let admin_permissions = if let Some(ctx) = &auth_ctx {
            if let Some(username) = ctx.auth.username() {
                let db = ctx.services.db.lock().await;
                let perms = {
                    let mut combined = AdminPermissions::default();
                    if let Some(user) = User::Entity::find()
                        .filter(User::Column::Username.eq(username))
                        .one(&*db)
                        .await
                        .context("loading user")?
                    {
                        let roles: Vec<AdminRole::Model> = user
                            .find_related(AdminRole::Entity)
                            .all(&*db)
                            .await
                            .context("loading roles")?;
                        for r in roles {
                            combined.targets_create |= r.targets_create;
                            combined.targets_edit |= r.targets_edit;
                            combined.targets_delete |= r.targets_delete;
                            combined.users_create |= r.users_create;
                            combined.users_edit |= r.users_edit;
                            combined.users_delete |= r.users_delete;
                            combined.access_roles_create |= r.access_roles_create;
                            combined.access_roles_edit |= r.access_roles_edit;
                            combined.access_roles_delete |= r.access_roles_delete;
                            combined.access_roles_assign |= r.access_roles_assign;
                            combined.sessions_view |= r.sessions_view;
                            combined.sessions_terminate |= r.sessions_terminate;
                            combined.recordings_view |= r.recordings_view;
                            combined.config_edit |= r.config_edit;
                            combined.admin_roles_manage |= r.admin_roles_manage;
                        }
                    }
                    combined
                };
                Some(perms)
            } else {
                None
            }
        } else {
            None
        };

        Ok(InstanceInfoResponse::Ok(Json(Info {
            version: auth_ctx.is_some().then(|| warpgate_version().to_string()),
            username: session.get_username(),
            selected_target: session.get_target_name(),
            external_host,
            minimize_password_login: parameters.minimize_password_login,
            authorized_via_ticket: matches!(
                session.get_auth(),
                Some(SessionAuthorization::Ticket { .. })
            ),
            authorized_via_sso_with_single_logout: session
                .get_sso_login_state()
                .is_some_and(|state| state.supports_single_logout),
            ports: if auth_ctx.is_some() {
                PortsInfo {
                    ssh: if config.store.ssh.enable {
                        Some(config.store.ssh.external_port())
                    } else {
                        None
                    },
                    http: Some(config.store.http.external_port()),
                    mysql: if config.store.mysql.enable {
                        Some(config.store.mysql.external_port())
                    } else {
                        None
                    },
                    postgres: if config.store.postgres.enable {
                        Some(config.store.postgres.external_port())
                    } else {
                        None
                    },
                    kubernetes: if config.store.kubernetes.enable {
                        Some(config.store.kubernetes.external_port())
                    } else {
                        None
                    },
                }
            } else {
                PortsInfo {
                    ssh: None,
                    http: None,
                    mysql: None,
                    postgres: None,
                    kubernetes: None,
                }
            },
            own_credential_management_allowed: parameters.allow_own_credential_management,
            setup_state,
            has_ldap: auth_ctx.is_some() && has_ldap,
            admin_permissions,
        })))
    }
}

use anyhow::Context;
use poem::Request;
use poem::session::Session;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{EntityTrait, IntoActiveModel, ModelTrait, QueryFilter, Set};
use serde::Serialize;
use warpgate_common::version::warpgate_version;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::{AuthenticatedRequestContext, SessionAuthorization};
use warpgate_core::ConfigProvider;
use warpgate_db_entities::{AdminRole, LdapServer, Parameters, User};

use crate::common::{SessionExt, is_user_admin};

pub struct Api;

#[derive(Serialize, Object)]
pub struct PortsInfo {
    ssh: Option<u16>,
    http: Option<u16>,
    mysql: Option<u16>,
    postgres: Option<u16>,
    kubernetes: Option<u16>,
    vnc: Option<u16>,
    rdp: Option<u16>,
}

#[derive(Serialize, Object)]
pub struct ExternalHostsInfo {
    ssh: Option<String>,
    http: Option<String>,
    mysql: Option<String>,
    postgres: Option<String>,
    kubernetes: Option<String>,
    vnc: Option<String>,
    rdp: Option<String>,
}

#[derive(Serialize, Object, Debug)]
pub struct SetupState {
    has_targets: bool,
    has_users: bool,
    tutorial_dismissed: bool,
}

impl SetupState {
    pub const fn completed(&self) -> bool {
        self.tutorial_dismissed || (self.has_targets && self.has_users)
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
    ticket_requests_manage: bool,
    approve_sessions: bool,
}

#[derive(Serialize, Object)]
pub struct Info {
    version: Option<String>,
    username: Option<String>,
    selected_target: Option<String>,
    external_host: Option<String>,
    external_hosts: Option<ExternalHostsInfo>,
    ports: PortsInfo,
    password_login_mode: Parameters::PasswordLoginMode,
    /// Deprecated in 0.26: superseded by `password_login_mode`
    minimize_password_login: bool,
    authorized_via_ticket: bool,
    authorized_via_sso_with_single_logout: bool,
    own_credential_management_allowed: bool,
    ticket_self_service_enabled: bool,
    ticket_max_duration_seconds: Option<i64>,
    ticket_max_uses: Option<i16>,
    ticket_require_description: bool,
    ticket_request_show_all_targets: bool,
    target_click_action: Parameters::TargetClickAction,
    max_api_token_duration_seconds: Option<i64>,
    web_clients_enabled: bool,
    has_ldap: bool,
    setup_state: Option<SetupState>,
    admin_permissions: Option<AdminPermissions>,
    running_on_ec2: Option<bool>,
    should_prompt_analytics: bool,
}

#[derive(ApiResponse)]
enum InstanceInfoResponse {
    #[oai(status = 200)]
    Ok(Json<Info>),
}

#[derive(ApiResponse)]
enum DismissTutorialResponse {
    #[oai(status = 201)]
    Done,
    #[oai(status = 403)]
    Forbidden,
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
        let config = ctx.services().config.lock().await;
        let external_host = construct_external_url(Some(req), &config, None)
            .await
            .ok()
            .as_ref()
            .and_then(url::Url::host)
            .map(|x| x.to_string());

        let parameters = ctx.parameters().await?;

        let setup_state = {
            let (users, targets) = {
                let p = &ctx.services().config_provider;
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
                    has_targets: !targets.is_empty(),
                    has_users: users.len() > 1,
                    tutorial_dismissed: parameters.tutorial_dismissed,
                };
                if state.completed() { None } else { Some(state) }
            } else {
                None
            }
        };

        let has_ldap = LdapServer::Entity::find()
            .one(&ctx.services().db)
            .await
            .context("loading LDAP servers")?
            .is_some();

        let fallback_host = external_host.clone();

        let protocol_external_hosts = if auth_ctx.is_some() {
            Some(ExternalHostsInfo {
                ssh: config
                    .store
                    .ssh
                    .external_host
                    .clone()
                    .or_else(|| fallback_host.clone()),
                http: config
                    .store
                    .http
                    .external_host
                    .clone()
                    .or_else(|| fallback_host.clone()),
                mysql: config
                    .store
                    .mysql
                    .external_host
                    .clone()
                    .or_else(|| fallback_host.clone()),
                postgres: config
                    .store
                    .postgres
                    .external_host
                    .clone()
                    .or_else(|| fallback_host.clone()),
                kubernetes: config
                    .store
                    .kubernetes
                    .external_host
                    .clone()
                    .or_else(|| fallback_host.clone()),
                vnc: config
                    .store
                    .vnc
                    .external_host
                    .clone()
                    .or_else(|| fallback_host.clone()),
                rdp: config
                    .store
                    .rdp
                    .external_host
                    .clone()
                    .or_else(|| fallback_host.clone()),
            })
        } else {
            None
        };

        // compute admin permissions (only if authenticated)
        let admin_permissions = if let Some(ctx) = &auth_ctx {
            if let Some(username) = ctx.auth.username() {
                let db = &ctx.services().db;
                let perms = {
                    let mut combined = AdminPermissions::default();
                    if let Some(user) = User::Entity::find()
                        .filter(User::Entity::username_eq_ci(username))
                        .one(db)
                        .await
                        .context("loading user")?
                    {
                        let roles: Vec<AdminRole::Model> = user
                            .find_related(AdminRole::Entity)
                            .all(db)
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
                            combined.tickets_create |= r.tickets_create;
                            combined.tickets_delete |= r.tickets_delete;
                            combined.config_edit |= r.config_edit;
                            combined.admin_roles_manage |= r.admin_roles_manage;
                            combined.ticket_requests_manage |= r.ticket_requests_manage;
                            combined.approve_sessions |= r.approve_sessions;
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

        let should_prompt_analytics = {
            let instance_older_than_a_week = time::OffsetDateTime::now_utc()
                - parameters.instance_created_at
                >= time::Duration::weeks(1);

            admin_permissions.as_ref().is_some_and(|p| p.config_edit)
                && parameters.analytics_consent == Parameters::AnalyticsConsent::Undecided
                && setup_state.is_none()
                && instance_older_than_a_week
        };

        Ok(InstanceInfoResponse::Ok(Json(Info {
            version: auth_ctx.is_some().then(|| warpgate_version().to_string()),
            username: auth_ctx
                .as_ref()
                .and_then(|auth_ctx| auth_ctx.auth.username().map(ToString::to_string)),
            selected_target: session.get_target_name(),
            external_host,
            password_login_mode: parameters.password_login_mode,
            minimize_password_login: parameters.password_login_mode
                == Parameters::PasswordLoginMode::Minimized,
            authorized_via_ticket: matches!(
                session.get_auth(),
                Some(SessionAuthorization::Ticket { .. })
            ),
            authorized_via_sso_with_single_logout: session
                .get_sso_login_state()
                .is_some_and(|state| state.supports_single_logout),
            external_hosts: protocol_external_hosts,
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
                    vnc: if config.store.vnc.enable {
                        Some(config.store.vnc.external_port())
                    } else {
                        None
                    },
                    rdp: if config.store.rdp.enable {
                        Some(config.store.rdp.external_port())
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
                    vnc: None,
                    rdp: None,
                }
            },
            own_credential_management_allowed: parameters.allow_own_credential_management,
            ticket_self_service_enabled: parameters.ticket_self_service_enabled,
            ticket_max_duration_seconds: parameters.ticket_max_duration_seconds,
            ticket_max_uses: parameters.ticket_max_uses,
            ticket_require_description: parameters.ticket_require_description,
            ticket_request_show_all_targets: parameters.ticket_request_show_all_targets,
            target_click_action: parameters.target_click_action,
            max_api_token_duration_seconds: parameters.max_api_token_duration_seconds,
            web_clients_enabled: parameters.web_clients_enabled,
            setup_state,
            has_ldap: auth_ctx.is_some() && has_ldap,
            admin_permissions,
            running_on_ec2: if auth_ctx.is_some() {
                Some(warpgate_aws::check_ec2().await)
            } else {
                None
            },
            should_prompt_analytics,
        })))
    }

    #[oai(
        path = "/dismiss-tutorial",
        method = "post",
        operation_id = "dismiss_tutorial"
    )]
    async fn api_dismiss_tutorial(
        &self,
        ctx: Data<&UnauthenticatedRequestContext>,
        auth_ctx: Option<Data<&AuthenticatedRequestContext>>,
    ) -> poem::Result<DismissTutorialResponse> {
        let user_is_admin = if let Some(ctx) = &auth_ctx {
            is_user_admin(ctx).await?
        } else {
            false
        };

        if !user_is_admin {
            return Ok(DismissTutorialResponse::Forbidden);
        }

        let db = &ctx.services().db;
        let mut parameters = ctx.parameters().await?.clone().into_active_model();
        parameters.tutorial_dismissed = Set(true);
        Parameters::Entity::update(parameters)
            .exec(db)
            .await
            .context("updating parameters")?;

        Ok(DismissTutorialResponse::Done)
    }
}

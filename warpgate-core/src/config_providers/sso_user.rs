use tracing::debug;
use warpgate_common::WarpgateError;
use warpgate_common::auth::AuthCredential;
use warpgate_sso::{RoleMapping, SsoLoginResponse, SsoProviderConfig};

use crate::ConfigProvider;

/// Resolve the Warpgate username for a verified SSO response (creating the user
/// if `auto_create_users` is set), then apply role and admin-role mappings.
/// Returns `None` when no user matches and auto-create is disabled.
pub async fn resolve_and_map_sso_user<C: ConfigProvider + Send + ?Sized>(
    cp: &mut C,
    provider_config: &SsoProviderConfig,
    response: &SsoLoginResponse,
) -> Result<Option<String>, WarpgateError> {
    let Some(email) = response.email.clone() else {
        return Ok(None);
    };
    if response.email_verified == Some(false) {
        tracing::warn!("Rejecting SSO user with explicitly unverified email");
        return Ok(None);
    }

    let cred = AuthCredential::Sso {
        provider: provider_config.name.clone(),
        email,
    };

    let Some(username) = cp
        .username_for_sso_credential(
            &cred,
            response.preferred_username.clone(),
            provider_config.clone(),
        )
        .await?
    else {
        return Ok(None);
    };

    let mappings = provider_config.provider.role_mappings();
    if let Some(remote_groups) = response.access_roles.clone() {
        let managed_role_names = mappings
            .as_ref()
            .map(|m| m.iter().flat_map(|(_, v)| v.roles()).collect::<Vec<_>>());

        let mut active_role_names: Vec<String> = if let Some(ref mappings) = mappings {
            let mut roles: Vec<String> = if remote_groups.is_empty() {
                Vec::new()
            } else {
                mappings
                    .get("*")
                    .map(RoleMapping::roles)
                    .unwrap_or_default()
            };
            for group in &remote_groups {
                if let Some(mapping) = mappings.get(group) {
                    roles.extend(mapping.roles());
                }
            }
            roles
        } else {
            remote_groups
        };
        active_role_names.sort();
        active_role_names.dedup();

        debug!(
            "SSO role mappings for {username}: active={active_role_names:?}, managed={managed_role_names:?}"
        );
        cp.apply_sso_role_mappings(&username, managed_role_names, active_role_names)
            .await?;
    }

    if let Some(remote_admins) = response.admin_roles.clone() {
        let admin_map = provider_config.provider.admin_role_mappings();
        let managed_admin_names: Option<Vec<String>> = admin_map
            .as_ref()
            .map(|m| m.values().flat_map(RoleMapping::roles).collect());

        let active_admin_names: Vec<String> = if let Some(ref mappings) = admin_map {
            remote_admins
                .iter()
                .flat_map(|r| {
                    mappings
                        .get(r)
                        .map(RoleMapping::roles)
                        .into_iter()
                        .flatten()
                })
                .collect()
        } else {
            remote_admins
        };

        debug!(
            "SSO admin role mappings for {username}: active={active_admin_names:?}, managed={managed_admin_names:?}"
        );
        cp.apply_sso_admin_role_mappings(&username, managed_admin_names, active_admin_names)
            .await?;
    }

    Ok(Some(username))
}

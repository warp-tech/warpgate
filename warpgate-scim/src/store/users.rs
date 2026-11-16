//! SCIM Users over the `users` table.
//!
//! Mapped attributes: `id`, `userName`, `externalId`, `active`, `groups`
//! (read-only, from the active role assignments) and `meta`. Everything else
//! the client sends is kept verbatim in `scim_attributes` and returned as is.

use std::collections::HashMap;

use sea_orm::sea_query::{Expr, Func};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common::audit::AuditEvent;
use warpgate_core::logging::format_related_ids;
use warpgate_db_entities::{Parameters, Role, User, UserAdminRoleAssignment, UserRoleAssignment};

use super::common::{
    MAX_ATTRIBUTES_BYTES, ScimTimestamps, body_object, optional_bool, optional_string, without,
};
use super::{Effects, Store, sso_link};
use crate::protocol::resource::{
    SCHEMA_ENTERPRISE_USER, SCHEMA_USER, attr_get, attr_key, attr_str,
};
use crate::protocol::{ListQuery, PatchRequest, ScimError, apply_patch};

/// Attributes with a column of their own; never part of `scim_attributes`.
const MAPPED: &[&str] = &[
    "schemas",
    "id",
    "userName",
    "externalId",
    "active",
    "groups",
    "meta",
];

/// Attributes a PATCH may not touch.
const READ_ONLY: &[&str] = &["id", "meta", "groups"];

/// What a request body resolves to before it is written.
struct UserFields {
    username: String,
    external_id: Option<String>,
    /// `None` leaves the flag as it is.
    active: Option<bool>,
    primary_email: Option<String>,
    attributes: String,
}

impl UserFields {
    fn from_body(body: &Value) -> Result<Self, ScimError> {
        let object = body_object(body)?;
        let Some(username) = attr_str(body, "userName") else {
            return Err(ScimError::invalid_value("userName is required"));
        };
        check_username(username)?;
        let rest = without(object, MAPPED);
        let attributes =
            serde_json::to_string(&rest).map_err(|e| ScimError::invalid_value(e.to_string()))?;
        if attributes.len() > MAX_ATTRIBUTES_BYTES {
            return Err(ScimError::invalid_value(format!(
                "the user's attributes exceed {MAX_ATTRIBUTES_BYTES} bytes"
            )));
        }
        Ok(Self {
            username: username.to_owned(),
            external_id: optional_string(body, "externalId")?,
            active: optional_bool(body, "active")?,
            primary_email: primary_email(body)?,
            attributes,
        })
    }
}

/// Warpgate usernames double as the user part of SSH and database selectors,
/// which split on `:` and `#`; such a user could never connect.
fn check_username(username: &str) -> Result<(), ScimError> {
    if username.trim().is_empty() {
        return Err(ScimError::invalid_value("userName must not be empty"));
    }
    if username.contains([':', '#']) {
        return Err(ScimError::invalid_value(
            "userName must not contain ':' or '#'",
        ));
    }
    Ok(())
}

/// The `primary` email, else the first one with a value.
fn primary_email(body: &Value) -> Result<Option<String>, ScimError> {
    let Some(emails) = attr_get(body, "emails") else {
        return Ok(None);
    };
    let emails = match emails {
        Value::Null => return Ok(None),
        Value::Array(emails) => emails,
        _ => return Err(ScimError::invalid_value("emails must be an array")),
    };
    let value_of = |email: &Value| -> Option<String> {
        match email {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Object(_) => attr_str(email, "value")
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
            _ => None,
        }
    };
    let primary = emails
        .iter()
        .find(|email| optional_bool(email, "primary").ok().flatten() == Some(true))
        .and_then(value_of);
    Ok(primary.or_else(|| emails.iter().find_map(value_of)))
}

type Assignment = (UserRoleAssignment::Model, Option<Role::Model>);

impl Store<'_> {
    /// Builds the SCIM form of a user; `assignments` are all of the user's
    /// role assignments, active or not.
    pub fn user_resource(&self, user: &User::Model, assignments: &[Assignment]) -> Value {
        let mut resource: Map<String, Value> = user
            .scim_attributes
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        resource = without(&resource, MAPPED);

        let mut schemas = vec![json!(SCHEMA_USER)];
        if attr_key(&resource, SCHEMA_ENTERPRISE_USER).is_some() {
            schemas.push(json!(SCHEMA_ENTERPRISE_USER));
        }
        resource.insert("schemas".into(), Value::Array(schemas));
        resource.insert("id".into(), json!(user.id.to_string()));
        if let Some(external_id) = &user.scim_external_id {
            resource.insert("externalId".into(), json!(external_id));
        }
        resource.insert("userName".into(), json!(user.username));
        resource.insert("active".into(), json!(user.enabled));

        let groups: Vec<Value> = assignments
            .iter()
            .filter(|(assignment, _)| assignment.active())
            .filter_map(|(_, role)| role.as_ref())
            .map(|role| {
                json!({
                    "value": role.id.to_string(),
                    "display": role.name,
                    "$ref": self.group_location(role.id),
                })
            })
            .collect();
        resource.insert("groups".into(), Value::Array(groups));

        let timestamps = ScimTimestamps::new(
            user.created_at,
            user.updated_at,
            assignments.iter().map(|(assignment, _)| assignment),
        );
        resource.insert(
            "meta".into(),
            timestamps.meta("User", &self.user_location(user.id)),
        );
        Value::Object(resource)
    }

    async fn assignments_of(
        &self,
        user_ids: Option<&[Uuid]>,
    ) -> Result<HashMap<Uuid, Vec<Assignment>>, ScimError> {
        let mut query = UserRoleAssignment::Entity::find().find_also_related(Role::Entity);
        if let Some(ids) = user_ids {
            query = query.filter(UserRoleAssignment::Column::UserId.is_in(ids.iter().copied()));
        }
        let mut by_user: HashMap<Uuid, Vec<Assignment>> = HashMap::new();
        for (assignment, role) in query.all(self.db).await? {
            by_user
                .entry(assignment.user_id)
                .or_default()
                .push((assignment, role));
        }
        Ok(by_user)
    }

    async fn find_user(&self, id: Uuid) -> Result<Option<User::Model>, ScimError> {
        Ok(User::Entity::find_by_id(id).one(self.db).await?)
    }

    pub async fn get_user(&self, id: Uuid) -> Result<Option<Value>, ScimError> {
        let Some(user) = self.find_user(id).await? else {
            return Ok(None);
        };
        let assignments = self.assignments_of(Some(&[id])).await?;
        Ok(Some(self.user_resource(
            &user,
            assignments.get(&id).map_or(&[], Vec::as_slice),
        )))
    }

    /// The page and the filtered total.
    pub async fn list_users(&self, query: &ListQuery) -> Result<(Vec<Value>, usize), ScimError> {
        let mut select = User::Entity::find().order_by_asc(User::Column::Username);
        // An identity provider syncing looks each user up by one of these; the
        // generic filter still runs over what the lookup returns.
        match query.single_eq() {
            Some((attr, value)) if attr.eq_ignore_ascii_case("userName") => {
                select = select.filter(User::Entity::username_eq_ci(value));
            }
            Some((attr, value)) if attr.eq_ignore_ascii_case("externalId") => {
                select = select.filter(
                    Expr::expr(Func::lower(Expr::col(User::Column::ScimExternalId)))
                        .eq(value.to_lowercase()),
                );
            }
            _ => {}
        }
        let users = select.all(self.db).await?;
        let ids: Vec<Uuid> = users.iter().map(|user| user.id).collect();
        let assignments = self.assignments_of(Some(&ids)).await?;
        let resources = users
            .iter()
            .map(|user| {
                self.user_resource(user, assignments.get(&user.id).map_or(&[], Vec::as_slice))
            })
            .collect();
        Ok(query.apply(resources))
    }

    pub async fn create_user(&self, body: &Value) -> Result<(Value, Effects), ScimError> {
        let fields = UserFields::from_body(body)?;
        self.ensure_username_free(&fields.username, None).await?;

        let parameters = Parameters::Entity::get(self.db).await?;
        let credential_policy = parameters
            .default_credential_policy()
            .and_then(serde_json::to_value)
            .map_err(WarpgateError::from)?;
        let user = User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(fields.username.clone()),
            credential_policy: Set(credential_policy),
            description: Set(String::new()),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(Value::Null),
            enabled: Set(fields.active.unwrap_or(true)),
            scim_external_id: Set(fields.external_id.clone()),
            scim_attributes: Set(Some(fields.attributes.clone())),
            created_at: Set(None),
            updated_at: Set(None),
        }
        .insert(self.db)
        .await?;

        AuditEvent::UserCreated {
            user_id: user.id,
            username: user.username.clone(),
            actor_user_id: Uuid::nil(),
        }
        .emit();
        for role in Role::Entity::grant_default_roles(self.db, user.id).await? {
            AuditEvent::AccessRoleGranted {
                grantee_id: user.id,
                grantee_username: user.username.clone(),
                role_id: role.id,
                role_name: role.name,
                actor_user_id: Uuid::nil(),
                related_access_roles: format_related_ids(&[role.id]),
            }
            .emit();
        }
        if !user.enabled {
            AuditEvent::UserDisabled {
                user_id: user.id,
                username: user.username.clone(),
                actor_user_id: Uuid::nil(),
            }
            .emit();
        }
        self.link_sso(&user, fields.primary_email.as_deref())
            .await?;

        let resource = self
            .get_user(user.id)
            .await?
            .ok_or_else(|| ScimError::not_found("the user vanished after creation"))?;
        Ok((resource, Effects::default()))
    }

    /// PUT: the body is the whole resource. `active` left out keeps its value
    /// rather than silently flipping the account.
    pub async fn replace_user(
        &self,
        id: Uuid,
        body: &Value,
    ) -> Result<Option<(Value, Effects)>, ScimError> {
        let Some(user) = self.find_user(id).await? else {
            return Ok(None);
        };
        let fields = UserFields::from_body(body)?;
        self.save_user(user, fields).await.map(Some)
    }

    pub async fn patch_user(
        &self,
        id: Uuid,
        request: &PatchRequest,
    ) -> Result<Option<(Value, Effects)>, ScimError> {
        let Some(user) = self.find_user(id).await? else {
            return Ok(None);
        };
        let assignments = self.assignments_of(Some(&[id])).await?;
        let mut resource =
            self.user_resource(&user, assignments.get(&id).map_or(&[], Vec::as_slice));
        apply_patch(&mut resource, request, READ_ONLY)?;
        let fields = UserFields::from_body(&resource)?;
        self.save_user(user, fields).await.map(Some)
    }

    async fn save_user(
        &self,
        user: User::Model,
        fields: UserFields,
    ) -> Result<(Value, Effects), ScimError> {
        self.ensure_username_free(&fields.username, Some(user.id))
            .await?;
        let was_enabled = user.enabled;
        let mut model: User::ActiveModel = user.into();
        model.username = Set(fields.username);
        model.scim_external_id = Set(fields.external_id);
        model.scim_attributes = Set(Some(fields.attributes));
        if let Some(active) = fields.active {
            model.enabled = Set(active);
        }
        let user = model.update(self.db).await?;

        let mut effects = Effects::default();
        match (was_enabled, user.enabled) {
            (true, false) => {
                AuditEvent::UserDisabled {
                    user_id: user.id,
                    username: user.username.clone(),
                    actor_user_id: Uuid::nil(),
                }
                .emit();
                effects.close_sessions_of_users.push(user.id);
            }
            (false, true) => AuditEvent::UserEnabled {
                user_id: user.id,
                username: user.username.clone(),
                actor_user_id: Uuid::nil(),
            }
            .emit(),
            _ => {}
        }
        self.link_sso(&user, fields.primary_email.as_deref())
            .await?;

        let resource = self
            .get_user(user.id)
            .await?
            .ok_or_else(|| ScimError::not_found("the user vanished after the update"))?;
        Ok((resource, effects))
    }

    pub async fn delete_user(&self, id: Uuid) -> Result<Option<Effects>, ScimError> {
        let Some(user) = self.find_user(id).await? else {
            return Ok(None);
        };
        UserRoleAssignment::Entity::delete_many()
            .filter(UserRoleAssignment::Column::UserId.eq(id))
            .exec(self.db)
            .await?;
        UserAdminRoleAssignment::Entity::delete_many()
            .filter(UserAdminRoleAssignment::Column::UserId.eq(id))
            .exec(self.db)
            .await?;
        AuditEvent::UserDeleted {
            user_id: user.id,
            username: user.username.clone(),
            actor_user_id: Uuid::nil(),
        }
        .emit();
        user.delete(self.db).await?;
        Ok(Some(Effects {
            close_sessions_of_users: vec![id],
            role_access_changed: false,
        }))
    }

    async fn ensure_username_free(
        &self,
        username: &str,
        excluding: Option<Uuid>,
    ) -> Result<(), ScimError> {
        let mut query = User::Entity::find().filter(User::Entity::username_eq_ci(username));
        if let Some(id) = excluding {
            query = query.filter(User::Column::Id.ne(id));
        }
        if query.one(self.db).await?.is_some() {
            return Err(ScimError::conflict(format!(
                "a user named {username:?} already exists"
            )));
        }
        Ok(())
    }

    async fn link_sso(&self, user: &User::Model, email: Option<&str>) -> Result<(), ScimError> {
        if let Some(provider) = self.sso_provider {
            sso_link::reconcile(self.db, user, provider, email).await?;
        }
        Ok(())
    }
}

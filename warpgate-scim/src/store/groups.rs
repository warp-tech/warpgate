//! SCIM Groups over access roles (`roles`) and their memberships (`user_roles`).
//!
//! `members` are the active assignments. Adding a member grants the role (an
//! earlier revoked grant is re-activated); removing one revokes it, keeping the
//! history row. Deleting a group deletes the role, target grants included.

use std::collections::{HashMap, HashSet};

use sea_orm::sea_query::{Expr, Func};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::audit::AuditEvent;
use warpgate_core::db::is_unique_violation;
use warpgate_core::logging::format_related_ids;
use warpgate_core::resources::ResourceError;
use warpgate_db_entities::{Role, User, UserRoleAssignment};

use super::common::{ScimTimestamps, body_object, optional_string};
use super::{Effects, Store};
use crate::protocol::resource::{SCHEMA_GROUP, attr_get, attr_str};
use crate::protocol::{ListQuery, PatchRequest, ScimError, apply_patch};

const READ_ONLY: &[&str] = &["id", "meta"];

struct GroupFields {
    name: String,
    external_id: Option<String>,
    /// Absent `members` means none: a PUT replaces the whole resource.
    members: Vec<Uuid>,
}

impl GroupFields {
    fn from_body(body: &Value) -> Result<Self, ScimError> {
        body_object(body)?;
        let Some(name) = attr_str(body, "displayName") else {
            return Err(ScimError::invalid_value("displayName is required"));
        };
        if name.trim().is_empty() {
            return Err(ScimError::invalid_value("displayName must not be empty"));
        }
        let members = match attr_get(body, "members") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(members)) => {
                let mut ids = vec![];
                for member in members {
                    let value = match member {
                        Value::String(id) => Some(id.as_str()),
                        Value::Object(_) => attr_str(member, "value"),
                        _ => None,
                    };
                    let Some(id) = value.and_then(|id| Uuid::parse_str(id).ok()) else {
                        return Err(ScimError::invalid_value(format!(
                            "member {member} has no user id as its value"
                        )));
                    };
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                }
                ids
            }
            Some(_) => return Err(ScimError::invalid_value("members must be an array")),
        };
        Ok(Self {
            name: name.to_owned(),
            external_id: optional_string(body, "externalId")?,
            members,
        })
    }
}

type Membership = (UserRoleAssignment::Model, Option<User::Model>);

impl Store<'_> {
    pub fn group_resource(&self, role: &Role::Model, memberships: &[Membership]) -> Value {
        let mut resource = Map::new();
        resource.insert("schemas".into(), json!([SCHEMA_GROUP]));
        resource.insert("id".into(), json!(role.id.to_string()));
        if let Some(external_id) = &role.scim_external_id {
            resource.insert("externalId".into(), json!(external_id));
        }
        resource.insert("displayName".into(), json!(role.name));
        let members: Vec<Value> = memberships
            .iter()
            .filter(|(assignment, _)| assignment.active())
            .map(|(assignment, user)| {
                json!({
                    "value": assignment.user_id.to_string(),
                    "display": user.as_ref().map(|user| user.username.clone()),
                    "$ref": self.user_location(assignment.user_id),
                })
            })
            .collect();
        resource.insert("members".into(), Value::Array(members));
        let timestamps = ScimTimestamps::new(
            role.created_at,
            role.updated_at,
            memberships.iter().map(|(assignment, _)| assignment),
        );
        resource.insert(
            "meta".into(),
            timestamps.meta("Group", &self.group_location(role.id)),
        );
        Value::Object(resource)
    }

    async fn memberships_of(
        &self,
        role_ids: Option<&[Uuid]>,
    ) -> Result<HashMap<Uuid, Vec<Membership>>, ScimError> {
        let mut query = UserRoleAssignment::Entity::find().find_also_related(User::Entity);
        if let Some(ids) = role_ids {
            query = query.filter(UserRoleAssignment::Column::RoleId.is_in(ids.iter().copied()));
        }
        let mut by_role: HashMap<Uuid, Vec<Membership>> = HashMap::new();
        for (assignment, user) in query.all(self.db).await? {
            by_role
                .entry(assignment.role_id)
                .or_default()
                .push((assignment, user));
        }
        Ok(by_role)
    }

    async fn find_role(&self, id: Uuid) -> Result<Option<Role::Model>, ScimError> {
        Ok(Role::Entity::find_by_id(id).one(self.db).await?)
    }

    pub async fn get_group(&self, id: Uuid) -> Result<Option<Value>, ScimError> {
        let Some(role) = self.find_role(id).await? else {
            return Ok(None);
        };
        let memberships = self.memberships_of(Some(&[id])).await?;
        Ok(Some(self.group_resource(
            &role,
            memberships.get(&id).map_or(&[], Vec::as_slice),
        )))
    }

    pub async fn list_groups(&self, query: &ListQuery) -> Result<(Vec<Value>, usize), ScimError> {
        let mut select = Role::Entity::find().order_by_asc(Role::Column::Name);
        match query.single_eq() {
            Some((attr, value)) if attr.eq_ignore_ascii_case("displayName") => {
                select = select.filter(name_eq_ci(value));
            }
            Some((attr, value)) if attr.eq_ignore_ascii_case("externalId") => {
                select = select.filter(
                    Expr::expr(Func::lower(Expr::col(Role::Column::ScimExternalId)))
                        .eq(value.to_lowercase()),
                );
            }
            _ => {}
        }
        let roles = select.all(self.db).await?;
        let ids: Vec<Uuid> = roles.iter().map(|role| role.id).collect();
        let memberships = self.memberships_of(Some(&ids)).await?;
        let resources = roles
            .iter()
            .map(|role| {
                self.group_resource(role, memberships.get(&role.id).map_or(&[], Vec::as_slice))
            })
            .collect();
        Ok(query.apply(resources))
    }

    pub async fn create_group(&self, body: &Value) -> Result<(Value, Effects), ScimError> {
        let fields = GroupFields::from_body(body)?;
        self.ensure_group_name_free(&fields.name, None).await?;
        let role = Role::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(fields.name),
            description: Set(String::new()),
            is_default: Set(false),
            scim_external_id: Set(fields.external_id),
            created_at: Set(None),
            updated_at: Set(None),
        }
        .insert(self.db)
        .await
        .map_err(name_taken)?;
        let effects = self.sync_members(&role, &fields.members).await?;
        let resource = self
            .get_group(role.id)
            .await?
            .ok_or_else(|| ScimError::not_found("the group vanished after creation"))?;
        Ok((resource, effects))
    }

    pub async fn replace_group(
        &self,
        id: Uuid,
        body: &Value,
    ) -> Result<Option<(Value, Effects)>, ScimError> {
        let Some(role) = self.find_role(id).await? else {
            return Ok(None);
        };
        let fields = GroupFields::from_body(body)?;
        self.save_group(role, fields).await.map(Some)
    }

    pub async fn patch_group(
        &self,
        id: Uuid,
        request: &PatchRequest,
    ) -> Result<Option<(Value, Effects)>, ScimError> {
        let Some(role) = self.find_role(id).await? else {
            return Ok(None);
        };
        let memberships = self.memberships_of(Some(&[id])).await?;
        let mut resource =
            self.group_resource(&role, memberships.get(&id).map_or(&[], Vec::as_slice));
        apply_patch(&mut resource, request, READ_ONLY)?;
        let fields = GroupFields::from_body(&resource)?;
        self.save_group(role, fields).await.map(Some)
    }

    async fn save_group(
        &self,
        role: Role::Model,
        fields: GroupFields,
    ) -> Result<(Value, Effects), ScimError> {
        self.ensure_group_name_free(&fields.name, Some(role.id))
            .await?;
        let mut model: Role::ActiveModel = role.into();
        model.name = Set(fields.name);
        model.scim_external_id = Set(fields.external_id);
        let role = model.update(self.db).await.map_err(name_taken)?;
        let effects = self.sync_members(&role, &fields.members).await?;
        let resource = self
            .get_group(role.id)
            .await?
            .ok_or_else(|| ScimError::not_found("the group vanished after the update"))?;
        Ok((resource, effects))
    }

    /// Deletes the role outright, as `DELETE /Groups/{id}` asks: its target
    /// grants go with it (see the design, D5).
    pub async fn delete_group(&self, id: Uuid) -> Result<Option<Effects>, ScimError> {
        let Some(role) = self.find_role(id).await? else {
            return Ok(None);
        };
        let memberships = self.memberships_of(Some(&[id])).await?;
        match warpgate_core::resources::roles::delete(self.db, id).await {
            Ok(()) => {}
            Err(ResourceError::NotFound) => return Ok(None),
            Err(err) => return Err(ScimError::Internal(err.into())),
        }
        for (assignment, user) in memberships.get(&id).map_or(&[][..], Vec::as_slice) {
            if assignment.active() {
                revoked_event(&role, assignment.user_id, user.as_ref());
            }
        }
        Ok(Some(Effects {
            close_sessions_of_users: vec![],
            role_access_changed: true,
        }))
    }

    /// Makes the active memberships of `role` exactly `desired`.
    async fn sync_members(
        &self,
        role: &Role::Model,
        desired: &[Uuid],
    ) -> Result<Effects, ScimError> {
        let users: HashMap<Uuid, User::Model> = User::Entity::find()
            .filter(User::Column::Id.is_in(desired.iter().copied()))
            .all(self.db)
            .await?
            .into_iter()
            .map(|user| (user.id, user))
            .collect();
        let unknown: Vec<String> = desired
            .iter()
            .filter(|id| !users.contains_key(id))
            .map(ToString::to_string)
            .collect();
        if !unknown.is_empty() {
            return Err(ScimError::invalid_value(format!(
                "no user with id {}",
                unknown.join(", ")
            )));
        }

        let current: Vec<UserRoleAssignment::Model> = UserRoleAssignment::Entity::find_active()
            .filter(UserRoleAssignment::Column::RoleId.eq(role.id))
            .all(self.db)
            .await?;
        let current_ids: HashSet<Uuid> = current.iter().map(|a| a.user_id).collect();
        let desired_ids: HashSet<Uuid> = desired.iter().copied().collect();

        for user_id in desired.iter().filter(|id| !current_ids.contains(id)) {
            UserRoleAssignment::Entity::idempotent_grant(self.db, *user_id, role.id, None).await?;
            if let Some(user) = users.get(user_id) {
                AuditEvent::AccessRoleGranted {
                    grantee_id: user.id,
                    grantee_username: user.username.clone(),
                    role_id: role.id,
                    role_name: role.name.clone(),
                    actor_user_id: Uuid::nil(),
                    related_access_roles: format_related_ids(&[role.id]),
                }
                .emit();
            }
        }

        let mut revoked = false;
        for assignment in current
            .into_iter()
            .filter(|a| !desired_ids.contains(&a.user_id))
        {
            let user_id = assignment.user_id;
            let mut model: UserRoleAssignment::ActiveModel = assignment.into();
            model.revoked_at = Set(Some(OffsetDateTime::now_utc()));
            model.update(self.db).await?;
            let user = User::Entity::find_by_id(user_id).one(self.db).await?;
            revoked_event(role, user_id, user.as_ref());
            revoked = true;
        }
        Ok(Effects {
            close_sessions_of_users: vec![],
            role_access_changed: revoked,
        })
    }

    async fn ensure_group_name_free(
        &self,
        name: &str,
        excluding: Option<Uuid>,
    ) -> Result<(), ScimError> {
        let mut query = Role::Entity::find().filter(name_eq_ci(name));
        if let Some(id) = excluding {
            query = query.filter(Role::Column::Id.ne(id));
        }
        if query.one(self.db).await?.is_some() {
            return Err(ScimError::conflict(format!(
                "a group named {name:?} already exists"
            )));
        }
        Ok(())
    }
}

/// Role names are unique case-sensitively in the database, but a SCIM filter
/// compares case-insensitively, so two roles differing only by case would
/// both match one `displayName eq` lookup.
fn name_eq_ci(name: &str) -> sea_orm::sea_query::SimpleExpr {
    Expr::expr(Func::lower(Expr::col(Role::Column::Name))).eq(name.to_lowercase())
}

/// The unique index is the backstop for a name race.
fn name_taken(err: sea_orm::DbErr) -> ScimError {
    if is_unique_violation(&err) {
        ScimError::conflict("a group with this name already exists")
    } else {
        err.into()
    }
}

fn revoked_event(role: &Role::Model, user_id: Uuid, user: Option<&User::Model>) {
    AuditEvent::AccessRoleRevoked {
        grantee_id: user_id,
        grantee_username: user.map(|user| user.username.clone()).unwrap_or_default(),
        role_id: role.id,
        role_name: role.name.clone(),
        actor_user_id: Uuid::nil(),
        related_access_roles: format_related_ids(&[role.id]),
    }
    .emit();
}

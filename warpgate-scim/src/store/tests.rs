//! Store tests on an in-memory SQLite database with the real migrations.
#![allow(clippy::indexing_slicing, clippy::panic)]

use sea_orm::{ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter};
use serde_json::{Value, json};
use uuid::Uuid;
use warpgate_core::resources::targets::{self, TargetDataRequest};
use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
use warpgate_db_entities::{Role, SsoCredential, TargetRoleAssignment, User, UserRoleAssignment};
use warpgate_db_migrations::migrate_database;

use super::{Effects, Store};
use crate::protocol::resource::{SCHEMA_ENTERPRISE_USER, SCHEMA_USER};
use crate::protocol::{ListQuery, PatchRequest, ScimError, ScimType};

const BASE: &str = "https://wg.example/@warpgate/scim/v2";

async fn db() -> DatabaseConnection {
    set_config_migration_values(ConfigMigrationValues::default());
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrate_database(&db).await.unwrap();
    db
}

fn store<'a>(db: &'a DatabaseConnection, sso_provider: Option<&'a str>) -> Store<'a> {
    Store {
        db,
        base: BASE,
        sso_provider,
    }
}

fn user_body(name: &str) -> Value {
    json!({
        "schemas": [SCHEMA_USER, SCHEMA_ENTERPRISE_USER],
        "userName": name,
        "externalId": format!("ext-{name}"),
        "active": true,
        "name": {"givenName": "Alice", "familyName": "Smith"},
        "displayName": "Alice Smith",
        "emails": [
            {"value": "alice@home.example", "type": "home"},
            {"value": "alice@work.example", "type": "work", "primary": true},
        ],
        SCHEMA_ENTERPRISE_USER: {"department": "ops"},
    })
}

fn id_of(resource: &Value) -> Uuid {
    Uuid::parse_str(resource["id"].as_str().unwrap()).unwrap()
}

fn scim_type<T: std::fmt::Debug>(result: Result<T, ScimError>) -> (u16, Option<ScimType>) {
    match result {
        Err(ScimError::Protocol {
            status, scim_type, ..
        }) => (status, scim_type),
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

fn patch(operations: Value) -> PatchRequest {
    PatchRequest::parse(&json!({"Operations": operations})).unwrap()
}

async fn sso_creds(db: &DatabaseConnection, user_id: Uuid) -> Vec<SsoCredential::Model> {
    SsoCredential::Entity::find()
        .filter(SsoCredential::Column::UserId.eq(user_id))
        .all(db)
        .await
        .unwrap()
}

async fn list_groups(store: &Store<'_>, filter: &str) -> (Vec<Value>, usize) {
    let query = ListQuery::from_params([("filter", filter)]).unwrap();
    store.list_groups(&query).await.unwrap()
}

async fn query(store: &Store<'_>, filter: &str) -> Vec<Value> {
    let query = ListQuery::from_params([("filter", filter)]).unwrap();
    store.list_users(&query).await.unwrap().0
}

// ---- users ----

#[tokio::test]
async fn a_created_user_round_trips_and_gets_the_default_roles() {
    let db = db().await;
    let store = store(&db, None);
    let default_role = Role::ActiveModel {
        id: sea_orm::Set(Uuid::new_v4()),
        name: sea_orm::Set("everyone".into()),
        description: sea_orm::Set(String::new()),
        is_default: sea_orm::Set(true),
        ..Default::default()
    };
    let default_role = sea_orm::ActiveModelTrait::insert(default_role, &db)
        .await
        .unwrap();

    let (user, effects) = store.create_user(&user_body("alice")).await.unwrap();
    assert_eq!(effects, Effects::default());
    assert_eq!(user["userName"], "alice");
    assert_eq!(user["externalId"], "ext-alice");
    assert_eq!(user["active"], true);
    assert_eq!(user["name"]["familyName"], "Smith");
    assert_eq!(user["displayName"], "Alice Smith");
    assert_eq!(user["emails"].as_array().unwrap().len(), 2);
    assert_eq!(user[SCHEMA_ENTERPRISE_USER]["department"], "ops");
    assert_eq!(
        user["schemas"],
        json!([SCHEMA_USER, SCHEMA_ENTERPRISE_USER])
    );
    assert_eq!(user["groups"][0]["value"], default_role.id.to_string());
    assert_eq!(user["groups"][0]["display"], "everyone");
    assert_eq!(
        user["groups"][0]["$ref"],
        format!("{BASE}/Groups/{}", default_role.id)
    );
    assert_eq!(user["meta"]["resourceType"], "User");
    assert_eq!(
        user["meta"]["location"],
        format!("{BASE}/Users/{}", id_of(&user))
    );
    let created = user["meta"]["created"].as_str().unwrap();
    assert!(created.ends_with('Z'), "{created}");
    assert!(user["meta"]["lastModified"].as_str().unwrap() >= created);

    let row = User::Entity::find_by_id(id_of(&user))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(row.enabled);
    assert_eq!(row.scim_external_id.as_deref(), Some("ext-alice"));
    assert!(row.created_at.is_some() && row.updated_at.is_some());
    let stored: Value = serde_json::from_str(row.scim_attributes.as_deref().unwrap()).unwrap();
    assert!(
        stored.get("userName").is_none(),
        "mapped attributes stay out of the blob"
    );
    assert!(stored.get("id").is_none());
    assert_eq!(stored["displayName"], "Alice Smith");

    assert_eq!(store.get_user(id_of(&user)).await.unwrap().unwrap(), user);
    assert!(store.get_user(Uuid::new_v4()).await.unwrap().is_none());
}

#[tokio::test]
async fn usernames_are_unique_case_insensitively_and_guarded() {
    let db = db().await;
    let store = store(&db, None);
    let _ = store
        .create_user(&json!({"userName": "Alice"}))
        .await
        .unwrap();
    assert_eq!(
        scim_type(store.create_user(&json!({"userName": "alice"})).await),
        (409, Some(ScimType::Uniqueness))
    );
    for bad in [
        json!({}),
        json!({"userName": ""}),
        json!({"userName": "  "}),
        json!({"userName": "a:b"}),
        json!({"userName": "a#b"}),
        json!({"userName": 5}),
    ] {
        assert_eq!(scim_type(store.create_user(&bad).await).0, 400, "{bad}");
    }
    assert_eq!(
        scim_type(store.create_user(&json!([])).await),
        (400, Some(ScimType::InvalidSyntax))
    );
    assert_eq!(
        scim_type(
            store
                .create_user(&json!({"userName": "x", "active": "maybe"}))
                .await
        ),
        (400, Some(ScimType::InvalidValue))
    );
    assert_eq!(
        scim_type(
            store
                .create_user(&json!({"userName": "x", "emails": "a@b"}))
                .await
        ),
        (400, Some(ScimType::InvalidValue))
    );
    let huge = "x".repeat(70 * 1024);
    assert_eq!(
        scim_type(
            store
                .create_user(&json!({"userName": "x", "title": huge}))
                .await
        ),
        (400, Some(ScimType::InvalidValue))
    );
}

#[tokio::test]
async fn listing_fast_paths_agree_with_the_generic_filter() {
    let db = db().await;
    let store = store(&db, None);
    for name in ["carol", "Alice", "bob"] {
        let _ = store.create_user(&user_body(name)).await.unwrap();
    }
    let names = |page: &[Value]| -> Vec<String> {
        page.iter()
            .map(|u| u["userName"].as_str().unwrap().to_owned())
            .collect()
    };

    // Fast path (userName / externalId) ...
    assert_eq!(
        names(&query(&store, r#"userName eq "ALICE""#).await),
        ["Alice"]
    );
    assert_eq!(
        names(&query(&store, r#"externalId eq "EXT-bob""#).await),
        ["bob"]
    );
    assert!(query(&store, r#"userName eq "nobody""#).await.is_empty());
    // ... and the generic path give the same answers.
    assert_eq!(
        names(&query(&store, r#"userName eq "ALICE" and active eq true"#).await),
        ["Alice"]
    );
    assert_eq!(
        names(&query(&store, r#"externalId eq "EXT-bob" or userName eq "nobody""#).await),
        ["bob"]
    );
    assert_eq!(
        names(&query(&store, r#"emails[type eq "work"].value co "work""#).await).len(),
        3
    );
    assert_eq!(
        names(&query(&store, r#"name.givenName eq "alice" and userName sw "c""#).await),
        ["carol"]
    );

    let all = ListQuery::from_params([("sortBy", "userName"), ("count", "2"), ("startIndex", "2")])
        .unwrap();
    let (page, total) = store.list_users(&all).await.unwrap();
    assert_eq!(total, 3);
    assert_eq!(names(&page), ["bob", "carol"]);
}

#[tokio::test]
async fn put_replaces_everything_but_keeps_active_when_absent() {
    let db = db().await;
    let store = store(&db, None);
    let (user, _) = store.create_user(&user_body("alice")).await.unwrap();
    let id = id_of(&user);

    let (replaced, effects) = store
        .replace_user(id, &json!({"userName": "alice2", "title": "Eng"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(effects, Effects::default());
    assert_eq!(replaced["userName"], "alice2");
    assert_eq!(replaced["title"], "Eng");
    assert!(
        replaced.get("name").is_none(),
        "absent attributes are cleared"
    );
    assert!(replaced.get("externalId").is_none());
    assert_eq!(
        replaced["active"], true,
        "an absent active keeps the account as it was"
    );

    let (disabled, effects) = store
        .replace_user(id, &json!({"userName": "alice2", "active": false}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(disabled["active"], false);
    assert_eq!(effects.close_sessions_of_users, vec![id]);
    assert!(
        !User::Entity::find_by_id(id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );

    let (_, effects) = store
        .replace_user(id, &json!({"userName": "alice2", "active": "True"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(effects, Effects::default(), "re-enabling closes nothing");
    assert!(
        User::Entity::find_by_id(id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );

    assert!(
        store
            .replace_user(Uuid::new_v4(), &json!({"userName": "x"}))
            .await
            .unwrap()
            .is_none()
    );

    let _ = store
        .create_user(&json!({"userName": "taken"}))
        .await
        .unwrap();
    assert_eq!(
        scim_type(store.replace_user(id, &json!({"userName": "TAKEN"})).await),
        (409, Some(ScimType::Uniqueness))
    );
}

#[tokio::test]
async fn patch_applies_idp_shapes_and_refuses_read_only_attributes() {
    let db = db().await;
    let store = store(&db, None);
    let (user, _) = store.create_user(&user_body("alice")).await.unwrap();
    let id = id_of(&user);

    // Entra: deactivate with a capitalised op and a string boolean.
    let (patched, effects) = store
        .patch_user(
            id,
            &patch(json!([{"op": "Replace", "path": "active", "value": "False"}])),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(patched["active"], false);
    assert_eq!(effects.close_sessions_of_users, vec![id]);

    // Okta: a path-less replace object.
    let (patched, _) = store
        .patch_user(id, &patch(json!([{"op": "replace", "value": {"active": true, "externalId": "new-ext", "name": {"givenName": "Alicia"}}}])))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(patched["active"], true);
    assert_eq!(patched["externalId"], "new-ext");
    assert_eq!(
        patched["name"],
        json!({"givenName": "Alicia", "familyName": "Smith"})
    );
    let row = User::Entity::find_by_id(id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.scim_external_id.as_deref(), Some("new-ext"));

    let (patched, _) = store
        .patch_user(id, &patch(json!([{"op": "remove", "path": "externalId"}])))
        .await
        .unwrap()
        .unwrap();
    assert!(patched.get("externalId").is_none());

    assert_eq!(
        scim_type(
            store
                .patch_user(
                    id,
                    &patch(json!([{"op": "add", "path": "groups", "value": [{"value": "x"}]}]))
                )
                .await
        ),
        (400, Some(ScimType::Mutability))
    );
    assert_eq!(
        scim_type(
            store
                .patch_user(
                    id,
                    &patch(json!([{"op": "replace", "path": "userName", "value": ""}]))
                )
                .await
        ),
        (400, Some(ScimType::InvalidValue))
    );
    assert!(
        store
            .patch_user(
                Uuid::new_v4(),
                &patch(json!([{"op": "replace", "path": "active", "value": true}]))
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn deleting_a_user_removes_the_account_and_its_memberships() {
    let db = db().await;
    let store = store(&db, None);
    let (group, _) = store
        .create_group(&json!({"displayName": "ops"}))
        .await
        .unwrap();
    let (user, _) = store.create_user(&user_body("alice")).await.unwrap();
    let id = id_of(&user);
    store
        .patch_group(
            id_of(&group),
            &patch(json!([{"op": "add", "path": "members", "value": [{"value": id.to_string()}]}])),
        )
        .await
        .unwrap();
    assert_eq!(
        UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id))
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );

    let effects = store.delete_user(id).await.unwrap().unwrap();
    assert_eq!(effects.close_sessions_of_users, vec![id]);
    assert!(
        User::Entity::find_by_id(id)
            .one(&db)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id))
            .all(&db)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(store.delete_user(id).await.unwrap().is_none());
}

#[tokio::test]
async fn the_primary_email_follows_into_the_sso_credential_when_a_provider_is_set() {
    let db = db().await;
    let store = store(&db, Some("okta"));
    let (user, _) = store.create_user(&user_body("alice")).await.unwrap();
    let id = id_of(&user);
    let current = sso_creds(&db, id).await;
    assert_eq!(current.len(), 1);
    assert_eq!(
        current[0].email, "alice@work.example",
        "the primary one, not the first"
    );
    assert_eq!(current[0].provider.as_deref(), Some("okta"));
    let first_id = current[0].id;

    // Unchanged email keeps the row (and so its identity).
    store.replace_user(id, &user_body("alice")).await.unwrap();
    assert_eq!(sso_creds(&db, id).await[0].id, first_id);

    // A changed email replaces it.
    store
        .patch_user(id, &patch(json!([{"op": "replace", "path": "emails[type eq \"work\"].value", "value": "new@work.example"}])))
        .await
        .unwrap();
    let current = sso_creds(&db, id).await;
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].email, "new@work.example");

    // No emails: no credential for that provider; others are untouched.
    sea_orm::ActiveModelTrait::insert(
        SsoCredential::ActiveModel {
            id: sea_orm::Set(Uuid::new_v4()),
            user_id: sea_orm::Set(id),
            provider: sea_orm::Set(Some("other".into())),
            email: sea_orm::Set("x@y".into()),
        },
        &db,
    )
    .await
    .unwrap();
    store
        .replace_user(id, &json!({"userName": "alice"}))
        .await
        .unwrap();
    let current = sso_creds(&db, id).await;
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].provider.as_deref(), Some("other"));
}

#[tokio::test]
async fn without_a_provider_sso_credentials_are_left_alone() {
    let db = db().await;
    let store = store(&db, None);
    let (user, _) = store.create_user(&user_body("alice")).await.unwrap();
    assert!(
        SsoCredential::Entity::find()
            .filter(SsoCredential::Column::UserId.eq(id_of(&user)))
            .all(&db)
            .await
            .unwrap()
            .is_empty()
    );
}

// ---- groups ----

#[tokio::test]
async fn group_lifecycle_with_members() {
    let db = db().await;
    let store = store(&db, None);
    let (alice, _) = store.create_user(&user_body("alice")).await.unwrap();
    let (bob, _) = store.create_user(&user_body("bob")).await.unwrap();
    let (alice_id, bob_id) = (id_of(&alice), id_of(&bob));

    let (group, effects) = store
        .create_group(&json!({
            "displayName": "ops",
            "externalId": "g-1",
            "members": [{"value": alice_id.to_string(), "display": "ignored"}, bob_id.to_string(), {"value": alice_id.to_string()}],
        }))
        .await
        .unwrap();
    assert_eq!(effects, Effects::default());
    let gid = id_of(&group);
    assert_eq!(group["displayName"], "ops");
    assert_eq!(group["externalId"], "g-1");
    assert_eq!(group["meta"]["resourceType"], "Group");
    let members = group["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.iter().any(|m| m["value"] == alice_id.to_string()
        && m["display"] == "alice"
        && m["$ref"] == format!("{BASE}/Users/{alice_id}")));
    let created = group["meta"]["created"].as_str().unwrap().to_owned();
    let last_modified = group["meta"]["lastModified"].as_str().unwrap().to_owned();
    assert!(last_modified >= created);

    // The user side shows the membership.
    let alice = store.get_user(alice_id).await.unwrap().unwrap();
    assert_eq!(alice["groups"][0]["display"], "ops");

    // Entra: remove one member by filter, add one back later.
    let (group, effects) = store
        .patch_group(
            gid,
            &patch(json!([{"op": "Remove", "path": format!("members[value eq \"{alice_id}\"]")}])),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(effects.role_access_changed);
    assert_eq!(group["members"].as_array().unwrap().len(), 1);
    assert_eq!(group["members"][0]["value"], bob_id.to_string());
    let revoked = UserRoleAssignment::Entity::find()
        .filter(UserRoleAssignment::Column::UserId.eq(alice_id))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(
        revoked.revoked_at.is_some(),
        "the history row stays, revoked"
    );
    assert!(
        group["meta"]["lastModified"].as_str().unwrap() >= last_modified.as_str(),
        "a membership change moves lastModified"
    );
    let alice = store.get_user(alice_id).await.unwrap().unwrap();
    assert_eq!(alice["groups"], json!([]));

    let (group, effects) = store
        .patch_group(gid, &patch(json!([{"op": "add", "path": "members", "value": [{"value": alice_id.to_string()}]}])))
        .await
        .unwrap()
        .unwrap();
    assert!(!effects.role_access_changed);
    assert_eq!(group["members"].as_array().unwrap().len(), 2);
    let regranted = UserRoleAssignment::Entity::find()
        .filter(UserRoleAssignment::Column::UserId.eq(alice_id))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(regranted.len(), 1, "re-granting re-activates the same row");
    assert!(regranted[0].active());

    // Okta: replace the whole member list, then rename via PUT with members.
    let (group, effects) = store
        .patch_group(
            gid,
            &patch(
                json!([{"op": "replace", "value": {"members": [{"value": bob_id.to_string()}]}}]),
            ),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(effects.role_access_changed);
    assert_eq!(group["members"].as_array().unwrap().len(), 1);

    let (group, effects) = store
        .replace_group(
            gid,
            &json!({"displayName": "ops-renamed", "members": [{"value": alice_id.to_string()}]}),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(effects.role_access_changed);
    assert_eq!(group["displayName"], "ops-renamed");
    assert!(
        group.get("externalId").is_none(),
        "PUT clears what it does not carry"
    );
    assert_eq!(group["members"][0]["value"], alice_id.to_string());
    assert_eq!(
        Role::Entity::find_by_id(gid)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .name,
        "ops-renamed"
    );

    // A PUT without members empties the group.
    let (group, _) = store
        .replace_group(gid, &json!({"displayName": "ops-renamed"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(group["members"], json!([]));

    assert!(
        store
            .replace_group(Uuid::new_v4(), &json!({"displayName": "x"}))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .patch_group(
                Uuid::new_v4(),
                &patch(json!([{"op": "remove", "path": "members"}]))
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn group_names_are_unique_case_insensitively_and_members_must_exist() {
    let db = db().await;
    let store = store(&db, None);
    let (group, _) = store
        .create_group(&json!({"displayName": "Ops"}))
        .await
        .unwrap();
    assert_eq!(
        scim_type(store.create_group(&json!({"displayName": "ops"})).await),
        (409, Some(ScimType::Uniqueness))
    );
    let _ = store
        .create_group(&json!({"displayName": "dba"}))
        .await
        .unwrap();
    assert_eq!(
        scim_type(
            store
                .replace_group(id_of(&group), &json!({"displayName": "DBA"}))
                .await
        ),
        (409, Some(ScimType::Uniqueness))
    );
    // Re-casing one's own name is fine.
    let (renamed, _) = store
        .replace_group(id_of(&group), &json!({"displayName": "OPS"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(renamed["displayName"], "OPS");

    for bad in [
        json!({}),
        json!({"displayName": ""}),
        json!({"displayName": "x", "members": "nope"}),
        json!({"displayName": "x", "members": [{"value": "not-a-uuid"}]}),
        json!({"displayName": "x", "members": [5]}),
    ] {
        assert_eq!(scim_type(store.create_group(&bad).await).0, 400, "{bad}");
    }
    assert_eq!(
        scim_type(
            store
                .create_group(
                    &json!({"displayName": "x", "members": [{"value": Uuid::new_v4().to_string()}]})
                )
                .await
        ),
        (400, Some(ScimType::InvalidValue))
    );
    assert_eq!(
        scim_type(
            store
                .patch_group(
                    id_of(&group),
                    &patch(json!([{"op": "replace", "path": "id", "value": "x"}]))
                )
                .await
        ),
        (400, Some(ScimType::Mutability))
    );
}

#[tokio::test]
async fn listing_groups_by_name_and_external_id() {
    let db = db().await;
    let store = store(&db, None);
    for (name, ext) in [("ops", "g-ops"), ("dba", "g-dba")] {
        let _ = store
            .create_group(&json!({"displayName": name, "externalId": ext}))
            .await
            .unwrap();
    }
    let (page, total) = list_groups(&store, r#"displayName eq "OPS""#).await;
    assert_eq!((page.len(), total), (1, 1));
    assert_eq!(page[0]["displayName"], "ops");
    let (page, _) = list_groups(&store, r#"externalId eq "G-DBA""#).await;
    assert_eq!(page[0]["displayName"], "dba");
    let (page, _) = list_groups(&store, r#"displayName co "b" or displayName eq "ops""#).await;
    assert_eq!(page.len(), 2);
    let (page, total) = store
        .list_groups(
            &ListQuery::from_params([
                ("count", "1"),
                ("sortBy", "displayName"),
                ("sortOrder", "descending"),
            ])
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!((page.len(), total), (1, 2));
    assert_eq!(page[0]["displayName"], "ops");
}

#[tokio::test]
async fn deleting_a_group_deletes_the_role_and_every_assignment() {
    let db = db().await;
    let store = store(&db, None);
    let (alice, _) = store.create_user(&user_body("alice")).await.unwrap();
    let (group, _) = store
        .create_group(&json!({"displayName": "ops", "members": [{"value": alice["id"]}]}))
        .await
        .unwrap();
    let gid = id_of(&group);
    let target = targets::create(
        &db,
        &TargetDataRequest {
            name: "web".into(),
            description: None,
            options: serde_json::from_value(json!({"ssh": {"host": "h"}})).unwrap(),
            rate_limit_bytes_per_second: None,
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            require_approval: false,
            ticket_max_uses: None,
        },
    )
    .await
    .unwrap();
    targets::add_role(&db, target.id, gid).await.unwrap();

    let effects = store.delete_group(gid).await.unwrap().unwrap();
    assert!(effects.role_access_changed);
    assert!(
        Role::Entity::find_by_id(gid)
            .one(&db)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::RoleId.eq(gid))
            .all(&db)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::RoleId.eq(gid))
            .all(&db)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(store.get_group(gid).await.unwrap().is_none());
    assert!(store.delete_group(gid).await.unwrap().is_none());
    let alice = store.get_user(id_of(&alice)).await.unwrap().unwrap();
    assert_eq!(alice["groups"], json!([]));
}

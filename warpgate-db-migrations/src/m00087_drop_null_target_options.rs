use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, Order, Set};
use sea_orm_migration::prelude::*;
use uuid::Uuid;

mod target {
    use sea_orm::entity::prelude::*;

    /// Only the primary key and the JSON blob: reading `kind` would tie this
    /// migration to whichever protocols existed when it was written.
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "targets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub options: serde_json::Value,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Fields that stopped being `Option`. They were serialized without
/// `skip_serializing_if`, so a target saved while one was unset carries an
/// explicit `null` that no longer deserializes — and one such row fails the
/// whole target list, not just itself. Dropping the key lets the field's
/// `serde` default stand in, which is the value the old `unwrap_or` produced.
const NULLABLE_UNTIL_NOW: &[(&str, &str)] = &[
    ("ssh", "allow_insecure_algos"),
    ("http", "headers"),
    ("mysql", "auth"),
    ("postgres", "auth"),
    ("postgres", "protocol_version"),
    ("rdp", "compression"),
    ("rdp", "tls_security"),
];

/// The pre-`auth` database password. m00037 folded it into `auth` and dropped
/// it, but a row that slipped past would still hold an encrypted credential
/// that nothing reads and no key rotation revisits.
const RETIRED: &[(&str, &str)] = &[("mysql", "password"), ("postgres", "password")];

const BATCH: u64 = 1000;

/// Works on `targets.options` and on a session's `target_snapshot` alike: a
/// snapshot is a flattened `Target`, so its protocol block sits at the top
/// level too. Returns whether anything was dropped.
fn strip_retired_options(options: &mut serde_json::Value) -> bool {
    let mut changed = false;
    let nulled = NULLABLE_UNTIL_NOW.iter().map(|pair| (pair, true));
    let retired = RETIRED.iter().map(|pair| (pair, false));
    for ((protocol, field), only_when_null) in nulled.chain(retired) {
        let Some(proto_obj) = options.get_mut(protocol).and_then(|v| v.as_object_mut()) else {
            continue;
        };
        if proto_obj
            .get(*field)
            .is_some_and(|value| value.is_null() || !only_when_null)
        {
            proto_obj.remove(*field);
            changed = true;
        }
    }
    changed
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00087_drop_null_target_options"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        for t in target::Entity::find().all(db).await? {
            let mut options = t.options.clone();
            if strip_retired_options(&mut options) {
                let mut model: target::ActiveModel = t.into();
                model.options = Set(options);
                model.update(db).await?;
            }
        }

        // Snapshots parse with `.ok()`, so a stale null does not fail anything —
        // it silently blanks the target on every historical session that had
        // one, which for `headers` and `allow_insecure_algos` is most of them.
        let backend = db.get_database_backend();
        let sessions = Alias::new("target_sessions");
        let id_col = Alias::new("id");
        let snapshot_col = Alias::new("target_snapshot");

        // Keyset pagination: an offset would drift as rows are rewritten. The
        // NOT NULL guard matters on SQLite, which never got m00082's tightening.
        let mut last_id: Option<Uuid> = None;
        loop {
            let mut select = Query::select()
                .column(id_col.clone())
                .column(snapshot_col.clone())
                .from(sessions.clone())
                .and_where(Expr::col(snapshot_col.clone()).is_not_null())
                .order_by(id_col.clone(), Order::Asc)
                .limit(BATCH)
                .to_owned();
            if let Some(last_id) = last_id {
                select.and_where(Expr::col(id_col.clone()).gt(last_id));
            }

            let rows = db.query_all(backend.build(&select)).await?;
            let done = (rows.len() as u64) < BATCH;

            for row in &rows {
                let id: Uuid = row.try_get("", "id")?;
                last_id = Some(id);

                let snapshot: String = row.try_get("", "target_snapshot")?;
                // A snapshot that was never valid JSON is not this migration's
                // problem; the reader already tolerates it.
                let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&snapshot) else {
                    continue;
                };
                if strip_retired_options(&mut value) {
                    let update = Query::update()
                        .table(sessions.clone())
                        .value(snapshot_col.clone(), value.to_string())
                        .and_where(Expr::col(id_col.clone()).eq(id))
                        .to_owned();
                    db.execute(backend.build(&update)).await?;
                }
            }

            if done {
                return Ok(());
            }
        }
    }

    #[allow(clippy::panic, reason = "dev only")]
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        panic!("This migration is irreversible");
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::strip_retired_options;

    #[test]
    fn only_the_nulled_out_fields_are_dropped() {
        let mut options = json!({"http": {
            "url": "http://t",
            "headers": null,
            "external_host": null,
        }});

        assert!(strip_retired_options(&mut options));
        // `external_host` is still an `Option`, so its null has to survive
        assert_eq!(
            options,
            json!({"http": {"url": "http://t", "external_host": null}})
        );
    }

    #[test]
    fn a_field_holding_a_value_is_left_alone() {
        let mut options = json!({"rdp": {
            "compression": "lossless",
            "tls_security": null,
        }});

        assert!(strip_retired_options(&mut options));
        assert_eq!(options, json!({"rdp": {"compression": "lossless"}}));
    }

    /// The retired password goes whatever it holds — it is a credential
    /// nothing can read any more.
    #[test]
    fn the_retired_password_is_dropped_even_when_set() {
        let mut options = json!({"mysql": {
            "auth": {"kind": "password", "password": "current"},
            "password": "enc:legacy",
        }});

        assert!(strip_retired_options(&mut options));
        assert_eq!(
            options,
            json!({"mysql": {"auth": {"kind": "password", "password": "current"}}})
        );
    }

    /// A same-named field under a different protocol must not be touched, and a
    /// row with nothing to fix must not be rewritten.
    #[test]
    fn an_untouched_row_reports_no_change() {
        let mut options = json!({"mysql": {"host": "db", "protocol_version": null}});

        assert!(!strip_retired_options(&mut options));
        assert_eq!(
            options,
            json!({"mysql": {"host": "db", "protocol_version": null}})
        );
    }

    /// A session snapshot is a flattened `Target`: the protocol block is a
    /// sibling of `name`, not nested under `options`.
    #[test]
    fn a_session_snapshot_is_handled_in_place() {
        let mut snapshot = json!({
            "id": "7c1c0e1e-0000-0000-0000-000000000000",
            "name": "web",
            "http": {"url": "http://t", "headers": null},
        });

        assert!(strip_retired_options(&mut snapshot));
        assert_eq!(snapshot["name"], "web");
        assert_eq!(snapshot["http"], json!({"url": "http://t"}));

        let mut bare = json!({"name": "web"});
        assert!(!strip_retired_options(&mut bare));
    }
}

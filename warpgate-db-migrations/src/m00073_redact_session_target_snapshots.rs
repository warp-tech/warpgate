use sea_orm::{ConnectionTrait, Order};
use sea_orm_migration::prelude::*;
use uuid::Uuid;

const SECRET_PATHS: &[&[&str]] = &[
    &["ssh", "auth", "password"],
    &["mysql", "auth", "password"],
    &["mysql", "password"],
    &["postgres", "auth", "password"],
    &["postgres", "password"],
    &["vnc", "auth", "password"],
    &["rdp", "auth", "password"],
    &["kubernetes", "auth", "token"],
    &["kubernetes", "auth", "private_key"],
];

const BATCH: u64 = 1000;

fn redact(snapshot: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(snapshot).ok()?;

    let mut changed = false;
    for path in SECRET_PATHS {
        let node = path
            .iter()
            .try_fold(&mut value, |node, step| node.get_mut(step));
        if let Some(serde_json::Value::String(secret)) = node
            && !secret.is_empty()
        {
            secret.clear();
            changed = true;
        }
    }

    changed.then(|| value.to_string())
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        let sessions = Alias::new("sessions");
        let id_col = Alias::new("id");
        let snapshot_col = Alias::new("target_snapshot");

        // Keyset pagination: rows already redacted still match the `IS NOT NULL`
        // filter, so an offset would revisit them on a large table.
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
                if let Some(redacted) = redact(&snapshot) {
                    let update = Query::update()
                        .table(sessions.clone())
                        .value(snapshot_col.clone(), redacted)
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

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // The removed credentials are gone; there is nothing to restore.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn blanks_credentials_and_leaves_the_rest() {
        let redacted = redact(
            r#"{"name":"t","mysql":{"host":"db","auth":{"kind":"password","password":"hunter2"},"password":"legacy"}}"#,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(value["mysql"]["auth"]["password"], "");
        assert_eq!(value["mysql"]["password"], "");
        assert_eq!(value["mysql"]["host"], "db");
        assert_eq!(value["name"], "t");
    }

    #[test]
    fn already_clean_rows_are_not_rewritten() {
        assert_eq!(
            redact(r#"{"name":"t","http":{"url":"http://x"}}"#),
            None,
            "no credentials present"
        );
        assert_eq!(
            redact(r#"{"ssh":{"auth":{"kind":"password","password":""}}}"#),
            None,
            "already blank"
        );
        assert_eq!(redact("not json"), None);
    }
}

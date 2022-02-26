use super::schema::*;
use crate::UUID;
use chrono::NaiveDateTime;

#[derive(Queryable, Insertable)]
pub struct Session {
    pub id: UUID,
    pub target_snapshot: Option<String>,
    pub user_snapshot: Option<String>,
    pub remote_address: String,
    pub started: NaiveDateTime,
    pub ended: Option<NaiveDateTime>,
}

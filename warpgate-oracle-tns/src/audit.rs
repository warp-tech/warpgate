//! Stateful SQL audit: remembers the SQL parsed on each cursor so that
//! re-executes (which omit the text) can still be attributed, and emits one
//! audit record per observed EXECUTE call.

use std::collections::HashMap;

use crate::execute::ExecuteCall;

/// One auditable event derived from an EXECUTE call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRecord {
    /// A statement whose SQL text was seen in this call (a parse).
    Statement { cursor_id: u32, sql: String },
    /// A re-execution of a cursor; `sql` is the remembered text when the cursor
    /// was parsed earlier in this session, otherwise `None`.
    ReExecute { cursor_id: u32, sql: Option<String> },
}

/// Cursors remembered per session; a session holding more open cursors than
/// this still has every parse logged, only later re-executes of the excess
/// cursors are logged without their text.
const MAX_REMEMBERED_CURSORS: usize = 4096;

/// Remembers cursor -> SQL for a single session so re-executes can be labelled.
#[derive(Debug, Default)]
pub struct SqlAuditor {
    cursors: HashMap<u32, String>,
}

impl SqlAuditor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one parsed EXECUTE call into the audit state, returning the record
    /// to log (if the call is auditable).
    pub fn record(&mut self, call: ExecuteCall) -> Option<AuditRecord> {
        match call.sql {
            // The statement was parsed, so its SQL text is present. Remember it
            // against a real cursor so later re-executes on that cursor can be
            // attributed; a first parse before the server assigns a cursor
            // arrives on cursor 0, which we log but cannot store for lookup.
            Some(text) => {
                if call.cursor_id != 0
                    && (self.cursors.len() < MAX_REMEMBERED_CURSORS
                        || self.cursors.contains_key(&call.cursor_id))
                {
                    self.cursors.insert(call.cursor_id, text.clone());
                }
                Some(AuditRecord::Statement {
                    cursor_id: call.cursor_id,
                    sql: text,
                })
            }
            // A re-execute (func 4 / 78) omits the SQL text; recover it from the
            // cursor map when we saw the parse, otherwise emit `None`.
            //
            // Edge case: a re-execute on cursor 0 references no parsed statement
            // and no cursor we could ever have stored, so it is degenerate and
            // non-auditable — drop it rather than log an empty re-execute.
            None => {
                if call.cursor_id == 0 {
                    return None;
                }
                Some(AuditRecord::ReExecute {
                    cursor_id: call.cursor_id,
                    sql: self.cursors.get(&call.cursor_id).cloned(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `ExecuteCall` directly. `record` never inspects `function` or
    /// `options` (dispatch is driven by `sql`/`cursor_id`), so they are fixed.
    fn call(cursor_id: u32, sql: Option<&str>) -> ExecuteCall {
        ExecuteCall {
            function: 0,
            cursor_id,
            options: 0,
            sql: sql.map(str::to_owned),
        }
    }

    #[test]
    fn parse_emits_statement_and_remembers_cursor() {
        let mut auditor = SqlAuditor::new();
        let rec = auditor.record(call(5, Some("select 1 from dual")));
        assert_eq!(
            rec,
            Some(AuditRecord::Statement {
                cursor_id: 5,
                sql: "select 1 from dual".to_owned(),
            })
        );
        assert_eq!(
            auditor.cursors.get(&5).map(String::as_str),
            Some("select 1 from dual")
        );
    }

    #[test]
    fn reexecute_of_known_cursor_recovers_sql() {
        let mut auditor = SqlAuditor::new();
        auditor.record(call(5, Some("select 1 from dual")));
        let rec = auditor.record(call(5, None));
        assert_eq!(
            rec,
            Some(AuditRecord::ReExecute {
                cursor_id: 5,
                sql: Some("select 1 from dual".to_owned()),
            })
        );
    }

    #[test]
    fn reexecute_of_unknown_cursor_has_no_sql() {
        let mut auditor = SqlAuditor::new();
        let rec = auditor.record(call(99, None));
        assert_eq!(
            rec,
            Some(AuditRecord::ReExecute {
                cursor_id: 99,
                sql: None,
            })
        );
    }

    #[test]
    fn degenerate_reexecute_on_cursor_zero_is_dropped() {
        let mut auditor = SqlAuditor::new();
        assert_eq!(auditor.record(call(0, None)), None);
    }

    #[test]
    fn parse_on_cursor_zero_is_logged_but_not_stored() {
        let mut auditor = SqlAuditor::new();
        let rec = auditor.record(call(0, Some("insert into t values (1)")));
        assert_eq!(
            rec,
            Some(AuditRecord::Statement {
                cursor_id: 0,
                sql: "insert into t values (1)".to_owned(),
            })
        );
        assert!(auditor.cursors.is_empty());
    }

    #[test]
    fn remembered_cursors_are_bounded() {
        let mut a = SqlAuditor::new();
        for id in 1..=(MAX_REMEMBERED_CURSORS as u32 + 10) {
            a.record(call(id, Some("select 1 from dual")));
        }
        assert_eq!(a.cursors.len(), MAX_REMEMBERED_CURSORS);
        // A remembered cursor can still be re-parsed with new text.
        a.record(call(1, Some("select 2 from dual")));
        assert_eq!(
            a.cursors.get(&1).map(String::as_str),
            Some("select 2 from dual")
        );
    }
}

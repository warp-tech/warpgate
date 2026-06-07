use sea_orm::DbBackend;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::SimpleExpr;

/// MySQL 8.0.13+ requires expression defaults (parenthesised) for TEXT columns
pub(crate) fn string_default_value(backend: DbBackend, value: &str) -> SimpleExpr {
    if backend == DbBackend::MySql {
        Expr::cust(format!("('{value}')"))
    } else {
        value.into()
    }
}

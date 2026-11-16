//! List parameters (RFC 7644 §3.4.2): filter, pagination and sorting, from
//! either the query string or a `.search` request body.

use std::cmp::Ordering;

use serde_json::Value;

use super::error::ScimError;
use super::filter::{AttrPath, CompareOp, Filter};

/// The most resources one page returns (`ServiceProviderConfig.filter.maxResults`).
pub const MAX_RESULTS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    #[default]
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    pub filter: Option<Filter>,
    /// 1-based.
    pub start_index: usize,
    /// Already clamped to `0..=MAX_RESULTS`.
    pub count: usize,
    pub sort_by: Option<AttrPath>,
    pub sort_order: SortOrder,
}

impl ListQuery {
    /// From query-string pairs. Parameter names are matched case-insensitively,
    /// which the spec does not require but some clients assume.
    pub fn from_params<'a>(
        params: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, ScimError> {
        let mut raw = RawQuery::default();
        for (name, value) in params {
            raw.set(name, Value::String(value.to_owned()));
        }
        raw.finish()
    }

    /// From a `SearchRequest` body (`POST /Users/.search`).
    pub fn from_search_request(body: &Value) -> Result<Self, ScimError> {
        let Some(object) = body.as_object() else {
            return Err(ScimError::invalid_syntax(
                "a SearchRequest must be an object",
            ));
        };
        let mut raw = RawQuery::default();
        for (name, value) in object {
            raw.set(name, value.clone());
        }
        raw.finish()
    }

    /// The whole query is `attr eq "value"` on a top-level core attribute:
    /// the shape identity providers send when syncing, which the store can
    /// answer with an indexed lookup instead of loading everything.
    pub const fn single_eq(&self) -> Option<(&str, &str)> {
        match &self.filter {
            Some(Filter::Compare {
                path,
                op: CompareOp::Eq,
                value: Value::String(value),
            }) if path.schema.is_none() && path.value_filter.is_none() && path.sub.is_none() => {
                Some((path.attr.as_str(), value.as_str()))
            }
            _ => None,
        }
    }

    /// Filters, sorts and pages `resources`, returning the page and the
    /// filtered total.
    pub fn apply(&self, resources: Vec<Value>) -> (Vec<Value>, usize) {
        let mut matched: Vec<Value> = match &self.filter {
            Some(filter) => resources
                .into_iter()
                .filter(|resource| filter.matches(resource))
                .collect(),
            None => resources,
        };
        if let Some(sort_by) = &self.sort_by {
            matched.sort_by(|a, b| {
                let (a, b) = (
                    sort_by.resolve(a).first().copied(),
                    sort_by.resolve(b).first().copied(),
                );
                let ordering = compare_for_sort(a, b);
                match self.sort_order {
                    // Missing values stay last in either direction.
                    SortOrder::Descending if a.is_some() && b.is_some() => ordering.reverse(),
                    SortOrder::Ascending | SortOrder::Descending => ordering,
                }
            });
        }
        let total = matched.len();
        let page = matched
            .into_iter()
            .skip(self.start_index.saturating_sub(1))
            .take(self.count)
            .collect();
        (page, total)
    }
}

/// Missing values sort last in either direction.
fn compare_for_sort(a: Option<&Value>, b: Option<&Value>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(Value::String(a)), Some(Value::String(b))) => a.to_lowercase().cmp(&b.to_lowercase()),
        (Some(Value::Number(a)), Some(Value::Number(b))) => a
            .as_f64()
            .partial_cmp(&b.as_f64())
            .unwrap_or(Ordering::Equal),
        (Some(Value::Bool(a)), Some(Value::Bool(b))) => a.cmp(b),
        (Some(a), Some(b)) => a.to_string().cmp(&b.to_string()),
    }
}

#[derive(Default)]
struct RawQuery {
    filter: Option<Value>,
    start_index: Option<Value>,
    count: Option<Value>,
    sort_by: Option<Value>,
    sort_order: Option<Value>,
}

impl RawQuery {
    fn set(&mut self, name: &str, value: Value) {
        match name.to_ascii_lowercase().as_str() {
            "filter" => self.filter = Some(value),
            "startindex" => self.start_index = Some(value),
            "count" => self.count = Some(value),
            "sortby" => self.sort_by = Some(value),
            "sortorder" => self.sort_order = Some(value),
            // `attributes` / `excludedAttributes` are accepted and ignored:
            // every response carries the full resource.
            _ => {}
        }
    }

    fn finish(self) -> Result<ListQuery, ScimError> {
        let filter = match self.filter {
            Some(Value::String(filter)) if filter.trim().is_empty() => None,
            Some(Value::String(filter)) => Some(Filter::parse(&filter)?),
            Some(Value::Null) | None => None,
            Some(_) => return Err(ScimError::invalid_filter("filter must be a string")),
        };
        let start_index = match integer(self.start_index.as_ref(), "startIndex")? {
            Some(index) => usize::try_from(index.max(1)).unwrap_or(1),
            None => 1,
        };
        let count = match integer(self.count.as_ref(), "count")? {
            Some(count) => usize::try_from(count.max(0)).unwrap_or(0).min(MAX_RESULTS),
            None => MAX_RESULTS,
        };
        let sort_by = match self.sort_by {
            Some(Value::String(sort_by)) if sort_by.trim().is_empty() => None,
            Some(Value::String(sort_by)) => Some(AttrPath::parse(&sort_by).map_err(|_| {
                ScimError::invalid_value(format!("sortBy is not an attribute path: {sort_by}"))
            })?),
            Some(Value::Null) | None => None,
            Some(_) => return Err(ScimError::invalid_value("sortBy must be a string")),
        };
        let sort_order = match self.sort_order {
            Some(Value::String(order)) if order.eq_ignore_ascii_case("ascending") => {
                SortOrder::Ascending
            }
            Some(Value::String(order)) if order.eq_ignore_ascii_case("descending") => {
                SortOrder::Descending
            }
            Some(Value::String(order)) if order.trim().is_empty() => SortOrder::Ascending,
            Some(Value::Null) | None => SortOrder::Ascending,
            Some(other) => {
                return Err(ScimError::invalid_value(format!(
                    "sortOrder must be ascending or descending, not {other}"
                )));
            }
        };
        Ok(ListQuery {
            filter,
            start_index,
            count,
            sort_by,
            sort_order,
        })
    }
}

fn integer(value: Option<&Value>, name: &str) -> Result<Option<i64>, ScimError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(Some)
            .ok_or_else(|| ScimError::invalid_value(format!("{name} must be an integer"))),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => s
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| ScimError::invalid_value(format!("{name} must be an integer"))),
        Some(_) => Err(ScimError::invalid_value(format!(
            "{name} must be an integer"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use serde_json::json;

    use super::*;

    fn users() -> Vec<Value> {
        ["carol", "Alice", "bob"]
            .iter()
            .enumerate()
            .map(|(i, name)| json!({"id": i.to_string(), "userName": name, "active": i != 1}))
            .collect()
    }

    fn names(page: &[Value]) -> Vec<&str> {
        page.iter()
            .map(|u| u["userName"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn defaults() {
        let query = ListQuery::from_params([]).unwrap();
        assert!(query.filter.is_none());
        assert_eq!(query.start_index, 1);
        assert_eq!(query.count, MAX_RESULTS);
        assert!(query.sort_by.is_none());
        assert_eq!(query.sort_order, SortOrder::Ascending);
        let (page, total) = query.apply(users());
        assert_eq!(total, 3);
        assert_eq!(page.len(), 3);
    }

    #[test]
    fn filter_sort_and_page() {
        let query = ListQuery::from_params([
            ("filter", "active eq true"),
            ("sortBy", "userName"),
            ("sortOrder", "descending"),
            ("startIndex", "2"),
            ("count", "1"),
        ])
        .unwrap();
        let (page, total) = query.apply(users());
        assert_eq!(total, 2);
        assert_eq!(names(&page), ["bob"]);

        let query = ListQuery::from_params([("sortby", "username")]).unwrap();
        let (page, _) = query.apply(users());
        assert_eq!(names(&page), ["Alice", "bob", "carol"]);
    }

    #[test]
    fn bounds_are_clamped() {
        let query = ListQuery::from_params([("startIndex", "0"), ("count", "-5")]).unwrap();
        assert_eq!(query.start_index, 1);
        assert_eq!(query.count, 0);
        let (page, total) = query.apply(users());
        assert!(page.is_empty());
        assert_eq!(total, 3);
        let query = ListQuery::from_params([("count", "100000")]).unwrap();
        assert_eq!(query.count, MAX_RESULTS);
        let query = ListQuery::from_params([("startIndex", "10")]).unwrap();
        assert!(query.apply(users()).0.is_empty());
    }

    #[test]
    fn invalid_parameters() {
        use super::super::ScimType;
        let scim_type = |r: Result<ListQuery, ScimError>| match r {
            Err(ScimError::Protocol { scim_type, .. }) => scim_type,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            scim_type(ListQuery::from_params([("count", "x")])),
            Some(ScimType::InvalidValue)
        );
        assert_eq!(
            scim_type(ListQuery::from_params([("startIndex", "1.5")])),
            Some(ScimType::InvalidValue)
        );
        assert_eq!(
            scim_type(ListQuery::from_params([("sortOrder", "sideways")])),
            Some(ScimType::InvalidValue)
        );
        assert_eq!(
            scim_type(ListQuery::from_params([("sortBy", "a b")])),
            Some(ScimType::InvalidValue)
        );
        assert_eq!(
            scim_type(ListQuery::from_params([("filter", "userName")])),
            Some(ScimType::InvalidFilter)
        );
        assert!(
            ListQuery::from_params([("filter", "  "), ("attributes", "userName")])
                .unwrap()
                .filter
                .is_none()
        );
    }

    #[test]
    fn search_request_body() {
        let query = ListQuery::from_search_request(&json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
            "filter": "userName sw \"b\"",
            "startIndex": 1,
            "count": 10,
            "sortBy": "id",
            "sortOrder": "ascending"
        }))
        .unwrap();
        let (page, total) = query.apply(users());
        assert_eq!(total, 1);
        assert_eq!(names(&page), ["bob"]);
        assert!(ListQuery::from_search_request(&json!([])).is_err());
        assert!(ListQuery::from_search_request(&json!({"count": "ten"})).is_err());
        assert!(ListQuery::from_search_request(&json!({"filter": 5})).is_err());
    }

    #[test]
    fn single_eq_fast_path_shape() {
        let eq = |f: &str| ListQuery::from_params([("filter", f)]).unwrap();
        assert_eq!(
            eq(r#"userName eq "Alice""#).single_eq(),
            Some(("userName", "Alice"))
        );
        assert_eq!(
            eq(r#"urn:ietf:params:scim:schemas:core:2.0:User:externalId eq "x""#).single_eq(),
            Some(("externalId", "x"))
        );
        assert_eq!(eq(r#"userName ne "Alice""#).single_eq(), None);
        assert_eq!(
            eq(r#"userName eq "a" and active eq true"#).single_eq(),
            None
        );
        assert_eq!(eq(r#"name.givenName eq "a""#).single_eq(), None);
        assert_eq!(
            eq(r#"emails[type eq "work"].value eq "a""#).single_eq(),
            None
        );
        assert_eq!(eq("active eq true").single_eq(), None);
        assert_eq!(ListQuery::from_params([]).unwrap().single_eq(), None);
    }

    #[test]
    fn sorting_puts_missing_values_last_in_both_directions() {
        let items = vec![json!({"n": 2}), json!({}), json!({"n": 1})];
        let query = ListQuery::from_params([("sortBy", "n")]).unwrap();
        let (page, _) = query.apply(items.clone());
        assert_eq!(page, vec![json!({"n": 1}), json!({"n": 2}), json!({})]);
        let query = ListQuery::from_params([("sortBy", "n"), ("sortOrder", "DESCENDING")]).unwrap();
        let (page, _) = query.apply(items);
        assert_eq!(page, vec![json!({"n": 2}), json!({"n": 1}), json!({})]);

        let items = vec![json!({"s": "b"}), json!({"s": "A"}), json!({"s": "c"})];
        let query = ListQuery::from_params([("sortBy", "s"), ("sortOrder", "descending")]).unwrap();
        let (page, _) = query.apply(items);
        assert_eq!(
            page,
            vec![json!({"s": "c"}), json!({"s": "b"}), json!({"s": "A"})]
        );
    }
}

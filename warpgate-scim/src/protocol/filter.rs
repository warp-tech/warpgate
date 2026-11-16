//! SCIM filter expressions (RFC 7644 §3.4.2.2) and attribute paths (§3.10):
//! a tokenizer, a recursive-descent parser and an evaluator over resource JSON.
//!
//! Grammar, with `not` binding tighter than `and`, which binds tighter than `or`:
//!
//! ```text
//! FILTER    = attrExp / logExp / valuePath / *1"not" "(" FILTER ")"
//! valuePath = attrPath "[" valFilter "]"
//! attrExp   = (attrPath SP "pr") / (attrPath SP compareOp SP compValue)
//! logExp    = FILTER SP ("and" / "or") SP FILTER
//! compValue = false / null / true / number / string
//! compareOp = "eq" / "ne" / "co" / "sw" / "ew" / "gt" / "lt" / "ge" / "le"
//! attrPath  = [URI ":"] ATTRNAME *1subAttr
//! ```
//!
//! String comparisons are case-insensitive: every attribute Warpgate serves has
//! the schema default `caseExact: false`.

use std::cmp::Ordering;

use serde_json::Value;

use super::error::ScimError;
use super::resource::{attr_get, is_core_schema, is_present};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Lt,
    Ge,
    Le,
    /// `pr` — present; takes no value.
    Pr,
}

impl CompareOp {
    fn parse(word: &str) -> Option<Self> {
        Some(match word.to_ascii_lowercase().as_str() {
            "eq" => Self::Eq,
            "ne" => Self::Ne,
            "co" => Self::Co,
            "sw" => Self::Sw,
            "ew" => Self::Ew,
            "gt" => Self::Gt,
            "lt" => Self::Lt,
            "ge" => Self::Ge,
            "le" => Self::Le,
            "pr" => Self::Pr,
            _ => return None,
        })
    }
}

/// An attribute reference: an optional schema URI, the attribute, an optional
/// value filter selecting elements of a multi-valued attribute, and an optional
/// sub-attribute. `emails[type eq "work"].value` has all four.
#[derive(Debug, Clone, PartialEq)]
pub struct AttrPath {
    /// `None` for the core schema (whose attributes sit at the top level).
    pub schema: Option<String>,
    pub attr: String,
    pub value_filter: Option<Box<Filter>>,
    pub sub: Option<String>,
}

impl AttrPath {
    pub fn new(attr: &str) -> Self {
        Self {
            schema: None,
            attr: attr.to_owned(),
            value_filter: None,
            sub: None,
        }
    }

    /// Parses a path as used in PATCH `path` and `sortBy`.
    pub fn parse(input: &str) -> Result<Self, ScimError> {
        let tokens = tokenize(input).map_err(ScimError::invalid_path)?;
        let mut parser = Parser { tokens, pos: 0 };
        let path = parser.attr_path().map_err(ScimError::invalid_path)?;
        if parser.peek().is_some() {
            return Err(ScimError::invalid_path(format!(
                "unexpected input after the path: {input}"
            )));
        }
        Ok(path)
    }

    /// Whether this refers to `name` (top-level core attribute, no sub-attribute).
    pub fn is_attr(&self, name: &str) -> bool {
        self.schema.is_none() && self.attr.eq_ignore_ascii_case(name)
    }

    /// Values this path selects within `resource`. A multi-valued attribute
    /// yields each element; a value filter keeps the matching elements; a
    /// sub-attribute descends into each.
    pub fn resolve<'a>(&self, resource: &'a Value) -> Vec<&'a Value> {
        let base = match &self.schema {
            Some(schema) => match attr_get(resource, schema) {
                Some(base) => base,
                None => return vec![],
            },
            None => resource,
        };
        let Some(attr) = attr_get(base, &self.attr) else {
            return vec![];
        };
        let mut candidates: Vec<&Value> = match attr {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        if let Some(filter) = &self.value_filter {
            candidates.retain(|candidate| candidate.is_object() && filter.matches(candidate));
        }
        if let Some(sub) = &self.sub {
            candidates = candidates
                .into_iter()
                .filter_map(|candidate| attr_get(candidate, sub))
                .flat_map(|value| match value {
                    Value::Array(items) => items.iter().collect::<Vec<_>>(),
                    other => vec![other],
                })
                .collect();
        }
        candidates
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    Compare {
        path: AttrPath,
        op: CompareOp,
        value: Value,
    },
    /// A bare value path, e.g. `emails[type eq "work"]`: matches when it
    /// selects anything.
    Has(AttrPath),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
}

impl Filter {
    pub fn parse(input: &str) -> Result<Self, ScimError> {
        let tokens = tokenize(input).map_err(ScimError::invalid_filter)?;
        if tokens.is_empty() {
            return Err(ScimError::invalid_filter("the filter is empty"));
        }
        let mut parser = Parser { tokens, pos: 0 };
        let filter = parser.filter().map_err(ScimError::invalid_filter)?;
        if let Some(token) = parser.peek() {
            return Err(ScimError::invalid_filter(format!(
                "unexpected {token:?} after the end of the filter"
            )));
        }
        Ok(filter)
    }

    /// Whether `resource` satisfies the filter. Inside a value filter the
    /// "resource" is the element under test.
    pub fn matches(&self, resource: &Value) -> bool {
        match self {
            Self::And(a, b) => a.matches(resource) && b.matches(resource),
            Self::Or(a, b) => a.matches(resource) || b.matches(resource),
            Self::Not(inner) => !inner.matches(resource),
            Self::Has(path) => !path.resolve(resource).is_empty(),
            Self::Compare { path, op, value } => {
                let candidates = path.resolve(resource);
                if *op == CompareOp::Pr {
                    return candidates.iter().any(|candidate| is_present(candidate));
                }
                if value.is_null() {
                    // `eq null` is true for an absent attribute; `ne null` the inverse.
                    let absent = !candidates.iter().any(|candidate| is_present(candidate));
                    return match op {
                        CompareOp::Eq => absent,
                        CompareOp::Ne => !absent,
                        _ => false,
                    };
                }
                candidates.iter().any(|candidate| {
                    // A complex value without a sub-attribute compares its `value`.
                    let candidate = match (candidate.is_object(), path.sub.is_none()) {
                        (true, true) => attr_get(candidate, "value").unwrap_or(candidate),
                        _ => candidate,
                    };
                    compare(candidate, *op, value)
                })
            }
        }
    }
}

fn compare(actual: &Value, op: CompareOp, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::String(a), Value::String(e)) => {
            let (a, e) = (a.to_lowercase(), e.to_lowercase());
            match op {
                CompareOp::Eq => a == e,
                CompareOp::Ne => a != e,
                CompareOp::Co => a.contains(&e),
                CompareOp::Sw => a.starts_with(&e),
                CompareOp::Ew => a.ends_with(&e),
                CompareOp::Gt => a > e,
                CompareOp::Lt => a < e,
                CompareOp::Ge => a >= e,
                CompareOp::Le => a <= e,
                CompareOp::Pr => true,
            }
        }
        (Value::Number(a), Value::Number(e)) => {
            let (Some(a), Some(e)) = (a.as_f64(), e.as_f64()) else {
                return false;
            };
            let ordering = a.partial_cmp(&e);
            match op {
                CompareOp::Eq => ordering == Some(Ordering::Equal),
                CompareOp::Ne => ordering != Some(Ordering::Equal),
                CompareOp::Gt => ordering == Some(Ordering::Greater),
                CompareOp::Lt => ordering == Some(Ordering::Less),
                CompareOp::Ge => matches!(ordering, Some(Ordering::Greater | Ordering::Equal)),
                CompareOp::Le => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
                CompareOp::Co | CompareOp::Sw | CompareOp::Ew => false,
                CompareOp::Pr => true,
            }
        }
        (Value::Bool(a), Value::Bool(e)) => match op {
            CompareOp::Eq => a == e,
            CompareOp::Ne => a != e,
            _ => false,
        },
        // Mismatched types are never equal.
        _ => op == CompareOp::Ne,
    }
}

// ---- tokenizer ----

#[derive(Debug, Clone, PartialEq)]
enum Token {
    LParen,
    RParen,
    LBracket,
    RBracket,
    /// An attribute path, keyword or operator.
    Word(String),
    Str(String),
    Num(serde_json::Number),
    True,
    False,
    Null,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = vec![];
    let mut rest = input;
    while let Some(c) = rest.chars().next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => rest = &rest[c.len_utf8()..],
            '(' | ')' | '[' | ']' => {
                tokens.push(match c {
                    '(' => Token::LParen,
                    ')' => Token::RParen,
                    '[' => Token::LBracket,
                    _ => Token::RBracket,
                });
                rest = &rest[1..];
            }
            '"' => {
                let end = string_end(rest).ok_or("unterminated string")?;
                let literal = rest.get(..=end).ok_or("unterminated string")?;
                let value: String =
                    serde_json::from_str(literal).map_err(|e| format!("bad string: {e}"))?;
                tokens.push(Token::Str(value));
                rest = rest.get(end + 1..).unwrap_or("");
            }
            '-' | '0'..='9' => {
                let len = rest
                    .find(|ch: char| {
                        !(ch.is_ascii_digit() || matches!(ch, '-' | '+' | '.' | 'e' | 'E'))
                    })
                    .unwrap_or(rest.len());
                let literal = rest.get(..len).unwrap_or(rest);
                let number: serde_json::Number =
                    serde_json::from_str(literal).map_err(|_| format!("bad number: {literal}"))?;
                tokens.push(Token::Num(number));
                rest = rest.get(len..).unwrap_or("");
            }
            _ => {
                let len = rest
                    .find(|ch: char| {
                        ch.is_whitespace() || matches!(ch, '(' | ')' | '[' | ']' | '"')
                    })
                    .unwrap_or(rest.len());
                let word = rest.get(..len).unwrap_or(rest);
                tokens.push(match word.to_ascii_lowercase().as_str() {
                    "true" => Token::True,
                    "false" => Token::False,
                    "null" => Token::Null,
                    _ => Token::Word(word.to_owned()),
                });
                rest = rest.get(len..).unwrap_or("");
            }
        }
    }
    Ok(tokens)
}

/// Index of the closing quote of the JSON string literal `s` starts with.
fn string_end(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices().skip(1) {
        match (c, escaped) {
            ('\\', false) => escaped = true,
            ('"', false) => return Some(i),
            _ => escaped = false,
        }
    }
    None
}

// ---- parser ----

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
    }

    fn peek_word_ci(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(w)) if w.eq_ignore_ascii_case(word))
    }

    fn expect(&mut self, expected: &Token) -> Result<(), String> {
        match self.next() {
            Some(ref token) if token == expected => Ok(()),
            other => Err(format!("expected {expected:?}, found {other:?}")),
        }
    }

    fn filter(&mut self) -> Result<Filter, String> {
        let mut left = self.and_expr()?;
        while self.peek_word_ci("or") {
            self.pos += 1;
            let right = self.and_expr()?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and_expr(&mut self) -> Result<Filter, String> {
        let mut left = self.unary()?;
        while self.peek_word_ci("and") {
            self.pos += 1;
            let right = self.unary()?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Filter, String> {
        if self.peek_word_ci("not") {
            self.pos += 1;
            self.expect(&Token::LParen)?;
            let inner = self.filter()?;
            self.expect(&Token::RParen)?;
            return Ok(Filter::Not(Box::new(inner)));
        }
        if self.peek() == Some(&Token::LParen) {
            self.pos += 1;
            let inner = self.filter()?;
            self.expect(&Token::RParen)?;
            return Ok(inner);
        }
        self.attr_exp()
    }

    fn attr_exp(&mut self) -> Result<Filter, String> {
        let path = self.attr_path()?;
        let Some(Token::Word(word)) = self.peek() else {
            if path.value_filter.is_some() {
                return Ok(Filter::Has(path));
            }
            return Err(format!("expected an operator after {}", path.attr));
        };
        let Some(op) = CompareOp::parse(word) else {
            if path.value_filter.is_some() {
                return Ok(Filter::Has(path));
            }
            return Err(format!("unknown operator {word:?}"));
        };
        self.pos += 1;
        if op == CompareOp::Pr {
            return Ok(Filter::Compare {
                path,
                op,
                value: Value::Null,
            });
        }
        let value = match self.next() {
            Some(Token::Str(s)) => Value::String(s),
            Some(Token::Num(n)) => Value::Number(n),
            Some(Token::True) => Value::Bool(true),
            Some(Token::False) => Value::Bool(false),
            Some(Token::Null) => Value::Null,
            other => return Err(format!("expected a value, found {other:?}")),
        };
        Ok(Filter::Compare { path, op, value })
    }

    fn attr_path(&mut self) -> Result<AttrPath, String> {
        let Some(Token::Word(word)) = self.next() else {
            return Err("expected an attribute name".into());
        };
        let mut path = split_attr_word(&word)?;
        if self.peek() == Some(&Token::LBracket) {
            self.pos += 1;
            let inner = self.filter()?;
            self.expect(&Token::RBracket)?;
            path.value_filter = Some(Box::new(inner));
            // `emails[...].value` — the sub-attribute follows the bracket.
            if let Some(Token::Word(sub)) = self.peek()
                && let Some(sub) = sub.strip_prefix('.')
            {
                if path.sub.is_some() {
                    return Err("a value filter must come before the sub-attribute".into());
                }
                check_name(sub)?;
                path.sub = Some(sub.to_owned());
                self.pos += 1;
            }
        }
        Ok(path)
    }
}

/// `urn:…:User:name.givenName` → schema, attribute, sub-attribute.
fn split_attr_word(word: &str) -> Result<AttrPath, String> {
    let (schema, name) = match word.rsplit_once(':') {
        Some((schema, name)) => (Some(schema), name),
        None => (None, word),
    };
    let (attr, sub) = match name.split_once('.') {
        Some((attr, sub)) => (attr, Some(sub)),
        None => (name, None),
    };
    check_name(attr)?;
    if let Some(sub) = sub {
        check_name(sub)?;
    }
    Ok(AttrPath {
        schema: schema
            .filter(|schema| !is_core_schema(schema))
            .map(str::to_owned),
        attr: attr.to_owned(),
        value_filter: None,
        sub: sub.map(str::to_owned),
    })
}

/// `ATTRNAME = ALPHA *(nameChar)`; `$ref` is allowed as a sub-attribute name.
fn check_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '$'));
    if valid {
        Ok(())
    } else {
        Err(format!("invalid attribute name {name:?}"))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use serde_json::json;

    use super::*;

    fn user() -> Value {
        json!({
            "id": "u1",
            "userName": "Alice.Smith@example.com",
            "externalId": "ext-1",
            "active": true,
            "name": {"givenName": "Alice", "familyName": "Smith"},
            "emails": [
                {"value": "alice@work.example", "type": "work", "primary": true},
                {"value": "alice@home.example", "type": "home"}
            ],
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "ops"},
            "meta": {"created": "2026-01-01T00:00:00Z"}
        })
    }

    fn matches(filter: &str) -> bool {
        Filter::parse(filter).unwrap().matches(&user())
    }

    #[test]
    fn equality_is_case_insensitive_in_name_value_and_operator() {
        assert!(matches(r#"userName eq "alice.smith@example.com""#));
        assert!(matches(r#"USERNAME EQ "ALICE.SMITH@EXAMPLE.COM""#));
        assert!(!matches(r#"userName eq "bob""#));
        assert!(matches(r#"userName ne "bob""#));
        assert!(!matches(r#"userName ne "alice.smith@example.com""#));
    }

    #[test]
    fn string_operators() {
        assert!(matches(r#"userName co "smith""#));
        assert!(matches(r#"userName sw "ALICE""#));
        assert!(matches(r#"userName ew ".com""#));
        assert!(!matches(r#"userName sw "smith""#));
        assert!(matches(r#"meta.created gt "2025-12-31T00:00:00Z""#));
        assert!(matches(r#"meta.created le "2026-01-01T00:00:00Z""#));
        assert!(!matches(r#"meta.created lt "2026-01-01T00:00:00Z""#));
    }

    #[test]
    fn presence_and_null() {
        assert!(matches("externalId pr"));
        assert!(!matches("nickName pr"));
        assert!(matches("nickName eq null"));
        assert!(!matches("externalId eq null"));
        assert!(matches("externalId ne null"));
    }

    #[test]
    fn booleans_and_numbers() {
        assert!(matches("active eq true"));
        assert!(!matches("active eq false"));
        assert!(!matches(r#"active eq "true""#), "a string is not a boolean");
        let resource = json!({"count": 3});
        let check = |f: &str| Filter::parse(f).unwrap().matches(&resource);
        assert!(check("count eq 3"));
        assert!(check("count ge 3"));
        assert!(check("count lt 3.5"));
        assert!(!check("count gt 3"));
        assert!(!check("count co 3"));
    }

    #[test]
    fn logical_operators_and_precedence() {
        assert!(matches(r#"userName sw "alice" and active eq true"#));
        assert!(!matches(r#"userName sw "bob" and active eq true"#));
        assert!(matches(r#"userName sw "bob" or active eq true"#));
        // `and` binds tighter than `or`.
        assert!(matches(
            r#"userName sw "bob" or active eq true and externalId pr"#
        ));
        assert!(!matches(
            r#"(userName sw "bob" or active eq true) and nickName pr"#
        ));
        assert!(matches(r#"not (userName sw "bob")"#));
        assert!(!matches("not (active eq true)"));
    }

    #[test]
    fn multi_valued_and_complex_attributes() {
        // A complex multi-valued attribute compares its `value` sub-attribute.
        assert!(matches(r#"emails co "home.example""#));
        assert!(matches(r#"emails.value eq "alice@work.example""#));
        assert!(matches(
            r#"emails[type eq "work"].value eq "alice@work.example""#
        ));
        assert!(!matches(
            r#"emails[type eq "work"].value eq "alice@home.example""#
        ));
        assert!(matches(r#"emails[type eq "work" and primary eq true]"#));
        assert!(!matches(r#"emails[type eq "other"]"#));
        assert!(matches(r#"name.givenName eq "alice""#));
    }

    #[test]
    fn schema_prefixes() {
        assert!(matches(
            r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "alice.smith@example.com""#
        ));
        assert!(matches(
            r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "OPS""#
        ));
        let path = AttrPath::parse(
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value",
        )
        .unwrap();
        assert_eq!(
            path.schema.as_deref(),
            Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
        );
        assert_eq!(path.attr, "manager");
        assert_eq!(path.sub.as_deref(), Some("value"));
        let core =
            AttrPath::parse("urn:ietf:params:scim:schemas:core:2.0:User:name.familyName").unwrap();
        assert_eq!(core.schema, None);
        assert_eq!(core.attr, "name");
    }

    #[test]
    fn strings_may_contain_escapes_brackets_and_operators() {
        let resource = json!({"displayName": "a \"quoted\" [and] eq or"});
        let filter = Filter::parse(r#"displayName eq "a \"quoted\" [and] eq or""#).unwrap();
        assert!(filter.matches(&resource));
    }

    #[test]
    fn paths_for_patch() {
        let path = AttrPath::parse(r#"members[value eq "u1"]"#).unwrap();
        assert_eq!(path.attr, "members");
        assert!(path.value_filter.is_some());
        assert_eq!(path.sub, None);
        let path = AttrPath::parse(r#"emails[type eq "work"].value"#).unwrap();
        assert_eq!(path.sub.as_deref(), Some("value"));
        let path = AttrPath::parse("name.givenName").unwrap();
        assert_eq!(
            (path.attr.as_str(), path.sub.as_deref()),
            ("name", Some("givenName"))
        );
        let path = AttrPath::parse("members.$ref").unwrap();
        assert_eq!(path.sub.as_deref(), Some("$ref"));
        for bad in [
            "",
            "name.",
            "members[value eq \"x\"",
            "a b",
            "1abc",
            "name.given.name",
        ] {
            assert!(AttrPath::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn invalid_filters_are_rejected() {
        for bad in [
            "",
            "userName",
            "userName eq",
            r#"userName xx "a""#,
            r#"(userName eq "a""#,
            r#"userName eq "a" and"#,
            r#"userName eq "unterminated"#,
            r#"not userName eq "a""#,
            r#"userName eq "a" "b""#,
            r#"emails[type eq "work"#,
        ] {
            let result = Filter::parse(bad);
            assert!(result.is_err(), "{bad:?} parsed as {result:?}");
        }
    }

    #[test]
    fn resolve_descends_through_filters_and_sub_attributes() {
        let path = AttrPath::parse("emails[primary eq true].value").unwrap();
        assert_eq!(path.resolve(&user()), vec![&json!("alice@work.example")]);
        let path = AttrPath::parse("emails").unwrap();
        assert_eq!(path.resolve(&user()).len(), 2);
        let path = AttrPath::parse("nothing.here").unwrap();
        assert!(path.resolve(&user()).is_empty());
        assert!(
            AttrPath::parse("x")
                .unwrap()
                .resolve(&json!("scalar"))
                .is_empty()
        );
    }
}

//! The discovery documents (RFC 7644 §4): `/ServiceProviderConfig`,
//! `/ResourceTypes` and `/Schemas`. `base` is the absolute URL of the SCIM
//! root, without a trailing slash, for `meta.location`.

use serde_json::{Value, json};

use super::query::MAX_RESULTS;
use super::resource::{
    SCHEMA_ENTERPRISE_USER, SCHEMA_GROUP, SCHEMA_LIST_RESPONSE, SCHEMA_RESOURCE_TYPE,
    SCHEMA_SCHEMA, SCHEMA_SERVICE_PROVIDER_CONFIG, SCHEMA_USER,
};

pub fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": [SCHEMA_SERVICE_PROVIDER_CONFIG],
        "documentationUri": "https://warpgate.null.page/",
        "patch": {"supported": true},
        "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": true, "maxResults": MAX_RESULTS},
        "changePassword": {"supported": false},
        "sort": {"supported": true},
        "etag": {"supported": false},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "A Warpgate SCIM token presented as an OAuth 2.0 bearer token",
            "specUri": "https://www.rfc-editor.org/info/rfc6750",
            "primary": true,
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": format!("{base}/ServiceProviderConfig"),
        },
    })
}

fn resource_type(
    base: &str,
    name: &str,
    endpoint: &str,
    schema: &str,
    extensions: &Value,
) -> Value {
    json!({
        "schemas": [SCHEMA_RESOURCE_TYPE],
        "id": name,
        "name": name,
        "endpoint": endpoint,
        "description": format!("{name} resource"),
        "schema": schema,
        "schemaExtensions": extensions,
        "meta": {
            "resourceType": "ResourceType",
            "location": format!("{base}/ResourceTypes/{name}"),
        },
    })
}

pub fn resource_types(base: &str) -> Vec<Value> {
    vec![
        resource_type(
            base,
            "User",
            "/Users",
            SCHEMA_USER,
            &json!([{"schema": SCHEMA_ENTERPRISE_USER, "required": false}]),
        ),
        resource_type(base, "Group", "/Groups", SCHEMA_GROUP, &json!([])),
    ]
}

pub fn resource_type_by_id(base: &str, id: &str) -> Option<Value> {
    resource_types(base).into_iter().find(|rt| {
        rt["id"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(id))
    })
}

#[derive(Clone, Copy)]
struct Attr<'a> {
    name: &'a str,
    type_: &'a str,
    multi_valued: bool,
    required: bool,
    mutability: &'a str,
    uniqueness: &'a str,
    description: &'a str,
}

impl<'a> Attr<'a> {
    const fn new(name: &'a str, type_: &'a str, description: &'a str) -> Self {
        Self {
            name,
            type_,
            multi_valued: false,
            required: false,
            mutability: "readWrite",
            uniqueness: "none",
            description,
        }
    }

    const fn multi(mut self) -> Self {
        self.multi_valued = true;
        self
    }

    const fn required(mut self) -> Self {
        self.required = true;
        self
    }

    const fn read_only(mut self) -> Self {
        self.mutability = "readOnly";
        self
    }

    const fn unique(mut self) -> Self {
        self.uniqueness = "server";
        self
    }

    fn json(self, sub_attributes: Vec<Value>) -> Value {
        let mut attr = json!({
            "name": self.name,
            "type": self.type_,
            "multiValued": self.multi_valued,
            "description": self.description,
            "required": self.required,
            "caseExact": false,
            "mutability": self.mutability,
            "returned": "default",
            "uniqueness": self.uniqueness,
        });
        if !sub_attributes.is_empty()
            && let Some(object) = attr.as_object_mut()
        {
            object.insert("subAttributes".into(), Value::Array(sub_attributes));
        }
        attr
    }
}

fn string(name: &'static str, description: &'static str) -> Value {
    Attr::new(name, "string", description).json(vec![])
}

fn multi_valued_complex(
    name: &'static str,
    description: &'static str,
    mutability_read_only: bool,
) -> Value {
    let mut attr = Attr::new(name, "complex", description).multi();
    if mutability_read_only {
        attr = attr.read_only();
    }
    let mut subs = vec![
        string("value", "The value"),
        string("display", "A human-readable name"),
        string("type", "A label indicating the attribute's function"),
    ];
    if mutability_read_only {
        subs.insert(
            1,
            Attr::new("$ref", "reference", "The URI of the resource")
                .read_only()
                .json(vec![]),
        );
    } else {
        subs.push(
            Attr::new("primary", "boolean", "Whether this is the preferred value").json(vec![]),
        );
    }
    attr.json(subs)
}

fn user_schema(base: &str) -> Value {
    let attributes = vec![
        Attr::new(
            "userName",
            "string",
            "Unique identifier for the user, used to log in",
        )
        .required()
        .unique()
        .json(vec![]),
        Attr::new("name", "complex", "The components of the user's name").json(vec![
            string("formatted", "The full name"),
            string("familyName", "The family name"),
            string("givenName", "The given name"),
            string("middleName", "The middle name(s)"),
            string("honorificPrefix", "The honorific prefix"),
            string("honorificSuffix", "The honorific suffix"),
        ]),
        string("displayName", "The name shown to end users"),
        string("nickName", "The casual way to address the user"),
        Attr::new(
            "profileUrl",
            "reference",
            "A URI of the user's online profile",
        )
        .json(vec![]),
        string("title", "The user's title"),
        string(
            "userType",
            "The relationship between the organization and the user",
        ),
        string("preferredLanguage", "The user's preferred language"),
        string("locale", "The user's locale"),
        string("timezone", "The user's time zone"),
        Attr::new("active", "boolean", "Whether the account may log in").json(vec![]),
        multi_valued_complex(
            "emails",
            "Email addresses; the primary one links the SSO identity",
            false,
        ),
        multi_valued_complex("phoneNumbers", "Phone numbers", false),
        multi_valued_complex("groups", "Access roles the user holds", true),
    ];
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": SCHEMA_USER,
        "name": "User",
        "description": "User account",
        "attributes": attributes,
        "meta": {"resourceType": "Schema", "location": format!("{base}/Schemas/{SCHEMA_USER}")},
    })
}

fn group_schema(base: &str) -> Value {
    let attributes = vec![
        Attr::new("displayName", "string", "The access role name")
            .required()
            .unique()
            .json(vec![]),
        Attr::new("members", "complex", "Users holding the access role")
            .multi()
            .json(vec![
                Attr::new("value", "string", "The user's id").json(vec![]),
                Attr::new("$ref", "reference", "The URI of the user").json(vec![]),
                Attr::new("display", "string", "The user's name")
                    .read_only()
                    .json(vec![]),
            ]),
    ];
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": SCHEMA_GROUP,
        "name": "Group",
        "description": "Access role",
        "attributes": attributes,
        "meta": {"resourceType": "Schema", "location": format!("{base}/Schemas/{SCHEMA_GROUP}")},
    })
}

fn enterprise_user_schema(base: &str) -> Value {
    let attributes = vec![
        string(
            "employeeNumber",
            "An identifier assigned by the organization",
        ),
        string("costCenter", "The cost center"),
        string("organization", "The organization"),
        string("division", "The division"),
        string("department", "The department"),
        Attr::new("manager", "complex", "The user's manager").json(vec![
            string("value", "The manager's id"),
            Attr::new("$ref", "reference", "The URI of the manager").json(vec![]),
            Attr::new("displayName", "string", "The manager's name")
                .read_only()
                .json(vec![]),
        ]),
    ];
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": SCHEMA_ENTERPRISE_USER,
        "name": "EnterpriseUser",
        "description": "Enterprise User",
        "attributes": attributes,
        "meta": {"resourceType": "Schema", "location": format!("{base}/Schemas/{SCHEMA_ENTERPRISE_USER}")},
    })
}

pub fn schemas(base: &str) -> Vec<Value> {
    vec![
        user_schema(base),
        group_schema(base),
        enterprise_user_schema(base),
    ]
}

pub fn schema_by_id(base: &str, id: &str) -> Option<Value> {
    schemas(base).into_iter().find(|schema| {
        schema["id"]
            .as_str()
            .is_some_and(|urn| urn.eq_ignore_ascii_case(id))
    })
}

/// A `ListResponse` of discovery documents, which clients page like resources.
pub fn list(documents: &[Value]) -> Value {
    json!({
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": documents.len(),
        "startIndex": 1,
        "itemsPerPage": documents.len(),
        "Resources": documents,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    const BASE: &str = "https://wg.example/@warpgate/scim/v2";

    #[test]
    fn service_provider_config_declares_what_is_implemented() {
        let config = service_provider_config(BASE);
        assert_eq!(config["schemas"][0], SCHEMA_SERVICE_PROVIDER_CONFIG);
        assert_eq!(config["patch"]["supported"], true);
        assert_eq!(config["bulk"]["supported"], false);
        assert_eq!(config["filter"]["supported"], true);
        assert_eq!(config["filter"]["maxResults"], MAX_RESULTS);
        assert_eq!(config["etag"]["supported"], false);
        assert_eq!(config["changePassword"]["supported"], false);
        assert_eq!(
            config["authenticationSchemes"][0]["type"],
            "oauthbearertoken"
        );
        assert_eq!(
            config["meta"]["location"],
            format!("{BASE}/ServiceProviderConfig")
        );
    }

    #[test]
    fn resource_types_and_schemas_agree() {
        let types = resource_types(BASE);
        assert_eq!(types.len(), 2);
        assert_eq!(types[0]["endpoint"], "/Users");
        assert_eq!(types[0]["schema"], SCHEMA_USER);
        assert_eq!(
            types[0]["schemaExtensions"][0]["schema"],
            SCHEMA_ENTERPRISE_USER
        );
        assert_eq!(types[1]["endpoint"], "/Groups");
        assert!(resource_type_by_id(BASE, "user").is_some());
        assert!(resource_type_by_id(BASE, "Robot").is_none());

        let schemas = schemas(BASE);
        let ids: Vec<&str> = schemas.iter().map(|s| s["id"].as_str().unwrap()).collect();
        assert_eq!(ids, [SCHEMA_USER, SCHEMA_GROUP, SCHEMA_ENTERPRISE_USER]);
        assert!(schema_by_id(BASE, SCHEMA_GROUP).is_some());
        assert!(schema_by_id(BASE, "urn:nope").is_none());

        let user = schema_by_id(BASE, SCHEMA_USER).unwrap();
        let attrs = user["attributes"].as_array().unwrap();
        let find = |name: &str| attrs.iter().find(|a| a["name"] == name).unwrap().clone();
        assert_eq!(find("userName")["uniqueness"], "server");
        assert_eq!(find("userName")["required"], true);
        assert_eq!(find("groups")["mutability"], "readOnly");
        assert_eq!(find("groups")["multiValued"], true);
        assert_eq!(find("emails")["subAttributes"].as_array().unwrap().len(), 4);
        assert!(attrs.iter().all(|a| a["caseExact"] == false));

        let listed = list(&schemas);
        assert_eq!(listed["totalResults"], 3);
        assert_eq!(listed["Resources"].as_array().unwrap().len(), 3);
    }
}

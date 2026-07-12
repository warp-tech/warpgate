use std::time::Duration;

use anyhow::{Context, Result};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::{Map, Value, json};
use tracing::{debug, warn};
use warpgate_db_entities::Parameters::AnalyticsConsent;
use warpgate_db_entities::Target::TargetKind;
use warpgate_db_entities::{Parameters, Target, User};

const DEFAULT_ENDPOINT: &str = "https://api.openpanel.dev";
const DEFAULT_CLIENT_ID: &str = "33492e68-494c-4ad1-a8fe-8353afb66d53";
const DEFAULT_SECRET: &str = "sec_8828dbdfcf50be39c17f";
const STARTUP_DELAY: Duration = Duration::from_secs(30);
const REPORT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

const EVENT_NAME: &str = "instance_report";

pub fn start(db: DatabaseConnection) {
    tokio::spawn(async move {
        tokio::time::sleep(STARTUP_DELAY).await;
        loop {
            if let Err(e) = maybe_report_once(&db).await {
                warn!("Analytics report failed: {e}");
            }
            tokio::time::sleep(REPORT_INTERVAL).await;
        }
    });
}

/// patch part intentionally dropped so report doesn't fingerprint the exact build
fn major_minor_version() -> String {
    let mut parts = env!("CARGO_PKG_VERSION").split(['.', '-', '+']);
    let major = parts.next().unwrap_or("0");
    let minor = parts.next().unwrap_or("0");
    format!("{major}.{minor}")
}

fn round_up_to_10(n: u64) -> u64 {
    n.div_ceil(10) * 10
}

fn client_id() -> String {
    std::env::var("OPENPANEL_CLIENT_ID").unwrap_or_else(|_| DEFAULT_CLIENT_ID.into())
}

fn endpoint() -> String {
    std::env::var("WARPGATE_ANALYTICS_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.into())
}

async fn count_targets(db: &DatabaseConnection, kind: TargetKind) -> Result<u64> {
    Ok(Target::Entity::find()
        .filter(Target::Column::Kind.eq(kind))
        .count(db)
        .await?)
}

pub fn track_url() -> String {
    format!("{}/track", endpoint().trim_end_matches('/'))
}

async fn build_properties(
    db: &DatabaseConnection,
    normal: bool,
) -> Result<Map<String, Value>> {
    let mut properties = Map::new();
    properties.insert("version_series".into(), json!(major_minor_version()));

    if normal {
        properties.insert(
            "approximate_targets_ssh".into(),
            json!(round_up_to_10(count_targets(&db, TargetKind::Ssh).await?)),
        );
        properties.insert(
            "approximate_targets_http".into(),
            json!(round_up_to_10(count_targets(&db, TargetKind::Http).await?)),
        );
        properties.insert(
            "approximate_targets_mysql".into(),
            json!(round_up_to_10(count_targets(&db, TargetKind::MySql).await?)),
        );
        properties.insert(
            "approximate_targets_postgres".into(),
            json!(round_up_to_10(
                count_targets(&db, TargetKind::Postgres).await?
            )),
        );
        properties.insert(
            "approximate_targets_kubernetes".into(),
            json!(round_up_to_10(
                count_targets(&db, TargetKind::Kubernetes).await?
            )),
        );
        properties.insert(
            "approximate_users".into(),
            json!(round_up_to_10(User::Entity::find().count(&*db).await?)),
        );
    }

    Ok(properties)
}

fn track_payload(instance_id: &str, properties: Map<String, Value>) -> Value {
    json!({
        "type": "track",
        "payload": {
            "name": EVENT_NAME,
            "profileId": instance_id,
            "properties": Value::Object(properties),
        },
    })
}

pub async fn preview(db: &DatabaseConnection, normal: bool) -> Result<(String, Value)> {
    let instance_id = {
        Parameters::Entity::get(&db).await?.analytics_instance_id
    };
    let properties = build_properties(db, normal).await?;
    Ok((track_url(), track_payload(&instance_id, properties)))
}

async fn maybe_report_once(db: &DatabaseConnection) -> Result<()> {
    let (consent, normal, instance_id) = {
        let params = Parameters::Entity::get(&db).await?;
        (
            params.analytics_consent,
            params.analytics_normal,
            params.analytics_instance_id,
        )
    };
    if consent != AnalyticsConsent::On {
        return Ok(());
    }

    let properties = build_properties(db, normal).await?;

    let client = reqwest::Client::new();
    let url = track_url();

    let identify = json!({
        "type": "identify",
        "payload": {
            "profileId": instance_id,
            "properties": Value::Object(properties.clone()),
        },
    });
    if let Err(e) = post_event(&client, &url, &identify).await {
        warn!("Analytics identify failed: {e}");
    }

    let response = post_event(&client, &url, &track_payload(&instance_id, properties)).await?;

    if response.status().is_success() {
        debug!("Analytics report sent");
    } else {
        warn!("Analytics endpoint returned {}", response.status().as_u16());
    }

    Ok(())
}

async fn post_event(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
) -> Result<reqwest::Response> {
    client
        .post(url)
        .header("openpanel-client-id", client_id())
        .header("openpanel-client-secret", DEFAULT_SECRET)
        .json(body)
        .send()
        .await
        .context("sending analytics request")
}

use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use sea_orm::ActiveValue::Set;
use sea_orm::{EntityTrait, IntoActiveModel};
use warpgate_common::{AdminPermission, SlackConfig, StoredSecret, WarpgateError};
use warpgate_core::slack::{config_from_parameters, send_test_message};
use warpgate_db_entities::Parameters;

use super::AdminContext;

pub struct Api;

#[derive(Enum, PartialEq, Eq)]
#[oai(rename_all = "snake_case")]
enum SlackSettingsSource {
    /// The settings saved here
    Database,
    /// The `slack` section of the config file
    ConfigFile,
    /// Not active
    None,
}

/// The stored secrets are never sent to the browser
#[derive(Object)]
struct SlackSettings {
    enabled: bool,
    bot_token_set: bool,
    signing_secret_set: bool,
    sso_provider: Option<String>,
    channel: Option<String>,
    /// Names of the configured SSO providers
    sso_providers: Vec<String>,
    /// Which settings are currently in effect
    active_source: SlackSettingsSource,
}

/// Empty or omitted secrets keep the stored ones
#[derive(Object)]
struct SlackSettingsUpdate {
    enabled: bool,
    bot_token: Option<String>,
    signing_secret: Option<String>,
    sso_provider: Option<String>,
    channel: Option<String>,
}

#[derive(Object)]
struct SlackTestResult {
    success: bool,
    workspace: Option<String>,
    error: Option<String>,
}

#[derive(ApiResponse)]
enum GetSlackSettingsResponse {
    #[oai(status = 200)]
    Ok(Json<SlackSettings>),
}

#[derive(ApiResponse)]
enum UpdateSlackSettingsResponse {
    #[oai(status = 200)]
    Done,
}

#[derive(ApiResponse)]
enum TestSlackSettingsResponse {
    #[oai(status = 200)]
    Ok(Json<SlackTestResult>),
}

fn non_empty(value: Option<&String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

/// A typed-in secret replaces the stored one
fn merge_secret(incoming: Option<&String>, stored: &StoredSecret) -> Option<StoredSecret> {
    match non_empty(incoming) {
        Some(value) => Some(value.into()),
        None => (!stored.stored_value().is_empty()).then(|| stored.clone()),
    }
}

impl SlackSettingsUpdate {
    /// The settings as they would be after saving, with stored secrets filled in
    fn merged(&self, current: &Parameters::Model) -> (Option<StoredSecret>, Option<StoredSecret>) {
        (
            merge_secret(self.bot_token.as_ref(), &current.slack_bot_token),
            merge_secret(self.signing_secret.as_ref(), &current.slack_signing_secret),
        )
    }
}

#[OpenApi]
impl Api {
    #[oai(path = "/slack", method = "get", operation_id = "get_slack_settings")]
    async fn api_get(
        &self,
        admin: AdminContext,
    ) -> Result<GetSlackSettingsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let parameters = admin.parameters().await?;
        let config = admin.services().config.lock().await;

        let active_source = if config_from_parameters(parameters)?.is_some() {
            SlackSettingsSource::Database
        } else if config.store.slack.as_ref().is_some_and(|s| s.enable) {
            SlackSettingsSource::ConfigFile
        } else {
            SlackSettingsSource::None
        };

        Ok(GetSlackSettingsResponse::Ok(Json(SlackSettings {
            enabled: parameters.slack_enabled,
            bot_token_set: !parameters.slack_bot_token.stored_value().is_empty(),
            signing_secret_set: !parameters.slack_signing_secret.stored_value().is_empty(),
            sso_provider: parameters.slack_sso_provider.clone(),
            channel: parameters.slack_channel.clone(),
            sso_providers: config
                .store
                .sso_providers
                .iter()
                .map(|p| p.name.clone())
                .collect(),
            active_source,
        })))
    }

    #[oai(
        path = "/slack",
        method = "put",
        operation_id = "update_slack_settings"
    )]
    async fn api_update(
        &self,
        admin: AdminContext,
        body: Json<SlackSettingsUpdate>,
    ) -> Result<UpdateSlackSettingsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let current = admin.parameters().await?;
        let (bot_token, signing_secret) = body.merged(current);

        if body.enabled && (bot_token.is_none() || signing_secret.is_none()) {
            return Err(WarpgateError::InvalidRequest(
                "The bot token and the signing secret are required to enable Slack".into(),
            ));
        }

        let encrypt = |secret: Option<StoredSecret>| -> Result<StoredSecret, WarpgateError> {
            let mut secret = secret.unwrap_or_default();
            if !secret.stored_value().is_empty() {
                secret.encrypt()?;
            }
            Ok(secret)
        };

        let mut model = current.clone().into_active_model();
        model.slack_enabled = Set(body.enabled);
        model.slack_bot_token = Set(encrypt(bot_token)?);
        model.slack_signing_secret = Set(encrypt(signing_secret)?);
        model.slack_sso_provider = Set(non_empty(body.sso_provider.as_ref()));
        model.slack_channel = Set(non_empty(body.channel.as_ref()));
        Parameters::Entity::update(model)
            .exec(&admin.services().db)
            .await?;

        Ok(UpdateSlackSettingsResponse::Done)
    }

    /// Sends a test DM to the calling admin with the given (unsaved) settings
    #[oai(
        path = "/slack/test",
        method = "post",
        operation_id = "test_slack_settings"
    )]
    async fn api_test(
        &self,
        admin: AdminContext,
        body: Json<SlackSettingsUpdate>,
    ) -> Result<TestSlackSettingsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let fail = |error: String| {
            Ok(TestSlackSettingsResponse::Ok(Json(SlackTestResult {
                success: false,
                workspace: None,
                error: Some(error),
            })))
        };

        let Some(user) = admin.auth.as_full_user() else {
            return fail("Sign in as a user to send yourself a test message".into());
        };
        let current = admin.parameters().await?;
        let (bot_token, signing_secret) = body.merged(current);
        let (Some(bot_token), Some(signing_secret)) = (bot_token, signing_secret) else {
            return fail("The bot token and the signing secret are required".into());
        };

        let config = SlackConfig {
            enable: true,
            bot_token: bot_token.reveal()?,
            signing_secret: signing_secret.reveal()?,
            sso_provider: non_empty(body.sso_provider.as_ref()),
            channel: non_empty(body.channel.as_ref()),
        };
        match send_test_message(&admin.services().db, &config, user.user_id()).await {
            Ok(workspace) => Ok(TestSlackSettingsResponse::Ok(Json(SlackTestResult {
                success: true,
                workspace: Some(workspace),
                error: None,
            }))),
            Err(WarpgateError::InvalidRequest(error)) => fail(error),
            Err(error) => fail(error.to_string()),
        }
    }
}

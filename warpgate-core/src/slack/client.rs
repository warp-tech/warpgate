use anyhow::anyhow;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use warpgate_common::{Secret, WarpgateError};

const API_BASE: &str = "https://slack.com/api/";

/// Minimal Slack Web API client
#[derive(Clone)]
pub struct SlackClient {
    http: reqwest::Client,
    token: Secret<String>,
}

#[derive(Deserialize)]
struct Envelope {
    ok: bool,
    error: Option<String>,
}

#[derive(Deserialize)]
struct UserResponse {
    user: SlackUser,
}

#[derive(Deserialize)]
struct SlackUser {
    id: String,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    profile: SlackProfile,
}

#[derive(Deserialize, Default)]
struct SlackProfile {
    email: Option<String>,
}

#[derive(Deserialize)]
struct PostMessageResponse {
    channel: String,
    ts: String,
}

pub struct PostedMessage {
    pub channel: String,
    pub ts: String,
}

enum SlackCallError {
    Api(String),
    Other(WarpgateError),
}

impl From<SlackCallError> for WarpgateError {
    fn from(error: SlackCallError) -> Self {
        match error {
            SlackCallError::Api(error) => anyhow!("Slack API error: {error}").into(),
            SlackCallError::Other(error) => error,
        }
    }
}

impl SlackClient {
    pub fn new(token: Secret<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            token,
        }
    }

    async fn parse<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, SlackCallError> {
        let body: Value = response
            .json()
            .await
            .map_err(|e| SlackCallError::Other(e.into()))?;
        let envelope: Envelope = serde_json::from_value(body.clone())
            .map_err(|e| SlackCallError::Other(anyhow!(e).into()))?;
        if !envelope.ok {
            return Err(SlackCallError::Api(
                envelope.error.unwrap_or_else(|| "unknown_error".into()),
            ));
        }
        serde_json::from_value(body).map_err(|e| SlackCallError::Other(anyhow!(e).into()))
    }

    /// Read methods only accept query/form arguments
    async fn get<T: DeserializeOwned>(
        &self,
        method: &str,
        args: &[(&str, &str)],
    ) -> Result<T, SlackCallError> {
        let mut url = url::Url::parse(API_BASE)
            .and_then(|base| base.join(method))
            .map_err(|e| SlackCallError::Other(e.into()))?;
        url.query_pairs_mut().extend_pairs(args);
        let response = self
            .http
            .get(url)
            .bearer_auth(self.token.expose_secret())
            .send()
            .await
            .map_err(|e| SlackCallError::Other(e.into()))?;
        Self::parse(response).await
    }

    async fn post<T: DeserializeOwned>(
        &self,
        method: &str,
        body: &Value,
    ) -> Result<T, SlackCallError> {
        let response = self
            .http
            .post(format!("{API_BASE}{method}"))
            .bearer_auth(self.token.expose_secret())
            .json(body)
            .send()
            .await
            .map_err(|e| SlackCallError::Other(e.into()))?;
        Self::parse(response).await
    }

    /// Validates the token, returns the workspace name
    pub async fn auth_test(&self) -> Result<String, WarpgateError> {
        #[derive(Deserialize)]
        struct AuthTest {
            team: String,
        }
        Ok(self
            .post::<AuthTest>("auth.test", &serde_json::json!({}))
            .await?
            .team)
    }

    /// Slack user ID of an active account with this e-mail
    pub async fn lookup_user_by_email(&self, email: &str) -> Result<Option<String>, WarpgateError> {
        match self
            .get::<UserResponse>("users.lookupByEmail", &[("email", email)])
            .await
        {
            Ok(response) if !response.user.deleted => Ok(Some(response.user.id)),
            Ok(_) => Ok(None),
            Err(SlackCallError::Api(error)) if error == "users_not_found" => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// E-mail of an active Slack account
    pub async fn user_email(&self, user_id: &str) -> Result<Option<String>, WarpgateError> {
        let response = self
            .get::<UserResponse>("users.info", &[("user", user_id)])
            .await?;
        if response.user.deleted {
            return Ok(None);
        }
        Ok(response.user.profile.email)
    }

    /// `channel` may also be a user ID, which posts to the app's DM with them
    pub async fn post_message(
        &self,
        channel: &str,
        text: &str,
        blocks: &Value,
    ) -> Result<PostedMessage, WarpgateError> {
        let response: PostMessageResponse = self
            .post(
                "chat.postMessage",
                &serde_json::json!({
                    "channel": channel,
                    "text": text,
                    "blocks": blocks,
                    "unfurl_links": false,
                }),
            )
            .await?;
        Ok(PostedMessage {
            channel: response.channel,
            ts: response.ts,
        })
    }

    pub async fn update_message(
        &self,
        channel: &str,
        ts: &str,
        text: &str,
        blocks: &Value,
    ) -> Result<(), WarpgateError> {
        match self
            .post::<Value>(
                "chat.update",
                &serde_json::json!({
                    "channel": channel,
                    "ts": ts,
                    "text": text,
                    "blocks": blocks,
                }),
            )
            .await
        {
            // deleted by someone in Slack, nothing left to update
            Err(SlackCallError::Api(error)) if error == "message_not_found" => Ok(()),
            result => result.map(|_| ()).map_err(Into::into),
        }
    }

    /// Reply through an interaction's `response_url`, visible only to the clicking user
    pub async fn respond_ephemeral(
        &self,
        response_url: &str,
        text: &str,
    ) -> Result<(), WarpgateError> {
        self.http
            .post(response_url)
            .json(&serde_json::json!({
                "response_type": "ephemeral",
                "replace_original": false,
                "text": text,
            }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

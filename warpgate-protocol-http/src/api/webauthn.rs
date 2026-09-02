use anyhow::anyhow;
use poem::session::Session;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::error;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_core::Services;
use warpgate_db_entities::WebauthnCredential;

use super::auth_scheme::AuthedSession;

pub struct Api;

/// Maximum number of WebAuthn credentials per user.
const MAX_CREDENTIALS_PER_USER: usize = 8;

#[derive(Object, Serialize, Deserialize)]
struct RegistrationStartResponse {
    /// JSON-serialized CreationChallengeResponse from webauthn-rs
    challenge_json: String,
}

#[derive(ApiResponse)]
enum StartRegistrationResponse {
    #[oai(status = 200)]
    Ok(Json<RegistrationStartResponse>),
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 409)]
    TooManyCredentials,
    #[oai(status = 500)]
    InternalError,
}

#[derive(Object, Deserialize)]
struct RegistrationCompleteRequest {
    /// JSON-serialized RegisterPublicKeyCredential from the browser
    credential_json: String,
    /// Friendly label for this key (e.g. "Office Yubikey", "Backup key")
    label: String,
}

#[derive(Object, Serialize)]
struct RegistrationCompleteResponse {
    id: Uuid,
    label: String,
}

#[derive(ApiResponse)]
enum CompleteRegistrationResponse {
    #[oai(status = 201)]
    Created(Json<RegistrationCompleteResponse>),
    #[oai(status = 400)]
    BadRequest,
    #[oai(status = 500)]
    InternalError,
}

#[derive(Object, Serialize, Deserialize)]
pub(crate) struct AuthenticationStartResponse {
    /// JSON-serialized RequestChallengeResponse from webauthn-rs
    pub challenge_json: String,
}

#[derive(ApiResponse)]
pub(crate) enum StartAuthenticationResponse {
    #[oai(status = 200)]
    Ok(Json<AuthenticationStartResponse>),
    #[oai(status = 400)]
    NoCredentials,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 500)]
    InternalError,
}

#[derive(Object, Deserialize)]
pub(crate) struct AuthenticationCompleteRequest {
    /// JSON-serialized PublicKeyCredential from the browser
    pub credential_json: String,
}

#[derive(ApiResponse)]
pub(crate) enum CompleteAuthenticationResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 400)]
    BadRequest,
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 500)]
    InternalError,
}

/// Session key for storing the in-progress webauthn registration state
const SESSION_KEY_REG_STATE: &str = "webauthn_reg_state";
/// Session key for storing the in-progress webauthn authentication state
pub(crate) const SESSION_KEY_AUTH_STATE: &str = "webauthn_auth_state";

/// Construct the Webauthn verifier from config.
/// RP ID comes from `http.external_host` (or top-level `external_host`).
pub(crate) async fn build_webauthn(
    services: &Services,
) -> Result<webauthn_rs::Webauthn, WarpgateError> {
    let config = services.config.lock().await;
    let external_host = config
        .store
        .http
        .external_host
        .clone()
        .or_else(|| config.store.external_host.clone())
        .unwrap_or_else(|| "localhost".to_string());
    drop(config);

    // RP ID must be just the domain (no port)
    let rp_id = external_host
        .split(':')
        .next()
        .unwrap_or(&external_host)
        .to_string();
    // Origin must include the port if non-standard
    let rp_origin = url::Url::parse(&format!("https://{external_host}"))
        .map_err(|e| WarpgateError::from(anyhow!("Invalid RP origin: {e}")))?;

    let builder = webauthn_rs::WebauthnBuilder::new(&rp_id, &rp_origin)
        .map_err(|e| WarpgateError::from(anyhow!("WebAuthn builder error: {e}")))?
        .rp_name("Warpgate")
        // Allow subdomains: Warpgate uses DNS binding (e.g. target.wg.example.com)
        // where the RP ID is the base domain (wg.example.com) but the browser
        // origin may be a subdomain for a specific target.
        .allow_subdomains(true)
        // We only require user presence (touch), not full user verification (PIN).
        // This disables CredProtect extensions that conflict with non-resident
        // credentials on many authenticators, and sets UV=Discouraged so a simple
        // tap on the key suffices — matching the AWS IAM MFA UX.
        .danger_set_user_presence_only_security_keys(true);

    builder
        .build()
        .map_err(|e| WarpgateError::from(anyhow!("WebAuthn build error: {e}")))
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/auth/webauthn/registration/start",
        method = "post",
        operation_id = "start_webauthn_registration"
    )]
    async fn api_registration_start(
        &self,
        session: &Session,
        ctx: AuthedSession,
    ) -> Result<StartRegistrationResponse, WarpgateError> {
        let services = ctx.services();
        let Some(username) = ctx.auth.username().cloned() else {
            return Ok(StartRegistrationResponse::Unauthorized);
        };
        let user_id = ctx.auth.user_id();

        let db = &services.db;

        let existing_models = WebauthnCredential::Entity::find()
            .filter(WebauthnCredential::Column::UserId.eq(user_id))
            .all(db)
            .await?;

        if existing_models.len() >= MAX_CREDENTIALS_PER_USER {
            return Ok(StartRegistrationResponse::TooManyCredentials);
        }

        let webauthn = match build_webauthn(services).await {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to build WebAuthn instance: {e}");
                return Ok(StartRegistrationResponse::InternalError);
            }
        };

        let existing_cred_ids: Vec<webauthn_rs::prelude::CredentialID> = existing_models
            .into_iter()
            .filter_map(|c| {
                serde_json::from_str::<webauthn_rs::prelude::SecurityKey>(&c.credential_json)
                    .map_err(|e| {
                        tracing::warn!(
                            credential_id = %c.id,
                            "Failed to deserialize WebAuthn credential, skipping: {e}"
                        );
                    })
                    .ok()
                    .map(|sk| sk.cred_id().clone())
            })
            .collect();

        let (ccr, reg_state) = match webauthn.start_securitykey_registration(
            user_id,
            &username,
            &username,
            Some(existing_cred_ids),
            None, // no attestation CA list = attestation "none"
            None, // no UI hint override
        ) {
            Ok(result) => result,
            Err(e) => {
                error!("WebAuthn registration start ceremony failed: {e}");
                return Ok(StartRegistrationResponse::InternalError);
            }
        };

        let state_json = serde_json::to_string(&reg_state)
            .map_err(|e| WarpgateError::from(anyhow!("Serialize reg state: {e}")))?;
        session.set(SESSION_KEY_REG_STATE, state_json);

        let challenge_json = serde_json::to_string(&ccr)
            .map_err(|e| WarpgateError::from(anyhow!("Serialize challenge: {e}")))?;

        Ok(StartRegistrationResponse::Ok(Json(
            RegistrationStartResponse { challenge_json },
        )))
    }

    #[oai(
        path = "/auth/webauthn/registration/complete",
        method = "post",
        operation_id = "complete_webauthn_registration"
    )]
    async fn api_registration_complete(
        &self,
        session: &Session,
        ctx: AuthedSession,
        body: Json<RegistrationCompleteRequest>,
    ) -> Result<CompleteRegistrationResponse, WarpgateError> {
        let services = ctx.services();
        let user_id = ctx.auth.user_id();

        if body.label.trim().is_empty() || body.label.len() > 255 {
            return Ok(CompleteRegistrationResponse::BadRequest);
        }

        // Prevent duplicate names for the same user
        let db = &services.db;
        let existing_with_name = WebauthnCredential::Entity::find()
            .filter(WebauthnCredential::Column::UserId.eq(user_id))
            .filter(WebauthnCredential::Column::Label.eq(body.label.trim()))
            .one(db)
            .await?;
        if existing_with_name.is_some() {
            return Ok(CompleteRegistrationResponse::BadRequest);
        }

        let webauthn = match build_webauthn(services).await {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to build WebAuthn instance: {e}");
                return Ok(CompleteRegistrationResponse::InternalError);
            }
        };

        let Some(state_json) = session.get::<String>(SESSION_KEY_REG_STATE) else {
            return Ok(CompleteRegistrationResponse::BadRequest);
        };
        session.remove(SESSION_KEY_REG_STATE);

        let reg_state: webauthn_rs::prelude::SecurityKeyRegistration =
            match serde_json::from_str(&state_json) {
                Ok(s) => s,
                Err(e) => {
                    error!("Invalid registration state in session: {e}");
                    return Ok(CompleteRegistrationResponse::BadRequest);
                }
            };

        let reg_response: webauthn_rs_proto::RegisterPublicKeyCredential =
            match serde_json::from_str(&body.credential_json) {
                Ok(r) => r,
                Err(e) => {
                    error!("Invalid credential response from client: {e}");
                    return Ok(CompleteRegistrationResponse::BadRequest);
                }
            };

        let security_key = match webauthn.finish_securitykey_registration(&reg_response, &reg_state)
        {
            Ok(sk) => sk,
            Err(e) => {
                error!("WebAuthn registration verification failed: {e}");
                return Ok(CompleteRegistrationResponse::BadRequest);
            }
        };

        let credential_id = data_encoding::BASE64URL_NOPAD.encode(security_key.cred_id().as_ref());
        let credential_json = serde_json::to_string(&security_key)
            .map_err(|e| WarpgateError::from(anyhow!("Serialize security key: {e}")))?;

        let db = &services.db;
        let current_count = WebauthnCredential::Entity::find()
            .filter(WebauthnCredential::Column::UserId.eq(user_id))
            .all(db)
            .await?
            .len();
        if current_count >= MAX_CREDENTIALS_PER_USER {
            return Ok(CompleteRegistrationResponse::BadRequest);
        }

        let id = Uuid::new_v4();
        WebauthnCredential::ActiveModel {
            id: Set(id),
            user_id: Set(user_id),
            label: Set(body.label.clone()),
            credential_id: Set(credential_id),
            credential_json: Set(credential_json),
            date_added: Set(Some(OffsetDateTime::now_utc())),
            last_used: Set(None),
        }
        .insert(db)
        .await?;

        // Auto-upgrade credential policy (same as OTP self-service registration)
        if let Some(user_model) = warpgate_db_entities::User::Entity::find_by_id(user_id)
            .one(db)
            .await?
        {
            let details = user_model.clone().load_details(db).await?;
            let mut user_cfg: warpgate_common::User = user_model.try_into()?;
            user_cfg.credential_policy = Some(
                user_cfg
                    .credential_policy
                    .unwrap_or_default()
                    .upgrade_to_webauthn(details.credentials.as_slice()),
            );
            let user_active = warpgate_db_entities::User::ActiveModel::try_from(user_cfg)?;
            user_active.update(db).await?;
        }

        warpgate_core::logging::AuditEvent::CredentialCreated {
            credential_type: "webauthn".to_string(),
            credential_name: Some(body.label.clone()),
            via: warpgate_core::logging::CredentialChangedVia::SelfService,
            user_id,
            username: ctx.auth.username().cloned().unwrap_or_default(),
            actor_user_id: ctx.auth.user_id(),
        }
        .emit();

        Ok(CompleteRegistrationResponse::Created(Json(
            RegistrationCompleteResponse {
                id,
                label: body.label.clone(),
            },
        )))
    }
}

/// Verify a WebAuthn authentication response and update the credential's
/// counter and last_used timestamp. This is the core verification logic
/// shared between the login flow and any future step-up authentication.
///
/// `expected_user_id` is the user whose login this ceremony belongs to. The
/// verified credential MUST belong to that user; this is enforced explicitly
/// below as defense-in-depth, in addition to the challenge being scoped to
/// that user's keys at start time (see `serve_webauthn_auth_start`).
///
/// Returns `Ok(())` on success, or an error string on failure.
pub(crate) async fn verify_webauthn_authentication(
    services: &Services,
    session: &poem::session::Session,
    credential_json: &str,
    expected_user_id: Uuid,
) -> Result<(), String> {
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

    let webauthn = build_webauthn(services)
        .await
        .map_err(|e| format!("Failed to build WebAuthn instance: {e}"))?;

    let state_json = session
        .get::<String>(SESSION_KEY_AUTH_STATE)
        .ok_or_else(|| "No pending WebAuthn challenge in session".to_string())?;
    session.remove(SESSION_KEY_AUTH_STATE);

    let auth_state: webauthn_rs::prelude::SecurityKeyAuthentication =
        serde_json::from_str(&state_json)
            .map_err(|e| format!("Invalid authentication state: {e}"))?;

    let auth_response: webauthn_rs_proto::PublicKeyCredential =
        serde_json::from_str(credential_json)
            .map_err(|e| format!("Invalid credential response: {e}"))?;

    let auth_result = webauthn
        .finish_securitykey_authentication(&auth_response, &auth_state)
        .map_err(|e| format!("Verification failed: {e}"))?;

    // Locate the credential that just signed the assertion.
    let db = &services.db;
    let cred_id_b64 = data_encoding::BASE64URL_NOPAD.encode(auth_result.cred_id().as_ref());
    let cred_model = WebauthnCredential::Entity::find()
        .filter(WebauthnCredential::Column::CredentialId.eq(&cred_id_b64))
        .one(db)
        .await
        .map_err(|e| format!("Failed to load credential: {e}"))?
        .ok_or_else(|| "Verified credential is not registered".to_string())?;

    // Defense-in-depth: the verified credential must belong to the user whose
    // login this ceremony is completing. The challenge was already scoped to
    // this user's keys at start time, so a mismatch should be impossible, but
    // we enforce it explicitly rather than trusting that invariant implicitly.
    if cred_model.user_id != expected_user_id {
        return Err(format!(
            "Verified credential belongs to user {} but this login is for user {expected_user_id}",
            cred_model.user_id
        ));
    }

    // Update last_used and counter
    let mut active: WebauthnCredential::ActiveModel = cred_model.clone().into();
    active.last_used = Set(Some(time::OffsetDateTime::now_utc()));

    if let Ok(mut security_key) =
        serde_json::from_str::<webauthn_rs::prelude::SecurityKey>(&cred_model.credential_json)
        && security_key.update_credential(&auth_result) == Some(true)
        && let Ok(updated_json) = serde_json::to_string(&security_key)
    {
        active.credential_json = Set(updated_json);
    }

    let _ = active.update(db).await;

    Ok(())
}

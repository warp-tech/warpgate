use chrono::{DateTime, Utc};
use http::StatusCode;
use poem::web::Data;
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};
use uuid::Uuid;
use warpgate_common::{User, UserPasswordCredential, UserRequireCredentialsPolicy, WarpgateError};
use warpgate_core::Services;
use warpgate_db_entities::{self as entities, Parameters, PasswordCredential, PublicKeyCredential, CertificateCredential};

use super::common::get_user;
use crate::api::AnySecurityScheme;
use crate::common::{endpoint_auth, RequestAuthorization};

fn validate_certificate_pem(cert: &str) -> Result<(), WarpgateError> {
    // Check if it looks like a PEM certificate
    let cert = cert.trim();
    if !cert.starts_with("-----BEGIN CERTIFICATE-----") {
        return Err(WarpgateError::Other(
            "Certificate must be in PEM format and start with '-----BEGIN CERTIFICATE-----'".into()
        ));
    }
    if !cert.ends_with("-----END CERTIFICATE-----") {
        return Err(WarpgateError::Other(
            "Certificate must be in PEM format and end with '-----END CERTIFICATE-----'".into()
        ));
    }

    // Try to parse the certificate using rustls-pemfile
    use rustls_pemfile::Item;
    let mut reader = std::io::Cursor::new(cert.as_bytes());
    match rustls_pemfile::read_one(&mut reader) {
        Ok(Some(Item::X509Certificate(_))) => Ok(()),
        Ok(Some(_)) => Err(WarpgateError::Other(
            "PEM file does not contain a certificate".into()
        )),
        Ok(None) => Err(WarpgateError::Other(
            "No valid PEM items found in certificate".into()
        )),
        Err(_) => Err(WarpgateError::Other(
            "Invalid PEM certificate format".into()
        )),
    }
}

pub struct Api;

#[derive(Enum)]
enum PasswordState {
    Unset,
    Set,
    MultipleSet,
}

#[derive(Object)]
struct ExistingSsoCredential {
    id: Uuid,
    provider: Option<String>,
    email: String,
}

impl From<entities::SsoCredential::Model> for ExistingSsoCredential {
    fn from(credential: entities::SsoCredential::Model) -> Self {
        Self {
            id: credential.id,
            provider: credential.provider,
            email: credential.email,
        }
    }
}

#[derive(Object)]
struct ChangePasswordRequest {
    password: String,
}

#[derive(ApiResponse)]
enum ChangePasswordResponse {
    #[oai(status = 201)]
    Done(Json<PasswordState>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(Object)]
pub struct CredentialsState {
    password: PasswordState,
    otp: Vec<ExistingOtpCredential>,
    public_keys: Vec<ExistingPublicKeyCredential>,
    certificates: Vec<ExistingCertificateCredential>,
    sso: Vec<ExistingSsoCredential>,
    credential_policy: UserRequireCredentialsPolicy,
}

#[derive(ApiResponse)]
enum CredentialsStateResponse {
    #[oai(status = 200)]
    Ok(Json<CredentialsState>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(Object)]
struct NewPublicKeyCredential {
    label: String,
    openssh_public_key: String,
}

#[derive(Object)]
struct ExistingPublicKeyCredential {
    id: Uuid,
    label: String,
    date_added: Option<DateTime<Utc>>,
    last_used: Option<DateTime<Utc>>,
    abbreviated: String,
}

fn abbreviate_public_key(k: &str) -> String {
    let l = 10;
    if k.len() <= l {
        return k.to_string(); // Return the full key if it's shorter than or equal to `l`.
    }

    format!(
        "{}...{}",
        &k[..l.min(k.len())],            // Take the first `l` characters.
        &k[k.len().saturating_sub(l)..]  // Take the last `l` characters safely.
    )
}

impl From<entities::PublicKeyCredential::Model> for ExistingPublicKeyCredential {
    fn from(credential: entities::PublicKeyCredential::Model) -> Self {
        Self {
            id: credential.id,
            label: credential.label,
            date_added: credential.date_added,
            last_used: credential.last_used,
            abbreviated: abbreviate_public_key(&credential.openssh_public_key),
        }
    }
}
#[derive(ApiResponse)]
enum CreatePublicKeyCredentialResponse {
    #[oai(status = 201)]
    Created(Json<ExistingPublicKeyCredential>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(ApiResponse)]
enum DeleteCredentialResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 404)]
    NotFound,
}

#[derive(Object)]
struct NewOtpCredential {
    secret_key: Vec<u8>,
}

#[derive(Object)]
struct ExistingOtpCredential {
    id: Uuid,
}

impl From<entities::OtpCredential::Model> for ExistingOtpCredential {
    fn from(credential: entities::OtpCredential::Model) -> Self {
        Self { id: credential.id }
    }
}

#[derive(ApiResponse)]
enum CreateOtpCredentialResponse {
    #[oai(status = 201)]
    Created(Json<ExistingOtpCredential>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(Object)]
struct NewCertificateCredential {
    label: String,
    certificate_pem: String,
}

#[derive(Object)]
struct ExistingCertificateCredential {
    id: Uuid,
    label: String,
    date_added: Option<DateTime<Utc>>,
    last_used: Option<DateTime<Utc>>,
    abbreviated: String,
}

fn abbreviate_certificate(cert: &str) -> String {
    // Extract the subject or first few lines of the certificate for display
    if let Some(first_line) = cert.lines().next() {
        if first_line.len() > 50 {
            format!("{}...", &first_line[..47])
        } else {
            first_line.to_string()
        }
    } else {
        "Invalid certificate".to_string()
    }
}

impl From<entities::CertificateCredential::Model> for ExistingCertificateCredential {
    fn from(credential: entities::CertificateCredential::Model) -> Self {
        Self {
            id: credential.id,
            label: credential.label,
            date_added: credential.date_added,
            last_used: credential.last_used,
            abbreviated: abbreviate_certificate(&credential.certificate_pem),
        }
    }
}

#[derive(ApiResponse)]
enum CreateCertificateCredentialResponse {
    #[oai(status = 201)]
    Created(Json<ExistingCertificateCredential>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(ApiResponse)]
enum DeleteCertificateCredentialResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 404)]
    NotFound,
}

pub fn parameters_based_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let services = Data::<&Services>::from_request_without_body(&req).await?;
        let parameters = Parameters::Entity::get(&*services.db.lock().await)
            .await
            .map_err(WarpgateError::from)?;
        if !parameters.allow_own_credential_management {
            return Ok(poem::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body("Credential management is disabled")
                .into_response());
        }
        Ok(endpoint_auth(ep).call(req).await?.into_response())
    })
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/profile/credentials",
        method = "get",
        operation_id = "get_my_credentials",
        transform = "parameters_based_auth"
    )]
    async fn api_get_credentials_state(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CredentialsStateResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(user_model) = get_user(*auth, &db).await? else {
            return Ok(CredentialsStateResponse::Unauthorized);
        };

        let user = User::try_from(user_model.clone())?;

        let otp_creds = user_model
            .find_related(entities::OtpCredential::Entity)
            .all(&*db)
            .await?;
        let password_creds = user_model
            .find_related(entities::PasswordCredential::Entity)
            .all(&*db)
            .await?;
        let sso_creds = user_model
            .find_related(entities::SsoCredential::Entity)
            .all(&*db)
            .await?;

        let pk_creds = user_model
            .find_related(entities::PublicKeyCredential::Entity)
            .all(&*db)
            .await?;

        let cert_creds = user_model
            .find_related(entities::CertificateCredential::Entity)
            .all(&*db)
            .await?;

        Ok(CredentialsStateResponse::Ok(Json(CredentialsState {
            password: match password_creds.len() {
                0 => PasswordState::Unset,
                1 => PasswordState::Set,
                _ => PasswordState::MultipleSet,
            },
            otp: otp_creds.into_iter().map(Into::into).collect(),
            public_keys: pk_creds.into_iter().map(Into::into).collect(),
            certificates: cert_creds.into_iter().map(Into::into).collect(),
            sso: sso_creds.into_iter().map(Into::into).collect(),
            credential_policy: user.credential_policy.unwrap_or_default(),
        })))
    }

    #[oai(
        path = "/profile/credentials/password",
        method = "post",
        operation_id = "change_my_password",
        transform = "parameters_based_auth"
    )]
    async fn api_change_password(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        body: Json<ChangePasswordRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<ChangePasswordResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(user_model) = get_user(&auth, &db).await? else {
            return Ok(ChangePasswordResponse::Unauthorized);
        };

        entities::PasswordCredential::Entity::delete_many()
            .filter(entities::PasswordCredential::Column::UserId.eq(user_model.id))
            .exec(&*db)
            .await
            .map_err(WarpgateError::from)?;

        let new_credential = entities::PasswordCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_model.id),
            ..PasswordCredential::ActiveModel::from(UserPasswordCredential::from_password(
                &body.password.clone().into(),
            ))
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        entities::PasswordCredential::Entity::find()
            .filter(
                entities::PasswordCredential::Column::UserId
                    .eq(user_model.id)
                    .and(entities::PasswordCredential::Column::Id.ne(new_credential.id)),
            )
            .all(&*db)
            .await?;

        Ok(ChangePasswordResponse::Done(Json(PasswordState::Set)))
    }

    #[oai(
        path = "/profile/credentials/public-keys",
        method = "post",
        operation_id = "add_my_public_key",
        transform = "parameters_based_auth"
    )]
    async fn api_create_pk(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        body: Json<NewPublicKeyCredential>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreatePublicKeyCredentialResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(user_model) = get_user(&auth, &db).await? else {
            return Ok(CreatePublicKeyCredentialResponse::Unauthorized);
        };

        let object = PublicKeyCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_model.id),
            date_added: Set(Some(Utc::now())),
            last_used: Set(None),
            label: Set(body.label.clone()),
            openssh_public_key: Set(body.openssh_public_key.clone()),
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        Ok(CreatePublicKeyCredentialResponse::Created(Json(
            object.into(),
        )))
    }

    #[oai(
        path = "/profile/credentials/public-keys/:id",
        method = "delete",
        operation_id = "delete_my_public_key",
        transform = "parameters_based_auth"
    )]
    async fn api_delete_pk(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteCredentialResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(user_model) = get_user(&auth, &db).await? else {
            return Ok(DeleteCredentialResponse::Unauthorized);
        };

        let Some(model) = user_model
            .find_related(entities::PublicKeyCredential::Entity)
            .filter(entities::PublicKeyCredential::Column::Id.eq(id.0))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        model.delete(&*db).await?;
        Ok(DeleteCredentialResponse::Deleted)
    }

    #[oai(
        path = "/profile/credentials/otp",
        method = "post",
        operation_id = "add_my_otp",
        transform = "parameters_based_auth"
    )]
    async fn api_create_otp(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        body: Json<NewOtpCredential>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateOtpCredentialResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(user_model) = get_user(&auth, &db).await? else {
            return Ok(CreateOtpCredentialResponse::Unauthorized);
        };

        let mut user: User = user_model.clone().try_into()?;

        let object = entities::OtpCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_model.id),
            secret_key: Set(body.secret_key.clone()),
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        let details = user_model.load_details(&db).await?;
        user.credential_policy = Some(
            user.credential_policy
                .unwrap_or_default()
                .upgrade_to_otp(details.credentials.as_slice()),
        );

        entities::User::ActiveModel::try_from(user)?
            .update(&*db)
            .await?;

        Ok(CreateOtpCredentialResponse::Created(Json(object.into())))
    }

    #[oai(
        path = "/profile/credentials/otp/:id",
        method = "delete",
        operation_id = "delete_my_otp",
        transform = "parameters_based_auth"
    )]
    async fn api_delete_otp(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteCredentialResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(user_model) = get_user(&auth, &db).await? else {
            return Ok(DeleteCredentialResponse::Unauthorized);
        };

        let Some(model) = user_model
            .find_related(entities::OtpCredential::Entity)
            .filter(entities::OtpCredential::Column::Id.eq(id.0))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        model.delete(&*db).await?;
        Ok(DeleteCredentialResponse::Deleted)
    }

    #[oai(
        path = "/profile/credentials/certificates",
        method = "post",
        operation_id = "add_my_certificate",
        transform = "parameters_based_auth"
    )]
    async fn api_create_certificate(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        body: Json<NewCertificateCredential>,
    ) -> Result<CreateCertificateCredentialResponse, WarpgateError> {
        // Validate the certificate PEM format
        validate_certificate_pem(&body.certificate_pem)?;

        let db = services.db.lock().await;

        let Some(user_model) = get_user(&auth, &db).await? else {
            return Ok(CreateCertificateCredentialResponse::Unauthorized);
        };

        let object = CertificateCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_model.id),
            date_added: Set(Some(Utc::now())),
            last_used: Set(None),
            label: Set(body.label.clone()),
            certificate_pem: Set(body.certificate_pem.clone()),
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        Ok(CreateCertificateCredentialResponse::Created(Json(
            object.into(),
        )))
    }

    #[oai(
        path = "/profile/credentials/certificates/:id",
        method = "delete",
        operation_id = "delete_my_certificate",
        transform = "parameters_based_auth"
    )]
    async fn api_delete_certificate(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        id: Path<Uuid>,
    ) -> Result<DeleteCertificateCredentialResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(user_model) = get_user(&auth, &db).await? else {
            return Ok(DeleteCertificateCredentialResponse::Unauthorized);
        };

        let Some(model) = user_model
            .find_related(entities::CertificateCredential::Entity)
            .filter(entities::CertificateCredential::Column::Id.eq(id.0))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteCertificateCredentialResponse::NotFound);
        };

        model.delete(&*db).await?;
        Ok(DeleteCertificateCredentialResponse::Ok)
    }
}

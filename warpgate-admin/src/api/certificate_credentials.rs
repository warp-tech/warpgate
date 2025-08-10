use std::sync::Arc;

use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, ModelTrait,
    QueryFilter, Set,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_ca::{deserialize_certificate, serialize_certificate_serial};
use warpgate_common::WarpgateError;
use warpgate_db_entities::{CertificateCredential, CertificateRevocation, Parameters, User};

use super::AnySecurityScheme;

fn certificate_fingerprint(certificate_pem: &str) -> Result<String, WarpgateError> {
    Ok(warpgate_ca::certificate_sha256_hex_fingerprint(
        &warpgate_ca::deserialize_certificate(certificate_pem)?,
    )?)
}

#[derive(Object)]
struct ExistingCertificateCredential {
    id: Uuid,
    label: String,
    date_added: Option<DateTime<Utc>>,
    last_used: Option<DateTime<Utc>>,
    fingerprint: String,
}

#[derive(Object)]
struct IssuedCertificateCredential {
    credential: ExistingCertificateCredential,
    certificate_pem: String,
}

#[derive(Object)]
struct IssueCertificateCredentialRequest {
    label: String,
    public_key_pem: String,
}

#[derive(Object)]
struct UpdateCertificateCredential {
    label: String,
}

impl From<CertificateCredential::Model> for ExistingCertificateCredential {
    fn from(credential: CertificateCredential::Model) -> Self {
        Self {
            id: credential.id,
            date_added: credential.date_added,
            last_used: credential.last_used,
            label: credential.label,
            fingerprint: certificate_fingerprint(&credential.certificate_pem)
                .unwrap_or_else(|_| "Invalid certificate".into()),
        }
    }
}

#[derive(ApiResponse)]
enum GetCertificateCredentialsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ExistingCertificateCredential>>),
}

#[derive(ApiResponse)]
enum IssueCertificateCredentialResponse {
    #[oai(status = 201)]
    Issued(Json<IssuedCertificateCredential>),
}

#[derive(ApiResponse)]
enum UpdateCertificateCredentialResponse {
    #[oai(status = 200)]
    Updated(Json<ExistingCertificateCredential>),
    #[oai(status = 404)]
    NotFound,
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/users/:user_id/credentials/certificates",
        method = "get",
        operation_id = "get_certificate_credentials"
    )]
    async fn api_get_all(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        _auth: AnySecurityScheme,
    ) -> Result<GetCertificateCredentialsResponse, WarpgateError> {
        let db = db.lock().await;

        let objects = CertificateCredential::Entity::find()
            .filter(CertificateCredential::Column::UserId.eq(*user_id))
            .all(&*db)
            .await?;

        Ok(GetCertificateCredentialsResponse::Ok(Json(
            objects.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/users/:user_id/credentials/certificates",
        method = "post",
        operation_id = "issue_certificate_credential"
    )]
    async fn api_issue(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<IssueCertificateCredentialRequest>,
        user_id: Path<Uuid>,
        _auth: AnySecurityScheme,
    ) -> Result<IssueCertificateCredentialResponse, WarpgateError> {
        let db = db.lock().await;
        let params = Parameters::Entity::get(&*db).await?;
        let ca =
            warpgate_ca::deserialize_ca(&params.ca_certificate_pem, &params.ca_private_key_pem)?;
        let user = User::Entity::find_by_id(*user_id)
            .one(&*db)
            .await?
            .ok_or(WarpgateError::UserNotFound(user_id.to_string()))?;

        let public_key_pem = body.public_key_pem.trim();
        let client_cert =
            warpgate_ca::issue_client_certificate(&ca, &user.username, public_key_pem, *user_id)?;

        let client_cert_pem = warpgate_ca::certificate_to_pem(&client_cert)?;

        let object = CertificateCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(*user_id),
            date_added: Set(Some(Utc::now())),
            last_used: Set(None),
            label: Set(body.label.clone()),
            certificate_pem: Set(client_cert_pem.clone()),
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        Ok(IssueCertificateCredentialResponse::Issued(Json(
            IssuedCertificateCredential {
                credential: object.into(),
                certificate_pem: client_cert_pem,
            },
        )))
    }
}

#[derive(ApiResponse)]
enum RevokeCertificateCredentialResponse {
    #[oai(status = 204)]
    Revoked,
    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/users/:user_id/credentials/certificates/:id",
        method = "patch",
        operation_id = "update_certificate_credential"
    )]
    async fn api_update(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<UpdateCertificateCredential>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
        _auth: AnySecurityScheme,
    ) -> Result<UpdateCertificateCredentialResponse, WarpgateError> {
        let db = db.lock().await;
        let Some(cred) = CertificateCredential::Entity::find_by_id(id.0)
            .filter(CertificateCredential::Column::UserId.eq(*user_id))
            .one(&*db)
            .await?
        else {
            return Ok(UpdateCertificateCredentialResponse::NotFound);
        };

        let mut am = cred.into_active_model();

        am.label = Set(body.label.clone());
        let model = am.update(&*db).await?;

        Ok(UpdateCertificateCredentialResponse::Updated(Json(
            model.into(),
        )))
    }

    #[oai(
        path = "/users/:user_id/credentials/certificates/:id",
        method = "delete",
        operation_id = "revoke_certificate_credential"
    )]
    async fn api_delete(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
        _auth: AnySecurityScheme,
    ) -> Result<RevokeCertificateCredentialResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(model) = CertificateCredential::Entity::find_by_id(id.0)
            .filter(CertificateCredential::Column::UserId.eq(*user_id))
            .one(&*db)
            .await?
        else {
            return Ok(RevokeCertificateCredentialResponse::NotFound);
        };

        let cert = deserialize_certificate(&model.certificate_pem)?;

        CertificateRevocation::ActiveModel {
            id: Set(Uuid::new_v4()),
            date_added: Set(Utc::now()),
            serial_number_base64: Set(serialize_certificate_serial(&cert)),
        }
        .insert(&*db)
        .await?;

        model.delete(&*db).await?;
        Ok(RevokeCertificateCredentialResponse::Revoked)
    }
}

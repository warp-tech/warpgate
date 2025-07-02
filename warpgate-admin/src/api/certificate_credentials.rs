use std::sync::Arc;

use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, ModelTrait, QueryFilter,
    Set,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{UserCertificateCredential, WarpgateError, Secret};
use warpgate_db_entities::CertificateCredential;

use super::AnySecurityScheme;

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

#[derive(Object)]
struct ExistingCertificateCredential {
    id: Uuid,
    label: String,
    date_added: Option<DateTime<Utc>>,
    last_used: Option<DateTime<Utc>>,
    abbreviated: String,
}

#[derive(Object)]
struct NewCertificateCredential {
    label: String,
    certificate: String,
}

impl From<CertificateCredential::Model> for ExistingCertificateCredential {
    fn from(credential: CertificateCredential::Model) -> Self {
        Self {
            id: credential.id,
            date_added: credential.date_added,
            last_used: credential.last_used,
            label: credential.label,
            abbreviated: abbreviate_certificate(&credential.certificate),
        }
    }
}

impl From<&NewCertificateCredential> for UserCertificateCredential {
    fn from(credential: &NewCertificateCredential) -> Self {
        Self {
            certificate: Secret::new(credential.certificate.clone()),
        }
    }
}

#[derive(ApiResponse)]
enum GetCertificateCredentialsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ExistingCertificateCredential>>),
}

#[derive(ApiResponse)]
enum CreateCertificateCredentialResponse {
    #[oai(status = 201)]
    Created(Json<ExistingCertificateCredential>),
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
        _sec_scheme: AnySecurityScheme,
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
        operation_id = "create_certificate_credential"
    )]
    async fn api_create(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<NewCertificateCredential>,
        user_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateCertificateCredentialResponse, WarpgateError> {
        // Validate the certificate PEM format
        validate_certificate_pem(&body.certificate)?;

        let db = db.lock().await;

        let object = CertificateCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(*user_id),
            date_added: Set(Some(Utc::now())),
            last_used: Set(None),
            label: Set(body.label.clone()),
            ..CertificateCredential::ActiveModel::from(UserCertificateCredential::from(&*body))
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        Ok(CreateCertificateCredentialResponse::Created(Json(
            object.into(),
        )))
    }
}

#[derive(ApiResponse)]
enum DeleteCredentialResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/users/:user_id/credentials/certificates/:id",
        method = "put",
        operation_id = "update_certificate_credential"
    )]
    async fn api_update(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<NewCertificateCredential>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateCertificateCredentialResponse, WarpgateError> {
        let db = db.lock().await;

        let model = CertificateCredential::ActiveModel {
            id: Set(id.0),
            user_id: Set(*user_id),
            date_added: Set(Some(Utc::now())),
            label: Set(body.label.clone()),
            ..<_>::from(UserCertificateCredential::from(&*body))
        }
        .update(&*db)
        .await;

        match model {
            Ok(model) => Ok(UpdateCertificateCredentialResponse::Updated(Json(
                model.into(),
            ))),
            Err(DbErr::RecordNotFound(_)) => Ok(UpdateCertificateCredentialResponse::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    #[oai(
        path = "/users/:user_id/credentials/certificates/:id",
        method = "delete",
        operation_id = "delete_certificate_credential"
    )]
    async fn api_delete(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteCredentialResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(model) = CertificateCredential::Entity::find_by_id(id.0)
            .filter(CertificateCredential::Column::UserId.eq(*user_id))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        model.delete(&*db).await?;
        Ok(DeleteCredentialResponse::Deleted)
    }
}

use anyhow::Result;
use rocket::http::Status;
use rocket::request::FromParam;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::Request;
use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::{Parameter, Responses};
use rocket_okapi::request::OpenApiFromParam;
use rocket_okapi::response::OpenApiResponderInner;
use rocket_okapi::{JsonSchema, OpenApiError};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize, JsonSchema)]
pub enum ApiError {
    NotFound,
    InvalidRequestParameter,
}

pub type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Debug, PartialEq, Eq)]
pub struct UuidParam(Uuid);

impl Into<Uuid> for UuidParam {
    fn into(self) -> Uuid {
        self.0
    }
}

impl AsRef<Uuid> for UuidParam {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EmptyResponse {}

impl<'r, 'o: 'r> Responder<'r, 'o> for ApiError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'o> {
        match self {
            ApiError::NotFound => return Err(Status::NotFound),
            ApiError::InvalidRequestParameter => return Err(Status::BadRequest),
        };
    }
}

fn add_404_error(
    gen: &mut OpenApiGenerator,
    responses: &mut Responses,
) -> Result<(), OpenApiError> {
    let response = Json::<EmptyResponse>::responses(gen)?
        .responses
        .remove("200")
        .unwrap();
    responses
        .responses
        .entry("404".to_owned())
        .or_insert_with(|| response);
    Ok(())
}

impl OpenApiResponderInner for ApiError {
    fn responses(gen: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        let mut responses = Responses::default();
        add_404_error(gen, &mut responses)?;
        Ok(responses)
    }
}

impl<'a> FromParam<'a> for UuidParam {
    type Error = ApiError;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        Ok(UuidParam(
            uuid::Uuid::parse_str(param).map_err(|_| ApiError::InvalidRequestParameter)?,
        ))
    }
}

impl OpenApiFromParam<'_> for UuidParam {
    fn path_parameter(gen: &mut OpenApiGenerator, name: String) -> Result<Parameter, OpenApiError> {
        String::path_parameter(gen, name)
    }
}

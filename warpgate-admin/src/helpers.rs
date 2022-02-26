use anyhow::Result;
use rocket::http::Status;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::Request;
use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::Responses;
use rocket_okapi::response::OpenApiResponderInner;
use rocket_okapi::{JsonSchema, OpenApiError};
use serde::Serialize;

#[derive(Debug, Serialize, JsonSchema)]
pub enum ApiError {
    NotFound,
    // InvalidRequestParameter,
}

pub type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Debug, Serialize, JsonSchema)]
pub struct EmptyResponse {}

impl<'r, 'o: 'r> Responder<'r, 'o> for ApiError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'o> {
        match self {
            ApiError::NotFound => return Err(Status::NotFound),
            // ApiError::InvalidRequestParameter => return Err(Status::BadRequest),
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

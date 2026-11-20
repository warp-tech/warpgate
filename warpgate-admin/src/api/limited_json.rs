use poem::http::Method;
use poem::{Request, RequestBody};
use poem_openapi::payload::{Json, ParsePayload, Payload};
use poem_openapi::registry::{MetaSchemaRef, Registry};
use poem_openapi::types::{ParseFromJSON, Type};
use warpgate_common_http::read_body_limited_with_timeout;

/// Every route that takes a [`LimitedJson`], relative to the admin API mount.
/// The HTTP server leaves the body of these unread, for the handler to read
/// under its own limit.
pub const SELF_LIMITED_ROUTES: &[(Method, &str)] = &[
    (Method::POST, "/gitops/sync"),
    (Method::POST, "/gitops/dry-run"),
    (Method::PUT, "/parameters/logo"),
];

/// A JSON body of up to `LIMIT` bytes, for the routes that take more than the
/// HTTP server allows everywhere else. A route that takes one is listed in
/// [`SELF_LIMITED_ROUTES`].
///
/// Goes after `AdminContext` in the handler's arguments: they are extracted in
/// order, so nothing is read for a caller who is not an admin.
pub struct LimitedJson<T, const LIMIT: usize>(pub T);

impl<T: Type, const LIMIT: usize> Payload for LimitedJson<T, LIMIT> {
    const CONTENT_TYPE: &'static str = Json::<T>::CONTENT_TYPE;

    fn check_content_type(content_type: &str) -> bool {
        Json::<T>::check_content_type(content_type)
    }

    fn schema_ref() -> MetaSchemaRef {
        Json::<T>::schema_ref()
    }

    fn register(registry: &mut Registry) {
        Json::<T>::register(registry);
    }
}

impl<T: ParseFromJSON, const LIMIT: usize> ParsePayload for LimitedJson<T, LIMIT> {
    const IS_REQUIRED: bool = <Json<T> as ParsePayload>::IS_REQUIRED;

    async fn from_request(request: &Request, body: &mut RequestBody) -> poem::Result<Self> {
        let bytes = read_body_limited_with_timeout(request.headers(), body.take()?, LIMIT).await?;
        let mut body = RequestBody::new(bytes.into());
        let Json(value) = <Json<T> as ParsePayload>::from_request(request, &mut body).await?;
        Ok(Self(value))
    }
}

poem_openapi::impl_apirequest_for_payload!(LimitedJson<T, LIMIT>, T: ParseFromJSON, const LIMIT: usize);

#[cfg(test)]
mod tests {
    use poem_openapi::OpenApi;
    use poem_openapi::registry::MetaApi;

    use super::SELF_LIMITED_ROUTES;

    fn meta<T: OpenApi>(_: &T) -> Vec<MetaApi> {
        T::meta()
    }

    #[test]
    fn self_limited_routes_are_operations_with_a_body() {
        let apis = meta(&crate::api::get());
        for (method, path) in SELF_LIMITED_ROUTES {
            let found = apis.iter().flat_map(|api| &api.paths).any(|api_path| {
                api_path.path == *path
                    && api_path
                        .operations
                        .iter()
                        .any(|operation| operation.method == *method && operation.request.is_some())
            });
            assert!(found, "{method} {path}");
        }
    }
}

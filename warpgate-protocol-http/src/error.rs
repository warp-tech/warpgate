use http::StatusCode;
use poem::IntoResponse;
use tracing::error;
use uuid::Uuid;

/// Renders any failure of the proxied-target path, the one leg an
/// unauthenticated visitor to a shared link can hit. `poem::Error`'s
/// `Display` falls through to whatever actually failed, so only a generic
/// message and a correlation id cross the wire.
pub fn error_page(e: &poem::Error) -> impl IntoResponse {
    let correlation_id = Uuid::new_v4();
    error!(correlation_id = %correlation_id, "{:?}", e);
    // Ours, so it needs no escaping.
    let e = format!("Bad Gateway (reference: {correlation_id})");
    poem::web::Html(format!(
        r#"<!DOCTYPE html>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
            }}

            img {{
                width: 100px;
            }}

            main {{
                width: 400px;
                margin: 200px auto;
            }}
        </style>
        <main>
            <img src="/@warpgate/assets/brand.svg" />
            <h1>Request failed</h1>
            <p>{e}</p>
        </main>
        "#
    )).with_status(StatusCode::BAD_GATEWAY)
}

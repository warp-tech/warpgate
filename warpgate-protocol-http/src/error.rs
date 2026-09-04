use http::StatusCode;
use poem::IntoResponse;
use tracing::error;
use uuid::Uuid;

/// This renders any failure of the proxied-target path -- the one leg of
/// Warpgate an unauthenticated visitor to a shared link can hit -- so unlike
/// an admin API error it must never repeat `poem::Error`'s `Display`
/// verbatim: that falls straight through to whatever error type actually
/// failed (a `WarpgateError` variant, but just as easily a raw
/// `std::io::Error` or `hyper::Error` from the proxy plumbing) with no
/// review point in between. Only a generic message and a correlation id
/// cross the wire; the full detail stays in the log this already writes.
pub fn error_page(e: &poem::Error) -> impl IntoResponse {
    let correlation_id = Uuid::new_v4();
    error!(correlation_id = %correlation_id, "{:?}", e);
    // No `html_escape` needed here (unlike the code this replaced): unlike
    // the error's own `Display`, this text is entirely ours.
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

use http::StatusCode;
use poem::IntoResponse;
use tracing::error;

/// The branded standalone page Warpgate serves in place of a proxied response.
/// `head` is dropped into the document head (a `<meta refresh>`, say); `body` is
/// already-escaped markup for inside `<main>`.
pub fn branded_page(head: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
        {head}
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
            {body}
        </main>
        "#
    )
}

pub fn error_page(e: &poem::Error) -> impl IntoResponse {
    error!("{:?}", e);
    let e = html_escape::encode_text(&e.to_string()).into_owned();
    poem::web::Html(branded_page(
        "",
        &format!("<h1>Request failed</h1><p>{e}</p>"),
    ))
    .with_status(StatusCode::BAD_GATEWAY)
}

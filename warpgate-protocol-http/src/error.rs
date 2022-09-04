use http::StatusCode;
use poem::IntoResponse;

pub fn error_page(e: poem::Error) -> impl IntoResponse {
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
            <img src="/@warpgate/assets/logo.svg" />
            <h1>Request failed</h1>
            <p>{e}</p>
        </main>
        "#
    )).with_status(StatusCode::BAD_GATEWAY)
}

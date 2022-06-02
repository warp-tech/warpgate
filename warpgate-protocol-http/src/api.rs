use http::uri::Authority;
use http::Uri;
use poem::http::{HeaderValue, StatusCode};
use poem::{handler, Body, IntoResponse, Request, Response};
use tracing::*;
use warpgate_common::{Target, TargetHTTPOptions};

#[handler]
pub async fn test_endpoint(req: &Request, body: Body) -> poem::Result<Response> {
    let mut res = String::new();
    let mut has_auth = false;
    for h in req.headers().iter() {
        if h.0 == "Authorization" {
            // println!("Found {:?} {:?}", h.0, h.1);
            // let v = BASE64
            // .decode(h.1.as_bytes())
            // .map_err(poem::error::BadRequest)?;
            // println!("v: {:?}", v);
            if h.1 == "Basic dGVzdDpwdw==" {
                has_auth = true;
            }
        }
        res.push_str(&format!("{}: {:?}\n", h.0, h.1));
    }
    res.push('\n');
    res.push_str(&req.original_uri().to_string());

    proxy_request(req, body).await
    // let mut r = res.into_response();
    // if !has_auth {
    //     r.headers_mut().insert(
    //         "WWW-Authenticate",
    //         HeaderValue::try_from("Basic realm=\"Test\"".to_string()).unwrap(),
    //     );
    //     r.set_status(StatusCode::UNAUTHORIZED);
    // }
    // Ok(r)
}

async fn proxy_request(req: &Request, body: Body) -> poem::Result<Response> {
    let target = Target {
        allow_roles: vec![],
        http: Some(TargetHTTPOptions {
            url: "http://192.168.78.233/".to_string(),
        }),
        name: "Target".to_string(),
        ssh: None,
        web_admin: None,
    };

    let target_uri = Uri::try_from(target.http.unwrap().url).unwrap();
    let source_uri = req.uri().clone();

    let authority = target_uri.authority().unwrap().to_string();
    let authority = authority.split("@").last().unwrap();
    let authority: Authority = authority.try_into().unwrap();
    let uri = http::uri::Builder::new()
        .authority(authority)
        .path_and_query(source_uri.path_and_query().unwrap().clone())
        .scheme(target_uri.scheme().unwrap().clone())
        .build()
        .unwrap()
        .to_string();

    tracing::debug!("URI: {:?}", uri);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connection_verbose(true)
        .build()
        .unwrap();
    let mut client_request = client.request(req.method().into(), uri.clone());

    for k in req.headers().keys() {
        client_request = client_request.header(
            k.clone(),
            req.headers()
                .get_all(k)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
                .join("; "),
        );
    }

    client_request = client_request.body(reqwest::Body::wrap_stream(body.into_bytes_stream()));

    let client_request = client_request.build().unwrap();
    let client_response = client.execute(client_request).await.unwrap();

    let mut response: Response = "".into();

    response
        .headers_mut()
        .extend(client_response.headers().clone().into_iter());

    tracing::info!(
        "{:?} {:?} - {:?}",
        client_response.status(),
        uri,
        client_response.content_length().unwrap_or(0)
    );

    response.set_status(client_response.status());
    response.set_body(Body::from_bytes_stream(client_response.bytes_stream()));

    Ok(response)
}

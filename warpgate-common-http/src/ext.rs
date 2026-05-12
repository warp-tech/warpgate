use poem::FromRequest;
use poem::http::uri::Scheme;
use poem::web::Data;
use url::Url;
use warpgate_common::WarpgateError;

use crate::auth::UnauthenticatedRequestContext;

pub async fn construct_external_url(
    for_request: Option<&poem::Request>,
    config: &warpgate_common::WarpgateConfig,
    domain_whitelist: Option<&[String]>,
) -> Result<Url, WarpgateError> {
    let ctx = if let Some(for_request) = for_request {
        Some(
            Data::<&UnauthenticatedRequestContext>::from_request_without_body(for_request)
                .await
                .map_err(|e| WarpgateError::Other(Box::new(e)))?,
        )
    } else {
        None
    };

    let Some((Some(scheme), Some(host), port)) = (if let Some(for_request) = for_request {
        let ctx = ctx
            .as_ref()
            .ok_or_else(|| WarpgateError::InconsistentState("no ctx in request".into()))?;
        Some((
            Some(ctx.trusted_proto(for_request)),
            ctx.trusted_hostname(for_request),
            ctx.trusted_port(for_request),
        ))
    } else {
        config.store.external_host.as_ref().map(|external_host| {
            #[allow(clippy::unwrap_used)]
            let external_host = external_host.split(':').next().unwrap();

            (
                Some(Scheme::HTTPS),
                Some(external_host.to_owned()),
                config
                    .store
                    .http
                    .external_port
                    .or_else(|| Some(config.store.http.listen.port())),
            )
        })
    }) else {
        return Err(WarpgateError::ExternalHostUnknown);
    };

    if let Some(list) = domain_whitelist
        && !list.contains(&host)
    {
        return Err(WarpgateError::ExternalHostNotWhitelisted(
            host,
            list.to_vec(),
        ));
    }

    let mut url = format!("{scheme}://{host}");
    if let Some(port) = port {
        // can't `match` `Scheme`
        if scheme == Scheme::HTTP && port != 80 || scheme == Scheme::HTTPS && port != 443 {
            url = format!("{url}:{port}");
        }
    }
    Url::parse(&url).map_err(WarpgateError::UrlParse)
}

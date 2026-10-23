/// Which HTTP listener a request arrived on. Set as request data by the HTTP
/// server; absent outside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpListenerKind {
    /// `http.listen`
    Main,
    /// `http.admin.listen`
    Admin,
}

impl HttpListenerKind {
    pub fn of(req: &poem::Request) -> Option<Self> {
        req.data::<Self>().copied()
    }

    /// `trust_x_forwarded_headers` as configured for this listener.
    pub fn trust_x_forwarded_headers(self, config: &warpgate_common::WarpgateConfig) -> bool {
        let http = &config.store.http;
        match self {
            Self::Main => http.trust_x_forwarded_headers,
            Self::Admin => http
                .admin
                .as_ref()
                .and_then(|admin| admin.trust_x_forwarded_headers)
                .unwrap_or(http.trust_x_forwarded_headers),
        }
    }
}

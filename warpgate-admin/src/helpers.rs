use poem::http::StatusCode;
use poem::session::Session;

pub type ApiResult<T> = poem::Result<T>;

pub trait SessionExt {
    fn is_authorized(&self) -> bool;
}

impl SessionExt for Session {
    fn is_authorized(&self) -> bool {
        self.get::<String>("username").is_some()
    }
}

pub async fn authorized<FN, FT, R>(session: &Session, f: FN) -> ApiResult<R>
where
    FN: FnOnce() -> FT,
    FT: futures::Future<Output = ApiResult<R>>,
{
    if !session.is_authorized() {
        return Err(poem::Error::from_string(
            "Unauthorized",
            StatusCode::UNAUTHORIZED,
        ));
    }
    f().await
}

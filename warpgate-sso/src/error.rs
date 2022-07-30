use std::error::Error;

#[derive(thiserror::Error, Debug)]
pub enum SsoError {
    #[error("config parse error: {0}")]
    UrlParse(#[from] openidconnect::url::ParseError),
    #[error("I/O: {0}")]
    Discovery(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}

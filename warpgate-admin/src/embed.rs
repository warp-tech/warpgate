use std::marker::PhantomData;

use async_trait::async_trait;
use poem::http::{header, Method, StatusCode};
use poem::{Endpoint, Request, Response};
use rust_embed::RustEmbed;

pub struct EmbeddedFileEndpoint<E: RustEmbed + Send + Sync> {
    _embed: PhantomData<E>,
    path: String,
}

impl<E: RustEmbed + Send + Sync> EmbeddedFileEndpoint<E> {
    pub fn new(path: &str) -> Self {
        EmbeddedFileEndpoint {
            _embed: PhantomData,
            path: path.to_owned(),
        }
    }
}

#[async_trait]
impl<E: RustEmbed + Send + Sync> Endpoint for EmbeddedFileEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> Result<Self::Output, poem::Error> {
        if req.method() != Method::GET {
            return Err(StatusCode::METHOD_NOT_ALLOWED.into());
        }

        match E::get(&self.path) {
            Some(content) => {
                let hash = hex::encode(content.metadata.sha256_hash());
                if req
                    .headers()
                    .get(header::IF_NONE_MATCH)
                    .map(|etag| etag.to_str().unwrap_or("000000").eq(&hash))
                    .unwrap_or(false)
                {
                    return Err(StatusCode::NOT_MODIFIED.into());
                }

                // otherwise, return 200 with etag hash
                let body: Vec<u8> = content.data.into();
                let mime = mime_guess::from_path(&self.path).first_or_octet_stream();
                Ok(Response::builder()
                    .header(header::CONTENT_TYPE, mime.as_ref())
                    .header(header::ETAG, hash)
                    .body(body))
            }
            None => Err(StatusCode::NOT_FOUND.into()),
        }
    }
}

pub struct EmbeddedFilesEndpoint<E: RustEmbed + Send + Sync> {
    _embed: PhantomData<E>,
}

impl<E: RustEmbed + Send + Sync> EmbeddedFilesEndpoint<E> {
    pub fn new() -> Self {
        EmbeddedFilesEndpoint {
            _embed: PhantomData,
        }
    }
}

#[async_trait]
impl<E: RustEmbed + Send + Sync> Endpoint for EmbeddedFilesEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> Result<Self::Output, poem::Error> {
        let mut path = req
            .uri()
            .path()
            .trim_start_matches('/')
            .trim_end_matches('/')
            .to_string();
        if path.is_empty() {
            path = "index.html".to_string();
        }
        let path = path.as_ref();
        EmbeddedFileEndpoint::<E>::new(path).call(req).await
    }
}

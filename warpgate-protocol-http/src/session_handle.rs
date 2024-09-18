use std::any::type_name;
use std::future::Future;
use std::sync::Arc;

use poem::error::GetDataError;
use poem::session::Session;
use poem::web::Data;
use poem::{FromRequest, Request, RequestBody};
use tokio::sync::{mpsc, Mutex};
use warpgate_core::{SessionHandle, WarpgateServerHandle};

use crate::session::SessionStore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionHandleCommand {
    Close,
}

pub struct HttpSessionHandle {
    sender: mpsc::UnboundedSender<SessionHandleCommand>,
}

impl HttpSessionHandle {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<SessionHandleCommand>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (HttpSessionHandle { sender }, receiver)
    }
}

impl SessionHandle for HttpSessionHandle {
    fn close(&mut self) {
        let _ = self.sender.send(SessionHandleCommand::Close);
    }
}

#[derive(Clone)]
pub struct WarpgateServerHandleFromRequest(pub Arc<Mutex<WarpgateServerHandle>>);

impl std::ops::Deref for WarpgateServerHandleFromRequest {
    type Target = Arc<Mutex<WarpgateServerHandle>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> FromRequest<'a> for WarpgateServerHandleFromRequest {
    fn from_request(
        req: &'a Request,
        _: &mut RequestBody,
    ) -> impl Future<Output = poem::Result<Self>> {
        async move {
            let sm = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req).await?;
            let session = <&Session>::from_request_without_body(req).await?;
            Ok(sm
                .lock()
                .await
                .handle_for(session)
                .map(WarpgateServerHandleFromRequest)
                .ok_or_else(|| GetDataError(type_name::<WarpgateServerHandle>()))?)
        }
    }
}

impl From<Arc<Mutex<WarpgateServerHandle>>> for WarpgateServerHandleFromRequest {
    fn from(handle: Arc<Mutex<WarpgateServerHandle>>) -> Self {
        WarpgateServerHandleFromRequest(handle)
    }
}

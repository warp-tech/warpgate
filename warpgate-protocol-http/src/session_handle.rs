use std::any::type_name;
use std::sync::Arc;

use poem::error::GetDataError;
use poem::session::Session;
use poem::web::Data;
use poem::{FromRequest, Request};
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
        (Self { sender }, receiver)
    }
}

impl SessionHandle for HttpSessionHandle {
    fn close(&mut self) {
        let _ = self.sender.send(SessionHandleCommand::Close);
    }
}

pub async fn warpgate_server_handle_for_request(
    req: &Request,
) -> poem::Result<Arc<Mutex<WarpgateServerHandle>>> {
    let sm = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req).await?;
    let session = <&Session>::from_request_without_body(req).await?;
    Ok(sm
        .lock()
        .await
        .handle_for(session)
        .ok_or_else(|| GetDataError(type_name::<WarpgateServerHandle>()))?)
}

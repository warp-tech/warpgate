use std::sync::{Arc, Mutex, PoisonError};

use ironrdp::cliprdr::backend::{ClipboardMessage, CliprdrBackend, CliprdrBackendFactory};
use ironrdp_server::{CliprdrServerFactory, ServerEvent, ServerEventSender};
use tokio::sync::mpsc::UnboundedSender;
use warpgate_core::DesktopInput;

use super::protocol::Event;
use crate::clipboard::{Clipboard, ClipboardSink};

type ServerSender = Arc<Mutex<Option<UnboundedSender<ServerEvent>>>>;

#[derive(Clone, Debug)]
struct ViewerSink {
    server: ServerSender,
    to_warpgate: UnboundedSender<Event>,
}

impl ClipboardSink for ViewerSink {
    fn request(&self, message: ClipboardMessage) {
        if let Some(server) = self
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            let _ = server.send(ServerEvent::Clipboard(message));
        }
    }

    fn text_received(&self, text: String) {
        let _ = self
            .to_warpgate
            .send(Event::Input(DesktopInput::Clipboard(text)));
    }
}

#[derive(Clone, Debug)]
pub(super) struct ViewerClipboard(Clipboard<ViewerSink>);

impl ViewerClipboard {
    pub(super) fn new(to_warpgate: UnboundedSender<Event>) -> Self {
        Self(Clipboard::new(ViewerSink {
            server: ServerSender::default(),
            to_warpgate,
        }))
    }

    pub(super) fn offer(&self, text: String) {
        self.0.offer(text);
    }
}

impl CliprdrBackendFactory for ViewerClipboard {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        Box::new(self.0.backend())
    }
}

impl ServerEventSender for ViewerClipboard {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self
            .0
            .sink()
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(sender);
    }
}

impl CliprdrServerFactory for ViewerClipboard {}

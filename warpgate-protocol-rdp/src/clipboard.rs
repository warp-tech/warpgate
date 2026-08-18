// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeclip/

use std::any::Any;
use std::sync::{Arc, Mutex, PoisonError};

use ironrdp::cliprdr::backend::{ClipboardMessage, CliprdrBackend};
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp::core::{AsAny, IntoOwned as _};
use tracing::debug;
use warpgate_core::MAX_CLIPBOARD_BYTES;

const TEXT: ClipboardFormatId = ClipboardFormatId::CF_UNICODETEXT;

/// truncate so that utf16 encoded `text` fits in `max` bytes
fn truncate_for_wire(text: &mut String, max: usize) {
    let mut wire = 0;
    for (idx, ch) in text.char_indices() {
        wire += ch.len_utf16() * 2;
        if wire > max {
            text.truncate(idx);
            return;
        }
    }
}

fn advertise_text(sink: &impl ClipboardSink) {
    sink.request(ClipboardMessage::SendInitiateCopy(vec![
        ClipboardFormat::new(TEXT),
    ]));
}

/// Underlying sink for TextClipboard
pub(crate) trait ClipboardSink: core::fmt::Debug + Send + 'static {
    fn request(&self, message: ClipboardMessage);
    fn text_received(&self, text: String);
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ClipboardText(Arc<Mutex<String>>);

impl ClipboardText {
    fn get(&self) -> String {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set(&self, text: String) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = text;
    }
}

/// THe "one" connection-side end of the clipboard bridge
#[derive(Clone, Debug)]
pub(crate) struct Clipboard<S> {
    store: ClipboardText,
    sink: S,
}

impl<S: ClipboardSink + Clone> Clipboard<S> {
    pub(crate) fn new(sink: S) -> Self {
        Self {
            store: ClipboardText::default(),
            sink,
        }
    }

    pub(crate) fn sink(&self) -> &S {
        &self.sink
    }

    pub(crate) fn backend(&self) -> TextClipboard<S> {
        TextClipboard {
            store: self.store.clone(),
            sink: self.sink.clone(),
        }
    }

    /// Offer local clipboard contents to remote
    pub(crate) fn offer(&self, mut text: String) {
        truncate_for_wire(&mut text, MAX_CLIPBOARD_BYTES);
        self.store.set(text);
        advertise_text(&self.sink);
    }
}

/// The "many" per-channel side of the clipboard bridge
#[derive(Debug)]
pub(crate) struct TextClipboard<S> {
    store: ClipboardText,
    sink: S,
}

impl<S: ClipboardSink> AsAny for TextClipboard<S> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl<S: ClipboardSink> CliprdrBackend for TextClipboard<S> {
    fn temporary_directory(&self) -> &str {
        "."
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {}

    // Remote asks to advertise available contents
    fn on_request_format_list(&mut self) {
        if !self.store.get().is_empty() {
            advertise_text(&self.sink);
        }
    }

    fn on_process_negotiated_capabilities(
        &mut self,
        _capabilities: ClipboardGeneralCapabilityFlags,
    ) {
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        if available_formats.iter().any(|format| format.id() == TEXT) {
            self.sink.request(ClipboardMessage::SendInitiatePaste(TEXT));
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let response = if request.format == TEXT {
            FormatDataResponse::new_unicode_string(&self.store.get())
        } else {
            FormatDataResponse::new_error()
        };
        self.sink
            .request(ClipboardMessage::SendFormatData(response.into_owned()));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() {
            debug!("remote failed to render clipboard text");
            return;
        }
        match response.to_unicode_string() {
            Ok(mut text) => {
                truncate_for_wire(&mut text, MAX_CLIPBOARD_BYTES);
                self.sink.text_received(text);
            }
            Err(error) => debug!(%error, "undecodable clipboard text"),
        }
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _data_id: LockDataId) {}
    fn on_unlock(&mut self, _data_id: LockDataId) {}
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Sender, channel};

    use super::*;

    #[derive(Clone, Debug)]
    struct TestSink {
        requests: Sender<ClipboardMessage>,
        texts: Sender<String>,
    }

    impl ClipboardSink for TestSink {
        fn request(&self, message: ClipboardMessage) {
            let _ = self.requests.send(message);
        }

        fn text_received(&self, text: String) {
            let _ = self.texts.send(text);
        }
    }

    fn fixture() -> (
        Clipboard<TestSink>,
        TextClipboard<TestSink>,
        std::sync::mpsc::Receiver<ClipboardMessage>,
        std::sync::mpsc::Receiver<String>,
    ) {
        let (requests, requests_rx) = channel();
        let (texts, texts_rx) = channel();
        let clipboard = Clipboard::new(TestSink { requests, texts });
        let backend = clipboard.backend();
        (clipboard, backend, requests_rx, texts_rx)
    }

    /// A remote copy has to be pulled: the format list only names what is available.
    #[test]
    fn remote_text_copy_triggers_a_paste_request() {
        let (_clipboard, mut backend, requests, _texts) = fixture();

        backend.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_DIB)]);
        assert!(requests.try_recv().is_err());

        backend.on_remote_copy(&[ClipboardFormat::new(TEXT)]);
        assert!(matches!(
            requests.try_recv(),
            Ok(ClipboardMessage::SendInitiatePaste(TEXT))
        ));
    }

    /// End to end through the shared store: what one side offers is what the other
    /// renders, and back again.
    #[test]
    fn text_is_rendered_and_received_as_utf16() {
        let (clipboard, mut backend, requests, texts) = fixture();
        clipboard.offer("héllo".to_owned());
        assert!(matches!(
            requests.try_recv(),
            Ok(ClipboardMessage::SendInitiateCopy(_))
        ));

        backend.on_format_data_request(FormatDataRequest { format: TEXT });
        let Ok(ClipboardMessage::SendFormatData(response)) = requests.try_recv() else {
            panic!("expected format data");
        };
        // Feeding it straight back models the remote answering our own paste request.
        backend.on_format_data_response(response);
        assert_eq!(texts.try_recv().ok().as_deref(), Some("héllo"));
    }

    #[test]
    fn a_non_text_request_is_refused_rather_than_answered_with_text() {
        let (clipboard, mut backend, requests, _texts) = fixture();
        clipboard.offer("secret".to_owned());
        let _ = requests.try_recv();

        backend.on_format_data_request(FormatDataRequest {
            format: ClipboardFormatId::CF_DIB,
        });
        let Ok(ClipboardMessage::SendFormatData(response)) = requests.try_recv() else {
            panic!("expected format data");
        };
        assert!(response.is_error());
        assert!(response.data().is_empty());
    }

    /// The cap applies to the UTF-16 wire encoding, cutting on a char boundary — a
    /// surrogate pair (🦀 is 4 wire bytes) is kept or dropped whole.
    #[test]
    fn oversized_text_is_capped_by_its_wire_size() {
        let (clipboard, _backend, _requests, _texts) = fixture();
        clipboard.offer("🦀".repeat(MAX_CLIPBOARD_BYTES / 3));
        let stored = clipboard.store.get();
        let wire_len = stored.encode_utf16().count() * 2;
        assert!(wire_len <= MAX_CLIPBOARD_BYTES);
        assert!(wire_len > MAX_CLIPBOARD_BYTES - 4);
        assert!(stored.ends_with('🦀'));
    }

    /// A rebuilt channel asks for a fresh format list; text copied through the previous
    /// channel generation must be re-advertised, an empty store must not be.
    #[test]
    fn channel_bringup_readvertises_stored_text() {
        let (clipboard, mut backend, requests, _texts) = fixture();
        backend.on_request_format_list();
        assert!(requests.try_recv().is_err());

        clipboard.offer("kept".to_owned());
        let _ = requests.try_recv();
        let mut next = clipboard.backend();
        next.on_request_format_list();
        assert!(matches!(
            requests.try_recv(),
            Ok(ClipboardMessage::SendInitiateCopy(_))
        ));
    }
}

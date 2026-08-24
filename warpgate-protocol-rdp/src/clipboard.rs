// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeclip/

use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use ironrdp::cliprdr::backend::{ClipboardMessage, CliprdrBackend};
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp::core::{AsAny, IntoOwned as _};
use tracing::debug;
use warpgate_core::MAX_CLIPBOARD_BYTES;

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

/// Only Unicode is advertised: a peer that wants ANSI text synthesises it from this in its
/// own code page, which we have no way to render for it.
fn advertise_text(sink: &impl ClipboardSink) {
    sink.request(ClipboardMessage::SendInitiateCopy(vec![
        ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
    ]));
}

/// The best text format a peer offers; some only put up ANSI text.
fn preferred_text_format(formats: &[ClipboardFormat]) -> Option<ClipboardFormatId> {
    [
        ClipboardFormatId::CF_UNICODETEXT,
        ClipboardFormatId::CF_TEXT,
        ClipboardFormatId::CF_OEMTEXT,
    ]
    .into_iter()
    .find(|id| formats.iter().any(|format| format.id() == *id))
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
    ready: Arc<AtomicBool>,
    sink: S,
}

impl<S: ClipboardSink + Clone> Clipboard<S> {
    /// A clipboard that may advertise from the moment it exists — the cliprdr *server* role,
    /// which opens the channel itself and is free to announce formats at any time.
    pub(crate) fn new(sink: S) -> Self {
        Self::with_readiness(sink, true)
    }

    /// A clipboard that holds offers back until [`CliprdrBackend::on_ready`] — the cliprdr
    /// *client* role, whose format list is only legal once the remote's initialization
    /// sequence has run ([MS-RDPECLIP] 3.1.5.1). Text offered before then seeds the store and
    /// rides the initialization batch instead of racing ahead of it.
    pub(crate) fn deferred(sink: S) -> Self {
        Self::with_readiness(sink, false)
    }

    fn with_readiness(sink: S, ready: bool) -> Self {
        Self {
            store: ClipboardText::default(),
            ready: Arc::new(AtomicBool::new(ready)),
            sink,
        }
    }

    pub(crate) fn sink(&self) -> &S {
        &self.sink
    }

    pub(crate) fn backend(&self) -> TextClipboard<S> {
        TextClipboard {
            store: self.store.clone(),
            ready: Arc::clone(&self.ready),
            sink: self.sink.clone(),
            paste_format: None,
        }
    }

    /// Offer local clipboard contents to remote
    pub(crate) fn offer(&self, mut text: String) {
        truncate_for_wire(&mut text, MAX_CLIPBOARD_BYTES);
        self.store.set(text);
        if self.ready.load(Ordering::SeqCst) {
            advertise_text(&self.sink);
        }
    }
}

/// The "many" per-channel side of the clipboard bridge
#[derive(Debug)]
pub(crate) struct TextClipboard<S> {
    store: ClipboardText,
    ready: Arc<AtomicBool>,
    sink: S,
    paste_format: Option<ClipboardFormatId>,
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

    fn on_ready(&mut self) {
        // Text offered while the channel was coming up was stored but not announced; announce
        // it now. If it was already carried by the initialization batch this repeats one format
        // list of identical content, which is legal and cheap — unlike an offer that outruns
        // the initialization sequence, which wedges the remote's clipboard for the session.
        if !self.ready.swap(true, Ordering::SeqCst) && !self.store.get().is_empty() {
            advertise_text(&self.sink);
        }
    }

    /// Remote asks to advertise available contents. Answered unconditionally: this is the
    /// remote's Monitor Ready, and the format list replying to it is what carries our
    /// capabilities and completes the initialization sequence. Staying silent because there is
    /// nothing to offer leaves the channel unusable in both directions, so an empty clipboard
    /// answers with an empty format list — the standard "nothing to offer" announcement.
    fn on_request_format_list(&mut self) {
        if self.store.get().is_empty() {
            self.sink
                .request(ClipboardMessage::SendInitiateCopy(vec![]));
        } else {
            advertise_text(&self.sink);
        }
    }

    fn on_process_negotiated_capabilities(
        &mut self,
        _capabilities: ClipboardGeneralCapabilityFlags,
    ) {
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        if let Some(format) = preferred_text_format(available_formats) {
            self.paste_format = Some(format);
            self.sink
                .request(ClipboardMessage::SendInitiatePaste(format));
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let response = if request.format == ClipboardFormatId::CF_UNICODETEXT {
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
        let format = self
            .paste_format
            .take()
            .unwrap_or(ClipboardFormatId::CF_UNICODETEXT);
        let decoded = if format == ClipboardFormatId::CF_UNICODETEXT {
            response.to_unicode_string()
        } else {
            response.to_string()
        };
        match decoded {
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

    type Fixture = (
        Clipboard<TestSink>,
        TextClipboard<TestSink>,
        std::sync::mpsc::Receiver<ClipboardMessage>,
        std::sync::mpsc::Receiver<String>,
    );

    fn fixture() -> Fixture {
        build_fixture(Clipboard::new)
    }

    fn deferred_fixture() -> Fixture {
        build_fixture(Clipboard::deferred)
    }

    fn build_fixture(make: fn(TestSink) -> Clipboard<TestSink>) -> Fixture {
        let (requests, requests_rx) = channel();
        let (texts, texts_rx) = channel();
        let clipboard = make(TestSink { requests, texts });
        let backend = clipboard.backend();
        (clipboard, backend, requests_rx, texts_rx)
    }

    fn offered_formats(message: ClipboardMessage) -> Vec<ClipboardFormatId> {
        match message {
            ClipboardMessage::SendInitiateCopy(formats) => {
                formats.iter().map(ClipboardFormat::id).collect()
            }
            _ => panic!("expected a format list"),
        }
    }

    /// A remote copy has to be pulled: the format list only names what is available.
    #[test]
    fn remote_text_copy_triggers_a_paste_request() {
        let (_clipboard, mut backend, requests, _texts) = fixture();

        backend.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_DIB)]);
        assert!(requests.try_recv().is_err());

        backend.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        assert!(matches!(
            requests.try_recv(),
            Ok(ClipboardMessage::SendInitiatePaste(
                ClipboardFormatId::CF_UNICODETEXT
            ))
        ));
    }

    #[test]
    fn ansi_text_copy_is_used_as_a_fallback() {
        let (_clipboard, mut backend, requests, texts) = fixture();

        backend.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_TEXT)]);
        assert!(matches!(
            requests.try_recv(),
            Ok(ClipboardMessage::SendInitiatePaste(
                ClipboardFormatId::CF_TEXT
            ))
        ));

        backend.on_format_data_response(FormatDataResponse::new_string("hello"));
        assert_eq!(texts.try_recv().ok().as_deref(), Some("hello"));
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

        backend.on_format_data_request(FormatDataRequest {
            format: ClipboardFormatId::CF_UNICODETEXT,
        });
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

    /// A channel asking for a format list is running its initialization sequence, and the
    /// reply is what completes it — so an empty store answers with an empty list rather than
    /// staying silent. Text copied through a previous channel generation is re-advertised.
    #[test]
    fn channel_bringup_always_answers_with_a_format_list() {
        let (clipboard, mut backend, requests, _texts) = fixture();
        backend.on_request_format_list();
        assert_eq!(offered_formats(requests.try_recv().unwrap()), []);

        clipboard.offer("kept".to_owned());
        let _ = requests.try_recv();
        let mut next = clipboard.backend();
        next.on_request_format_list();
        assert_eq!(
            offered_formats(requests.try_recv().unwrap()),
            [ClipboardFormatId::CF_UNICODETEXT]
        );
    }

    /// A deferred clipboard belongs to a channel that may not announce formats before the
    /// remote's initialization sequence has run: text offered early is stored silently and
    /// announced once the channel reports itself ready.
    #[test]
    fn a_deferred_clipboard_holds_offers_until_ready() {
        let (clipboard, mut backend, requests, _texts) = deferred_fixture();

        clipboard.offer("early".to_owned());
        assert!(requests.try_recv().is_err());

        backend.on_ready();
        assert_eq!(
            offered_formats(requests.try_recv().unwrap()),
            [ClipboardFormatId::CF_UNICODETEXT]
        );
        backend.on_format_data_request(FormatDataRequest {
            format: ClipboardFormatId::CF_UNICODETEXT,
        });
        assert!(matches!(
            requests.try_recv(),
            Ok(ClipboardMessage::SendFormatData(_))
        ));

        clipboard.offer("later".to_owned());
        assert_eq!(
            offered_formats(requests.try_recv().unwrap()),
            [ClipboardFormatId::CF_UNICODETEXT]
        );
    }

    /// Nothing was offered while the channel came up, so becoming ready has nothing to
    /// announce — the initialization reply already said as much.
    #[test]
    fn an_idle_deferred_clipboard_announces_nothing_when_ready() {
        let (_clipboard, mut backend, requests, _texts) = deferred_fixture();

        backend.on_request_format_list();
        assert_eq!(offered_formats(requests.try_recv().unwrap()), []);

        backend.on_ready();
        assert!(requests.try_recv().is_err());
    }

    /// Text offered before the remote asked for a format list rides that reply, which is the
    /// earliest legal moment to announce it.
    #[test]
    fn early_text_rides_the_initialization_format_list() {
        let (clipboard, mut backend, requests, _texts) = deferred_fixture();

        clipboard.offer("early".to_owned());
        backend.on_request_format_list();
        assert_eq!(
            offered_formats(requests.try_recv().unwrap()),
            [ClipboardFormatId::CF_UNICODETEXT]
        );
    }
}

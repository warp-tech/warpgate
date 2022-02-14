use bytes::Bytes;
use thrussh::{ChannelId, Pty, Sig};


#[derive(Clone, Debug)]
pub struct PtyRequest {
    pub term: String,
    pub col_width: u32,
    pub row_height: u32,
    pub pix_width: u32,
    pub pix_height: u32,
    pub modes: Vec<(Pty, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
pub struct ServerChannelId(pub ChannelId);

#[derive(Debug)]
pub enum ChannelOperation {
    OpenShell,
    RequestPty(PtyRequest),
    ResizePty(PtyRequest),
    RequestShell,
    RequestExec(String),
    RequestSubsystem(String),
    Data(Bytes),
    ExtendedData {
        data: Bytes,
        ext: u32,
    },
    Close,
    Eof,
    Signal(Sig),
}

pub use ironrdp_rdpdr::server::{NoopRdpdrServerBackend, RdpdrServerBackend, RdpdrServerMessage};

use crate::ServerEventSender;

pub trait RdpdrServerFactory: ServerEventSender {
    fn build_backend(&self) -> Box<dyn RdpdrServerBackend>;
}

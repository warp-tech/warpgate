pub use ironrdp_rdpeai::server::{NoopRdpeaiServerBackend, RdpeaiServerBackend, RdpeaiServerMessage};

use crate::ServerEventSender;

pub trait RdpeaiServerFactory: ServerEventSender {
    fn build_backend(&self) -> Box<dyn RdpeaiServerBackend>;
}

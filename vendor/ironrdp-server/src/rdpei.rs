pub use ironrdp_rdpei::pdu::{
    CsReadyFlags, CsReadyPdu, DismissHoveringTouchContactPdu, PenContact, PenContactDataFlags, PenContactFields,
    PenContactFlags, PenEventPdu, PenFlags, PenFrame, RdpInputProtocolVersion, ScReadyFeatures, TouchContact,
    TouchContactDataFlags, TouchContactFields, TouchContactFlags, TouchEventPdu, TouchFrame,
};
pub use ironrdp_rdpei::{RdpeiHandler, RdpeiServer};

use crate::ServerEventSender;

pub trait RdpeiServerFactory: ServerEventSender {
    /// Builds the configured server endpoint for a new connection. Returning the
    /// whole [`RdpeiServer`], rather than just its handler, lets the factory call
    /// [`RdpeiServer::with_protocol_version`] or [`RdpeiServer::with_supported_features`]
    /// to advertise non-default capabilities.
    fn build_server(&self) -> RdpeiServer;
}

#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]
#![allow(clippy::arithmetic_side_effects)] // TODO: should we enable this lint back?

mod macros;

pub mod autodetect;
mod builder;
mod capabilities;
mod clipboard;
mod display;
mod echo;
mod encoder;
mod error;
#[cfg(feature = "egfx")]
mod gfx;
mod handler;
pub mod heartbeat;
#[cfg(feature = "helper")]
mod helper;
mod multitransport;
mod rdpdr;
mod rdpeai;
mod rdpei;
mod server;
mod sound;
#[cfg(feature = "usb")]
mod urbdrc;

pub use clipboard::CliprdrServerFactory;
pub use display::{
    BitmapUpdate, ColorPointer, DesktopSize, DisplayContext, DisplayUpdate, Framebuffer, LargePointer, PixelFormat,
    RGBAPointer, RdpServerDisplay, RdpServerDisplayUpdates,
};
pub use echo::{EchoDvcBridge, EchoRoundTripMeasurement, EchoServerHandle, EchoServerMessage};
#[cfg(all(feature = "__test", feature = "qoiz"))]
pub use encoder::qoiz::Compressor as QoizCompressor;
#[cfg(feature = "__test")]
pub use encoder::{RemoteFxCodec, UpdateEncoder, UpdateEncoderCodecs};
pub use error::{ServerError, ServerErrorExt, ServerErrorKind, ServerResult, ServerResultExt};
#[cfg(feature = "egfx")]
pub use gfx::{EgfxServerMessage, GfxContext, GfxDvcBridge, GfxServerFactory, GfxServerHandle};
pub use handler::{KeyboardEvent, MouseButton, MouseEvent, RdpServerInputHandler};
#[cfg(feature = "helper")]
pub use helper::TlsIdentityCtx;
pub use ironrdp_acceptor::{Acceptor, CredentialOrigin, ReceivedCredentials};
pub use ironrdp_pdu::rdp::server_error_info::ErrorInfo;
pub use ironrdp_pdu::rdp::session_info::ServerAutoReconnect;
#[cfg(feature = "usb")]
pub use ironrdp_rdpeusb::io::{CompletionData, DeviceAnnounce, DeviceText, InternalIoControlPacket};
pub use rdpdr::{NoopRdpdrServerBackend, RdpdrServerBackend, RdpdrServerFactory, RdpdrServerMessage};
pub use rdpeai::{NoopRdpeaiServerBackend, RdpeaiServerBackend, RdpeaiServerFactory, RdpeaiServerMessage};
pub use rdpei::{
    CsReadyFlags, CsReadyPdu, DismissHoveringTouchContactPdu, PenContact, PenContactDataFlags, PenContactFields,
    PenContactFlags, PenEventPdu, PenFlags, PenFrame, RdpInputProtocolVersion, RdpeiHandler, RdpeiServer,
    RdpeiServerFactory, ScReadyFeatures, TouchContact, TouchContactDataFlags, TouchContactFields, TouchContactFlags,
    TouchEventPdu, TouchFrame,
};
#[cfg(feature = "__test")]
pub use server::autodetect_response_from_sub_header;
#[cfg(all(feature = "__test", feature = "egfx"))]
pub use server::autodetect_sub_header;
#[cfg(feature = "__test")]
pub use server::pick_remotefx_codec;
pub use server::{
    AuthenticatedConnection, AutoReconnectCookieHandle, BoundConnection, ConnectionBinder, ConnectionHandler,
    ConnectionInfo, ConnectionPolicy, ConnectionSource, CredentialDecision, CredentialValidationError,
    CredentialValidator, Credentials, ErrorInfoDisconnectHandle, ExactMatchCredentialValidator, IncomingConnection,
    NextConnection, PostConnectionAction, RdpServer, RdpServerOptions, RdpServerSecurity, ServerEvent,
    ServerEventSender, ServerRedirectionHandle, SessionOutcome, StaticChannelFactory, TransportTls,
    pick_remotefx_entropy_coder,
};
pub use sound::{RdpsndServerHandler, RdpsndServerMessage, SoundServerFactory};
#[cfg(feature = "usb")]
pub use urbdrc::{
    CompletionFut, DeviceFactory, PendingHandle, PendingRequest, RdpUsbDeviceAnnounceInfo, UsbDeviceHandle,
    UsbRedirDevice, UsbRequestCompletion,
};
#[cfg(feature = "__bench")]
pub mod bench {
    pub mod encoder {
        pub mod rfx {
            pub use crate::encoder::rfx::bench::{rfx_enc, rfx_enc_tile};
        }

        pub use crate::encoder::{RemoteFxCodec, UpdateEncoder, UpdateEncoderCodecs};
    }
}

#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]
#![allow(clippy::arithmetic_side_effects)] // TODO: should we enable this lint back?

pub use {tokio, tokio_rustls};

mod macros;

pub mod autodetect;
mod builder;
mod capabilities;
mod clipboard;
mod display;
mod echo;
mod encoder;
#[cfg(feature = "egfx")]
mod gfx;
mod handler;
#[cfg(feature = "helper")]
mod helper;
mod server;
mod sound;

pub use clipboard::CliprdrServerFactory;
pub use display::{
    BitmapUpdate, ColorPointer, DesktopSize, DisplayUpdate, Framebuffer, PixelFormat, RGBAPointer, RdpServerDisplay,
    RdpServerDisplayUpdates,
};
pub use echo::{EchoDvcBridge, EchoRoundTripMeasurement, EchoServerHandle, EchoServerMessage};
#[cfg(feature = "egfx")]
pub use gfx::{EgfxServerMessage, GfxDvcBridge, GfxServerFactory, GfxServerHandle};
pub use handler::{KeyboardEvent, MouseEvent, RdpServerInputHandler};
#[cfg(feature = "helper")]
pub use helper::TlsIdentityCtx;
pub use server::{
    ConnectionHandler, CredentialDecision, CredentialValidationError, CredentialValidator, Credentials,
    ExactMatchCredentialValidator, PostConnectionAction, RdpServer, RdpServerOptions, RdpServerSecurity, ServerEvent,
    ServerEventSender, TransportTls,
};
pub use sound::{RdpsndServerHandler, RdpsndServerMessage, SoundServerFactory};

#[cfg(feature = "__bench")]
pub mod bench {
    pub mod encoder {
        pub mod rfx {
            pub use crate::encoder::rfx::bench::{rfx_enc, rfx_enc_tile};
        }

        pub use crate::encoder::{UpdateEncoder, UpdateEncoderCodecs};
    }
}

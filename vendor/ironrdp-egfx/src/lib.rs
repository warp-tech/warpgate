#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]

/// EGFX dynamic virtual channel name per MS-RDPEGFX
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

pub mod client;
pub mod decode;
pub mod pdu;
pub mod server;

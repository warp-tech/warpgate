#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]
#![allow(clippy::arithmetic_side_effects)] // FIXME: remove

pub mod clearcodec;
pub mod color_conversion;
pub mod diff;
pub mod dwt;
pub mod dwt_extrapolate;
pub mod image_processing;
pub mod pointer;
pub mod progressive;
pub mod quantization;
pub mod rdp6;
pub mod rectangle_processing;
pub mod rle;
pub mod rlgr;
pub mod srl;
pub mod subband_reconstruction;
pub mod zgfx;

mod utils;

/// # Panics
///
/// Panics if `input.len()` is not 4096 (64 * 46).
pub fn rfx_encode_component(
    input: &mut [i16],
    output: &mut [u8],
    quant: &ironrdp_pdu::codecs::rfx::Quant,
    mode: ironrdp_pdu::codecs::rfx::EntropyAlgorithm,
) -> Result<usize, rlgr::RlgrError> {
    assert_eq!(input.len(), 64 * 64);

    let mut temp = [0; 64 * 64]; // size = 8k, too big?

    dwt::encode(input, temp.as_mut_slice());
    quantization::encode(input, quant);
    subband_reconstruction::encode(&mut input[4032..]);
    rlgr::encode(mode, input, output)
}

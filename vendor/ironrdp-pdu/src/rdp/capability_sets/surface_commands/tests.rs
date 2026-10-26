use std::sync::LazyLock;

use ironrdp_core::{decode, encode_vec};

use super::*;

const SURFACE_COMMANDS_BUFFER: [u8; 8] = [
    0x52, 0x00, 0x00, 0x00, // flags
    0x00, 0x00, 0x00, 0x00, // reserved
];

static SURFACE_COMMANDS: LazyLock<SurfaceCommands> = LazyLock::new(|| SurfaceCommands {
    flags: CmdFlags::SET_SURFACE_BITS | CmdFlags::FRAME_MARKER | CmdFlags::STREAM_SURFACE_BITS,
});

#[test]
fn from_buffer_correctly_parses_surface_commands_capset() {
    assert_eq!(*SURFACE_COMMANDS, decode(SURFACE_COMMANDS_BUFFER.as_ref()).unwrap());
}

#[test]
fn to_buffer_correctly_serializes_surface_commands_capset() {
    let surf = SURFACE_COMMANDS.clone();

    let buffer = encode_vec(&surf).unwrap();

    assert_eq!(buffer, SURFACE_COMMANDS_BUFFER.as_ref());
}

#[test]
fn buffer_length_is_correct_for_surface_commands_capset() {
    assert_eq!(SURFACE_COMMANDS_BUFFER.len(), SURFACE_COMMANDS.size());
}

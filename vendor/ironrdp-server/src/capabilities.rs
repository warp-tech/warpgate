use ironrdp_pdu::rdp::capability_sets::{self, GeneralExtraFlags};

use crate::{DesktopSize, RdpServerOptions};

pub(crate) fn capabilities(opts: &RdpServerOptions, size: DesktopSize) -> Vec<capability_sets::CapabilitySet> {
    vec![
        capability_sets::CapabilitySet::General(general_capabilities()),
        capability_sets::CapabilitySet::Bitmap(bitmap_capabilities(&size)),
        capability_sets::CapabilitySet::Order(order_capabilities()),
        capability_sets::CapabilitySet::SurfaceCommands(surface_capabilities()),
        capability_sets::CapabilitySet::Pointer(pointer_capabilities()),
        capability_sets::CapabilitySet::Input(input_capabilities()),
        capability_sets::CapabilitySet::VirtualChannel(virtual_channel_capabilities()),
        capability_sets::CapabilitySet::MultiFragmentUpdate(multifragment_update(opts)),
        capability_sets::CapabilitySet::BitmapCodecs(opts.codecs.clone()),
    ]
}

fn general_capabilities() -> capability_sets::General {
    capability_sets::General {
        extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED,
        // Advertise that the server handles `SuppressOutput` and
        // `RefreshRectangle` (per MS-RDPBCGR 2.2.7.1.1) — spec-compliant
        // clients only send these PDUs when the server says it supports
        // them. mstsc sends them regardless, but FreeRDP and others
        // follow the spec; without both flags, those clients never
        // benefit from the minimize→refocus backlog fix.
        refresh_rect_support: true,
        suppress_output_support: true,
        ..Default::default()
    }
}

fn bitmap_capabilities(size: &DesktopSize) -> capability_sets::Bitmap {
    capability_sets::Bitmap {
        pref_bits_per_pix: 32,
        desktop_width: size.width,
        desktop_height: size.height,
        // This makes freerdp keep the flag up and handle desktop resize/deactivation-reactivation.
        // Likely okay to advertize if the server doesn't resize anyway.
        desktop_resize_flag: true,
        drawing_flags: capability_sets::BitmapDrawingFlags::empty(),
    }
}

fn order_capabilities() -> capability_sets::Order {
    capability_sets::Order::new(
        capability_sets::OrderFlags::empty(),
        capability_sets::OrderSupportExFlags::empty(),
        2048,
        224,
    )
}

fn surface_capabilities() -> capability_sets::SurfaceCommands {
    capability_sets::SurfaceCommands {
        flags: capability_sets::CmdFlags::all(),
    }
}

fn pointer_capabilities() -> capability_sets::Pointer {
    capability_sets::Pointer {
        color_pointer_cache_size: 2048,
        pointer_cache_size: 2048,
    }
}

fn input_capabilities() -> capability_sets::Input {
    capability_sets::Input {
        input_flags: capability_sets::InputFlags::SCANCODES
            | capability_sets::InputFlags::MOUSE_RELATIVE
            | capability_sets::InputFlags::MOUSEX
            | capability_sets::InputFlags::FASTPATH_INPUT
            | capability_sets::InputFlags::UNICODE
            | capability_sets::InputFlags::FASTPATH_INPUT_2,
        keyboard_layout: 0,
        keyboard_type: None,
        keyboard_subtype: 0,
        keyboard_function_key: 128,
        keyboard_ime_filename: "".into(),
    }
}

fn virtual_channel_capabilities() -> capability_sets::VirtualChannel {
    capability_sets::VirtualChannel {
        flags: capability_sets::VirtualChannelFlags::NO_COMPRESSION,
        chunk_size: None,
    }
}

fn multifragment_update(opts: &RdpServerOptions) -> capability_sets::MultifragmentUpdate {
    capability_sets::MultifragmentUpdate {
        max_request_size: opts.max_request_size,
    }
}

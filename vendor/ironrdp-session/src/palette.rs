use tracing::{debug, warn};

/// 8bpp color palette (256 RGB entries).
///
/// Initialized with the default Windows system palette (VGA colors)
/// per MS-RDPBCGR 2.2.9.1.1.3.1.1. Updated by TS_UPDATE_PALETTE_DATA
/// fast-path updates during the session.
#[derive(Debug, Clone)]
pub(crate) struct Palette {
    colors: [[u8; 3]; 256],
}

impl Palette {
    /// Create a palette initialized with the 20 static colors from the
    /// Windows default system palette. Indices 0-9 and 246-255 are the
    /// reserved static colors; the middle 236 entries (10-245) are black.
    ///
    /// Reference: <https://learn.microsoft.com/en-us/windows/win32/gdi/default-palette>
    pub(crate) fn system_default() -> Self {
        let mut colors = [[0u8; 3]; 256];
        // Lower 10 static colors (indices 0-9)
        colors[0] = [0, 0, 0]; // Black
        colors[1] = [128, 0, 0]; // Dark Red
        colors[2] = [0, 128, 0]; // Dark Green
        colors[3] = [128, 128, 0]; // Dark Yellow
        colors[4] = [0, 0, 128]; // Dark Blue
        colors[5] = [128, 0, 128]; // Dark Magenta
        colors[6] = [0, 128, 128]; // Dark Cyan
        colors[7] = [192, 192, 192]; // Light Gray
        colors[8] = [192, 220, 192]; // Money Green
        colors[9] = [166, 202, 240]; // Sky Blue
        // Upper 10 static colors (indices 246-255)
        colors[246] = [255, 251, 240]; // Cream
        colors[247] = [160, 160, 164]; // Medium Gray
        colors[248] = [128, 128, 128]; // Dark Gray
        colors[249] = [255, 0, 0]; // Red
        colors[250] = [0, 255, 0]; // Green
        colors[251] = [255, 255, 0]; // Yellow
        colors[252] = [0, 0, 255]; // Blue
        colors[253] = [255, 0, 255]; // Magenta
        colors[254] = [0, 255, 255]; // Cyan
        colors[255] = [255, 255, 255]; // White
        Self { colors }
    }

    /// Parse TS_UPDATE_PALETTE_DATA and update palette entries.
    /// Wire format: pad(2) + numberColors(u32) + N x TS_COLOR_QUAD [B, G, R, pad].
    pub(crate) fn process_update(&mut self, data: &[u8]) {
        if data.len() < 6 {
            warn!("Palette update too short: {} bytes", data.len());
            return;
        }

        let raw_count = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        // Palette can have at most 256 entries; clamp before any arithmetic
        // to prevent overflow on untrusted input
        let clamped = raw_count.min(256);
        let number_colors = usize::try_from(clamped).unwrap_or(256);
        let entry_data = &data[6..];

        let Some(required_len) = number_colors.checked_mul(4) else {
            warn!("Palette entry count overflow");
            return;
        };

        if entry_data.len() < required_len {
            warn!(
                "Palette data truncated: expected {} bytes for {} colors, got {}",
                required_len,
                number_colors,
                entry_data.len()
            );
            return;
        }

        for i in 0..number_colors {
            let offset = i * 4;
            // TS_COLOR_QUAD: Blue, Green, Red, Pad
            self.colors[i] = [entry_data[offset + 2], entry_data[offset + 1], entry_data[offset]];
        }

        debug!("Updated palette with {} colors", number_colors);
    }

    /// Borrow the underlying color table for bitmap application.
    pub(crate) fn colors(&self) -> &[[u8; 3]; 256] {
        &self.colors
    }
}

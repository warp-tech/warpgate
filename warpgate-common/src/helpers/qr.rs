use qrcode::QrCode;
use qrcode::types::{Color, QrError};

const ANSI_RESET: &str = "\x1b[0m";
// White background (47), Black foreground (30)
const ANSI_BG_WHITE_FG_BLACK: &str = "\x1b[47;30m";
// Black background (40), White foreground (37)
const ANSI_BG_BLACK_FG_WHITE: &str = "\x1b[40;37m";

/// The standard QR quiet zone thickness in modules (ISO/IEC 18004 recommends 4).
const QUIET_ZONE_MODULES: usize = 4;

#[derive(Copy, Clone, PartialEq, Eq)]
enum AnsiStyle {
    None,
    BgWhiteFgBlack,
    BgBlackFgWhite,
}

/// Renders a scannable QR code formatted for terminal display.
///
/// Uses ANSI background/foreground color escapes and the Unicode lower half-block (`▄`)
/// to render two vertical modules per character cell without horizontal lines or font-metric gaps.
/// Explicit colors ensure true black-on-white polarity regardless of whether the user has a dark,
/// light, or custom terminal theme.
pub fn render_qr_code_terminal(data: &str) -> Result<String, QrError> {
    let code = QrCode::new(data.as_bytes())?;
    let base_width = code.width();
    let colors = code.to_colors();

    let quiet = QUIET_ZONE_MODULES;
    let total_width = base_width + quiet * 2;

    let get_color = |x: usize, y: usize| -> Color {
        if x < quiet || x >= quiet + base_width || y < quiet || y >= quiet + base_width {
            Color::Light
        } else {
            let orig_x = x - quiet;
            let orig_y = y - quiet;
            colors
                .get(orig_y * base_width + orig_x)
                .copied()
                .unwrap_or(Color::Light)
        }
    };

    let mut out = String::new();
    let mut y = 0;
    while y < total_width {
        let has_next_row = y + 1 < total_width;
        let mut current_style = AnsiStyle::None;

        for x in 0..total_width {
            let top = get_color(x, y);
            let bottom = if has_next_row {
                get_color(x, y + 1)
            } else {
                Color::Light
            };

            let (needed_style, ch) = match (top, bottom) {
                // Top Black, Bottom Black: Black background, space
                (Color::Dark, Color::Dark) => (AnsiStyle::BgBlackFgWhite, ' '),
                // Top Black, Bottom White: Black background, White foreground with lower block ▄
                (Color::Dark, Color::Light) => (AnsiStyle::BgBlackFgWhite, '▄'),
                // Top White, Bottom Black: White background, Black foreground with lower block ▄
                (Color::Light, Color::Dark) => (AnsiStyle::BgWhiteFgBlack, '▄'),
                // Top White, Bottom White: White background, space
                (Color::Light, Color::Light) => (AnsiStyle::BgWhiteFgBlack, ' '),
            };

            if current_style != needed_style {
                match needed_style {
                    AnsiStyle::BgWhiteFgBlack => out.push_str(ANSI_BG_WHITE_FG_BLACK),
                    AnsiStyle::BgBlackFgWhite => out.push_str(ANSI_BG_BLACK_FG_WHITE),
                    AnsiStyle::None => out.push_str(ANSI_RESET),
                }
                current_style = needed_style;
            }
            out.push(ch);
        }

        if current_style != AnsiStyle::None {
            out.push_str(ANSI_RESET);
        }
        out.push('\n');
        y += 2;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_qr_code_terminal_valid_url() -> Result<(), QrError> {
        let url = "https://warpgate.example.com/@warpgate#/login/test-session-id";
        let qr = render_qr_code_terminal(url)?;
        assert!(!qr.is_empty());
        assert!(qr.contains('\n'));
        assert!(qr.contains(ANSI_RESET));
        assert!(qr.contains(ANSI_BG_WHITE_FG_BLACK));
        assert!(qr.contains(ANSI_BG_BLACK_FG_WHITE));
        Ok(())
    }

    #[test]
    fn test_render_qr_code_terminal_empty_string() -> Result<(), QrError> {
        let qr = render_qr_code_terminal("")?;
        assert!(!qr.is_empty());
        Ok(())
    }
}

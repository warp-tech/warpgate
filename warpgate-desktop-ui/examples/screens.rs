use std::convert::Infallible;
use std::error::Error;

use minifb::{Key, KeyRepeat, Window, WindowOptions};
use warpgate_desktop_ui::{
    AuthPrompt, SCREEN_H, SCREEN_W, render_authentication, render_connecting,
};

fn screen(n: u8, tick: u64) -> Result<Vec<u8>, Infallible> {
    match n {
        2 => render_authentication(
            tick,
            &AuthPrompt::WebApproval {
                url: Some("https://warpgate.acme.inc/test".into()),
                security_key: "1234".into(),
            },
        ),
        3 => render_authentication(tick, &AuthPrompt::Otp { entered: "".into() }),
        4 => render_authentication(
            tick,
            &AuthPrompt::Otp {
                entered: "042".into(),
            },
        ),
        5 => render_authentication(
            tick,
            &AuthPrompt::WebApproval {
                url: None,
                security_key: "1234".into(),
            },
        ),
        _ => render_connecting(tick),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let (w, h) = (usize::from(SCREEN_W), usize::from(SCREEN_H));
    let mut window = Window::new(
        "Warpgate hold screen — keys 1-5 switch, Esc quits",
        w,
        h,
        WindowOptions::default(),
    )?;
    window.set_target_fps(30);

    let switch_keys = [
        (Key::Key1, 1u8),
        (Key::Key2, 2),
        (Key::Key3, 3),
        (Key::Key4, 4),
        (Key::Key5, 5),
    ];

    let mut current = 1u8;
    let mut tick = 0u64;
    let mut buffer = vec![0u32; w * h];

    while window.is_open() && !window.is_key_down(Key::Escape) {
        for (key, n) in switch_keys {
            if window.is_key_pressed(key, KeyRepeat::No) {
                current = n;
            }
        }

        let rgb = screen(current, tick)?;

        // Pack RGB888 into the 0x00RRGGBB words minifb expects.
        for (px, out) in rgb.chunks_exact(3).zip(buffer.iter_mut()) {
            if let [r, g, b] = *px {
                *out = (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b);
            }
        }

        window.update_with_buffer(&buffer, w, h)?;
        tick += 1;
    }

    Ok(())
}

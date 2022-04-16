use ansi_term::Color::{Black, White};
use ansi_term::Style;
use anyhow::Result;
use data_encoding::BASE64;
use qrcode::{Color, QrCode};
use tracing::*;
use warpgate_common::helpers::otp::{generate_key, generate_setup_url};

pub(crate) async fn command() -> Result<()> {
    let key = generate_key();
    let url = generate_setup_url(&key, "test");

    let code = QrCode::new(url.expose_secret().as_bytes())?;
    let width = code.width();
    let pixels = code.into_colors();

    for _ in 0..width + 4 {
        print!("{}", Style::new().on(White).paint(" "));
    }
    println!();

    for hy in 0..(pixels.len() + width - 1) / width / 2 + 1 {
        print!("{}", Style::new().on(White).paint("  "));
        for x in 0..width {
            let top = pixels
                .get(hy * 2 * width + x)
                .map(|x| *x == Color::Dark)
                .unwrap_or(false);
            let bottom = pixels
                .get((hy * 2 + 1) * width + x)
                .map(|x| *x == Color::Dark)
                .unwrap_or(false);

            print!(
                "{}",
                match (top, bottom) {
                    (true, true) => Style::new().fg(Black).paint("█"),
                    (true, false) => Style::new().fg(Black).on(White).paint("▀"),
                    (false, true) => Style::new().fg(Black).on(White).paint("▄"),
                    (false, false) => Style::new().on(White).paint(" "),
                }
            );
        }
        println!("{}", Style::new().on(White).paint("  "));
    }

    println!();
    info!("Setup URL: {}", url.expose_secret());
    info!("Config file snippet:");
    println!();
    println!("  - type: otp");
    println!("    key: {}", BASE64.encode(key.expose_secret()));
    Ok(())
}

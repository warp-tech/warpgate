//! Warpgate's standalone RDP helper — a single binary with two subcommands:
//!
//! * `connect` — the target-facing RDP **client** (drives IronRDP toward a target).
//! * `serve`   — the viewer-facing RDP **server** (terminates the RDP protocol for a
//!   native viewer like mstsc / FreeRDP).
//!
//! Both speak line-delimited JSON over stdio to Warpgate. The helper lives **outside**
//! the Warpgate cargo workspace: IronRDP's CredSSP stack (`picky`/`sspi`) pins RustCrypto
//! pre-release crates that conflict with `russh`'s pins in a shared lockfile, so it has
//! its own lockfile — the same isolation approach Apache Guacamole uses with `guacd`.

mod client;
mod server;

fn main() {
    let command = std::env::args().nth(1).unwrap_or_default();
    match command.as_str() {
        // The client uses blocking IronRDP; run it directly on the main thread.
        "connect" => client::entry(),
        // The server uses async IronRDP; give it a Tokio runtime.
        "serve" => match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime.block_on(server::entry()),
            Err(error) => {
                eprintln!("warpgate-rdp-helper: failed to start Tokio runtime: {error}");
                std::process::exit(1);
            }
        },
        other => {
            eprintln!("usage: warpgate-rdp-helper <connect|serve> (got {other:?})");
            std::process::exit(2);
        }
    }
}

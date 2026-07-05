# Vendored `vnc-rs` — Warpgate fork

This is a vendored copy of [`vnc-rs`](https://github.com/HsuJv/vnc-rs) **0.5.3**
(`package = "vnc-rs"`, crate name `vnc`), dual-licensed MIT OR Apache-2.0. The source is
byte-for-byte upstream 0.5.3 except for the changes listed below. Each change is also
marked inline with a `Warpgate fork` comment.

## Why we vendor

Warpgate proxies native VNC connections and records the session. Upstream `vnc-rs` is a
full client: it *owns* the socket, performs the RFB handshake, and only exposes the
decoded `VncEvent` stream through `VncClient::poll_event`. To record a *proxied*
connection at full fidelity (Tight/JPEG/Zrle/CopyRect/cursor) without a second backend
connection or re-encoding to Raw, Warpgate needs to run the RFB **decode loop** over a
*tee* of the bytes flowing between the real viewer and the target — driving the decoder
itself, with a handshake and socket it already owns.

Upstream's decode loop is a private free function, and its server-message parser panics on
colour-map servers. Both are trivial to fix but need a fork; we vendor rather than depend
on a personal Git fork so the build is hermetic and reviewable.

## Changes vs upstream 0.5.3

1. **Expose the RFB decode loop** — `src/client/connection.rs`
   - Renamed the private `asycn_vnc_read_loop` (sic) to `decode_loop` and made it `pub`.
   - Re-exported it: `client::decode_loop` (`src/client/mod.rs`) and crate root
     `vnc::decode_loop` (`src/lib.rs`).
   - Signature unchanged:
     `pub async fn decode_loop<S: AsyncRead + Unpin, F: Fn(VncEvent) -> Fut, Fut>(stream, pf, output_func, stop_ch)`.
   - Lets a caller drive framebuffer decoding over any byte stream positioned at a server
     message boundary, using a caller-supplied `PixelFormat` and output closure. The
     internal encoding decoders (`codec::*`) remain `pub(crate)` — only the loop is public.

2. **Don't panic on `SetColorMapEntries`** — `src/client/messages.rs`, `src/client/connection.rs`
   - Upstream `ServerMsg::read` hits `unimplemented!()` for server message type 1
     (colour-map / non-truecolor servers), which would panic (and abort) the decode task.
   - Now it drains the palette body (padding + first-colour + count + `count*6` bytes) and
     returns a new `ServerMsg::SetColorMapEntries` variant, which the decode loop ignores.
   - Warpgate records a decoded *truecolor* framebuffer, so the palette itself is not
     applied — a legacy 8bpp palette server would record with wrong colours, but it will no
     longer crash. Modern servers negotiate truecolor and are unaffected.

## Nothing else changed

`PixelFormat` (incl. `TryFrom<[u8;16]>`), `VncEvent`, `VncEncoding`, `VncError`, `Rect` are
already public upstream and are what Warpgate needs to build the pixel format from the
wire and consume decoded events — no additional exposure required.

## Updating

To re-sync with a newer upstream, re-apply the two changes above (grep the tree for
`Warpgate fork`). The `Cargo.toml` here is a hand-written minimal manifest equivalent to
upstream's `Cargo.toml.orig` (same dependencies), with `publish = false`.

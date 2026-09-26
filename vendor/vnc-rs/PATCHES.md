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

3. **Memory-safety hardening against untrusted targets** — `src/client/auth.rs`,
   `src/client/connector.rs`, `src/client/connection.rs`, `src/client/messages.rs`,
   `src/codec/mod.rs`, `src/codec/zrle.rs`, `src/codec/trle.rs`
   - **Removed an unsound `transmute`.** Upstream `impl From<u32> for AuthResult`
     (`auth.rs`) did `unsafe { std::mem::transmute(num) }` into a 2-variant `#[repr(u32)]`
     enum — any SecurityResult word other than 0/1 read off the target socket was instant
     UB. Replaced with `impl TryFrom<u32> for AuthResult` (a plain validating `match`, no
     `unsafe`); `AuthHelper::finish` now `try_into()`s and the unknown-value error
     propagates as a protocol error instead of transmuting garbage.
   - **Bounded all target-driven allocations/reads** — each rejects with a `VncError`
     when the wire length exceeds a fixed cap (a legitimate target never does):
     - Failure-reason strings: upstream read them with `read_to_string` (to EOF), so a
       hostile target could stream forever. New `read_reason_string` helper (`auth.rs`)
       honors the U32 length prefix with a `MAX_REASON_LEN` (4 KiB) cap; used by the three
       call sites in `auth.rs` and `connector.rs`.
     - ServerInit desktop-name length (`connection.rs`): capped at `MAX_NAME_LEN` (4 KiB).
     - `ServerCutText` length (`messages.rs`): capped at `MAX_CUT_TEXT_LEN` (1 MiB).
     - ZRLE/TRLE per-rectangle zlib blob length (`zrle.rs`, `trle.rs`): new
       `uninit_vec_capped` helper (`codec/mod.rs`) rejects lengths above
       `MAX_RECT_DATA_LEN` (64 MiB) before allocating. `uninit_vec` itself is left as-is —
       the buffer it returns is only ever filled by an immediately following `read_exact`
       of the same length, so once the length is capped the uninitialised bytes are never
       observed.
   - Unit tests added in `auth.rs` (`#[cfg(test)]`) cover the `AuthResult` conversion
     (0/1 map correctly, 2 and `u32::MAX` reject) and the reason-string length cap
     (rejects over-limit, reads in-limit).

## Nothing else changed

`PixelFormat` (incl. `TryFrom<[u8;16]>`), `VncEvent`, `VncEncoding`, `VncError`, `Rect` are
already public upstream and are what Warpgate needs to build the pixel format from the
wire and consume decoded events — no additional exposure required.

## Updating

To re-sync with a newer upstream, re-apply the changes above (grep the tree for
`Warpgate fork`). The `Cargo.toml` here is a hand-written minimal manifest equivalent to
upstream's `Cargo.toml.orig` (same dependencies), with `publish = false` and a
`[lints.rust] warnings = "allow"` so this vendored path dependency's warnings don't surface
in Warpgate's builds.

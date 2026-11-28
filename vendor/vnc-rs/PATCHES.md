Fork of `vnc-rs` 0.6.1.

## End-of-update event

The decoder emits `VncEvent::FramebufferUpdateEnd` after the last rectangle of each
`FramebufferUpdate` message (`src/client/connection.rs`, `src/event.rs`). Upstream reports
rectangles only, so a client cannot tell where an update ends and has no correct place to
send the next `FramebufferUpdateRequest`: requesting per rectangle leaves several requests
outstanding, which defeats the protocol's client-driven flow control
(warp-tech/warpgate#2945). No other change. Drop the fork once upstream exposes an
equivalent event.

`tests/` is not vendored, so the `[[test]]` target is removed from the published
`Cargo.toml`, which also gains `warnings = { level = "allow", priority = 1 }` under
`[lints.rust]` so this vendored path dependency's warnings don't surface in Warpgate's
builds. Neither is in `warpgate.patch` (which is source-only); re-apply them by hand on
re-vendor.

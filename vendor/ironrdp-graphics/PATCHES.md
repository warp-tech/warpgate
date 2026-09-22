Fork of `ironrdp-graphics` 0.9.0, with `src/` taken from IronRDP master at
`9b151c4c2e47c6014e1e8e55909d4180aa8bdb99`.

## RemoteFX Progressive and ClearCodec decode for EGFX

The client-side Graphics Pipeline in `vendor/ironrdp-egfx` drives master's reworked
progressive decoder (`ProgressiveDecoder::begin_frame` / `end_frame` / `delete_surface`,
per-tile update rectangles, `TILE_DIM`) and ClearCodec, none of which 0.9.0 has.
Without an H.264 decoder, GNOME Remote Desktop encodes the Graphics Pipeline with
RemoteFX Progressive, so this is the codec path GNOME sessions actually take.

## Building against ironrdp-core 0.2.1 / ironrdp-pdu 0.9.0

- The stream-position arguments master's error constructors take are removed (5 call
  sites in `src/clearcodec/mod.rs` and `src/rdp6/bitmap_stream/encoder.rs`; see
  `vendor/ironrdp-egfx/PATCHES.md`).
- `TILE_FLAG_DIFFERENCE` (RFX_TILE_DIFFERENCE, `0x01`) is defined in `progressive.rs`
  instead of imported: master moved it into `ironrdp_pdu::codecs::rfx::progressive`,
  which 0.9.0 predates. Restore the import on re-vendor.

`Cargo.toml` is the published one, plus master's `wide` dependency (portable SIMD for
the inverse DWT) and the vendored-code lint override. `warpgate.patch` is the full
source difference from 0.9.0.

Drop this fork together with `vendor/ironrdp-egfx` once releases carry this code.

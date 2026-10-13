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
- The ClearCodec wire format lives in `src/clearcodec/pdu/`, copied from master's
  `ironrdp-pdu/src/codecs/clearcodec` at the same commit with the stream-position
  arguments removed. 0.9.0's `ironrdp_pdu::codecs::clearcodec` reads the
  SHORT_VBAR_CACHE_MISS header with `shortVBarYOn` and `shortVBarYOff` swapped (fixed by
  upstream #1694), so real Windows ClearCodec updates fail with "shortVBarYOff <
  shortVBarYOn" and the text and UI tiles they carry are never painted. On re-vendor
  against an `ironrdp-pdu` that has #1694, delete `src/clearcodec/pdu/` and import
  `ironrdp_pdu::codecs::clearcodec` again. `warpgate.patch` lists the directory by name
  only.

`Cargo.toml` is the published one, plus master's `wide` dependency (portable SIMD for
the inverse DWT) and the vendored-code lint override. `warpgate.patch` is the full
source difference from 0.9.0.

## RemoteFX Progressive SRL streams from Windows

Backport of upstream [PR #2010][1] (unmerged, head `f47878a`), applied verbatim. Windows
omits the trailing zero byte and trailing zero entries of an SRL stream, and can encode a
zero run longer than the coefficients left. Master's decoder rejects those with
`SrlError::MissingTerminator` / `SrlError::Truncated`, so Windows sessions failed on
their first TILE_UPGRADE pass. The decoder now reads them as FreeRDP does, and both error
variants are gone.

Drop this fork together with `vendor/ironrdp-egfx` once releases carry this code,
including #2010.

[1]: https://github.com/Devolutions/IronRDP/pull/2010

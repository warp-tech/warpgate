# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.9.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.8.1...ironrdp-graphics-v0.9.0)] - 2026-07-10

### <!-- 4 -->Bug Fixes

- Don't require CONTEXT block on every progressive frame ([#1395](https://github.com/Devolutions/IronRDP/issues/1395)) ([368fe8e68b](https://github.com/Devolutions/IronRDP/commit/368fe8e68b2d5d72da2e15dcf99469b98e965a2b)) 

  Fixes progressive RemoteFX (MS-RDPEGFX) decoding by no longer requiring a CONTEXT block on every WireToSurface2 progressive frame once a codec context has already been established (keyed by codec_context_id). This aligns the decoder with real-world server behavior and the spec’s “establish once, then reference” model for progressive contexts.

### <!-- 7 -->Build

- [**breaking**] Update `ironrdp-pdu` public dependency to 0.9



## [[0.8.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.8.0...ironrdp-graphics-v0.8.1)] - 2026-06-05

### <!-- 4 -->Bug Fixes

- Bound ZGFX compressor hash table size ([#1344](https://github.com/Devolutions/IronRDP/issues/1344)) ([4e11a17617](https://github.com/Devolutions/IronRDP/commit/4e11a1761750bb706f5c3cef370589d0eb63fc45)) 

  Bounds the ZGFX compressor's hash table to prevent O(n·table_size) per-frame compaction on incompressible payloads (e.g., already-encoded H.264). Previously, `compact_hash_table` only halved per-prefix position lists without reducing prefix count, so high-entropy input kept the table above the cap and triggered compaction on every literal byte. The fix evicts whole least-recently-seen prefixes down to a low watermark (half the cap), amortizing compaction to O(1) per byte while preserving reachable matches (distance is already capped at `MAX_MATCH_DISTANCE`).



## [[0.8.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.7.0...ironrdp-graphics-v0.8.0)] - 2026-05-27

### <!-- 1 -->Features

- Add segment wrapping utilities ([#1076](https://github.com/Devolutions/IronRDP/issues/1076)) ([5fa4964807](https://github.com/Devolutions/IronRDP/commit/5fa4964807fa15bbf1a5e3c23b365344758961aa)) 

  Adds ZGFX segment wrapping utilities for encoding data in RDP8 format.

- Add LZ77 compression support ([#1097](https://github.com/Devolutions/IronRDP/issues/1097)) ([48715483a3](https://github.com/Devolutions/IronRDP/commit/48715483a36c824af034a51f4db0580c34825d63)) 

  Adds ZGFX (RDP8) LZ77 compression to complement the existing
  decompressor, plus a high-level API for EGFX PDU preparation with
  auto/always/never mode selection.
  
  The compressor uses a hash table mapping 3-byte prefixes to history
  positions for O(1) match candidate lookup against the 2.5 MB sliding
  window.

- Complete pixel format support for bitmap updates ([#1134](https://github.com/Devolutions/IronRDP/issues/1134)) ([a6b41093ce](https://github.com/Devolutions/IronRDP/commit/a6b41093ce4ece081d2538c157f6bc547c3b2607)) 

  Wires missing bitmap pixel formats (8/15/24bpp) into the session rendering
  pipeline so bitmap updates at those depths are rendered instead of being
  dropped, and adds fast-path palette update parsing to support 8bpp indexed
  color sessions.

- Add RemoteFX Progressive codec primitives ([#1196](https://github.com/Devolutions/IronRDP/issues/1196)) ([49099f0c31](https://github.com/Devolutions/IronRDP/commit/49099f0c3136c25b67801fb1b07f78542dc796de)) 

  Add wire-format types for RemoteFX Progressive Codec (MS-RDPRFX
  Progressive Extension) and the computational primitives required for progressive refinement.

- Add progressive RFX decode and EGFX integration ([#1197](https://github.com/Devolutions/IronRDP/issues/1197)) ([a142799d1d](https://github.com/Devolutions/IronRDP/commit/a142799d1dcbdcd6546ec6e75173fbfe66f0ea67)) 

- Add progressive RFX server encode and mixed-codec frames ([#1198](https://github.com/Devolutions/IronRDP/issues/1198)) ([6d43d2692d](https://github.com/Devolutions/IronRDP/commit/6d43d2692d206b7557f722f294d3e51d7eac8ab1)) 

- Add ClearCodec bitmap compression codec ([#1174](https://github.com/Devolutions/IronRDP/issues/1174)) ([059ca902a5](https://github.com/Devolutions/IronRDP/commit/059ca902a5518113163042225bc5d2088869933a)) 

### <!-- 4 -->Bug Fixes

- Fix pixel format handling in bitmap decoders ([#1101](https://github.com/Devolutions/IronRDP/issues/1101)) ([75863245ab](https://github.com/Devolutions/IronRDP/commit/75863245ab376f15e35c00df434860c93b123633)) 

- Replace all from_bits_truncate with from_bits_retain ([#1144](https://github.com/Devolutions/IronRDP/issues/1144)) ([353e30ddfd](https://github.com/Devolutions/IronRDP/commit/353e30ddfdaafc897db10b8663e364ef7775a7fd)) 

  from_bits_truncate silently discards unknown bits, which breaks the
  encode/decode round-trip property. This matters for fuzzing because a
  PDU that decodes and re-encodes should produce identical bytes.
  from_bits_retain preserves all bits, including those not yet defined in
  our bitflags types, so the round-trip property holds.

### <!-- 7 -->Build

- Bump the patch group across 1 directory with 2 updates ([#1222](https://github.com/Devolutions/IronRDP/issues/1222)) ([3fe6d157e0](https://github.com/Devolutions/IronRDP/commit/3fe6d157e0b55bddfdac20af290a6cfa6e550576)) 


## [[0.7.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.6.0...ironrdp-graphics-v0.7.0)] - 2025-12-18

### Added

- [**breaking**] `InvalidIntegralConversion` variant in `RlgrError` and `ZgfxError`

### <!-- 7 -->Build

- Bump bytemuck from 1.23.2 to 1.24.0 ([#1008](https://github.com/Devolutions/IronRDP/issues/1008)) ([a24a1fa9e8](https://github.com/Devolutions/IronRDP/commit/a24a1fa9e8f1898b2fcdd41d87660ab9e38f89ed)) 

## [[0.6.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.5.0...ironrdp-graphics-v0.6.0)] - 2025-06-27

### <!-- 4 -->Bug Fixes

- `to_64x64_ycbcr_tile` now returns a `Result`

## [[0.4.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.4.0...ironrdp-graphics-v0.4.1)] - 2025-06-27

### <!-- 7 -->Build

- Bump the patch group across 1 directory with 3 updates (#816) ([5c5f441bdd](https://github.com/Devolutions/IronRDP/commit/5c5f441bdd514d3fe6a29b4df872709167a9916d)) 

## [[0.4.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.3.0...ironrdp-graphics-v0.4.0)] - 2025-05-27

### <!-- 1 -->Features

- Add helper to find diff between images ([20581bb6f1](https://github.com/Devolutions/IronRDP/commit/20581bb6f12561e22031ce0e233daeada836ea67)) 

  Add some helper to find "damaged" regions, as 64x64 tiles.

## [[0.3.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.2.0...ironrdp-graphics-v0.3.0)] - 2025-03-12

### <!-- 7 -->Build

- Bump ironrdp-pdu

## [[0.2.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.1.2...ironrdp-graphics-v0.2.0)] - 2025-03-07

### Performance

- Replace hand-coded yuv/rgb with yuvutils ([5f1c44027a](https://github.com/Devolutions/IronRDP/commit/5f1c44027a7f6da5271565461764dd3f61729ee4)) 

  cargo bench:
  to_ycbcr                time:   [2.2988 µs 2.3251 µs 2.3517 µs]
                          change: [-83.643% -83.534% -83.421%] (p = 0.00 < 0.05)
                          Performance has improved.

## [[0.1.2](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.1.1...ironrdp-graphics-v0.1.2)] - 2025-01-28

### <!-- 6 -->Documentation

- Use CDN URLs instead of the blob storage URLs for Devolutions logo (#631) ([dd249909a8](https://github.com/Devolutions/IronRDP/commit/dd249909a894004d4f728d30b3a4aa77a0f8193b)) 

## [[0.1.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-graphics-v0.1.0...ironrdp-graphics-v0.1.1)] - 2024-12-14

### Other

- Symlinks to license files in packages ([#604](https://github.com/Devolutions/IronRDP/pull/604)) ([6c2de344c2](https://github.com/Devolutions/IronRDP/commit/6c2de344c2dd93ce9621834e0497ed7c3bfaf91a)) 

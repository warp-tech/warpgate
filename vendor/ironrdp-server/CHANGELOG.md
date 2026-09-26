# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.13.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.12.0...ironrdp-server-v0.13.0)] - 2026-07-10

### <!-- 0 -->Security

- [**breaking**] Send NetworkAutoDetect over the MCS message channel ([#1348](https://github.com/Devolutions/IronRDP/issues/1348)) ([8a1fd0118e](https://github.com/Devolutions/IronRDP/commit/8a1fd0118e0bac214c9050b6ca6b36a040046dd3)) 

  Corrects Network Auto-Detect framing and routing to match MS-RDPBCGR by
  moving it off the I/O channel slow-path Share Data PDUs and onto the MCS
  message channel with the required Basic Security Header
  (SEC_AUTODETECT_REQ / SEC_AUTODETECT_RSP). This aligns IronRDP with
  mstsc/xfreerdp behavior and enables both connect-time and continuous
  auto-detection to actually function.

### <!-- 1 -->Features

- Expose NetworkAutoDetect RTT via a shared handle ([#1346](https://github.com/Devolutions/IronRDP/issues/1346)) ([481ea5d161](https://github.com/Devolutions/IronRDP/commit/481ea5d161964b06a08f0b1ace0a1efd11773b4a)) 

  Exposes the server’s NetworkAutoDetect RTT measurement via a shared Arc<AtomicU32> handle so display backends can read a fresh RTT value even after run() takes ownership of the server.

- Dispatch initiate_file_copy via ClipboardMessage ([#1388](https://github.com/Devolutions/IronRDP/issues/1388)) ([b6325f9ea6](https://github.com/Devolutions/IronRDP/commit/b6325f9ea6900a84643b4415f9ebc7b1010cf3cd)) 

  Extends the CLIPRDR backend-facing API to properly support offering clipboard file lists (so later FileContentsRequests can be serviced) by introducing ClipboardMessage::SendInitiateFileCopy(Vec<FileDescriptor>) and wiring it through the in-tree ClipboardMessage dispatchers.

- Honor the client-requested desktop size ([#1373](https://github.com/Devolutions/IronRDP/issues/1373)) ([d471bd066f](https://github.com/Devolutions/IronRDP/commit/d471bd066f303df22f4767801fd97ecdbf527869)) 

  Adds an opt-in server/acceptor knob to negotiate the RDP session desktop size using the client’s originally requested resolution (from GCC Client Core Data) so the server can start at the client’s native size without a Deactivation–Reactivation resize round trip.

- Accept connections with TLS terminated at a lower layer ([#1281](https://github.com/Devolutions/IronRDP/issues/1281)) ([18bf75c7b3](https://github.com/Devolutions/IronRDP/commit/18bf75c7b3442881b42ee79b5f530ca97ab391ed)) 

  Adds a way to run a single RDP connection over a byte stream whose
  confidentiality is already provided by the embedder's transport, rather
  than having ironrdp-server perform the inner TLS handshake itself when
  X.224 selects PROTOCOL_SSL.



## [[0.12.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.11.0...ironrdp-server-v0.12.0)] - 2026-06-05

### <!-- 1 -->Features

- Opt-in support for NSCodec via feature flag ([#1332](https://github.com/Devolutions/IronRDP/issues/1332)) ([54af8f677f](https://github.com/Devolutions/IronRDP/commit/54af8f677fde726e2734f7bb1b451f3099d63532)) 

  Adds an opt-in implementation of the legacy RDP NSCodec encoder as a standalone crate, and wires it into `ironrdp-server` behind a feature flag so servers can serve NSCodec-only clients (notably macOS Microsoft Remote Desktop / Windows App) without default-build behavior changes.

- Add CredentialValidator trait for server-side auth ([#1172](https://github.com/Devolutions/IronRDP/issues/1172)) ([8a3b126396](https://github.com/Devolutions/IronRDP/commit/8a3b12639632f58291442a292a89fc6e22f82985)) 

### <!-- 4 -->Bug Fixes

- Emit RGB-channel QOI for opaque captures so ironrdp-session can decode ([#1335](https://github.com/Devolutions/IronRDP/issues/1335)) ([8a9ee6268c](https://github.com/Devolutions/IronRDP/commit/8a9ee6268ccdb5704c2bb60bed6d2adf57761427)) 

### <!-- 7 -->Build

- [**breaking**] Update `ironrdp-displaycontrol`, `ironrdp-dvc`, and `ironrdp-echo` public dependencies



## [[0.11.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.10.0...ironrdp-server-v0.11.0)] - 2026-06-01

### <!-- 1 -->Features

- Add clipboard data locking methods ([#1064](https://github.com/Devolutions/IronRDP/issues/1064)) ([58c3df84bb](https://github.com/Devolutions/IronRDP/commit/58c3df84bb9cafc8669315834cead35a71483c34)) 

  Per MS-RDPECLIP sections 2.2.4.6 and 2.2.4.7, the Local
  Clipboard Owner may lock the Shared Clipboard Owner's clipboard data before
  requesting file contents to ensure data stability during multi-request transfers.
  
  This enables server implementations to safely request file data from
  clients when handling clipboard paste operations.

- Add request_file_contents method ([#1065](https://github.com/Devolutions/IronRDP/issues/1065)) ([c30fc35a28](https://github.com/Devolutions/IronRDP/commit/c30fc35a28d6218603c1662e98e8b3053bea3aa5)) 

  Per MS-RDPECLIP section 2.2.5.3, the Local Clipboard Owner
  sends File Contents Request PDU to retrieve file data from the Shared
  Clipboard Owner during paste operations.
  
  This enables server implementations to request file contents from
  clients, completing the bidirectional file transfer capability.

- Add SendFileContentsResponse message variant ([#1066](https://github.com/Devolutions/IronRDP/issues/1066)) ([25f81337aa](https://github.com/Devolutions/IronRDP/commit/25f81337aa494af9a21f55f12ec27fd946465cbe)) 

  Adds `SendFileContentsResponse` to `ClipboardMessage` enum, enabling
  clipboard backends to signal when file data is ready to send via
  `submit_file_contents()`.
  
  This provides the message-based interface pattern used consistently by
  server implementations for clipboard operations.

- Expose client display size to RdpServerDisplay ([#1083](https://github.com/Devolutions/IronRDP/issues/1083)) ([3cf570788d](https://github.com/Devolutions/IronRDP/commit/3cf570788d418ef0d83670c8581ddb61582237fe)) 

  This allows the server implementation to handle the requested initial
  client display size. The default implementation simply returns
  `self.size()` so there's no change to existing behavior.
  
  Note that this method is also called during reactivations.

- Add EGFX server integration with DVC bridge ([#1099](https://github.com/Devolutions/IronRDP/issues/1099)) ([4ba696c266](https://github.com/Devolutions/IronRDP/commit/4ba696c266c7065c93a691b9f818644fd471429b)) 

- Implement ECHO virtual channel ([#1109](https://github.com/Devolutions/IronRDP/issues/1109)) ([6f6496ad29](https://github.com/Devolutions/IronRDP/commit/6f6496ad29395099563d50417d6dfff623914ee6)) 

- Make run_connection generic over stream type ([#1181](https://github.com/Devolutions/IronRDP/issues/1181)) ([c30d853fa3](https://github.com/Devolutions/IronRDP/commit/c30d853fa34c2da02047b1dcb626f1009de2b61c)) 

  Generalizes `RdpServer::run_connection` to accept arbitrary Tokio `AsyncRead + AsyncWrite` streams instead of a concrete `TcpStream`, enabling non-TCP transports (e.g., Unix sockets, VSOCK, in-process streams) to reuse the same server connection logic.

- Add auto-detect RTT measurement ([#1177](https://github.com/Devolutions/IronRDP/issues/1177)) ([2515470fdb](https://github.com/Devolutions/IronRDP/commit/2515470fdb7187d20ee3fba8244b839efa4cbce4)) 

  Adds server-side RTT measurement using the protocol-standard auto-detect
  mechanism (MS-RDPBCGR 2.2.14).

- IPv6 dual-stack and SO_REUSEADDR for run() ([#1187](https://github.com/Devolutions/IronRDP/issues/1187)) ([f10625cc80](https://github.com/Devolutions/IronRDP/commit/f10625cc806cc0ea9128c711df0dfd3ba8456b4f)) 

- Add ConnectionHandler trait for connection lifecycle hooks ([#1194](https://github.com/Devolutions/IronRDP/issues/1194)) ([5c08c7fe3d](https://github.com/Devolutions/IronRDP/commit/5c08c7fe3ded6f645cbddc53cdc0a02e8c45a037)) 

- Implement clipboard file transfer support ([#1166](https://github.com/Devolutions/IronRDP/issues/1166)) ([c98a8fb774](https://github.com/Devolutions/IronRDP/commit/c98a8fb7741986e9afef00cb5615250c963a7fa9)) 

  Add end-to-end clipboard file transfer (upload and download) across the
  CLIPRDR channel per MS-RDPECLIP.

- Handle SuppressOutput / RefreshRectangle and expose state ([#1319](https://github.com/Devolutions/IronRDP/issues/1319)) ([aa7ff679b9](https://github.com/Devolutions/IronRDP/commit/aa7ff679b914dbbc9bfe137d7f4f26bea30d6323)) 

- Add pointer caching support to ironrdp-server ([1a6b4206d5](https://github.com/Devolutions/IronRDP/commit/1a6b4206d5f0fe3333da721adeaea3f7d2aa65cf)) 

### <!-- 4 -->Bug Fixes

- Make MultifragmentUpdate max_request_size configurable ([#1100](https://github.com/Devolutions/IronRDP/issues/1100)) ([d437b7e0b9](https://github.com/Devolutions/IronRDP/commit/d437b7e0b9a47f5b9246e24c76554df82f47670e)) 

  The hardcoded `max_request_size` of 16,777,215 in the server's
  MultifragmentUpdate capability causes mstsc to reject the connection (it
  likely tries to allocate that buffer upfront). FreeRDP hit the same
  problem and adjusted their value in FreeRDP/FreeRDP#1313.
  
  This adds a configurable `max_request_size` field to `RdpServerOptions`
  with a default of 8 MB (matching what `ironrdp-connector` already uses
  on the client side) and exposes it through the builder via
  `with_max_request_size()`.

- Tile bitmaps that exceed `MultifragmentUpdate` limit ([#1133](https://github.com/Devolutions/IronRDP/issues/1133)) ([db2f40b5b0](https://github.com/Devolutions/IronRDP/commit/db2f40b5b0af66a4c83e0e075e2814467c060b1d)) 

  Split oversized dirty rects into horizontal strips that fit within `max_request_size`
  before handing them to the bitmap encoder.

- Skip bitmap updates that exceed bounds ([#1146](https://github.com/Devolutions/IronRDP/issues/1146)) ([2b97a95e6d](https://github.com/Devolutions/IronRDP/commit/2b97a95e6da8833e8a84e9f42960da91eee87cd6)) 

  After a desktop resize, an RDP server can send a burst of bitmap updates
  for the old resolution before its rendering pipeline has fully
  transitioned to the new one. These updates reference coordinates beyond
  the current image buffer in `DecodedImage`, causing index-out-of-bounds
  panics in the `apply_*` methods. On the server side, the same stale
  bitmaps can reach the encoder with dimensions exceeding the negotiated
  desktop size, panicking in `NoneHandler::handle()`.
  
  This commit adds bounds checks at two levels:
  - `DecodedImage::rect_fits()` guard at the entry of each `apply_*`
  method, returning an empty rectangle when the update doesn't fit
  - Encoder-level guard in `EncoderIter::next()` that drops
  `BitmapUpdate`s exceeding the current desktop size

- Replace all from_bits_truncate with from_bits_retain ([#1144](https://github.com/Devolutions/IronRDP/issues/1144)) ([353e30ddfd](https://github.com/Devolutions/IronRDP/commit/353e30ddfdaafc897db10b8663e364ef7775a7fd)) 

  from_bits_truncate silently discards unknown bits, which breaks the
  encode/decode round-trip property. This matters for fuzzing because a
  PDU that decodes and re-encodes should produce identical bytes.
  from_bits_retain preserves all bits, including those not yet defined in
  our bitflags types, so the round-trip property holds.

- Keep newest queued waves on per-batch overflow ([#1276](https://github.com/Devolutions/IronRDP/issues/1276)) ([6e8479763f](https://github.com/Devolutions/IronRDP/commit/6e8479763f2bcf0938bd4091e35fd5a322a787dd)) 

- Drop raw user_data dump from McsMessage::SendDataRequest debug log ([#1295](https://github.com/Devolutions/IronRDP/issues/1295)) ([424590ac76](https://github.com/Devolutions/IronRDP/commit/424590ac76f3f82de19b3d6d1aa7a0119f616fab)) 

### <!-- 7 -->Build

- Bump rayon from 1.11.0 to 1.12.0 ([#1235](https://github.com/Devolutions/IronRDP/issues/1235)) ([a5dab356e5](https://github.com/Devolutions/IronRDP/commit/a5dab356e5bc29cde2fdcd71b6d11fdf38a96a9f)) 


## [[0.10.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.9.0...ironrdp-server-v0.10.0)] - 2025-12-18

### <!-- 4 -->Bug Fixes

- Send TLS close_notify during graceful RDP disconnect ([#1032](https://github.com/Devolutions/IronRDP/issues/1032)) ([a70e01d9c5](https://github.com/Devolutions/IronRDP/commit/a70e01d9c5675a7dffd65eda7428537c8ad6a857)) 

  Add support for sending a proper TLS close_notify message when the RDP
  client initiates a graceful disconnect PDU.

## [[0.9.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.8.0...ironrdp-server-v0.9.0)] - 2025-09-24

### <!-- 4 -->Bug Fixes

- [**breaking**] RdpServerDisplayUpdates::next_update now returns a Result

## [[0.8.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.7.0...ironrdp-server-v0.8.0)] - 2025-08-29

### <!-- 1 -->Features

- [**breaking**] Add server_codecs_capabilities() ([d3aaa43c23](https://github.com/Devolutions/IronRDP/commit/d3aaa43c23b252077b8720bb8ecfeceaaf7b7a7f)) 

  Teach the server to support customizable codecs set. Use the same
  logic/parsing as the client codecs configuration.
  
  Replace "with_remote_fx" with "codecs".

- Add QOI image codec ([613fd51f26](https://github.com/Devolutions/IronRDP/commit/613fd51f26315d8212662c46f8e625c541e4bb59)) 

  The Quite OK Image format ([1]) losslessly compresses images to a similar size
  of PNG, while offering 20x-50x faster encoding and 3x-4x faster decoding.

- Add QOIZ image codec ([87df67fdc7](https://github.com/Devolutions/IronRDP/commit/87df67fdc76ff4f39d4b83521e34bf3b5e2e73bb)) 

  Add a new QOIZ codec for SetSurface command. The PDU data contains the same
  data as the QOI codec, with zstd compression.

## [[0.7.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.6.1...ironrdp-server-v0.7.0)] - 2025-07-08

### Build

- Update sspi dependency (#839) ([33530212c4](https://github.com/Devolutions/IronRDP/commit/33530212c42bf28c875ac078ed2408657831b417)) 

## [[0.6.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.5.0...ironrdp-server-v0.6.0)] - 2025-05-27

### <!-- 1 -->Features

- Add stride debug info ([7f57817805](https://github.com/Devolutions/IronRDP/commit/7f578178056282e590179a10cd1eedb8f4d9ad63)) 

- Add Framebuffer helper struct ([1e87961d16](https://github.com/Devolutions/IronRDP/commit/1e87961d1611ed31f58b407f208295c97c0d2944)) 

  This will hold the updated bitmap data for the whole framebuffer.

- Add BitmapUpdate::sub() ([a76e84d459](https://github.com/Devolutions/IronRDP/commit/a76e84d45927d61e21c27abcfa31c4f0c7a17bbf)) 

- Implement some Encoder Debug ([137d91ae7a](https://github.com/Devolutions/IronRDP/commit/137d91ae7a096170ada289d420785c8f5de0663b)) 

- Keep last full-frame/desktop update ([aeb1193674](https://github.com/Devolutions/IronRDP/commit/aeb1193674641846ae1873def8c84a62a59213d5)) 

  It should reflect client drawing state.
  
  In following changes, we will fix it to draw bitmap updates on it, to
  keep it up to date.

- Find and send the damaged tiles ([fb3769c4a7](https://github.com/Devolutions/IronRDP/commit/fb3769c4a7fce56e340df8c4b19f7d90cda93e50)) 

  Keep a framebuffer and tile-diff against it, to save from
  encoding/sending the same bitmap data regions.

### <!-- 4 -->Bug Fixes

- Use desktop size for RFX channel size (#756) ([806f1d7694](https://github.com/Devolutions/IronRDP/commit/806f1d7694313b1a59842af300a437ae2f6c2463)) 

- [**breaking**] Remove time_warn! from the public API (#773) ([cc78b1e3dc](https://github.com/Devolutions/IronRDP/commit/cc78b1e3dc1c554dd3fcf6494763caa00ba28ad7)) 

  This is intended to be an internal macro.

### Refactor

- [**breaking**] Drop support for pixelOrder ([db6f4cdb7f](https://github.com/Devolutions/IronRDP/commit/db6f4cdb7f379713979b930e8e1fa1a813ebecc4)) 

  Dealing with multiple formats is sufficiently annoying, there isn't much
  need for awkward image layout. This was done for efficiency reason for
  bitmap encoding, but bitmap is really inefficient anyway and very few
  servers will actually provide bottom to top images (except with GL/GPU
  textures, but this is not in scope yet).

- [**breaking**] Use bytes, allowing shareable bitmap data ([3c43fdda76](https://github.com/Devolutions/IronRDP/commit/3c43fdda76f4ef6413db4010471364d6b1be2798)) 

- [**breaking**] Rename left/top -> x/y ([229070a435](https://github.com/Devolutions/IronRDP/commit/229070a43554927a01541052a819fe3fcd32a913)) 


## [[0.5.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.4.2...ironrdp-server-v0.5.0)] - 2025-03-12

### <!-- 7 -->Build

- Bump ironrdp-pdu


## [[0.4.2](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.4.1...ironrdp-server-v0.4.2)] - 2025-03-12

### <!-- 7 -->Build

- Update dependencies (#695) ([c21fa44fd6](https://github.com/Devolutions/IronRDP/commit/c21fa44fd6f3c6a6b74788ff68e83133c1314caa)) 


## [[0.4.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.4.0...ironrdp-server-v0.4.1)] - 2025-01-28

### <!-- 1 -->Features

- Advertize Bitmap::desktopResizeFlag ([a0fccf8d1a](https://github.com/Devolutions/IronRDP/commit/a0fccf8d1a3eeab6c73ed7d9cdbb4342cca173c4)) 

  This makes freerdp keep the flag up and handle desktop
  resize/deactivation-reactivation. It should be okay to advertize,
  if the server doesn't resize anyway, I guess.

- Add volume support (#641) ([a6c36511f6](https://github.com/Devolutions/IronRDP/commit/a6c36511f6584f67b8c6e795c34d5007ec2b24a4)) 

  Add server messages and API to support setting client volume.

### <!-- 4 -->Bug Fixes

- Drop unexpected PDUs during deactivation-reactivation ([63963182b5](https://github.com/Devolutions/IronRDP/commit/63963182b5af6ad45dc638e93de4b8a0b565c7d3)) 

  The current behaviour of handling unmatched PDUs in fn read_by_hint()
  isn't good enough. An unexpected PDUs may be received and fail to be
  decoded during Acceptor::step().
  
  Change the code to simply drop unexpected PDUs (as opposed to attempting
  to replay the unmatched leftover, which isn't clearly needed)

- Reattach existing channels ([c4587b537c](https://github.com/Devolutions/IronRDP/commit/c4587b537c7c0a148e11bc365bc3df88e2c92312)) 

  I couldn't find any explicit behaviour described in the specification,
  but apparently, we must just keep the channel state as they were during
  reactivation. This fixes various state issues during client resize.

- Do not restart static channels on reactivation ([82c7c2f5b0](https://github.com/Devolutions/IronRDP/commit/82c7c2f5b08c44b1a4f6b04c13ad24d9e2ffa371)) 

- Check client size ([0f9877ad39](https://github.com/Devolutions/IronRDP/commit/0f9877ad3901b37f58406095e05f345fbc8a5eaa)) 

  It's problematic when the client didn't resize, as we send bitmap
  updates that don't fit. The client will likely drop the connection.
  Let's have a warning for this case in the server.

### <!-- 6 -->Documentation

- Use CDN URLs instead of the blob storage URLs for Devolutions logo (#631) ([dd249909a8](https://github.com/Devolutions/IronRDP/commit/dd249909a894004d4f728d30b3a4aa77a0f8193b)) 


## [[0.4.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.3.1...ironrdp-server-v0.4.0)] - 2024-12-17

### <!-- 1 -->Features

- [**breaking**] Make TlsIdentityCtx accept PEM files ([#623](https://github.com/Devolutions/IronRDP/pull/623)) ([9198284263](https://github.com/Devolutions/IronRDP/commit/9198284263e11706fed76310f796200b75111126)) 

  This is in general more convenient than DER files.

  This patch also includes a breaking change in the public API. 
  The `cert` field in the `TlsIdentityCtx` struct is replaced by a `certs` field containing multiple `CertificateDer` items.

## [[0.3.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.3.0...ironrdp-server-v0.3.1)] - 2024-12-14

### Other

- Symlinks to license files in packages ([#604](https://github.com/Devolutions/IronRDP/pull/604)) ([6c2de344c2](https://github.com/Devolutions/IronRDP/commit/6c2de344c2dd93ce9621834e0497ed7c3bfaf91a)) 

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.14.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-server-v0.13.0...ironrdp-server-v0.14.0)] - 2026-10-27

### <!-- 0 -->Security

- Add `RdpServer::enable_heartbeat` and `HeartbeatConfig` to send periodic Server Heartbeat PDUs ([#1842](https://github.com/Devolutions/IronRDP/issues/1842)) ([8f57691a9a](https://github.com/Devolutions/IronRDP/commit/8f57691a9a6e497388dc2824bffe93eeed7bb698))

- Log the Initiate Multitransport Response at debug level instead of warning about an unhandled message channel PDU ([#1964](https://github.com/Devolutions/IronRDP/issues/1964)) ([6aebe6d0b1](https://github.com/Devolutions/IronRDP/commit/6aebe6d0b11c4aa3c99252bd986e138e43756a6d))

- Add `RdpServerBuilder::with_udp_transport` to offer UDP multitransport under TLS or Hybrid security and move EGFX traffic to it ([#1954](https://github.com/Devolutions/IronRDP/issues/1954)) ([73dfa30e38](https://github.com/Devolutions/IronRDP/commit/73dfa30e3831e51cf8aa58f93e27b1b00102a7ec))

- Add `ConnectionSource`, `IncomingConnection`, `RdpServer::serve` and `RdpServer::serve_connection`, which apply the connection policy to connections the embedder accepts ([#2116](https://github.com/Devolutions/IronRDP/issues/2116)) ([350520684c](https://github.com/Devolutions/IronRDP/commit/350520684c028f9d50343f64f6afb93475b7ac33))

- [**breaking**] Add `ServerRedirectionHandle` (`RdpServer::server_redirection_handle`) to send a Server Redirection PDU, and `ConnectionInfo::routing_token`, `redirected_session_id` and `password_cookie` ([#2208](https://github.com/Devolutions/IronRDP/issues/2208)) ([485657a6ec](https://github.com/Devolutions/IronRDP/commit/485657a6eca682a0356e100a9fda229342861fd7))

### <!-- 1 -->Features

- Add `StaticChannelFactory` and `RdpServerBuilder::with_static_channel_factory` to create static channel processors for each connection, and re-export `Acceptor` ([#1633](https://github.com/Devolutions/IronRDP/issues/1633)) ([e48b29c017](https://github.com/Devolutions/IronRDP/commit/e48b29c0173096c1718c9f657bed3a59926aa97c))

- Report the measured round-trip time and bandwidth to the client in Network Characteristics Results ([#1470](https://github.com/Devolutions/IronRDP/issues/1470)) ([224e8db7ce](https://github.com/Devolutions/IronRDP/commit/224e8db7cec2dad39032aac097f550a6600e742c))

- Add `RdpServerBuilder::with_remotefx_quant` to set the RemoteFX quantization table ([#1685](https://github.com/Devolutions/IronRDP/issues/1685)) ([925e7c0f7c](https://github.com/Devolutions/IronRDP/commit/925e7c0f7cb7ae937a92ec93d4cb758289594cc0))

- [**breaking**] Add `ConnectionInfo` with the client's keyboard layout, type and IME file name, passed to the new `ConnectionHandler::on_connection_info` ([#1691](https://github.com/Devolutions/IronRDP/issues/1691)) ([393869b30b](https://github.com/Devolutions/IronRDP/commit/393869b30b1078da7204c6bf20e8a5472e419070))

- Add `RdpServer::autodetect_baseline_rtt_handle` and `RdpServerBuilder::with_autodetect_baseline_rtt_handle` for the lowest round-trip time of the session ([#1737](https://github.com/Devolutions/IronRDP/issues/1737)) ([ac7800c989](https://github.com/Devolutions/IronRDP/commit/ac7800c989dd5926eef2a1adf983458ad0aec9ee))

- [**breaking**] `MouseEvent` button and scroll events carry the pointer position, and the new `MouseButton` covers X1 and X2 ([#1769](https://github.com/Devolutions/IronRDP/issues/1769)) ([e9c5b1c54a](https://github.com/Devolutions/IronRDP/commit/e9c5b1c54a1153e5d7116d7fadf636bd551020ea))

- Add `RdpeiServerFactory` and `RdpServerBuilder::with_rdpei_factory` for MS-RDPEI multitouch and pen input ([#1773](https://github.com/Devolutions/IronRDP/issues/1773)) ([aa260fef9e](https://github.com/Devolutions/IronRDP/commit/aa260fef9ebbc0a420b17e796616d710fb41e702))

- Add `RdpServerBuilder::with_usb_factory` for MS-RDPEUSB USB redirection ([#1417](https://github.com/Devolutions/IronRDP/issues/1417)) ([4755faec5e](https://github.com/Devolutions/IronRDP/commit/4755faec5efb1649e2cb839f553c8aaae7534aad))

- [**breaking**] Add `ServerError`, `ServerErrorKind` and `ServerResult` for the public API ([#1242](https://github.com/Devolutions/IronRDP/issues/1242)) ([b5b9558eae](https://github.com/Devolutions/IronRDP/commit/b5b9558eae164a3500ace069b4db12be25eba7bd))

- [**breaking**] `ConnectionHandler::on_disconnected` receives a `ServerError` instead of an `anyhow::Error` ([#1244](https://github.com/Devolutions/IronRDP/issues/1244)) ([b919a41932](https://github.com/Devolutions/IronRDP/commit/b919a419320dfabe4b932c0d3d623386883b072f))

- [**breaking**] The display traits return `ServerResult` instead of `anyhow::Result`, and `anyhow` is no longer a dependency ([#1245](https://github.com/Devolutions/IronRDP/issues/1245)) ([9abd6eb482](https://github.com/Devolutions/IronRDP/commit/9abd6eb482d8e7bcc64d578fc0a97bb12b6c82d9))

- Add `RdpServer::autodetect_bandwidth_handle` and `RdpServerBuilder::with_autodetect_bandwidth_handle` for the measured bandwidth ([#1734](https://github.com/Devolutions/IronRDP/issues/1734)) ([e01839bfd8](https://github.com/Devolutions/IronRDP/commit/e01839bfd84ff5a392ca81ae80c0350bf457f7b1))

- Add `RdpdrServerFactory` and `RdpServerBuilder::with_rdpdr_factory` for device redirection ([#1784](https://github.com/Devolutions/IronRDP/issues/1784)) ([695af5a6e8](https://github.com/Devolutions/IronRDP/commit/695af5a6e814badb3daa60184a8d2048d0e66716))

- Add `ServerEvent::Disconnect` and `ErrorInfoDisconnectHandle` (`RdpServer::error_info_disconnect_handle`) to disconnect a client with a Set Error Info PDU ([#1798](https://github.com/Devolutions/IronRDP/issues/1798)) ([f7253861fa](https://github.com/Devolutions/IronRDP/commit/f7253861faa430d28c9dbce29d3e9e930c54748f))

- [**breaking**] Support the Large Pointer Capability Set and add the `LargePointer` display update ([#1787](https://github.com/Devolutions/IronRDP/issues/1787)) ([bde5824213](https://github.com/Devolutions/IronRDP/commit/bde5824213bfbc59d83c8fb3d2cfbc69ad9dab77))

- Log EGFX flow-control changes and frame acknowledgements at debug level, and warn on an acknowledgement for an unknown frame ([#1834](https://github.com/Devolutions/IronRDP/issues/1834)) ([8d1e91eb32](https://github.com/Devolutions/IronRDP/commit/8d1e91eb3256e0ba007e909512bbaf84cb76d67b))

- Add `RdpServerBuilder::with_preempt_existing_session` to let an authenticated connection replace the active session ([#1476](https://github.com/Devolutions/IronRDP/issues/1476)) ([5198cde0f7](https://github.com/Devolutions/IronRDP/commit/5198cde0f73485f3fbd999ea7c49293c86b80387))

- Add `ConnectionPolicy` and `RdpServerBuilder::with_connection_policy` to queue or reject a connection that arrives during a session ([#1913](https://github.com/Devolutions/IronRDP/issues/1913)) ([f7732a1639](https://github.com/Devolutions/IronRDP/commit/f7732a16392b5857a698182ffd37221da1010a2a))

- Add `RdpeaiServerFactory` and `RdpServerBuilder::with_rdpeai_factory` for MS-RDPEAI audio input ([#1946](https://github.com/Devolutions/IronRDP/issues/1946)) ([5b139ba3df](https://github.com/Devolutions/IronRDP/commit/5b139ba3df92b05154bcedc5bc13b2c0b61866d8))

- Add `RdpServer::autodetect_bandwidth_generation_handle` and `RdpServerBuilder::with_autodetect_bandwidth_generation_handle`, which count completed bandwidth measurements ([#1963](https://github.com/Devolutions/IronRDP/issues/1963)) ([ded2caa118](https://github.com/Devolutions/IronRDP/commit/ded2caa1184fd3b2671b9725ff26052383a0be16))

- Add `RdpServerDisplay::monitor_count`, reported in the Display Control capabilities ([#1918](https://github.com/Devolutions/IronRDP/issues/1918)) ([25331598f3](https://github.com/Devolutions/IronRDP/commit/25331598f37f49573205c54ee45c878d291317f2))

- `ConnectionPolicy` defaults to `Preempt` under Hybrid security, where CredSSP authenticates every takeover; `ConnectionPolicy::default_for` returns the default for a security mode ([#1934](https://github.com/Devolutions/IronRDP/issues/1934)) ([9cb20336f6](https://github.com/Devolutions/IronRDP/commit/9cb20336f6f586cd5c9c06b6907d1b3f2e51b405))

- [**breaking**] Add `ConnectionBinder` and `RdpServerBuilder::with_connection_binder` to bind an authenticated connection to a per-user display and input handler ([#1413](https://github.com/Devolutions/IronRDP/issues/1413)) ([15bed4ee0e](https://github.com/Devolutions/IronRDP/commit/15bed4ee0ebef4b851c024edfcd4b1675d6e9ee8))

- Add `RdpServerBuilder::with_auto_reconnect_on_request` and `RdpServer::set_auto_reconnect_on_request` to issue auto-reconnect cookies only once the embedder authenticates the user ([#2046](https://github.com/Devolutions/IronRDP/issues/2046)) ([bf019ca502](https://github.com/Devolutions/IronRDP/commit/bf019ca502d1e52616853a5ded68c885cec1e322))

- Add `RdpServerDisplay::offers_display_control` to decline the Display Control channel ([#1985](https://github.com/Devolutions/IronRDP/issues/1985)) ([7b976a6965](https://github.com/Devolutions/IronRDP/commit/7b976a6965c96c76ff949313e174ea55dada8c44))

- Add `ConnectionInfo::client_monitors` with the client's monitors ([#2129](https://github.com/Devolutions/IronRDP/issues/2129)) ([da166aa488](https://github.com/Devolutions/IronRDP/commit/da166aa4883a4868638d3c65ecf44b8b3895acfb))

- Measure bandwidth on the UDP tunnel once EGFX uses it ([#2031](https://github.com/Devolutions/IronRDP/issues/2031)) ([cb7ca37680](https://github.com/Devolutions/IronRDP/commit/cb7ca3768092fcc43a09a1b401cdd8abb873db42))

### <!-- 4 -->Bug Fixes

- Add `RdpServerBuilder::with_remotefx_entropy_coder`, and pick the first entropy coder the client offers instead of the last one ([#1686](https://github.com/Devolutions/IronRDP/issues/1686)) ([185f312019](https://github.com/Devolutions/IronRDP/commit/185f3120199f0373a11c7e21cecfac77b7be56af))

- `run_connection` releases the static channels when the connection ends ([#1721](https://github.com/Devolutions/IronRDP/issues/1721)) ([8b1f0dab08](https://github.com/Devolutions/IronRDP/commit/8b1f0dab088c2205ec1d9e8cb1b49bf902971b23))

- [**breaking**] Remove the `tokio` and `tokio_rustls` re-exports ([#1796](https://github.com/Devolutions/IronRDP/issues/1796)) ([cac7bd6f37](https://github.com/Devolutions/IronRDP/commit/cac7bd6f37120711570b0156dd87c8ce6145fad6))

- Use New Pointer Updates only within the pointer cache size the client advertises ([#1786](https://github.com/Devolutions/IronRDP/issues/1786)) ([e01cc76116](https://github.com/Devolutions/IronRDP/commit/e01cc76116fc0b238bca25acccce03eadb158550))

- Disable Nagle's algorithm on accepted connections ([#1799](https://github.com/Devolutions/IronRDP/issues/1799)) ([915e681845](https://github.com/Devolutions/IronRDP/commit/915e681845d9c27198776d735952c272e19566b9))

- USB redirection requests a zero maximum packet size for each pipe instead of one derived from the device speed ([#1871](https://github.com/Devolutions/IronRDP/issues/1871)) ([6a5d7c23fe](https://github.com/Devolutions/IronRDP/commit/6a5d7c23fe312b6c7b01f25c6a8e4c436309df00))

- Time out connection finalization after 30 seconds, so a client that stops responding cannot hold the server ([#1890](https://github.com/Devolutions/IronRDP/issues/1890)) ([a8b4b2a7ed](https://github.com/Devolutions/IronRDP/commit/a8b4b2a7ed6f86a16a31e304538823520db0d830))

- A clipboard failure no longer ends the session ([#1980](https://github.com/Devolutions/IronRDP/issues/1980)) ([124406d881](https://github.com/Devolutions/IronRDP/commit/124406d881af377cb339e8c131831f69e3cf7e45))

- Drop RDPSND waves and volume changes that arrive before the channel negotiates, which failed the next connection ([#1990](https://github.com/Devolutions/IronRDP/issues/1990)) ([2e872b085b](https://github.com/Devolutions/IronRDP/commit/2e872b085b504cf3b9ce9994237270f71a35d13a))

- Keep calling `ConnectionHandler::on_connection_info` for the live connection while a `Preempt` candidate negotiates ([#2065](https://github.com/Devolutions/IronRDP/issues/2065)) ([458545e6d5](https://github.com/Devolutions/IronRDP/commit/458545e6d5c5963a3673e7f686c0bdee3848b58b))

- Drop the previous session's queued events before every connection ([#2034](https://github.com/Devolutions/IronRDP/issues/2034)) ([2c08bda7c5](https://github.com/Devolutions/IronRDP/commit/2c08bda7c5f9ad490e01f123b3be5521cf3c6e9d))

- [**breaking**] Remove `RdpServer::rtt_snapshot`, `get_svc_processor` and `get_channel_id_by_type`, as channels and auto-detect state now belong to each connection; the baseline round-trip time no longer carries over between connections ([#2059](https://github.com/Devolutions/IronRDP/issues/2059)) ([0e9dc1f712](https://github.com/Devolutions/IronRDP/commit/0e9dc1f71237c75ba1f856b1996f5994931dd31e))

- Respect the client's frame acknowledgement limit for EGFX frames ([#2102](https://github.com/Devolutions/IronRDP/issues/2102)) ([e4143f2630](https://github.com/Devolutions/IronRDP/commit/e4143f26306a6639a889d80c1c484ca69c365a8f))

- Measure bandwidth across a single large EGFX write instead of a fixed window that timed idle traffic ([#2021](https://github.com/Devolutions/IronRDP/issues/2021)) ([b5bbd8a598](https://github.com/Devolutions/IronRDP/commit/b5bbd8a59829450cb85ca834836b2e030fb53dde))

- Send an AND mask with 32 bpp pointers, which Windows App for macOS requires ([#2108](https://github.com/Devolutions/IronRDP/issues/2108)) ([fb25b47c0c](https://github.com/Devolutions/IronRDP/commit/fb25b47c0ce22233b4992ec0e70560fb56b8f200))

- Drive the clipboard channel timeouts, which released locks and failed abandoned file contents requests ([#1979](https://github.com/Devolutions/IronRDP/issues/1979)) ([3db08ba869](https://github.com/Devolutions/IronRDP/commit/3db08ba86983ce35c9d36ad33f59ceb4b607dce8))

- [**breaking**] `RdpServerDisplay::updates` takes a `DisplayContext` for the connection ([#2073](https://github.com/Devolutions/IronRDP/issues/2073)) ([9e85975616](https://github.com/Devolutions/IronRDP/commit/9e85975616c14fc2f4ad422d3a53255a4fbee345))

- [**breaking**] `GfxServerFactory` build methods take a `GfxContext`, and `DisplayContext::gfx_handle` replaces `RdpServer::gfx_handle` ([#2104](https://github.com/Devolutions/IronRDP/issues/2104)) ([7bca756755](https://github.com/Devolutions/IronRDP/commit/7bca756755ef856bd5aaaff97612bea875dbad5c))

- Advertise horizontal mouse wheel input, which mstsc otherwise does not send ([#2236](https://github.com/Devolutions/IronRDP/issues/2236)) ([2110ab2572](https://github.com/Devolutions/IronRDP/commit/2110ab25728ca0b2f1ad79aa90b834af2d3de5c6))

- Add `RdpServerBuilder::with_egfx_core_frame_ack_limit` and `RdpServer::set_egfx_core_frame_ack_limit`; the core frame acknowledgement limit no longer caps the EGFX window by default ([#2238](https://github.com/Devolutions/IronRDP/issues/2238)) ([0de133426b](https://github.com/Devolutions/IronRDP/commit/0de133426b8f7423f78dd6c63d8eba4f4d2365eb))

- Send RemoteFX in Stream Surface Bits when the client supports it, and prefer RemoteFX over ImageRemoteFX ([#2229](https://github.com/Devolutions/IronRDP/issues/2229)) ([e20a214703](https://github.com/Devolutions/IronRDP/commit/e20a2147038b8226701d9cf6b59d2c895fa51480))

### <!-- 7 -->Build

- [**breaking**] Update `ironrdp-acceptor` public dependency to 0.12

- [**breaking**] Update `ironrdp-cliprdr` public dependency to 0.9

- [**breaking**] Update `ironrdp-connector` public dependency to 0.12

- [**breaking**] Update `ironrdp-displaycontrol` public dependency to 0.10

- [**breaking**] Update `ironrdp-dvc` public dependency to 0.10

- [**breaking**] Update `ironrdp-echo` public dependency to 0.6

- [**breaking**] Update `ironrdp-graphics` public dependency to 0.11

- [**breaking**] Update `ironrdp-pdu` public dependency to 0.11

- [**breaking**] Update `ironrdp-rdpdr` public dependency to 0.9

- [**breaking**] Update `ironrdp-rdpeai` public dependency to 0.2

- [**breaking**] Update `ironrdp-rdpei` public dependency to 0.3

- [**breaking**] Update `ironrdp-rdpeudp-tokio` public dependency to 0.2

- [**breaking**] Update `ironrdp-rdpsnd` public dependency to 0.11

- [**breaking**] Update `ironrdp-svc` public dependency to 0.10



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

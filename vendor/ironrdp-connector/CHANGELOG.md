# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.12.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.11.0...ironrdp-connector-v0.12.0)] - 2026-10-27

### <!-- 0 -->Security

- Negotiate Entra ID authentication (`SecurityProtocol::RDSAAD`) with `Config::with_entra_auth`, exposing the server nonce through `entra_server_nonce` and sending the signed assertion with `submit_entra_assertion` ([#2248](https://github.com/Devolutions/IronRDP/issues/2248)) ([c790e6d4f2](https://github.com/Devolutions/IronRDP/commit/c790e6d4f2f8bf15ae66b2c29bffeca14ec19ff1))

### <!-- 1 -->Features

- [**breaking**] Add `Config::desktop_physical_size`, `desktop_orientation` and `device_scale_factor`, sent in the Client Core Data ([#2211](https://github.com/Devolutions/IronRDP/issues/2211)) ([98413f16cc](https://github.com/Devolutions/IronRDP/commit/98413f16cc3792a3debe14ef4a2956374957a615))

- [**breaking**] Add `Config::monitor_extended_layout`, sent as Client Monitor Extended Data when it describes every monitor of `monitor_layout` ([#2211](https://github.com/Devolutions/IronRDP/issues/2211)) ([98413f16cc](https://github.com/Devolutions/IronRDP/commit/98413f16cc3792a3debe14ef4a2956374957a615))

- [**breaking**] Add `Config::relative_mouse_input`, which announces relative mouse input and RDP 10.12 ([#2211](https://github.com/Devolutions/IronRDP/issues/2211)) ([98413f16cc](https://github.com/Devolutions/IronRDP/commit/98413f16cc3792a3debe14ef4a2956374957a615))

### <!-- 7 -->Build

- [**breaking**] Update `ironrdp-pdu` public dependency to 0.11

- [**breaking**] Update `ironrdp-svc` public dependency to 0.10



## [[0.11.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.10.0...ironrdp-connector-v0.11.0)] - 2026-10-23

### <!-- 1 -->Features

- [**breaking**] Implement multitransport bootstrapping: the connector pauses on each Initiate Multitransport Request until the caller answers it with `ClientConnector::complete_multitransport` or `ClientConnector::skip_multitransport`, and exposes `should_perform_multitransport`, `multitransport_request`, `multitransport_soft_sync_negotiated`, `MultitransportResult` and `ConnectionResult::multitransport_soft_sync` for callers that set up the UDP transport ([#1098](https://github.com/Devolutions/IronRDP/issues/1098)) ([e45fbfe0f5](https://github.com/Devolutions/IronRDP/commit/e45fbfe0f597011706e77fc174ca14e5e9d435b9)) ([#1858](https://github.com/Devolutions/IronRDP/issues/1858)) ([7036fb8c7e](https://github.com/Devolutions/IronRDP/commit/7036fb8c7ef32f71b456745902e14d34008c7add))

- Add `ClientConnector::attach_dynamic_static_channel` and `ClientConnector::try_attach_dynamic_static_channel` to attach several runtime-defined static virtual channels of the same processor type ([#1517](https://github.com/Devolutions/IronRDP/issues/1517)) ([8b4c483ba0](https://github.com/Devolutions/IronRDP/commit/8b4c483ba0c900a8de0b2718347754f56dd363ba)) ([#1522](https://github.com/Devolutions/IronRDP/issues/1522)) ([57b1366650](https://github.com/Devolutions/IronRDP/commit/57b13666506dc40c15b4c4702d35150beee99133))

- `ClientConnector::attach_static_channel` ignores a channel whose name is already registered or that exceeds the static channel limit ([#1517](https://github.com/Devolutions/IronRDP/issues/1517)) ([8b4c483ba0](https://github.com/Devolutions/IronRDP/commit/8b4c483ba0c900a8de0b2718347754f56dd363ba))

- [**breaking**] Add `ConnectionResult::input_flags` with the server's Input capability flags, so clients can choose between fast-path and slow-path input ([#1488](https://github.com/Devolutions/IronRDP/issues/1488)) ([9bcf13438c](https://github.com/Devolutions/IronRDP/commit/9bcf13438cb068b53a8cb0dc23477c498727d49f))

- [**breaking**] Add `ConnectionResult::refresh_rect_support` and `ConnectionResult::suppress_output_support` from the server's General capability set ([#1521](https://github.com/Devolutions/IronRDP/issues/1521)) ([20e2d414e5](https://github.com/Devolutions/IronRDP/commit/20e2d414e5ac060db25a100ed219f417e19f79b2))

- [**breaking**] Add `Config::connection_type` to set the network profile advertised in the Client Core Data ([#1522](https://github.com/Devolutions/IronRDP/issues/1522)) ([57b1366650](https://github.com/Devolutions/IronRDP/commit/57b13666506dc40c15b4c4702d35150beee99133))

- Add `ClientConnector::with_auto_reconnect_cookie` to resume a previous session by sending the Client Auto-Reconnect Packet derived from its cookie ([#1501](https://github.com/Devolutions/IronRDP/issues/1501)) ([74b3365c1f](https://github.com/Devolutions/IronRDP/commit/74b3365c1f98c0da6feed7507779c67e1b8e6d08))

- Advertise `BitmapConfig::color_depth` as the preferred color depth in the Confirm Active PDU instead of always 32, and reject depths other than 15, 16, 24 and 32 ([#1523](https://github.com/Devolutions/IronRDP/issues/1523)) ([ee58b7c5f2](https://github.com/Devolutions/IronRDP/commit/ee58b7c5f283ef64be93a8483242f49070c6cdc9))

- Add `ClientConnector::initiate_with_security_protocol` to start the connection with a chosen subset of the enabled security protocols, as Hyper-V VMConnect requires ([#1503](https://github.com/Devolutions/IronRDP/issues/1503)) ([a7cc067d50](https://github.com/Devolutions/IronRDP/commit/a7cc067d5069cbbcb13bae3e0561c0611da3bcf6))

- Omit the X.224 `mstshash` cookie when the username is empty ([#1503](https://github.com/Devolutions/IronRDP/issues/1503)) ([a7cc067d50](https://github.com/Devolutions/IronRDP/commit/a7cc067d5069cbbcb13bae3e0561c0611da3bcf6))

- [**breaking**] Add `Config::enable_standard_rdp_security` to allow Standard RDP Security without encryption, for trusted local transports such as Windows Sandbox named pipes ([#1580](https://github.com/Devolutions/IronRDP/issues/1580)) ([39b020343d](https://github.com/Devolutions/IronRDP/commit/39b020343d962962bfbefc89939be64d5c716196))

- Split static virtual channel data using the server's negotiated chunk size, keeping 1600 bytes when the server sends none or an invalid one ([#1622](https://github.com/Devolutions/IronRDP/issues/1622)) ([4e3903fbbe](https://github.com/Devolutions/IronRDP/commit/4e3903fbbef2904505f35e3437a7106807ac5987))

- [**breaking**] Echo the server's Window List capability in the Confirm Active PDU and add `ConnectionResult::window_support_level` ([#1631](https://github.com/Devolutions/IronRDP/issues/1631)) ([0c3fbe78b4](https://github.com/Devolutions/IronRDP/commit/0c3fbe78b4366533b9fcea046b2b53654e003a72))

- [**breaking**] Add `Config::remote_application_mode` and `Config::rail_support_level` to connect in RemoteApp mode, which fails when the server does not support RAIL and windowing ([#1637](https://github.com/Devolutions/IronRDP/issues/1637)) ([ab48c6cb8c](https://github.com/Devolutions/IronRDP/commit/ab48c6cb8c017504f8a92799aeb91b821c50a13a))

- [**breaking**] Add `Config::enable_audio_capture` to set `INFO_AUDIOCAPTURE` in the Client Info PDU ([#1642](https://github.com/Devolutions/IronRDP/issues/1642)) ([205fe038cc](https://github.com/Devolutions/IronRDP/commit/205fe038cc693598adf803fe181526b789b2ec3d))

- [**breaking**] Add `Config::monitor_layout` to advertise a client monitor layout, advertise Monitor Layout PDU support, and expose the server's layout through `ConnectionResult::monitor_layout`, `ConnectionFinalizationSequence::monitor_layout` and `ConnectionActivationSequence::monitor_layout` ([#1675](https://github.com/Devolutions/IronRDP/issues/1675)) ([063efcdc30](https://github.com/Devolutions/IronRDP/commit/063efcdc3088d8f44e423cc322077d40bf9aadf2))

- [**breaking**] `Sequence::step` takes the frame arrival time as an `Option<MonotonicInstant>`, now re-exported from `ironrdp-core` ([#1530](https://github.com/Devolutions/IronRDP/issues/1530)) ([6a499faece](https://github.com/Devolutions/IronRDP/commit/6a499faece8911e50a715a3fb08d4fd8e7d7dc87))

- Add `ClientConnector::with_cluster_data` and `ClientConnector::with_load_balance_info` to send GCC Client Cluster Data and load-balancing info in the X.224 Connection Request ([#1781](https://github.com/Devolutions/IronRDP/issues/1781)) ([14ef4fd49f](https://github.com/Devolutions/IronRDP/commit/14ef4fd49fcf950169806866ee67db0c49662cfc))

- [**breaking**] Add `Config::support_dyn_vc_gfx_protocol` to advertise Graphics Pipeline Extension support in the early capability flags ([#1237](https://github.com/Devolutions/IronRDP/issues/1237)) ([5bdb67980c](https://github.com/Devolutions/IronRDP/commit/5bdb67980cb98b070076acbff802254316e786de))

- [**breaking**] End the connection sequence in the new `ClientConnectorState::Redirected` and `ConnectionActivationState::Redirected` states when the server sends a Server Redirection PDU, with `ConnectionOutcome`, `ClientConnectorState::take_outcome` and `ClientConnector::with_redirection_password_cookie` to follow it ([#2208](https://github.com/Devolutions/IronRDP/issues/2208)) ([485657a6ec](https://github.com/Devolutions/IronRDP/commit/485657a6eca682a0356e100a9fda229342861fd7))

- [**breaking**] The `ConnectionActivationState::ConnectionFinalization` and `ConnectionActivationState::Finalized` variants carry the negotiated input flags, static channel chunk size, Refresh Rect and Suppress Output support, and window support level ([#1488](https://github.com/Devolutions/IronRDP/issues/1488)) ([9bcf13438c](https://github.com/Devolutions/IronRDP/commit/9bcf13438cb068b53a8cb0dc23477c498727d49f)) ([#1521](https://github.com/Devolutions/IronRDP/issues/1521)) ([20e2d414e5](https://github.com/Devolutions/IronRDP/commit/20e2d414e5ac060db25a100ed219f417e19f79b2)) ([#1622](https://github.com/Devolutions/IronRDP/issues/1622)) ([4e3903fbbe](https://github.com/Devolutions/IronRDP/commit/4e3903fbbef2904505f35e3437a7106807ac5987)) ([#1631](https://github.com/Devolutions/IronRDP/issues/1631)) ([0c3fbe78b4](https://github.com/Devolutions/IronRDP/commit/0c3fbe78b4366533b9fcea046b2b53654e003a72))

### <!-- 4 -->Bug Fixes

- During reactivation, keep waiting for Demand Active after a Set Error Info PDU without an error, and report the server's disconnect reason otherwise ([#1467](https://github.com/Devolutions/IronRDP/issues/1467)) ([f57d38ff74](https://github.com/Devolutions/IronRDP/commit/f57d38ff74624b99ebcc1369c220b646dd261b71))

- Answer the connect-time Bandwidth Measure Stop, which FreeRDP-based servers such as GNOME Remote Desktop wait for before licensing, with a byte count and interval measured from frame arrival times, and ignore requests outside the connect-time phase ([#1465](https://github.com/Devolutions/IronRDP/issues/1465)) ([f736b4e8b9](https://github.com/Devolutions/IronRDP/commit/f736b4e8b901f8889435449c26421dd45ec05bf4)) ([#1530](https://github.com/Devolutions/IronRDP/issues/1530)) ([6a499faece](https://github.com/Devolutions/IronRDP/commit/6a499faece8911e50a715a3fb08d4fd8e7d7dc87)) ([#1559](https://github.com/Devolutions/IronRDP/issues/1559)) ([36a848e085](https://github.com/Devolutions/IronRDP/commit/36a848e08571c76c0c3d1ef9cce899e0c99c9001))

- Advertise the surface command, bitmap codec and frame acknowledge capabilities only when the configuration includes a bitmap codec, so legacy servers keep sending basic bitmap updates ([#1860](https://github.com/Devolutions/IronRDP/issues/1860)) ([0d493e5aa0](https://github.com/Devolutions/IronRDP/commit/0d493e5aa070179f0ddc3cd548ebbd6ca5e1f349))

### <!-- 7 -->Build

- [**breaking**] Update the public `sspi` dependency to 0.23 ([#2080](https://github.com/Devolutions/IronRDP/issues/2080)) ([62246b364a](https://github.com/Devolutions/IronRDP/commit/62246b364a0282bab85087f658a81fe4207b6b31))

- Raise the minimum supported Rust version to 1.94 ([#1495](https://github.com/Devolutions/IronRDP/issues/1495)) ([0aeea76e95](https://github.com/Devolutions/IronRDP/commit/0aeea76e95e6b6b590d65be353dd00596d50a895))

- [**breaking**] Update `ironrdp-core` public dependency to 0.3

- [**breaking**] Update `ironrdp-pdu` public dependency to 0.10

- [**breaking**] Update `ironrdp-svc` public dependency to 0.9

## [[0.10.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.9.0...ironrdp-connector-v0.10.0)] - 2026-07-10

### <!-- 0 -->Security

- [**breaking**] Send NetworkAutoDetect over the MCS message channel ([#1348](https://github.com/Devolutions/IronRDP/issues/1348)) ([8a1fd0118e](https://github.com/Devolutions/IronRDP/commit/8a1fd0118e0bac214c9050b6ca6b36a040046dd3)) 

  Corrects Network Auto-Detect framing and routing to match MS-RDPBCGR by
  moving it off the I/O channel slow-path Share Data PDUs and onto the MCS
  message channel with the required Basic Security Header
  (SEC_AUTODETECT_REQ / SEC_AUTODETECT_RSP). This aligns IronRDP with
  mstsc/xfreerdp behavior and enables both connect-time and continuous
  auto-detection to actually function.

### <!-- 4 -->Bug Fixes

- Stay in CapabilitiesExchange when activation handles DeactivateAll ([#1371](https://github.com/Devolutions/IronRDP/issues/1371)) ([a4fde9fc50](https://github.com/Devolutions/IronRDP/commit/a4fde9fc50f41d1534f32e619bbe0bbbddc64f25)) 

- Propagate caller location through error constructor helpers ([#1392](https://github.com/Devolutions/IronRDP/issues/1392)) ([d6990d81a1](https://github.com/Devolutions/IronRDP/commit/d6990d81a17e8349e52768ad8a82f673b1e1462d)) 

  The error constructor helpers in several crates wrap the #[track_caller]
  ironrdp_error::Error::new, but were not themselves marked
  #[track_caller]. As a result, the captured location pointed at the
  helper body instead of the real call site, giving misleading "@
  file:line" info in error reports.

- Reduce dependency on ironrdp-connector ([#1419](https://github.com/Devolutions/IronRDP/issues/1419)) ([5c22f86a71](https://github.com/Devolutions/IronRDP/commit/5c22f86a7150bc10c26a3be39bfaebf84c67d781)) 

  Removes the leftover legacy modules and moves actually useful utilities to ironrdp-pdu crate.

- [**breaking**] Rework the connection activation API ([#1435](https://github.com/Devolutions/IronRDP/issues/1435)) ([c6a0286dcb](https://github.com/Devolutions/IronRDP/commit/c6a0286dcb49d9ac54c65c4f9325b41e05d541b8)) 

  Introduces a ConnectionActivationFactory (exposed on ConnectionResult)
  that builds a fresh ConnectionActivationSequence per
  Deactivation-Reactivation, replacing ConnectionActivationSequence::reset_clone,
  and turns Deactivate-All handling into a bare signal so consumers own the
  activation sequence.

### <!-- 7 -->Build

- Align sspi and picky dependencies ([#1385](https://github.com/Devolutions/IronRDP/issues/1385)) ([0a461b5d36](https://github.com/Devolutions/IronRDP/commit/0a461b5d366677fd2f0f664a4f0074e4ab697c42)) 



## [[0.9.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.8.0...ironrdp-connector-v0.9.0)] - 2026-05-27

### <!-- 1 -->Features

- Add alternate_shell and work_dir configuration support ([#1095](https://github.com/Devolutions/IronRDP/issues/1095)) ([a33d27fe67](https://github.com/Devolutions/IronRDP/commit/a33d27fe6771a5a155161ef40a04de88803dd84c)) 

  Add support for configuring `alternate_shell` and `work_dir` fields in
  ClientInfoPdu, which are used by:
    - CyberArk PSM (Privileged Session Manager) for session tokens
    - Remote application scenarios (RemoteApp)
    - Custom shell configurations

- Dispatch multitransport PDUs on IO channel ([#1096](https://github.com/Devolutions/IronRDP/issues/1096)) ([7853e3cc6f](https://github.com/Devolutions/IronRDP/commit/7853e3cc6f26acaf3da000c6177ca3cef6ef85fd)) 

  `decode_io_channel()` assumes all IO channel PDUs begin with
  a `ShareControlHeader`. Multitransport Request PDUs use a
  `BasicSecurityHeader` with `SEC_TRANSPORT_REQ` instead ([MS-RDPBCGR]
  2.2.15.1).
  
  This adds a peek-based dispatch: check the first `u16`
  for`TRANSPORT_REQ`, decode as `MultitransportRequestPdu` if set,
  otherwise fall through to the existing `decode_share_control()` path
  unchanged.
  
  The new variant is propagated through `ProcessorOutput` and
  'ActiveStageOutput` so applications can handle multitransport requests.
  Client and web consumers log the request (no UDP transport yet).

- Add bulk compression and wire negotiation ([ebf5da5f33](https://github.com/Devolutions/IronRDP/commit/ebf5da5f3380a3355f6c95814d669f8190425ded)) 

  Add support for bulk compression negotiation and payload decoding,
  including connector plumbing, CLI configuration flags, and integration
  updates across tests/examples/FFI/web.

- Advertise multitransport channel in GCC blocks ([#1092](https://github.com/Devolutions/IronRDP/issues/1092)) ([4f5fdd3628](https://github.com/Devolutions/IronRDP/commit/4f5fdd3628f4d0d2c2a4116e4e45269d802740f1)) 

  Add multitransport_flags config option to populate the
  MultiTransportChannelData GCC block during connection negotiation.
  When None (the default), behavior is unchanged.

### <!-- 4 -->Bug Fixes

- Propagate negotiated share_id to all outgoing ShareDataPdu ([#1147](https://github.com/Devolutions/IronRDP/issues/1147)) ([2b24e9664d](https://github.com/Devolutions/IronRDP/commit/2b24e9664dd05620ff63a24d092377477fdde863)) 

- Advertise all colour depths per FreeRDP pattern ([#1231](https://github.com/Devolutions/IronRDP/issues/1231)) ([2fa7c648cb](https://github.com/Devolutions/IronRDP/commit/2fa7c648cb4a2fc9c75d967ac878f817900dc1b8)) 

  Replace the per-depth supportedColorDepths bitmask with an unconditional
  BPP32 | BPP24 | BPP16 | BPP15, following FreeRDP's approach of treating
  the field as a capability set rather than a preferred-depth indicator
  (libfreerdp/core/settings.c).
  
  The preferred depth is expressed via the two dedicated fields:
  - highColorDepth: now derived from the configured depth (15 →
  Rgb555Bpp16 / 0x0F, 16 → Rgb565Bpp16 / 0x10, else Bpp24 / 0x18),
  matching FreeRDP's ColorDepthToHighColor()
  - WANT_32_BPP_SESSION earlyCapabilityFlag: unchanged, set only for 32bpp
  
  Previously, a client configured for 24bpp advertised BPP24 only. Modern
  Windows hosts (Server 2012+) dropped 24bpp RDP support and reset the
  connection instead of negotiating down, leaving no usable depth. With
  all four bits always advertised the server can freely negotiate to the
  highest depth it supports.

- Surface actual PDU type when an unexpected Share Control PDU arrives ([#1236](https://github.com/Devolutions/IronRDP/issues/1236)) ([78effb3f91](https://github.com/Devolutions/IronRDP/commit/78effb3f9144a482395be738b2c9fd4d909b7b89)) 

- Handle ServerDeactivateAll during CapabilitiesExchange ([#1254](https://github.com/Devolutions/IronRDP/issues/1254)) ([9cb5439b4a](https://github.com/Devolutions/IronRDP/commit/9cb5439b4a78c4a7facc854464894c7893f6a926)) 

  Some RDP servers (notably GNOME Remote Desktop / grd) send a
  ServerDeactivateAll PDU before ServerDemandActive during the initial
  Capabilities Exchange phase. This is valid per MS-RDPBCGR §1.3.1.3
  (Deactivation-Reactivation Sequence).
  
  Previously this caused a hard error:
  "unexpected Share Control Pdu (expected ServerDemandActive)"
  
  Now the connector skips the DeactivateAll and waits for the next PDU.

### <!-- 5 -->Performance

- Reduce connection latency when Kerberos is disabled ([#1107](https://github.com/Devolutions/IronRDP/issues/1107)) ([b1b0289e00](https://github.com/Devolutions/IronRDP/commit/b1b0289e0067228dbc973d3edb0e27136f7ca52a)) 

### <!-- 7 -->Build

- Upgrade to sspi 0.21 and picky rc.23 ([#1296](https://github.com/Devolutions/IronRDP/issues/1296)) ([d5b3fa7db8](https://github.com/Devolutions/IronRDP/commit/d5b3fa7db8a4ce74ac9a9aaff3064faf6cb6c920)) 


## [[0.8.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.7.1...ironrdp-connector-v0.8.0)] - 2025-12-18

### <!-- 7 -->Build

- Bump picky and sspi ([#1028](https://github.com/Devolutions/IronRDP/issues/1028)) ([5bd319126d](https://github.com/Devolutions/IronRDP/commit/5bd319126d32fbd8e505508e27ab2b1a18a83d04)) 

  This fixes build issues with some dependencies.

## [[0.7.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.7.0...ironrdp-connector-v0.7.1)] - 2025-09-04

### <!-- 1 -->Features

- Add API to retrieve registered SVC processors (#938) ([17833fe009](https://github.com/Devolutions/IronRDP/commit/17833fe009279823c4076d3e2e0c7d063fd24a43)) 

## [[0.7.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.6.0...ironrdp-connector-v0.7.0)] - 2025-08-29

### <!-- 1 -->Features

- Add QOI image codec ([613fd51f26](https://github.com/Devolutions/IronRDP/commit/613fd51f26315d8212662c46f8e625c541e4bb59)) 

  The Quite OK Image format ([1]) losslessly compresses images to a similar size
  of PNG, while offering 20x-50x faster encoding and 3x-4x faster decoding.

- Add QOIZ image codec ([87df67fdc7](https://github.com/Devolutions/IronRDP/commit/87df67fdc76ff4f39d4b83521e34bf3b5e2e73bb)) 

  Add a new QOIZ codec for SetSurface command. The PDU data contains the same
  data as the QOI codec, with zstd compression.

- Add an option to specify a timezone (#917) ([6fab9f8228](https://github.com/Devolutions/IronRDP/commit/6fab9f8228578b3c78db131b3c2e0526352116a9)) 

### <!-- 4 -->Bug Fixes

- [**breaking**] Rename option no_server_pointer into enable_server_pointer ([218fed03c7](https://github.com/Devolutions/IronRDP/commit/218fed03c7993af0f958453e3944c58bcf9f43cb)) 

- [**breaking**] Rename option no_audio_playback into enable_audio_playback ([5d8a487001](https://github.com/Devolutions/IronRDP/commit/5d8a487001c1280cbaf9f581f2a9a2f47d187bf0)) 

### <!-- 7 -->Build

- Bump rand to 0.9 ([de0877188c](https://github.com/Devolutions/IronRDP/commit/de0877188cbb3692c3ce0d9a72f6e96d515cde1f)) 

- Bump picky from 7.0.0-rc.16 to 7.0.0-rc.17 (#941) ([fe31cf2c57](https://github.com/Devolutions/IronRDP/commit/fe31cf2c574e0b06177a931db4cac95ea9cfbe7e)) 

## [[0.6.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.5.1...ironrdp-connector-v0.6.0)] - 2025-07-08

### Build

- [**breaking**] Update sspi dependency (#839) ([33530212c4](https://github.com/Devolutions/IronRDP/commit/33530212c42bf28c875ac078ed2408657831b417)) 

## [[0.5.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.5.0...ironrdp-connector-v0.5.1)] - 2025-07-03

### <!-- 7 -->Build

- Bump picky to v7.0.0-rc.15 (#850) ([eca256ae10](https://github.com/Devolutions/IronRDP/commit/eca256ae10c52c4a42e7e77d41c0a1d6c180ebf3)) 

## [[0.5.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.4.0...ironrdp-connector-v0.5.0)] - 2025-05-27

### <!-- 1 -->Features

- Add no_audio_playback flag to Config struct ([9f0edcc4c9](https://github.com/Devolutions/IronRDP/commit/9f0edcc4c9c49d59cc10de37f920aae073e3dd8a)) 

  Enable audio playback on the client.

### <!-- 4 -->Bug Fixes

- [**breaking**] Fix name of client address field (#754) ([bdde2c76de](https://github.com/Devolutions/IronRDP/commit/bdde2c76ded7315f7bc91d81a0909a1cb827d870)) 

- Inject socket local address for the client addr (#759) ([712da42ded](https://github.com/Devolutions/IronRDP/commit/712da42dedc193239e457d8270d33cc70bd6a4b9)) 

  We used to inject the resolved target server address, but that is not
  what is expected. Server typically ignores this field so this was not a
  problem up until now.

### Refactor

- [**breaking**] Add supported codecs in BitmapConfig ([f03ee393a3](https://github.com/Devolutions/IronRDP/commit/f03ee393a36906114b5bcba0e88ebc6869a99785)) 


## [[0.4.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.3.2...ironrdp-connector-v0.4.0)] - 2025-03-12

### <!-- 7 -->Build

- Bump ironrdp-pdu


## [[0.3.2](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.3.1...ironrdp-connector-v0.3.2)] - 2025-03-07

### Build

- Update dependencies


## [[0.3.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.3.0...ironrdp-connector-v0.3.1)] - 2025-01-30

### <!-- 4 -->Bug Fixes

- Decrease log verbosity for license exchange ([#655](https://github.com/Devolutions/IronRDP/issues/655)) ([c8597733fe](https://github.com/Devolutions/IronRDP/commit/c8597733fe9998318764064c3682506bf82026d2)) 


## [[0.3.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.2.2...ironrdp-connector-v0.3.0)] - 2025-01-28

### <!-- 1 -->Features

- Support license caching ([#634](https://github.com/Devolutions/IronRDP/issues/634)) ([dd221bf224](https://github.com/Devolutions/IronRDP/commit/dd221bf22401c4635798ec012724cba7e6d503b2)) 

  Adds support for license caching by storing the license obtained
  from SERVER_UPGRADE_LICENSE message and sending
  CLIENT_LICENSE_INFO if a license requested by the server is already
  stored in the cache.

### <!-- 6 -->Documentation

- Use CDN URLs instead of the blob storage URLs for Devolutions logo ([#631](https://github.com/Devolutions/IronRDP/issues/631)) ([dd249909a8](https://github.com/Devolutions/IronRDP/commit/dd249909a894004d4f728d30b3a4aa77a0f8193b)) 

### <!-- 7 -->Build

- Bump picky from 7.0.0-rc.11 to 7.0.0-rc.12 ([#639](https://github.com/Devolutions/IronRDP/issues/639)) ([a16a131e43](https://github.com/Devolutions/IronRDP/commit/a16a131e4301e0dfafe8f3b73e1a75a3a06cfdc7)) 


## [[0.2.2](https://github.com/Devolutions/IronRDP/compare/ironrdp-connector-v0.2.1...ironrdp-connector-v0.2.2)] - 2024-12-14

### Other

- Symlinks to license files in packages ([#604](https://github.com/Devolutions/IronRDP/pull/604)) ([6c2de344c2](https://github.com/Devolutions/IronRDP/commit/6c2de344c2dd93ce9621834e0497ed7c3bfaf91a)) 

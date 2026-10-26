# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.8.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-dvc-v0.7.0...ironrdp-dvc-v0.8.0)] - 2026-07-10

### <!-- 1 -->Features

- Expose dynamic channel accessors ([#1368](https://github.com/Devolutions/IronRDP/issues/1368)) ([985d353543](https://github.com/Devolutions/IronRDP/commit/985d353543cf45eacfe0cc57aca86502665a3a44)) 

### <!-- 7 -->Build

- [**breaking**] Update `ironrdp-pdu` public dependency to 0.9

- [**breaking**] Update `ironrdp-svc` public dependency to 0.8



## [[0.7.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-dvc-v0.6.0...ironrdp-dvc-v0.7.0)] - 2026-06-05

### <!-- 4 -->Bug Fixes

- [**breaking**] Add channel_id parameter to DvcChannelListener::create ([#1358](https://github.com/Devolutions/IronRDP/issues/1358)) ([f21470c6dc](https://github.com/Devolutions/IronRDP/commit/f21470c6dc20e1b10b4bbf750a406644479a4b35)) 

  Updates the dynamic virtual channel (DVC) client listener interface in ironrdp-dvc to pass the channel_id (from the incoming DYNVC_CREATE_REQ) into the listener’s create method, enabling listeners to differentiate/control per-instance behavior based on the negotiated dynamic channel ID.



## [[0.6.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-dvc-v0.5.0...ironrdp-dvc-v0.6.0)] - 2026-05-27

### <!-- 1 -->Features

- Implement ECHO virtual channel ([#1109](https://github.com/Devolutions/IronRDP/issues/1109)) ([6f6496ad29](https://github.com/Devolutions/IronRDP/commit/6f6496ad29395099563d50417d6dfff623914ee6)) 

- Add DvcChannelListener for multi-instance DVC support ([#1142](https://github.com/Devolutions/IronRDP/issues/1142)) ([28e8628f0e](https://github.com/Devolutions/IronRDP/commit/28e8628f0e3cea9f7723a73abf5fd7ed2da968f0)) 

- Close channel API for server and client ([#1302](https://github.com/Devolutions/IronRDP/issues/1302)) ([196d18dfaa](https://github.com/Devolutions/IronRDP/commit/196d18dfaa7ec899946bb90f4dcb8bad31872f48)) 

### <!-- 4 -->Bug Fixes

- Negotiate DVC version from server capabilities ([d094cbeb75](https://github.com/Devolutions/IronRDP/commit/d094cbeb7501c83fc6ad5401ba69d22f79d6657c)) 

  The client was hardcoded to respond with CapsVersion::V1 regardless
  of what the server requested. Servers that require V2 or V3 (such
  as XRDP) would reject the channel with "Dynamic Virtual Channel
  version 1 is not supported."
  
  Echo the server's requested version in the capabilities response
  instead. This correctly handles V1, V2, and V3 depending on what
  the server advertises. When a Create arrives before Capabilities
  (fallback path), default to V2 as the most broadly compatible
  version.
  
  Also bump the server-side capabilities request from V1 to V2 to
  advertise priority charge support.
  
  Add CapabilitiesRequestPdu::version() accessor to expose the
  server's requested version from the parsed PDU.

## [[0.4.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-dvc-v0.4.0...ironrdp-dvc-v0.4.1)] - 2025-09-04

### <!-- 1 -->Features

- Add API to attach dynamic channels to an already created `DrdynvcClient` instance (#938) ([17833fe009](https://github.com/Devolutions/IronRDP/commit/17833fe009279823c4076d3e2e0c7d063fd24a43)) 

## [[0.3.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-dvc-v0.3.0...ironrdp-dvc-v0.3.1)] - 2025-06-27

### <!-- 1 -->Features

- Add `DynamicChannelSet::get_by_channel_id` (#791) ([5482365655](https://github.com/Devolutions/IronRDP/commit/5482365655e5c171cd967eda401b01161a9f6602)) 

## [[0.2.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-dvc-v0.1.3...ironrdp-dvc-v0.2.0)] - 2025-03-12

### <!-- 7 -->Build

- Bump ironrdp-pdu

## [[0.1.3](https://github.com/Devolutions/IronRDP/compare/ironrdp-dvc-v0.1.2...ironrdp-dvc-v0.1.3)] - 2025-03-12

### <!-- 7 -->Build

- Update dependencies (#695) ([c21fa44fd6](https://github.com/Devolutions/IronRDP/commit/c21fa44fd6f3c6a6b74788ff68e83133c1314caa)) 

## [[0.1.2](https://github.com/Devolutions/IronRDP/compare/ironrdp-dvc-v0.1.1...ironrdp-dvc-v0.1.2)] - 2025-01-28

### <!-- 1 -->Features

- Some debug statement on invalid channel state ([265b661b81](https://github.com/Devolutions/IronRDP/commit/265b661b81af19860c4564ba35ad22564f61cd02)) 

- Add CreationStatus::NOT_FOUND ([ab8a87d942](https://github.com/Devolutions/IronRDP/commit/ab8a87d94259a4e1df5f3a2a8d4c592377857b21)) 

  For completeness, this error is used by FreeRDP.

### <!-- 6 -->Documentation

- Use CDN URLs instead of the blob storage URLs for Devolutions logo (#631) ([dd249909a8](https://github.com/Devolutions/IronRDP/commit/dd249909a894004d4f728d30b3a4aa77a0f8193b)) 

## [[0.1.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-dvc-v0.1.0...ironrdp-dvc-v0.1.1)] - 2024-12-14

### Other

- Symlinks to license files in packages ([#604](https://github.com/Devolutions/IronRDP/pull/604)) ([6c2de344c2](https://github.com/Devolutions/IronRDP/commit/6c2de344c2dd93ce9621834e0497ed7c3bfaf91a)) 

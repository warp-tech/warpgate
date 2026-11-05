# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.12.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-async-v0.11.0...ironrdp-async-v0.12.0)] - 2026-10-27

### <!-- 7 -->Build

- [**breaking**] Update `ironrdp-connector` public dependency to 0.12

- [**breaking**] Update `ironrdp-pdu` public dependency to 0.11



## [[0.11.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-async-v0.10.0...ironrdp-async-v0.11.0)] - 2026-10-23

### <!-- 1 -->Features

- [**breaking**] `connect_finalize` returns a `ConnectionOutcome` that is either `Connected` or `Redirected` when the server sends a Server Redirection PDU ([#2208](https://github.com/Devolutions/IronRDP/issues/2208)) ([485657a6ec](https://github.com/Devolutions/IronRDP/commit/485657a6eca682a0356e100a9fda229342861fd7))

- `connect_finalize` declines a server's multitransport request with `E_ABORT` and continues over TCP; `connect_finalize_with_multitransport` and `complete_multitransport` let the application set up the transport instead ([#1098](https://github.com/Devolutions/IronRDP/issues/1098)) ([e45fbfe0f5](https://github.com/Devolutions/IronRDP/commit/e45fbfe0f597011706e77fc174ca14e5e9d435b9)) ([#1858](https://github.com/Devolutions/IronRDP/issues/1858)) ([7036fb8c7e](https://github.com/Devolutions/IronRDP/commit/7036fb8c7ef32f71b456745902e14d34008c7add))

- Add `perform_credssp` to run the CredSSP exchange on an upgraded stream without a `ClientConnector` ([#1503](https://github.com/Devolutions/IronRDP/issues/1503)) ([a7cc067d50](https://github.com/Devolutions/IronRDP/commit/a7cc067d5069cbbcb13bae3e0561c0611da3bcf6))

- `connect_begin` no longer requires the stream to be `Sync` ([#1505](https://github.com/Devolutions/IronRDP/issues/1505)) ([5c1816244e](https://github.com/Devolutions/IronRDP/commit/5c1816244e83187a04249e9d9c240d096cb78f55))

- Add `Framed::last_read_at` and pass each frame's arrival time to `Sequence::step` so the connector can measure bandwidth ([#1530](https://github.com/Devolutions/IronRDP/issues/1530)) ([6a499faece](https://github.com/Devolutions/IronRDP/commit/6a499faece8911e50a715a3fb08d4fd8e7d7dc87))

### <!-- 4 -->Bug Fixes

- `Framed::read_by_hint` returns an error instead of spinning forever when a hint reports a zero-length unmatched PDU ([#1556](https://github.com/Devolutions/IronRDP/issues/1556)) ([2d2c37fc21](https://github.com/Devolutions/IronRDP/commit/2d2c37fc21bd7f089fbbca41831abba14fa2b72b))

### <!-- 7 -->Build

- Bump the minimum supported Rust version to 1.94 ([#1495](https://github.com/Devolutions/IronRDP/issues/1495)) ([0aeea76e95](https://github.com/Devolutions/IronRDP/commit/0aeea76e95e6b6b590d65be353dd00596d50a895))

- [**breaking**] Update `ironrdp-connector` public dependency to 0.11

- [**breaking**] Update `ironrdp-core` public dependency to 0.3

- [**breaking**] Update `ironrdp-pdu` public dependency to 0.10



## [[0.10.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-async-v0.9.0...ironrdp-async-v0.10.0)] - 2026-07-10

### <!-- 7 -->Build

- [**breaking**] Update `ironrdp-connector` public dependency to 0.10

- [**breaking**] Update `ironrdp-pdu` public dependency to 0.9



## [[0.9.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-async-v0.8.0...ironrdp-async-v0.9.0)] - 2026-05-27

### <!-- 4 -->Bug Fixes

- [**breaking**] Make Framed::read_exact crate-private ([#1247](https://github.com/Devolutions/IronRDP/issues/1247)) ([d02d24aad4](https://github.com/Devolutions/IronRDP/commit/d02d24aad44039c0425a022f1bd9677800706cea)) 


## [[0.8.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-async-v0.7.0...ironrdp-async-v0.8.0)] - 2025-12-18

### <!-- 4 -->Bug Fixes

- [**breaking**] Use static dispatch for NetworkClient trait ([#1043](https://github.com/Devolutions/IronRDP/issues/1043)) ([bca6d190a8](https://github.com/Devolutions/IronRDP/commit/bca6d190a870708468534d224ff225a658767a9a)) 

  - Rename `AsyncNetworkClient` to `NetworkClient`
  - Replace dynamic dispatch (`Option<&mut dyn ...>`) with static dispatch
  using generics (`&mut N where N: NetworkClient`)
  - Reorder `connect_finalize` parameters for consistency across crates

## [[0.3.2](https://github.com/Devolutions/IronRDP/compare/ironrdp-async-v0.3.1...ironrdp-async-v0.3.2)] - 2025-03-12

### <!-- 7 -->Build

- Bump ironrdp-pdu

## [[0.3.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-async-v0.3.0...ironrdp-async-v0.3.1)] - 2025-03-12

### <!-- 7 -->Build

- Update dependencies (#695) ([c21fa44fd6](https://github.com/Devolutions/IronRDP/commit/c21fa44fd6f3c6a6b74788ff68e83133c1314caa)) 

## [[0.3.0](https://github.com/Devolutions/IronRDP/compare/ironrdp-async-v0.2.1...ironrdp-async-v0.3.0)] - 2025-01-28

### <!-- 4 -->Changed

- Remove unmatched parameter from `Framed::read_by_hint` function ([63963182b5](https://github.com/Devolutions/IronRDP/commit/63963182b5af6ad45dc638e93de4b8a0b565c7d3)) 

### <!-- 6 -->Documentation

- Use CDN URLs instead of the blob storage URLs for Devolutions logo (#631) ([dd249909a8](https://github.com/Devolutions/IronRDP/commit/dd249909a894004d4f728d30b3a4aa77a0f8193b)) 


## [[0.2.1](https://github.com/Devolutions/IronRDP/compare/ironrdp-async-v0.2.0...ironrdp-async-v0.2.1)] - 2024-12-14

### Other

- Symlinks to license files in packages ([#604](https://github.com/Devolutions/IronRDP/pull/604)) ([6c2de344c2](https://github.com/Devolutions/IronRDP/commit/6c2de344c2dd93ce9621834e0497ed7c3bfaf91a)) 

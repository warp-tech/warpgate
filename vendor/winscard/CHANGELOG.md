# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.4.0](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.3.4...winscard-v0.4.0)] - 2026-10-01

### <!-- 1 -->Features

- Add the `Cache` trait for plugging in a shared, card-scoped smart card resource manager cache ([#755](https://github.com/Devolutions/sspi-rs/issues/755)) ([37ebbb8dcd](https://github.com/Devolutions/sspi-rs/commit/37ebbb8dcd07de8bdbacf2662508683213d6590c))
- [**breaking**] `ScardContext::new` now takes a `card_id: Uuid` and a `Box<dyn Cache>`, and seeds the emulated card's cache items only once per card so later minidriver writes are preserved across contexts ([#755](https://github.com/Devolutions/sspi-rs/issues/755)) ([37ebbb8dcd](https://github.com/Devolutions/sspi-rs/commit/37ebbb8dcd07de8bdbacf2662508683213d6590c))
- [**breaking**] `ScardContext` no longer implements `Clone` ([#755](https://github.com/Devolutions/sspi-rs/issues/755)) ([37ebbb8dcd](https://github.com/Devolutions/sspi-rs/commit/37ebbb8dcd07de8bdbacf2662508683213d6590c))
- [**breaking**] `SmartCard::new` now takes a `card_id: Uuid`, which is reported as the stable CHUID GUID instead of a random value ([#755](https://github.com/Devolutions/sspi-rs/issues/755)) ([37ebbb8dcd](https://github.com/Devolutions/sspi-rs/commit/37ebbb8dcd07de8bdbacf2662508683213d6590c))
- `ScardContext` cache reads and writes now honor the freshness counter ([#755](https://github.com/Devolutions/sspi-rs/issues/755)) ([37ebbb8dcd](https://github.com/Devolutions/sspi-rs/commit/37ebbb8dcd07de8bdbacf2662508683213d6590c))



## [[0.3.4](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.3.3...winscard-v0.3.4)] - 2026-09-15

### <!-- 7 -->Build

- Update `picky` to 7.0.0-rc.26 for compatibility with `sspi` ([#712](https://github.com/Devolutions/sspi-rs/issues/712)) ([847304fe35](https://github.com/Devolutions/sspi-rs/commit/847304fe35859a8aec401a50033e39df4c7235f4))



## [[0.3.3](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.3.2...winscard-v0.3.3)] - 2026-06-26

### <!-- 7 -->Build

- Update RC and crypto dependencies to latest versions ([#699](https://github.com/Devolutions/sspi-rs/issues/699)) ([c5922db0f4](https://github.com/Devolutions/sspi-rs/commit/c5922db0f4921323856a041c5e2987e569e62056)) 



## [[0.3.2](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.3.1...winscard-v0.3.2)] - 2026-04-29

### <!-- 7 -->Build

- Upgrade picky and RustCrypto dependencies ([#655](https://github.com/Devolutions/sspi-rs/issues/655)) ([26765bbe1f](https://github.com/Devolutions/sspi-rs/commit/26765bbe1f57f490ba1c37703eda8267c3b2dfb6)) 



## [[0.3.1](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.3.0...winscard-v0.3.1)] - 2026-04-27

Minor update.

## [[0.3.0](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.2.5...winscard-v0.3.0)] - 2026-03-13

### <!-- 1 -->Features

- [**breaking**] Introduce UTF-16 strings helpers and refactor auth identity types ([#606](https://github.com/Devolutions/sspi-rs/issues/606)) ([1bfee5e545](https://github.com/Devolutions/sspi-rs/commit/1bfee5e545c4a97ae631fe734b3bcf45b4b486f9)) 

## [[0.2.5](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.2.4...winscard-v0.2.5)] - 2025-12-11

### <!-- 4 -->Bug Fixes

- Use `String::from_utf16_lossy` over `String::from_utf16` to avoid changing the meaning of some buffers in case of invalid UTF-16 input ([#568](https://github.com/Devolutions/sspi-rs/issues/568)) ([a4889f5b1e](https://github.com/Devolutions/sspi-rs/commit/a4889f5b1e802395b09954f5846d1a6433546281)) 

## [[0.2.4](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.2.3...winscard-v0.2.4)] - 2025-11-18

### <!-- 7 -->Build

- No zlib for flate2 on WASM ([#547](https://github.com/Devolutions/sspi-rs/issues/547)) ([9867f451f0](https://github.com/Devolutions/sspi-rs/commit/9867f451f0ab75204f900977c85ff387c31d1423)) 

  This PR switches flate2 to the default `miniz_oxide` (Rust-only
  implementation) for WASM and keeps using system `zlib` otherwise.
  
  The zlib backends are described
  [here](https://github.com/rust-lang/flate2-rs?tab=readme-ov-file#backends).

## [[0.2.3](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.2.2...winscard-v0.2.3)] - 2025-10-06

### <!-- 1 -->Features

- System-provided smart card credentials (#483) ([786aae5ea1](https://github.com/Devolutions/sspi-rs/commit/786aae5ea14b76a4bcf262ed10a0ec9ca153ae1f)) 

- Data sigining using scard (#491) ([6728fb525c](https://github.com/Devolutions/sspi-rs/commit/6728fb525cedc96b395eed5dc4a8ea357b036b36)) 

- Automatic winscard cache initialization ([b799edf978](https://github.com/Devolutions/sspi-rs/commit/b799edf978834c2197d475d5c21d92d293180a17)) 

### <!-- 4 -->Bug Fixes

- General authenticate command validation (#509) ([748fa67c63](https://github.com/Devolutions/sspi-rs/commit/748fa67c63d4d3410e533d02c87f1bc253c3f1a0)) 

### <!-- 7 -->Build

- Bump the crypto dependencies (#489) ([1ecba764ec](https://github.com/Devolutions/sspi-rs/commit/1ecba764ec3b04e147ae76d018414afa8bec5f88)) 

## [[0.2.2](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.2.1...winscard-v0.2.2)] - 2025-08-26

### <!-- 4 -->Bug Fixes

- Incorrect `SCARD_IO_REQUEST` usage (#487) ([7e23472a7a](https://github.com/Devolutions/sspi-rs/commit/7e23472a7af347460a89379f28dc56701f7be97e)) 

  Fixes incorrect [`SCARD_IO_REQUEST`](https://learn.microsoft.com/en-us/windows/win32/secauthn/scard-io-request) usage.

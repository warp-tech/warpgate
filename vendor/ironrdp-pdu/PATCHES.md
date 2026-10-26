Fork of `ironrdp-pdu` 0.9.0.

## Permissive Client Core Data `keyboardType`

Backport of upstream [PR #1689][1] (merged as `c74e7c5c`, unreleased as of 0.9.0), with
the path of `src/rdp/capability_sets/input.rs` adjusted to 0.9.0's layout. 0.9.0 decodes
`keyboardType` as a closed enum of 1–7, so a client sending 8 (Korean) or Windows' `0x51`
(generic HID keyboard) fails the whole Client Core Data parse and is dropped before the
connection starts (warpgate#2757). `KeyboardType` is now a `u32` newtype with named
constants, so `KeyboardType::IbmEnhanced` becomes `KeyboardType::IBM_ENHANCED`.

`Cargo.toml` is the published one plus the vendored-code lint override. `warpgate.patch`
is the full source difference from 0.9.0.

Drop this fork once an `ironrdp-pdu` release (0.10+) carries #1689.

[1]: https://github.com/Devolutions/IronRDP/pull/1689

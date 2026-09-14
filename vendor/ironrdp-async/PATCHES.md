Fork of `ironrdp-async` 0.10.0.

## Credential-less CredSSP (interactive logon)

Companion to the `vendor/ironrdp-connector` fork: `perform_credssp_step` is the sole
caller of `CredsspSequence::init`, whose signature there gained a `credentialless: bool`
parameter. This fork only passes `connector.config.credssp_credentialless` through —
no other change. Drop it together with the connector fork once upstream exposes the
mode on `Config`.

## `Framed::read_by_hint` zero-length guard

Backport of upstream IronRDP's guard in `Framed::read_by_hint`: an unmatched frame whose
hint length is zero is rejected with `InvalidData` instead of being "skipped", which
consumed nothing and spun the reader at 100% CPU forever (warp-tech/warpgate#2585). Drop
once the vendored base is bumped past the upstream fix.

`Cargo.toml` additionally sets `[lints.rust] warnings = { level = "allow", priority = 1 }`
so this vendored path dependency's warnings don't surface in Warpgate's builds. This is
not in `warpgate.patch` (which is source-only); re-apply it by hand on re-vendor.

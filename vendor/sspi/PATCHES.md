Manifest-only fork of `sspi` 0.21.3.

Upstream pins a set of RustCrypto crates to release candidates purely to force transitive
resolution ("Pin transitive dependencies / TODO: Remove when stable versions will be
released"). Those crates now have stable releases, and the pins conflict with `russh`,
which resolves the same crates via caret requirements. `warpgate.patch` drops them and adds
a `[lints.rust] warnings = { level = "allow", priority = 1 }` so this vendored path
dependency's warnings don't surface in Warpgate's builds. No source is modified.

The pins also sit inside a `cfg(macos/ios)` target block, which looks unintended — Cargo
resolves every target into the lockfile, so they applied on Linux too.

Drop this fork once sspi publishes a release without the pins.

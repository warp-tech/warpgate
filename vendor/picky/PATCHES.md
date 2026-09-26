Manifest-only fork of `picky` 7.0.0-rc.25.

Upstream commit [74090c9][1] relaxes the RustCrypto release-candidate pins that now have
stable releases. It is not in a published release yet, and the pins it removes conflict
with `russh`, which resolves the same crates via caret requirements. `warpgate.patch`
replays that commit against the published manifest, and additionally adds a `[lints.rust]
warnings = "allow"` so this vendored path dependency's warnings don't surface in Warpgate's
builds. No source is modified.

Drop this fork once picky publishes a release containing 74090c9.

[1]: https://github.com/Devolutions/picky-rs/commit/74090c9d1ae301c8d46ed04f593acbfb3f5108e8

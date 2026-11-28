Fork of `winscard` 0.4.0.

## Relaxed `rsa` requirement

Upstream pins `rsa = "=0.10.0-rc.18"`; the fork changes it to `"0.10"` in `Cargo.toml`
and leaves the source untouched. See `vendor/picky/PATCHES.md` — `picky`, `sspi` and
`winscard` carry the same pin and are vendored together, and are dropped together.

`Cargo.toml` also gains `warnings = { level = "allow", priority = 1 }` under
`[lints.rust]`, so this vendored path dependency's warnings don't surface in Warpgate's
builds.

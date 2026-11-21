Fork of `sspi` 0.23.0.

## Relaxed `rsa` / `pkcs1` requirements

Upstream pins `rsa = "=0.10.0-rc.18"` and `pkcs1 = "=0.8.0-rc.4"`, which excludes the
stable `rsa` 0.10 that `russh` ≥ 0.65.2 requires. The fork changes those two requirements
to `"0.10"` / `"0.8"` in `Cargo.toml`; the source is untouched. See
`vendor/picky/PATCHES.md` — `picky`, `sspi` and `winscard` carry the same pin and are
vendored together.

Drop all three forks once upstream releases accept stable `rsa` 0.10 and
`ironrdp-connector` has moved to them.

`Cargo.toml` also gains `warnings = { level = "allow", priority = 1 }` under
`[lints.rust]`, so this vendored path dependency's warnings don't surface in Warpgate's
builds. Repository tooling files (CI, release config, toolchain pin) are omitted.

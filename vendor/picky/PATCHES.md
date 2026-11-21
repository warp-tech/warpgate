Fork of `picky` 7.0.0-rc.26.

## Relaxed `rsa` / `pkcs1` requirements

Upstream (through 7.0.0-rc.29) pins `rsa = "=0.10.0-rc.18"` and `pkcs1 = "=0.8.0-rc.4"`.
`russh` ≥ 0.65.2 requires the stable `rsa` 0.10 (which needs stable `pkcs1` 0.8), and Cargo
treats a release candidate and its final release as one semver-compatible line, so only
one can be in the graph. The fork changes those two requirements to `"0.10"` / `"0.8"` in
`Cargo.toml`; the source is untouched.

`sspi` and `winscard` carry the same pins and are vendored alongside for the same reason.
The version stays at rc.26 because `ironrdp-connector`, `sspi` and `winscard` all pin
`picky = "=7.0.0-rc.26"`.

Drop all three forks once upstream releases accept stable `rsa` 0.10 and
`ironrdp-connector` has moved to them.

`Cargo.toml` also gains `[lints.rust] warnings = "allow"`, so this vendored path
dependency's warnings don't surface in Warpgate's builds.

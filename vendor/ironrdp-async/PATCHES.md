Fork of `ironrdp-async` 0.12.0.

## Credential-less CredSSP (interactive logon)

Companion to the `vendor/ironrdp-connector` fork: `perform_credssp_step` is the sole
caller that builds the CredSSP sequence from `connector.config`, and now calls
`CredsspSequence::init_with_mode` with `connector.config.credssp_credentialless`. No other
change. Drop it together with the connector fork once upstream exposes the mode on
`Config`.

`Cargo.toml` is the published one plus `warnings = { level = "allow", priority = 1 }`
under `[lints.rust]`, so this vendored path dependency's warnings don't surface in
Warpgate's builds. That is not in `warpgate.patch` (which is source-only); re-apply it by
hand on re-vendor.

Fork of `ironrdp-connector` 0.10.0.

## Credential-less CredSSP (interactive logon)

Upstream hardcodes `CredSspMode::WithCredentials`, so every NLA connection delegates
`TSPasswordCreds` and the server auto-logs the session on with them. Warpgate's
interactive-logon target option needs the opposite: authenticate the connection over
CredSSP but delegate nothing, leaving the server to present its own sign-in screen.

The fork adds `Config::credssp_credentialless` and threads it into
`CredsspSequence::init` as a `credentialless: bool` parameter, selecting
`CredSspMode::CredentialLess` (sspi already implements it — empty `TSCredentials` in the
final TSRequest). The only caller of `init` is `perform_credssp_step` in
`ironrdp-async`, which is vendored alongside (see `vendor/ironrdp-async/PATCHES.md`)
solely to pass the new argument.

Worth offering upstream as a `Config` field; drop both forks once a release carries an
equivalent knob.

`Cargo.toml` additionally sets `[lints.rust] warnings = { level = "allow", priority = 1 }`
so this vendored path dependency's warnings don't surface in Warpgate's builds. This is
not in `warpgate.patch` (which is source-only); re-apply it by hand on re-vendor.

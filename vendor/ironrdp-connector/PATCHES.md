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

## Backported upstream fixes

Both are in upstream IronRDP after 0.10.0 and drop out on re-vendor:

- Answer a connect-time Bandwidth Measure Stop with Bandwidth Measure Results
  (upstream #1465). FreeRDP-based servers such as GNOME Remote Desktop wait for the reply
  before licensing, so the connection stalled without it.
- During reactivation, report a Server Set Error Info PDU as the server ending the session
  instead of an "unexpected PDU" error (upstream #1467).

`Cargo.toml` additionally sets `[lints.rust] warnings = { level = "allow", priority = 1 }`
so this vendored path dependency's warnings don't surface in Warpgate's builds. This is
not in `warpgate.patch` (which is source-only); re-apply it by hand on re-vendor.

## `Config::support_dyn_vc_gfx_protocol`

Backport of upstream #1237: an opt-in flag that sets
`RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` in the Client Core Data early capability flags,
which servers require before they open the Graphics Pipeline channel. Warpgate sets it
together with registering `GraphicsPipelineClient` (never one without the other).
Drops out on re-vendor from an upstream release that contains #1237.

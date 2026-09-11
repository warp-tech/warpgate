Fork of `ironrdp-session` 0.11.0.

## Batched Share Control PDUs and reactivation share IDs

Some Windows RDP servers concatenate multiple Share Control PDUs in one MCS
`SendDataIndication`. The upstream session processor passes the complete MCS payload to a
single Share Control decoder, causing the first PDU's `totalLength` to disagree with the
decoded size. `src/x224/mod.rs` splits these payloads on each validated `totalLength` boundary
and processes every PDU in wire order.

During Deactivation-Reactivation, the server may also assign a new share ID. The existing
`ActiveStage::set_share_id` updated slow-path responses only; the fork also updates the
fast-path frame-acknowledgement processor.

Warpgate drives the reactivation sequence itself when `ActiveStage` emits `DeactivateAll`,
using the `ConnectionResult::activation_factory` returned by the initial connection. That
consumer-side logic lives in `warpgate-protocol-rdp` and is therefore not part of the
source-only `warpgate.patch`.

When re-vendoring, check whether upstream splits concatenated Share Control PDUs and updates
both active-stage processors before retaining these hunks.

## Save Session Info PDU

The upstream session processor decodes the Server Save Session Info PDU ([MS-RDPBCGR]
2.2.10.1) only to log it, so a consumer cannot tell whether the session is still sitting at
the target's sign-in screen. The fork surfaces it as `ProcessorOutput::SaveSessionInfo` /
`ActiveStageOutput::SaveSessionInfo`; `warpgate-protocol-rdp` uses it to audit the target's
own logon and to keep credentials typed at that sign-in screen out of session recordings.

## Bitmap row padding

RDP servers may pad `TS_BITMAP_DATA` beyond the destination rectangle — the width up to a
multiple of 4 pixels (xrdp) and/or each row up to a multiple of 4 bytes. The `apply_*`
functions re-chunk the source at the rectangle width, so the padding offsets every
subsequent row and shears the image. `warpgate.patch` crops each decoded bitmap to the
rectangle before it reaches them.

Upstream [PR #1436][1] carries the same fix but is unmerged ([#1452][2] was closed as its
duplicate), so drop this fork once a release contains either.

`Cargo.toml` additionally sets `[lints.rust] warnings = { level = "allow", priority = 1 }`
so this vendored path dependency's warnings don't surface in Warpgate's builds. This is not
in `warpgate.patch` (which is source-only); re-apply it by hand on re-vendor.

[1]: https://github.com/Devolutions/IronRDP/pull/1436
[2]: https://github.com/Devolutions/IronRDP/pull/1452

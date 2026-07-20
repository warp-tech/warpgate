Fork of `ironrdp-session` 0.11.0.

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

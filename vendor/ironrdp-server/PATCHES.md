Snapshot of `ironrdp-server` from IronRDP master at `1f4dee6b` (2026-10-27, "fix(server):
size the display for non-resizing clients before input", #2261), version `0.14.0`.

## Why a git snapshot

IronRDP published the rest of its crates on 2026-10-27/28 (`ironrdp-pdu` 0.11,
`ironrdp-connector` 0.12, `ironrdp-session` 0.13, `ironrdp-egfx` 0.5, ...) but not
`ironrdp-server`, whose last release (0.13.0) only builds against the previous generation.
`1f4dee6b` is the latest server commit whose dependencies are all those published
releases: the commits after it (#2232, #2272, #2293, #2107, ...) rely on changes to
`ironrdp-acceptor`, `ironrdp-error` and `ironrdp-dvc` that have no release yet.

Re-vendor from a published `ironrdp-server` 0.14+ once one exists.

## RemoteFX header blocks lost to a buffer retry

`RemoteFxHandler` carries the desktop size as an `Option`, and `Some` is what makes
`RfxEncoder::encode` emit the once-per-connection RFX header blocks (`TS_RFX_SYNC`,
`TS_RFX_CONTEXT`, `TS_RFX_CHANNELS`, `TS_RFX_CODEC_VERSIONS`). The snapshot `take()`s that
`Option` *inside* the loop that grows the output buffer on `NotEnoughBytes`, so a first
frame whose encoding overruns the buffer consumes the headers on the attempt that failed
and re-encodes without them. The buffer is sized from the frame's raw BGRA length, and RFX
always emits whole 64x64 tiles, so anything tile-padded — a few-pixel rect, or a thin strip
like a 1px window border — encodes larger than its source and takes that path. The headers
are never re-armed, so every later frame is rejected (FreeRDP: `rfx_process_message:
incomplete header blocks processing`) and the viewer stays black for the life of the
connection while input still works; see warp-tech/warpgate#2606.

`warpgate.patch` reads the size without consuming it and clears it only once a message
carrying the headers has been built. It also drops a `* 2` from the adjacent buffer-resize
`debug!`, which reported twice the size actually allocated. Upstream fixed the same bug
differently in #2274 (take before the loop, buffer reused), which is past the snapshot.

## Manifest

`Cargo.toml` is the snapshot's with the `*.workspace = true` package fields inlined, the
`path = "../..."` dependency entries removed (every dependency resolves to its crates.io
release), `[lints] workspace = true` replaced by `warnings = { level = "allow", priority = 1 }`
under `[lints.rust]`, and `zstd-safe = "8.2"` (upstream pins `7.2`; the streaming API the
code uses is unchanged). `LICENSE-*` are copies: in the IronRDP repository they are
symlinks to the workspace root. None of this is in `warpgate.patch` (source-only).

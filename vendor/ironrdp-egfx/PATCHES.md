Fork of `ironrdp-egfx` 0.3.0, with `src/` taken from IronRDP master at
`9b151c4c2e47c6014e1e8e55909d4180aa8bdb99`.

## Client-side Graphics Pipeline

IronRDP finished client-side MS-RDPEGFX after 0.3.0 was released (tracking issue
IronRDP#1464, motivated by IronRDP#1446, "Client can't connect to GNOME Remote Desktop").
The published 0.3.0 has the PDUs and the server side, but not the client compositor
(`GraphicsPipelineClient::drain_output` / `take_output_reset`), nor ClearCodec and
RemoteFX Progressive decode. GNOME Remote Desktop and KDE KRDP close any connection that
does not advertise the Graphics Pipeline, and without an H.264 decoder GNOME encodes it
with RemoteFX Progressive, so all of that is needed.

## Building against ironrdp-core 0.2.1

Master's decode errors carry a stream position (IronRDP#1275), passed as a trailing
`in: <cursor>` or `at: <offset>` argument to `invalid_field_err!` / `cast_length!` and as
an extra `position` parameter to `not_enough_bytes_err`. ironrdp-core 0.2.1, the release
the rest of the dependency tree uses, has neither, so those arguments are removed (23 call
sites in `src/pdu/cmd.rs` and `src/pdu/avc.rs`). The only behavioural difference from
master is that egfx's decode errors do not report the byte offset. Remove them again after
copying a newer master `src/` in.

`Cargo.toml` is the published one, plus master's optional `yuv` dependency (used by the
`openh264` feature, which Warpgate does not enable) and the vendored-code lint override.
`warpgate.patch` is the full source difference from 0.3.0.

Drop this fork once an `ironrdp-egfx` release carries the client compositor (the next
release after 0.3.0 cut from master past #1461).
